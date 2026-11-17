//! Buzz Connect: scoped access for a peer relay's connection key
//! (docs/buzz-connect.md, "Scoped access, as implemented").
//!
//! A key that matches an `active` `channel_connections.peer_pubkey` is never a
//! relay member, so on a closed relay every route refuses it. Three seams
//! recognise it instead, each through this module: WebSocket AUTH, and HTTP
//! `POST /query` and `POST /count`. There it may read one channel's synced
//! kinds and nothing else. On an open relay, where any fresh key is admitted,
//! those seams recognise it first; other routes treat it like any unknown key,
//! which grants it nothing a peer could not get with another key.

use std::collections::HashSet;

use axum::http::StatusCode;
use axum::Json;
use buzz_core::kind::{
    KIND_DELETION, KIND_REACTION, KIND_STREAM_MESSAGE, KIND_STREAM_MESSAGE_EDIT,
};
use buzz_core::{CommunityId, TenantContext};
use buzz_db::channel_connection::{ChannelConnection, PeerConnectionScope};
use nostr::{Alphabet, Filter, SingleLetterTag};
use serde_json::Value;
use uuid::Uuid;

use crate::protocol::ClientMessage;
use crate::state::AppState;

pub(crate) mod handshake;
pub(crate) mod mirror;

/// The event kinds a peer connection may read from its channel.
pub(crate) const PEER_READABLE_KINDS: [u32; 4] = [
    KIND_STREAM_MESSAGE,
    KIND_REACTION,
    KIND_STREAM_MESSAGE_EDIT,
    KIND_DELETION,
];

/// Refusal sent for a filter outside the peer scope.
pub(crate) const FILTER_OUT_OF_SCOPE: &str =
    "restricted: a channel connection may only read its channel's messages";

/// Refusal sent for any frame a peer connection may not send at all.
pub(crate) const READ_ONLY: &str = "restricted: a channel connection is read-only";

/// The channel scope of `pubkey` when it is an active connection key in
/// `community`. Read from the writer on every call: a disconnect stops the
/// next admission and the next HTTP request.
pub(crate) async fn peer_scope(
    state: &AppState,
    community: CommunityId,
    pubkey: &[u8],
) -> buzz_db::Result<Option<PeerConnectionScope>> {
    state
        .db
        .active_peer_connection(community, &hex::encode(pubkey))
        .await
}

/// Whether `connection_id` supplied `event_id` here through the mirror path.
/// Serving that peer omits such events, so nothing echoes back (loop filter).
pub(crate) async fn supplied_by(
    state: &AppState,
    community: CommunityId,
    connection_id: Uuid,
    event_id: &[u8],
) -> buzz_db::Result<bool> {
    Ok(!state
        .db
        .mirrored_event_ids_from(community, connection_id, &[event_id.to_vec()])
        .await?
        .is_empty())
}

/// Most authors one profile read may name.
const MAX_PROFILE_AUTHORS: usize = 100;

/// The authors of a peer's profile read: a filter of exactly `kinds:[0]`
/// and 1..=100 `authors`, with at most a `limit` beside them. `None` for
/// any other filter.
fn profile_read_authors(raw: &Value) -> Option<Vec<Vec<u8>>> {
    let fields = raw.as_object()?;
    if !fields
        .keys()
        .all(|key| matches!(key.as_str(), "kinds" | "authors" | "limit"))
        || fields.get("kinds")? != &serde_json::json!([0])
    {
        return None;
    }
    let authors = fields.get("authors")?.as_array()?;
    if authors.is_empty() || authors.len() > MAX_PROFILE_AUTHORS {
        return None;
    }
    authors
        .iter()
        .map(|author| {
            let bytes = hex::decode(author.as_str()?).ok()?;
            (bytes.len() == 32).then_some(bytes)
        })
        .collect()
}

/// `None` when every filter stays inside `channels`; otherwise the refusal.
///
/// Each filter must list `kinds`, all from [`PEER_READABLE_KINDS`], name only
/// `channels` in a non-empty `#h`, and carry no NIP-50 `search`. The rest of
/// the read path then scopes SQL and live fan-out to those `#h` values.
pub(crate) fn filters_refusal(filters: &[Filter], channels: &[Uuid]) -> Option<&'static str> {
    let h = SingleLetterTag::lowercase(Alphabet::H);
    let in_scope = |filter: &Filter| {
        filter.search.is_none()
            && filter.kinds.as_ref().is_some_and(|kinds| {
                !kinds.is_empty()
                    && kinds
                        .iter()
                        .all(|kind| PEER_READABLE_KINDS.contains(&u32::from(kind.as_u16())))
            })
            && filter.generic_tags.get(&h).is_some_and(|values| {
                !values.is_empty()
                    && values.iter().all(|value| {
                        value
                            .parse::<Uuid>()
                            .is_ok_and(|channel| channels.contains(&channel))
                    })
            })
    };
    if filters.is_empty() || !filters.iter().all(in_scope) {
        return Some(FILTER_OUT_OF_SCOPE);
    }
    None
}

/// `None` when a peer connection may send `msg`; otherwise the refusal.
/// AUTH and CLOSE pass; EVENT and artifact sync never do.
pub(crate) fn frame_refusal(msg: &ClientMessage, channels: &[Uuid]) -> Option<&'static str> {
    match msg {
        ClientMessage::Event(_) | ClientMessage::ArtifactSync { .. } => Some(READ_ONLY),
        ClientMessage::Req { filters, .. } | ClientMessage::Count { filters, .. } => {
            filters_refusal(filters, channels)
        }
        _ => None,
    }
}

/// The top-level keys a peer's HTTP filter may carry. Bridge extensions
/// (thread windows, feeds, snapshots, artifact reads) answer from the
/// caller's own membership and are not offered to a peer.
const HTTP_FILTER_KEYS: [&str; 6] = ["ids", "authors", "kinds", "since", "until", "limit"];

/// Answer `POST /query` (`count = false`) or `POST /count` for an admitted
/// peer connection: plain NIP-01 filters, inside its scope, nothing else.
pub(crate) async fn http_read(
    state: &AppState,
    tenant: &TenantContext,
    scope: PeerConnectionScope,
    body: &[u8],
    count: bool,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let refuse = |status: StatusCode, message: &str| {
        (
            status,
            Json(serde_json::json!({ "error": "restricted", "message": message })),
        )
    };
    let raw: Vec<Value> = serde_json::from_slice(body)
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "invalid filters"))?;
    // Profiles of the channel's authors, and of nobody else.
    if !count && !raw.is_empty() {
        if let Some(authors) = raw
            .iter()
            .map(profile_read_authors)
            .collect::<Option<Vec<_>>>()
        {
            let authors: Vec<Vec<u8>> = authors.into_iter().flatten().collect();
            return read_author_profiles(state, tenant, scope, &authors)
                .await
                .map(Json)
                .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "query failed"));
        }
    }
    let plain = raw.iter().all(|filter| {
        filter.as_object().is_some_and(|fields| {
            fields
                .keys()
                .all(|key| HTTP_FILTER_KEYS.contains(&key.as_str()) || is_tag_key(key))
        })
    });
    let filters: Vec<Filter> = raw
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "invalid filters"))?;
    let channels = [scope.channel_id];
    if !plain || filters_refusal(&filters, &channels).is_some() {
        return Err(refuse(StatusCode::FORBIDDEN, FILTER_OUT_OF_SCOPE));
    }
    // An exact count needs every constraint in SQL.
    if count
        && !filters
            .iter()
            .all(crate::handlers::req::filter_fully_pushable)
    {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "count needs filters the relay can count exactly",
        ));
    }

    let mut total = 0_i64;
    let mut seen = HashSet::new();
    let mut events = Vec::new();
    for filter in &filters {
        let mut query = crate::handlers::req::build_event_query_from_filter(
            filter,
            &[],
            state,
            tenant.community(),
        )
        .await;
        crate::handlers::req::apply_channel_scope_to_query(&mut query, filter, None, &channels);
        if count {
            total += state
                .db
                .count_events(&query)
                .await
                .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "query failed"))?;
            continue;
        }
        let rows = state
            .db
            .query_events(&query)
            .await
            .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "query failed"))?;
        let ids: Vec<Vec<u8>> = rows
            .iter()
            .map(|row| row.event.id.as_bytes().to_vec())
            .collect();
        let supplied = state
            .db
            .mirrored_event_ids_from(tenant.community(), scope.connection_id, &ids)
            .await
            .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "query failed"))?;
        for row in rows {
            if row.channel_id == Some(scope.channel_id)
                && !supplied.contains(row.event.id.as_bytes().as_slice())
                && seen.insert(row.event.id)
            {
                events.push(serde_json::to_value(&row.event).unwrap_or(Value::Null));
            }
        }
    }
    Ok(Json(if count {
        serde_json::json!({ "count": total })
    } else {
        Value::Array(events)
    }))
}

/// The latest kind 0 of each of `authors` who has posted in the peer's
/// channel; the rest are left out without saying so.
async fn read_author_profiles(
    state: &AppState,
    tenant: &TenantContext,
    scope: PeerConnectionScope,
    authors: &[Vec<u8>],
) -> buzz_db::Result<Value> {
    let allowed = state
        .db
        .channel_authors_among(tenant.community(), scope.channel_id, authors)
        .await?;
    if allowed.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    let mut filter = Filter::new().kind(nostr::Kind::Metadata);
    for author in &allowed {
        if let Ok(pubkey) = nostr::PublicKey::from_slice(author) {
            filter = filter.author(pubkey);
        }
    }
    let query = crate::handlers::req::build_event_query_from_filter(
        &filter,
        &[],
        state,
        tenant.community(),
    )
    .await;
    let rows = state.db.query_events(&query).await?;
    Ok(Value::Array(
        rows.into_iter()
            .filter(|row| {
                row.event.kind == nostr::Kind::Metadata
                    && row.channel_id.is_none()
                    && allowed.contains(row.event.pubkey.to_bytes().as_slice())
            })
            .filter_map(|row| serde_json::to_value(&row.event).ok())
            .collect(),
    ))
}

fn is_tag_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next() == Some('#')
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.next().is_none()
}

/// End a connection from this side: no new admission from the next read
/// on, and every live socket of the peer key closed on every pod now.
/// `event_id` is the admin command that ended it, for the closing `OK`.
///
/// Returns the row as disconnected, or `None` when it was not live.
pub(crate) async fn disconnect(
    state: &AppState,
    tenant: &TenantContext,
    connection_id: Uuid,
    event_id: &str,
) -> buzz_db::Result<Option<ChannelConnection>> {
    let ended = state
        .db
        .disconnect_channel_connection(tenant.community(), connection_id)
        .await?;
    if let Some(peer) = ended
        .as_ref()
        .and_then(|connection| connection.peer_pubkey.as_deref())
        .and_then(|peer| hex::decode(peer).ok())
    {
        state.disconnect_pubkey_clusterwide(
            tenant,
            &peer,
            event_id,
            "blocked: channel connection ended",
        );
    }
    Ok(ended)
}

#[cfg(test)]
mod connect_postgres_tests;
#[cfg(test)]
mod postgres_tests;
