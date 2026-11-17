//! Buzz Connect handshake: the admin commands that offer, accept and end a
//! shared channel, and the two relay-to-relay HTTP endpoints the accepting
//! relay calls (docs/buzz-connect.md, "Protocol").
//!
//! - kind 9037 `connect-offer` (on A): a one-time code for a channel; the
//!   `OK` message is the `buzz://channel-connect` link.
//! - kind 9038 `connect-accept` (on B): B redeems the link's code at A with a
//!   fresh connection key (`POST /api/channel-connect/redeem`, NIP-98 signed
//!   by that key), then creates its copy of the channel with A's UUID.
//! - kind 9039 `disconnect` (either side): ends this side's connections for a
//!   channel. The other side learns of it from `POST
//!   /api/channel-connect/status` and ends its own.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use buzz_core::TenantContext;
use buzz_db::channel::{ChannelType, ChannelVisibility};
use buzz_db::channel_connection::{
    ChannelConnection, ConnectionRole, NewChannelConnection, OfferRedemption,
};
use buzz_db::DbError;
use nostr::{Event, Keys};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::access::AccessSlot;
use crate::api::bridge;
use crate::state::AppState;

/// How long an offer's link stays redeemable.
const OFFER_TTL: chrono::Duration = chrono::Duration::hours(24);

/// Bound on each relay-to-relay request.
const PEER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Path of the redeem endpoint.
pub(crate) const REDEEM_PATH: &str = "/api/channel-connect/redeem";

/// Path of the status endpoint.
pub(crate) const STATUS_PATH: &str = "/api/channel-connect/status";

/// Refusal for a code that is unknown, used or expired; never says which.
const CODE_REFUSED: &str = "invalid: the link is invalid, used or expired";

/// What a `buzz://channel-connect` link carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectLink {
    /// The offering relay's WebSocket URL.
    pub(crate) relay: String,
    /// The shared channel.
    pub(crate) channel: Uuid,
    /// The one-time code.
    pub(crate) code: String,
}

impl ConnectLink {
    /// Render as a `buzz://channel-connect?relay=…&channel=…&code=…` link.
    pub(crate) fn render(&self) -> String {
        let mut url = url::Url::parse("buzz://channel-connect").expect("static link base");
        url.query_pairs_mut()
            .append_pair("relay", &self.relay)
            .append_pair("channel", &self.channel.to_string())
            .append_pair("code", &self.code);
        url.to_string()
    }

    /// Parse a link; `None` for anything that is not a well-formed one with a
    /// `ws`/`wss` relay.
    pub(crate) fn parse(link: &str) -> Option<Self> {
        let url = url::Url::parse(link.trim()).ok()?;
        if url.scheme() != "buzz" || url.host_str() != Some("channel-connect") {
            return None;
        }
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        let relay = param("relay")?;
        let relay_url = url::Url::parse(&relay).ok()?;
        if !matches!(relay_url.scheme(), "ws" | "wss") || relay_url.host_str().is_none() {
            return None;
        }
        let code = param("code")?;
        if code.is_empty() || code.len() > 128 {
            return None;
        }
        Some(Self {
            relay,
            channel: param("channel")?.parse().ok()?,
            code,
        })
    }
}

/// The HTTP origin of a relay's WebSocket URL, for its relay-to-relay
/// endpoints: `wss://a.example/` → `https://a.example`.
pub(crate) fn http_origin(relay_url: &str) -> Option<String> {
    let url = url::Url::parse(relay_url).ok()?;
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        _ => return None,
    };
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

fn code_hash(code: &str) -> [u8; 32] {
    Sha256::digest(code.as_bytes()).into()
}

fn tag_value(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some(name))
            .then(|| parts.get(1).cloned())
            .flatten()
    })
}

fn channel_tag(event: &Event) -> Result<Uuid, String> {
    tag_value(event, "channel")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "invalid: missing or malformed channel tag".to_string())
}

/// This community's public WebSocket URL.
fn own_relay_url(state: &AppState, tenant: &TenantContext) -> String {
    crate::api::nip05::relay_url_for_tenant_host(&state.config.relay_url, tenant.host())
}

/// This community's display name for the other side. The host, until
/// communities carry a name of their own.
fn own_community_name(tenant: &TenantContext) -> String {
    tenant.host().to_owned()
}

/// Run one Buzz Connect command. `Ok` carries the `OK` message.
pub(crate) async fn handle_command(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: &Event,
) -> Result<String, String> {
    // Admin commands are freshly signed; refuse a replayed capture.
    let age = chrono::Utc::now().timestamp() - event.created_at.as_secs() as i64;
    if age.abs() > 120 {
        return Err("invalid: command timestamp out of range (max ±120s)".into());
    }
    let sender = event.pubkey.to_hex();
    let role = state
        .db
        .get_relay_member(tenant.community(), &sender)
        .await
        .map_err(|e| format!("error: database error: {e}"))?
        .map(|member| member.role);
    if !matches!(role.as_deref(), Some("admin" | "owner")) {
        return Err("restricted: must be a community admin or owner".into());
    }
    match event.kind.as_u16() as u32 {
        buzz_core::kind::KIND_CHANNEL_CONNECT_OFFER => offer(state, tenant, event).await,
        buzz_core::kind::KIND_CHANNEL_CONNECT_ACCEPT => accept(state, tenant, event).await,
        buzz_core::kind::KIND_CHANNEL_DISCONNECT => disconnect(state, tenant, event).await,
        _ => Err("invalid: not a channel connection command".into()),
    }
}

async fn offer(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: &Event,
) -> Result<String, String> {
    let channel_id = channel_tag(event)?;
    let channel = live_channel(state, tenant, channel_id).await?;
    if !matches!(channel.channel_type.as_str(), "stream" | "forum") {
        return Err("invalid: only stream and forum channels can be shared".into());
    }
    let keys = Keys::generate();
    let code = hex::encode(rand::random::<[u8; 32]>());
    state
        .db
        .create_channel_connection(NewChannelConnection {
            community: tenant.community(),
            channel_id,
            role: ConnectionRole::Offerer,
            local_pubkey: &keys.public_key().to_hex(),
            local_secret_key: &keys.secret_key().to_secret_hex(),
            offer_code_hash: Some(code_hash(&code)),
            offer_expires_at: Some(chrono::Utc::now() + OFFER_TTL),
            peer_pubkey: None,
            peer_relay_url: None,
            peer_community_name: None,
            created_by: &event.pubkey.to_hex(),
        })
        .await
        .map_err(|e| format!("error: could not create the offer: {e}"))?;
    Ok(ConnectLink {
        relay: own_relay_url(state, tenant),
        channel: channel_id,
        code,
    }
    .render())
}

async fn live_channel(
    state: &AppState,
    tenant: &TenantContext,
    channel_id: Uuid,
) -> Result<buzz_db::channel::ChannelRecord, String> {
    match state.db.get_channel(tenant.community(), channel_id).await {
        Ok(channel) if channel.deleted_at.is_none() && channel.archived_at.is_none() => Ok(channel),
        Ok(_) | Err(DbError::ChannelNotFound(_)) => Err("invalid: channel not found".into()),
        Err(e) => Err(format!("error: database error: {e}")),
    }
}

/// What B presents to A when redeeming a code.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RedeemRequest {
    /// The one-time code from the link.
    pub(crate) code: String,
    /// The channel the link names.
    pub(crate) channel: Uuid,
    /// B's public WebSocket URL.
    pub(crate) relay: String,
    /// B's display name.
    pub(crate) name: String,
}

/// What A answers to a redeemed code.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RedeemResponse {
    /// A's connection pubkey (hex), which B admits.
    pub(crate) pubkey: String,
    /// A's display name.
    pub(crate) community_name: String,
    /// The shared channel as A has it.
    pub(crate) channel: SharedChannel,
}

/// The facts of the shared channel B copies.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SharedChannel {
    /// The channel UUID, the same on both sides.
    pub(crate) id: Uuid,
    /// Its name on A.
    pub(crate) name: String,
    /// `stream` or `forum`.
    pub(crate) channel_type: String,
    /// `open` or `private`.
    pub(crate) visibility: String,
    /// Its description, if any.
    pub(crate) about: Option<String>,
}

async fn accept(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: &Event,
) -> Result<String, String> {
    let link = tag_value(event, "link")
        .as_deref()
        .and_then(ConnectLink::parse)
        .ok_or_else(|| "invalid: missing or malformed channel-connect link".to_string())?;
    let own_relay = own_relay_url(state, tenant);
    let keys = Keys::generate();
    let answer = redeem_at_peer(
        &link,
        &keys,
        &RedeemRequest {
            code: link.code.clone(),
            channel: link.channel,
            relay: own_relay,
            name: own_community_name(tenant),
        },
    )
    .await?;
    if answer.channel.id != link.channel
        || answer.pubkey.len() != 64
        || hex::decode(&answer.pubkey).is_err()
        || answer.community_name.trim().is_empty()
    {
        return Err("error: the other relay answered with an inconsistent connection".into());
    }
    let channel_type: ChannelType = answer
        .channel
        .channel_type
        .parse()
        .map_err(|_| "error: the other relay sent an unknown channel type".to_string())?;
    let visibility: ChannelVisibility = answer
        .channel
        .visibility
        .parse()
        .map_err(|_| "error: the other relay sent an unknown visibility".to_string())?;
    let creator = event.pubkey.to_bytes();
    let create = |name: String| {
        let about = answer.channel.about.clone();
        async move {
            state
                .db
                .create_channel_with_id(
                    tenant.community(),
                    link.channel,
                    &name,
                    channel_type,
                    visibility,
                    about.as_deref(),
                    &creator,
                    None,
                )
                .await
        }
    };
    // On a name clash the copy gets the other community's name in brackets.
    let created = match create(answer.channel.name.clone()).await {
        Err(DbError::ChannelNameTaken(_)) => {
            create(format!(
                "{} ({})",
                answer.channel.name, answer.community_name
            ))
            .await
        }
        other => other,
    };
    match created {
        Ok((_, true)) => {}
        // Never mirror into a channel that already exists here: its id came
        // from the other relay.
        Ok((_, false)) => return Err("invalid: that channel already exists here".into()),
        Err(DbError::ChannelNameTaken(name)) => {
            return Err(format!("invalid: a channel named {name:?} already exists"))
        }
        Err(e) => return Err(format!("error: could not create the channel: {e}")),
    }
    state
        .db
        .create_channel_connection(NewChannelConnection {
            community: tenant.community(),
            channel_id: link.channel,
            role: ConnectionRole::Acceptor,
            local_pubkey: &keys.public_key().to_hex(),
            local_secret_key: &keys.secret_key().to_secret_hex(),
            offer_code_hash: None,
            offer_expires_at: None,
            peer_pubkey: Some(&answer.pubkey.to_ascii_lowercase()),
            peer_relay_url: Some(&link.relay),
            peer_community_name: Some(&answer.community_name),
            created_by: &event.pubkey.to_hex(),
        })
        .await
        .map_err(|e| format!("error: could not record the connection: {e}"))?;
    publish_channel_state(state, tenant, link.channel).await;
    super::mirror::wake();
    Ok(link.channel.to_string())
}

/// Redeem `link` at the offering relay, authenticated by `keys`.
async fn redeem_at_peer(
    link: &ConnectLink,
    keys: &Keys,
    request: &RedeemRequest,
) -> Result<RedeemResponse, String> {
    let origin = http_origin(&link.relay)
        .ok_or_else(|| "invalid: the link's relay is not a ws:// or wss:// URL".to_string())?;
    let response = post_signed(&format!("{origin}{REDEEM_PATH}"), keys, request)
        .await
        .map_err(|e| format!("error: could not reach the other relay: {e}"))?;
    match response.status() {
        status if status.is_success() => response
            .json::<RedeemResponse>()
            .await
            .map_err(|e| format!("error: the other relay answered badly: {e}")),
        StatusCode::NOT_FOUND | StatusCode::GONE => Err(CODE_REFUSED.into()),
        status => Err(format!(
            "error: the other relay refused the link ({status})"
        )),
    }
}

/// POST `body` as JSON to `url` with a NIP-98 header signed by `keys`.
pub(crate) async fn post_signed<T: Serialize>(
    url: &str,
    keys: &Keys,
    body: &T,
) -> anyhow::Result<reqwest::Response> {
    let bytes = serde_json::to_vec(body)?;
    let authorization = crate::nip98::nip98_header(keys, url, &bytes)?;
    Ok(reqwest::Client::new()
        .post(url)
        .timeout(PEER_REQUEST_TIMEOUT)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes)
        .send()
        .await?)
}

async fn disconnect(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: &Event,
) -> Result<String, String> {
    let channel_id = channel_tag(event)?;
    let connections = state
        .db
        .list_channel_connections(tenant.community(), channel_id)
        .await
        .map_err(|e| format!("error: database error: {e}"))?;
    let mut ended = 0;
    for connection in connections
        .iter()
        .filter(|c| c.state != buzz_db::channel_connection::ConnectionState::Disconnected)
    {
        if super::disconnect(state, tenant, connection.id, &event.id.to_hex())
            .await
            .map_err(|e| format!("error: database error: {e}"))?
            .is_some()
        {
            ended += 1;
        }
    }
    if ended == 0 {
        return Err("invalid: the channel has no live connection".into());
    }
    publish_channel_state(state, tenant, channel_id).await;
    super::mirror::wake();
    Ok(format!("disconnected {ended}"))
}

/// Republish the channel's relay-signed group state, whose kind 39000 carries
/// the `connected` tags. Best effort, like every other caller.
pub(crate) async fn publish_channel_state(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    channel_id: Uuid,
) {
    if let Err(error) =
        crate::handlers::side_effects::emit_group_discovery_events(tenant, state, channel_id).await
    {
        tracing::warn!(%channel_id, %error, "channel connect: group state not republished");
    }
}

/// `["connected", <peer relay url>, <peer community name>]` for each active
/// connection of a channel, for its kind 39000.
pub(crate) fn connected_tags(connections: &[ChannelConnection]) -> Vec<Vec<String>> {
    connections
        .iter()
        .filter(|c| c.state == buzz_db::channel_connection::ConnectionState::Active)
        .filter_map(|c| {
            Some(vec![
                "connected".to_owned(),
                c.peer_relay_url.clone()?,
                c.peer_community_name.clone().unwrap_or_default(),
            ])
        })
        .collect()
}

type HttpResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

/// Bind the tenant and verify the request's NIP-98 proof (with replay
/// protection) for one of the relay-to-relay endpoints. The caller is
/// another relay's connection key, never a member, so this is exempt from
/// the membership gate by design; the code or the active row authorizes.
async fn authenticate_peer(
    state: &Arc<AppState>,
    slot: &AccessSlot,
    headers: &HeaderMap,
    path: &'static str,
    body: &[u8],
) -> Result<(TenantContext, nostr::PublicKey), (StatusCode, Json<Value>)> {
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&**state, raw_host)
        .await
        .map_err(|_| {
            crate::api::api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;
    let url = bridge::nip98_expected_url(&state.config.relay_url, &tenant, path);
    let bridge::VerifiedBridgeAuth {
        pubkey,
        event_id_bytes,
        ..
    } = bridge::verify_bridge_auth_with_options(
        slot,
        headers,
        "POST",
        &url,
        Some(body),
        true,
        true,
    )?;
    slot.attempt(crate::access::AuthMethod::Nip98, Some(pubkey), true);
    slot.in_community(tenant.community());
    slot.gate(
        bridge::check_nip98_replay(state, &tenant, event_id_bytes).await,
        bridge::ReplayRejection::auth_result,
    )?;
    slot.finish(crate::access::AuthResult::Success);
    Ok((tenant, pubkey))
}

/// `POST /api/channel-connect/redeem` on the offering relay: redeem a
/// one-time code for the signing connection key.
pub(crate) async fn redeem(
    State(state): State<Arc<AppState>>,
    slot: AccessSlot,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> HttpResult {
    let (tenant, pubkey) = authenticate_peer(&state, &slot, &headers, REDEEM_PATH, &body).await?;
    let request: RedeemRequest = serde_json::from_slice(&body)
        .map_err(|_| crate::api::api_error(StatusCode::BAD_REQUEST, "invalid redeem request"))?;
    if http_origin(&request.relay).is_none() || request.name.trim().is_empty() {
        return Err(crate::api::api_error(
            StatusCode::BAD_REQUEST,
            "invalid redeem request",
        ));
    }
    let internal = |e: DbError| crate::api::internal_error(&format!("channel connect: {e}"));
    let connection = state
        .db
        .redeem_channel_connection_offer(
            tenant.community(),
            OfferRedemption {
                code_hash: code_hash(&request.code),
                peer_pubkey: &pubkey.to_hex(),
                peer_relay_url: &request.relay,
                peer_community_name: request.name.trim(),
            },
        )
        .await
        .map_err(internal)?
        .ok_or_else(|| crate::api::api_error(StatusCode::NOT_FOUND, CODE_REFUSED))?;
    if connection.channel_id != request.channel {
        // The code was for another channel: end what it opened.
        super::disconnect(&state, &tenant, connection.id, "channel-connect-mismatch")
            .await
            .map_err(internal)?;
        return Err(crate::api::api_error(StatusCode::NOT_FOUND, CODE_REFUSED));
    }
    let channel = state
        .db
        .get_channel(tenant.community(), connection.channel_id)
        .await
        .map_err(internal)?;
    publish_channel_state(&state, &tenant, connection.channel_id).await;
    super::mirror::wake();
    Ok(Json(
        serde_json::to_value(RedeemResponse {
            pubkey: connection.local_pubkey,
            community_name: own_community_name(&tenant),
            channel: SharedChannel {
                id: channel.id,
                name: channel.name,
                channel_type: channel.channel_type,
                visibility: channel.visibility,
                about: channel.description,
            },
        })
        .unwrap_or(Value::Null),
    ))
}

/// `POST /api/channel-connect/status` on either relay: whether the signing
/// connection key still has an active connection here. The other side asks
/// before each pull, so a disconnect here ends it there too.
pub(crate) async fn status(
    State(state): State<Arc<AppState>>,
    slot: AccessSlot,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> HttpResult {
    let (tenant, pubkey) = authenticate_peer(&state, &slot, &headers, STATUS_PATH, &body).await?;
    let active = super::peer_scope(&state, tenant.community(), &pubkey.to_bytes())
        .await
        .map_err(|e| crate::api::internal_error(&format!("channel connect: {e}")))?
        .is_some();
    Ok(Json(serde_json::json!({ "active": active })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_round_trips_and_rejects_foreign_shapes() {
        let link = ConnectLink {
            relay: "wss://a.example".into(),
            channel: Uuid::new_v4(),
            code: "abc123".into(),
        };
        assert_eq!(ConnectLink::parse(&link.render()), Some(link.clone()));
        for bad in [
            "https://channel-connect?relay=wss://a.example&channel=x&code=y",
            "buzz://join?relay=wss://a.example",
            &link.render().replace("wss%3A", "https%3A"),
            &link.render().replace("code=abc123", "code="),
            &link
                .render()
                .replace(&link.channel.to_string(), "not-a-uuid"),
        ] {
            assert_eq!(ConnectLink::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn http_origin_maps_websocket_schemes() {
        assert_eq!(
            http_origin("wss://a.example/").as_deref(),
            Some("https://a.example")
        );
        assert_eq!(
            http_origin("ws://127.0.0.1:3000").as_deref(),
            Some("http://127.0.0.1:3000")
        );
        assert_eq!(http_origin("https://a.example"), None);
    }
}
