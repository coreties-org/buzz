//! Buzz Connect pull mirroring (docs/buzz-connect.md, "Mirroring").
//!
//! One worker per `active` connection, run by the pod holding the mirror
//! leader lock. A worker asks the peer whether the connection is still
//! active there, authenticates at the peer with NIP-42 using this side's
//! connection key, reads the channel's synced kinds from its cursor (paging
//! back when the backlog is longer than a page), keeps the subscription open
//! for live events, and stores each event through the mirror ingest path
//! ([`IngestAuth::Mirror`]). Authors' profiles come from an author-bounded
//! `POST /query`.
//!
//! Exactly once: an event is recorded in `mirrored_events` before it is
//! stored, so the loop filter already hides it from the peer when its
//! fan-out runs; storage is idempotent, and only a fresh insert fans out and
//! notifies. The cursor advances only over events that are settled (stored or
//! refused for good), so a crash re-reads and re-applies harmlessly.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use buzz_core::TenantContext;
use buzz_db::channel_connection::{ChannelConnection, ConnectionState};
use buzz_ws_client::{NostrWsConnection, RelayMessage, WsClientError};
use nostr::{Event, Keys};
use serde_json::json;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use crate::handlers::ingest::{ingest_event, IngestAuth, IngestError};
use crate::state::AppState;

/// Advisory lock key of the mirror leader ("BUZZCONN").
const MIRROR_LOCK_KEY: i64 = 0x4255_5A5A_434F_4E4E;

/// Backstop between supervisor passes; [`wake`] runs one sooner.
const SUPERVISE_EVERY: Duration = Duration::from_secs(30);

/// Events per history page.
const PAGE: usize = 500;

/// How long a worker waits on a quiet socket before it re-checks its row
/// and retries what is pending.
const IDLE: Duration = Duration::from_secs(30);

/// Retry passes for an event whose parent or target has not arrived yet.
const MAX_ATTEMPTS: u32 = 6;

/// Reconnect backoff cap.
const BACKOFF_CAP: Duration = Duration::from_secs(60);

static SUPERVISOR: Notify = Notify::const_new();
static WORKERS: Notify = Notify::const_new();

/// A connection was created, redeemed or ended: run the supervisor now and
/// have every worker re-check its row.
pub(crate) fn wake() {
    SUPERVISOR.notify_one();
    WORKERS.notify_waiters();
}

/// Start the mirror supervisor. Every pod runs one; only the pod holding the
/// leader lock runs workers, so a multi-pod relay pulls each connection once.
pub fn spawn_supervisor(state: Arc<AppState>) -> JoinHandle<()> {
    tokio::spawn(supervise(state))
}

async fn supervise(state: Arc<AppState>) {
    let mut leader: Option<buzz_db::SessionLeader> = None;
    let mut workers: HashMap<Uuid, JoinHandle<()>> = HashMap::new();
    loop {
        if let Some(guard) = leader.as_mut() {
            if !guard.is_live().await {
                warn!("channel connect: mirror leader lock lost");
                leader = None;
            }
        }
        if leader.is_none() {
            leader = match state.db.try_lock_session_leader(MIRROR_LOCK_KEY).await {
                Ok(guard) => guard,
                Err(error) => {
                    warn!(%error, "channel connect: mirror leader lock failed");
                    None
                }
            };
        }
        let active = match leader {
            Some(_) => state.db.all_active_channel_connections().await,
            None => Ok(Vec::new()),
        };
        match active {
            Ok(active) => {
                let ids: HashSet<Uuid> = active.iter().map(|c| c.id).collect();
                workers.retain(|id, worker| {
                    let keep = ids.contains(id) && !worker.is_finished();
                    if !keep {
                        worker.abort();
                    }
                    keep
                });
                for connection in active {
                    if workers.contains_key(&connection.id) {
                        continue;
                    }
                    match state.db.lookup_community_host(connection.community).await {
                        Ok(Some(host)) => {
                            let tenant = TenantContext::resolved(connection.community, host);
                            workers.insert(
                                connection.id,
                                tokio::spawn(run_connection(state.clone(), tenant, connection)),
                            );
                        }
                        Ok(None) => {}
                        Err(error) => warn!(%error, "channel connect: community host lookup"),
                    }
                }
            }
            // Keep the running workers; the next pass reads again.
            Err(error) => warn!(%error, "channel connect: listing connections failed"),
        }
        tokio::select! {
            _ = SUPERVISOR.notified() => {}
            _ = tokio::time::sleep(SUPERVISE_EVERY) => {}
        }
    }
}

/// Why a session ended without an error.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// This side's row is no longer active.
    Locally,
    /// The peer no longer knows the connection; this side ends it too.
    AtPeer,
}

/// One event waiting for its parent or target.
struct Pending {
    event: Event,
    attempts: u32,
}

struct Worker {
    state: Arc<AppState>,
    tenant: TenantContext,
    connection_id: Uuid,
    channel_id: Uuid,
    peer_url: String,
    peer_origin: String,
    keys: Keys,
    cursor: i64,
    last: Option<(nostr::Timestamp, nostr::EventId)>,
    pending: Vec<Pending>,
    profiles_fetched: HashSet<nostr::PublicKey>,
    authors_seen: HashSet<nostr::PublicKey>,
}

/// Pull one connection until it ends on either side. Errors reconnect with
/// jittered, capped backoff.
pub(crate) async fn run_connection(
    state: Arc<AppState>,
    tenant: TenantContext,
    connection: ChannelConnection,
) {
    let (Ok(keys), Some(peer_url)) = (
        Keys::parse(&connection.local_secret_key),
        connection.peer_relay_url.clone(),
    ) else {
        warn!(connection = %connection.id, "channel connect: unusable connection row");
        return;
    };
    let Some(peer_origin) = super::handshake::http_origin(&peer_url) else {
        warn!(connection = %connection.id, "channel connect: unusable peer relay URL");
        return;
    };
    let mut worker = Worker {
        state,
        tenant,
        connection_id: connection.id,
        channel_id: connection.channel_id,
        peer_url,
        peer_origin,
        keys,
        cursor: connection.cursor_created_at,
        last: None,
        pending: Vec::new(),
        profiles_fetched: HashSet::new(),
        authors_seen: HashSet::new(),
    };
    let mut failures = 0_u32;
    loop {
        match worker.session(&mut failures).await {
            Ok(Ended::Locally) => return,
            Ok(Ended::AtPeer) => {
                worker.end_here().await;
                return;
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                let delay = backoff(failures);
                warn!(connection = %worker.connection_id, %error, ?delay, "channel connect: pull failed");
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = WORKERS.notified() => {}
                }
            }
        }
    }
}

/// Exponential backoff from 1 s, capped, with up to 25% jitter.
fn backoff(failures: u32) -> Duration {
    let base = Duration::from_secs(1 << failures.clamp(1, 7).saturating_sub(1)).min(BACKOFF_CAP);
    base + base.mul_f64(rand::random::<f64>() * 0.25)
}

/// Whether a refused mirrored event may succeed later, once its parent,
/// reaction target or edit/delete target has arrived.
fn retryable(message: &str) -> bool {
    message.contains("not found")
}

impl Worker {
    async fn session(&mut self, failures: &mut u32) -> anyhow::Result<Ended> {
        if !self.locally_active().await? {
            return Ok(Ended::Locally);
        }
        if !self.active_at_peer().await? {
            return Ok(Ended::AtPeer);
        }
        let mut ws =
            NostrWsConnection::connect_authenticated(&self.peer_url, &self.keys, None).await?;
        *failures = 0;
        info!(connection = %self.connection_id, peer = %self.peer_url, "channel connect: pulling");
        let history = self.read_history(&mut ws).await?;
        self.apply_batch(history).await?;
        loop {
            let message = tokio::select! {
                message = ws.next_event(IDLE) => message,
                _ = WORKERS.notified() => Err(WsClientError::Timeout),
            };
            match message {
                Ok(RelayMessage::Event {
                    subscription_id,
                    event,
                }) if subscription_id == "live" => self.apply_batch(vec![*event]).await?,
                Ok(RelayMessage::Closed { message, .. }) => {
                    anyhow::bail!("peer closed the subscription: {message}")
                }
                Ok(_) => {}
                Err(WsClientError::Timeout) => {
                    if !self.locally_active().await? {
                        let _ = ws.disconnect().await;
                        return Ok(Ended::Locally);
                    }
                    self.settle_pending().await?;
                    self.advance().await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn filter(&self, until: Option<i64>) -> serde_json::Value {
        let mut filter = json!({
            "kinds": super::PEER_READABLE_KINDS,
            "#h": [self.channel_id.to_string()],
            "since": self.cursor,
            "limit": PAGE,
        });
        if let Some(until) = until {
            filter["until"] = json!(until);
        }
        filter
    }

    /// Open the live subscription from the cursor and read the history up
    /// to now, paging back while pages come back full. The live subscription
    /// stays open, so nothing falls between history and live.
    async fn read_history(&self, ws: &mut NostrWsConnection) -> anyhow::Result<Vec<Event>> {
        let mut events: HashMap<nostr::EventId, Event> = HashMap::new();
        ws.send_raw(&json!(["REQ", "live", self.filter(None)]))
            .await?;
        let mut page_len = collect_until_eose(ws, "live", &mut events).await?;
        let mut page = 0;
        while page_len >= PAGE {
            let Some(oldest) = events.values().map(|e| e.created_at.as_secs() as i64).min() else {
                break;
            };
            page += 1;
            let sub = format!("page-{page}");
            let before = events.len();
            ws.send_raw(&json!(["REQ", sub, self.filter(Some(oldest))]))
                .await?;
            page_len = collect_until_eose(ws, &sub, &mut events).await?;
            ws.send_raw(&json!(["CLOSE", sub])).await?;
            if events.len() == before {
                break;
            }
        }
        Ok(events.into_values().collect())
    }

    /// Apply `events` in `(created_at, id)` order, retry what was waiting
    /// for them, and move the cursor when nothing is left waiting.
    async fn apply_batch(&mut self, mut events: Vec<Event>) -> anyhow::Result<()> {
        events.sort_by_key(|e| (e.created_at, e.id));
        for event in events {
            let position = (event.created_at, event.id);
            if self.apply(event.clone()).await? {
                self.pending.push(Pending { event, attempts: 1 });
            }
            self.last = self.last.max(Some(position));
        }
        self.settle_pending().await?;
        self.advance().await?;
        self.fetch_profiles().await;
        Ok(())
    }

    /// One retry pass over the pending events; ones that keep failing are
    /// dropped after [`MAX_ATTEMPTS`].
    async fn settle_pending(&mut self) -> anyhow::Result<()> {
        let mut still = Vec::new();
        for mut pending in std::mem::take(&mut self.pending) {
            if !self.apply(pending.event.clone()).await? {
                continue;
            }
            pending.attempts += 1;
            if pending.attempts > MAX_ATTEMPTS {
                warn!(
                    connection = %self.connection_id,
                    event = %pending.event.id,
                    "channel connect: dropping an event whose target never arrived"
                );
                continue;
            }
            still.push(pending);
        }
        self.pending = still;
        Ok(())
    }

    /// Move the durable cursor to the last applied event once nothing waits;
    /// while something does, it stays put and a reconnect re-reads from there.
    async fn advance(&mut self) -> anyhow::Result<()> {
        let Some((created_at, id)) = self.last.filter(|_| self.pending.is_empty()) else {
            return Ok(());
        };
        let created_at = created_at.as_secs() as i64;
        if created_at > self.cursor {
            self.state
                .db
                .advance_channel_connection_cursor(
                    self.tenant.community(),
                    self.connection_id,
                    created_at,
                    id.as_bytes(),
                )
                .await?;
            self.cursor = created_at;
        }
        Ok(())
    }

    /// Store one event through the mirror path. `Ok(true)` when it must wait
    /// for its parent or target; `Ok(false)` once settled, stored or refused
    /// for good. `Err` for a failure that should end the session.
    async fn apply(&mut self, event: Event) -> anyhow::Result<bool> {
        let author = event.pubkey;
        let event_id = event.id;
        // Recorded first: the loop filter must hide the event from the peer
        // before its fan-out can reach the peer's socket.
        self.state
            .db
            .record_mirrored_event(
                self.tenant.community(),
                self.connection_id,
                event_id.as_bytes(),
                &self.peer_url,
            )
            .await?;
        let auth = IngestAuth::Mirror {
            author,
            channel_id: self.channel_id,
        };
        match ingest_event(&self.state, &self.tenant, event, auth).await {
            Ok(result) if result.accepted => {
                self.authors_seen.insert(author);
                Ok(false)
            }
            Ok(result) => {
                warn!(event = %event_id, message = %result.message, "channel connect: event refused");
                Ok(false)
            }
            Err(IngestError::Rejected(message)) if retryable(&message) => Ok(true),
            Err(IngestError::Internal(message)) => anyhow::bail!("storing {event_id}: {message}"),
            Err(error) => {
                warn!(event = %event_id, ?error, "channel connect: event refused");
                Ok(false)
            }
        }
    }

    /// Fetch, once per session, the profiles of authors whose events were
    /// stored. Best effort: a failure is retried next session.
    async fn fetch_profiles(&mut self) {
        let wanted: Vec<String> = self
            .authors_seen
            .difference(&self.profiles_fetched)
            .take(100)
            .map(|pubkey| pubkey.to_hex())
            .collect();
        if wanted.is_empty() {
            return;
        }
        let url = format!("{}/query", self.peer_origin);
        let filters = json!([{ "kinds": [0], "authors": wanted }]);
        let profiles = match super::handshake::post_signed(&url, &self.keys, &filters).await {
            Ok(response) if response.status().is_success() => {
                response.json::<Vec<Event>>().await.ok()
            }
            Ok(response) => {
                warn!(status = %response.status(), "channel connect: profile read refused");
                None
            }
            Err(error) => {
                warn!(%error, "channel connect: profile read failed");
                None
            }
        };
        let Some(profiles) = profiles else {
            return;
        };
        for profile in profiles {
            let wanted_author = wanted.contains(&profile.pubkey.to_hex());
            if wanted_author && profile.kind == nostr::Kind::Metadata {
                if let Err(error) = self.apply(profile).await {
                    warn!(%error, "channel connect: profile not stored");
                    return;
                }
            }
        }
        for author in wanted {
            if let Ok(pubkey) = nostr::PublicKey::from_hex(&author) {
                self.profiles_fetched.insert(pubkey);
            }
        }
    }

    async fn locally_active(&self) -> anyhow::Result<bool> {
        Ok(self
            .state
            .db
            .get_channel_connection(self.tenant.community(), self.connection_id)
            .await?
            .is_some_and(|c| c.state == ConnectionState::Active))
    }

    /// Ask the peer whether this connection's key is still active there.
    async fn active_at_peer(&self) -> anyhow::Result<bool> {
        let url = format!("{}{}", self.peer_origin, super::handshake::STATUS_PATH);
        let response = super::handshake::post_signed(&url, &self.keys, &json!({})).await?;
        if !response.status().is_success() {
            anyhow::bail!("peer status check answered {}", response.status());
        }
        let body: serde_json::Value = response.json().await?;
        Ok(body["active"] == json!(true))
    }

    /// The peer ended the connection: end it here too, keeping history.
    async fn end_here(&self) {
        info!(connection = %self.connection_id, "channel connect: ended by the peer");
        match super::disconnect(
            &self.state,
            &self.tenant,
            self.connection_id,
            "channel-connect-peer-ended",
        )
        .await
        {
            Ok(_) => {
                super::handshake::publish_channel_state(&self.state, &self.tenant, self.channel_id)
                    .await
            }
            Err(error) => warn!(%error, "channel connect: could not end the connection here"),
        }
    }
}

/// Read events for `sub` into `events` until its EOSE. Live events for other
/// subscriptions are kept too. Returns how many arrived for `sub`.
async fn collect_until_eose(
    ws: &mut NostrWsConnection,
    sub: &str,
    events: &mut HashMap<nostr::EventId, Event>,
) -> anyhow::Result<usize> {
    let mut count = 0;
    loop {
        match ws.next_event(IDLE).await? {
            RelayMessage::Event {
                subscription_id,
                event,
            } => {
                if subscription_id == sub {
                    count += 1;
                }
                events.insert(event.id, *event);
            }
            RelayMessage::Eose { subscription_id } if subscription_id == sub => return Ok(count),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id == sub || subscription_id == "live" => {
                anyhow::bail!("peer closed {subscription_id}: {message}")
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert!(backoff(1) >= Duration::from_secs(1) && backoff(1) < Duration::from_secs(2));
        assert!(backoff(3) >= Duration::from_secs(4));
        assert!(backoff(50) <= BACKOFF_CAP + BACKOFF_CAP / 4);
    }

    #[test]
    fn only_missing_targets_are_retried() {
        assert!(retryable("reply parent not found"));
        assert!(retryable("reaction target event not found"));
        assert!(!retryable("invalid: event is outside the shared channel"));
    }
}
