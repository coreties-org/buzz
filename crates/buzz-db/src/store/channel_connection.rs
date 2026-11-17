//! Buzz Connect persistence: channels shared with a community on another
//! relay (docs/buzz-connect.md).
//!
//! `channel_connections` holds one row per side of a shared channel.
//! `mirrored_events` records every event stored through the mirror path and
//! the connection that supplied it. Every statement binds `community_id`;
//! every write runs in a community-admitted transaction.

use buzz_core::CommunityId;
use buzz_datastore_tracing::datastore_span;
use chrono::{DateTime, Utc};
use sqlx::Row as _;
use uuid::Uuid;

use crate::error::{DbError, Result};
use crate::observability::{acquire_writer, WriterOperation};
use crate::{AdmittedTx, Db};

/// Which side of the handshake created this row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// The community that owns the channel and issued the link.
    Offerer,
    /// The community that redeemed the link.
    Acceptor,
}

impl ConnectionRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Offerer => "offerer",
            Self::Acceptor => "acceptor",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "offerer" => Ok(Self::Offerer),
            "acceptor" => Ok(Self::Acceptor),
            other => Err(DbError::InvalidData(format!(
                "channel connection role {other:?}"
            ))),
        }
    }
}

/// Lifecycle of a connection row. There is no way back from `Disconnected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Link issued, not yet redeemed (offerer only).
    Offered,
    /// Both sides registered; the peer key is admitted.
    Active,
    /// Ended by either side; history stays, nothing new crosses.
    Disconnected,
}

impl ConnectionState {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "offered" => Ok(Self::Offered),
            "active" => Ok(Self::Active),
            "disconnected" => Ok(Self::Disconnected),
            other => Err(DbError::InvalidData(format!(
                "channel connection state {other:?}"
            ))),
        }
    }
}

/// One side of a shared channel.
#[derive(Clone)]
pub struct ChannelConnection {
    /// Community this row belongs to.
    pub community: CommunityId,
    /// Row id, local to this relay.
    pub id: Uuid,
    /// The shared channel; the same UUID on both relays.
    pub channel_id: Uuid,
    /// Which side created this row.
    pub role: ConnectionRole,
    /// Lifecycle state.
    pub state: ConnectionState,
    /// The other relay's WebSocket URL, once known.
    pub peer_relay_url: Option<String>,
    /// The other community's display name, once known.
    pub peer_community_name: Option<String>,
    /// This side's connection pubkey (hex), used to authenticate at the peer.
    pub local_pubkey: String,
    /// This side's connection secret key (hex). Plaintext in the prototype.
    pub local_secret_key: String,
    /// The peer's connection pubkey (hex), admitted here with channel scope.
    pub peer_pubkey: Option<String>,
    /// Expiry of the outstanding one-time code, while `Offered`.
    pub offer_expires_at: Option<DateTime<Utc>>,
    /// `created_at` of the last applied peer event.
    pub cursor_created_at: i64,
    /// Id of the last applied peer event.
    pub cursor_event_id: Option<Vec<u8>>,
    /// Admin pubkey (hex) who offered or accepted.
    pub created_by: String,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Last state change.
    pub updated_at: DateTime<Utc>,
    /// When the connection was disconnected.
    pub disconnected_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for ChannelConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelConnection")
            .field("community", &self.community)
            .field("id", &self.id)
            .field("channel_id", &self.channel_id)
            .field("role", &self.role)
            .field("state", &self.state)
            .field("peer_relay_url", &self.peer_relay_url)
            .field("local_pubkey", &self.local_pubkey)
            .field("local_secret_key", &"[REDACTED]")
            .field("peer_pubkey", &self.peer_pubkey)
            .finish_non_exhaustive()
    }
}

/// What an admitted peer connection key may read: one channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerConnectionScope {
    /// The connection row that admitted the key.
    pub connection_id: Uuid,
    /// The only channel the key may read.
    pub channel_id: Uuid,
}

/// Input for [`Db::create_channel_connection`].
pub struct NewChannelConnection<'a> {
    /// Owning community.
    pub community: CommunityId,
    /// Existing, live channel in `community`.
    pub channel_id: Uuid,
    /// `Offerer` creates an `offered` row and needs the code fields;
    /// `Acceptor` creates an `active` row and needs the peer fields.
    pub role: ConnectionRole,
    /// This side's connection pubkey (hex).
    pub local_pubkey: &'a str,
    /// This side's connection secret key (hex).
    pub local_secret_key: &'a str,
    /// SHA-256 of the one-time code (offerer).
    pub offer_code_hash: Option<[u8; 32]>,
    /// Expiry of the one-time code (offerer).
    pub offer_expires_at: Option<DateTime<Utc>>,
    /// The peer's connection pubkey (acceptor).
    pub peer_pubkey: Option<&'a str>,
    /// The peer relay's URL (acceptor).
    pub peer_relay_url: Option<&'a str>,
    /// The peer community's display name (acceptor).
    pub peer_community_name: Option<&'a str>,
    /// Admin pubkey (hex).
    pub created_by: &'a str,
}

/// The peer side presented when redeeming an offer.
pub struct OfferRedemption<'a> {
    /// SHA-256 of the presented code.
    pub code_hash: [u8; 32],
    /// The redeeming side's connection pubkey (hex).
    pub peer_pubkey: &'a str,
    /// The redeeming relay's URL.
    pub peer_relay_url: &'a str,
    /// The redeeming community's display name.
    pub peer_community_name: &'a str,
}

/// The columns [`from_row`] reads, space-padded for `concat!` into static
/// statements (sqlx accepts only static SQL).
macro_rules! columns {
    () => {
        " id, channel_id, role, state, peer_relay_url, peer_community_name, \
         local_pubkey, local_secret_key, peer_pubkey, offer_expires_at, cursor_created_at, \
         cursor_event_id, created_by, created_at, updated_at, disconnected_at "
    };
}

fn is_hex_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn from_row(community: CommunityId, row: &sqlx::postgres::PgRow) -> Result<ChannelConnection> {
    Ok(ChannelConnection {
        community,
        id: row.try_get("id")?,
        channel_id: row.try_get("channel_id")?,
        role: ConnectionRole::parse(row.try_get("role")?)?,
        state: ConnectionState::parse(row.try_get("state")?)?,
        peer_relay_url: row.try_get("peer_relay_url")?,
        peer_community_name: row.try_get("peer_community_name")?,
        local_pubkey: row.try_get("local_pubkey")?,
        local_secret_key: row.try_get("local_secret_key")?,
        peer_pubkey: row.try_get("peer_pubkey")?,
        offer_expires_at: row.try_get("offer_expires_at")?,
        cursor_created_at: row.try_get("cursor_created_at")?,
        cursor_event_id: row.try_get("cursor_event_id")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        disconnected_at: row.try_get("disconnected_at")?,
    })
}

fn validate_new(new: &NewChannelConnection<'_>) -> Result<()> {
    let invalid = |what: &str| Err(DbError::InvalidData(format!("channel connection: {what}")));
    if !is_hex_key(new.local_pubkey) || !is_hex_key(new.local_secret_key) {
        return invalid("local keypair must be 64 hex characters");
    }
    match new.role {
        ConnectionRole::Offerer => {
            if new.offer_code_hash.is_none() || new.offer_expires_at.is_none() {
                return invalid("an offer needs a code hash and an expiry");
            }
            if new.peer_pubkey.is_some() {
                return invalid("an offer has no peer key yet");
            }
        }
        ConnectionRole::Acceptor => {
            if !new.peer_pubkey.is_some_and(is_hex_key) {
                return invalid("an accepted connection needs the peer key");
            }
            if new.peer_relay_url.is_none() || new.offer_code_hash.is_some() {
                return invalid("an accepted connection needs the peer relay and no code");
            }
        }
    }
    Ok(())
}

impl Db {
    /// Create one side of a connection for a live channel in the community.
    ///
    /// An offerer row starts `offered` (no peer key is admitted); an acceptor
    /// row starts `active`, so the peer key is admitted once this commits.
    /// Fails with [`DbError::ChannelNotFound`] when the channel is missing or
    /// deleted in this community.
    #[datastore_span(name = "create_channel_connection", system = "postgresql")]
    pub async fn create_channel_connection(
        &self,
        new: NewChannelConnection<'_>,
    ) -> Result<ChannelConnection> {
        validate_new(&new)?;
        let mut tx = crate::begin_community_write_transaction(
            &self.pool,
            new.community,
            WriterOperation::Authorization,
        )
        .await?;
        // No foreign key (docs/database.md rule 2): check the channel in this
        // transaction, locking it against a concurrent delete.
        let channel = sqlx::query(
            "SELECT 1 FROM channels \
             WHERE community_id = $1 AND id = $2 AND deleted_at IS NULL \
             FOR SHARE",
        )
        .bind(new.community.as_uuid())
        .bind(new.channel_id)
        .fetch_optional(tx.conn())
        .await?;
        if channel.is_none() {
            return Err(DbError::ChannelNotFound(new.channel_id));
        }
        let state = match new.role {
            ConnectionRole::Offerer => "offered",
            ConnectionRole::Acceptor => "active",
        };
        let row = sqlx::query(concat!(
            "INSERT INTO channel_connections \
             (community_id, id, channel_id, role, state, peer_relay_url, peer_community_name, \
              local_pubkey, local_secret_key, peer_pubkey, offer_code_hash, offer_expires_at, \
              created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             RETURNING",
            columns!(),
            ""
        ))
        .bind(new.community.as_uuid())
        .bind(Uuid::new_v4())
        .bind(new.channel_id)
        .bind(new.role.as_str())
        .bind(state)
        .bind(new.peer_relay_url)
        .bind(new.peer_community_name)
        .bind(new.local_pubkey)
        .bind(new.local_secret_key)
        .bind(new.peer_pubkey)
        .bind(new.offer_code_hash.map(|hash| hash.to_vec()))
        .bind(new.offer_expires_at)
        .bind(new.created_by)
        .fetch_one(tx.conn())
        .await?;
        let connection = from_row(new.community, &row)?;
        tx.commit().await?;
        Ok(connection)
    }

    /// Redeem a one-time offer: the row must be `offered` with this code and
    /// unexpired. It becomes `active` with the peer's key, and the code is
    /// cleared, so a second redemption finds nothing. One statement, so two
    /// concurrent redemptions cannot both win.
    ///
    /// `None` covers an unknown, used, expired or disconnected code alike.
    #[datastore_span(name = "redeem_channel_connection_offer", system = "postgresql")]
    pub async fn redeem_channel_connection_offer(
        &self,
        community: CommunityId,
        redemption: OfferRedemption<'_>,
    ) -> Result<Option<ChannelConnection>> {
        if !is_hex_key(redemption.peer_pubkey) {
            return Err(DbError::InvalidData(
                "channel connection: peer key must be 64 hex characters".into(),
            ));
        }
        let mut tx = crate::begin_community_write_transaction(
            &self.pool,
            community,
            WriterOperation::Authorization,
        )
        .await?;
        let row = sqlx::query(concat!(
            "UPDATE channel_connections SET \
                 state = 'active', peer_pubkey = $3, peer_relay_url = $4, \
                 peer_community_name = $5, offer_code_hash = NULL, offer_expires_at = NULL, \
                 updated_at = now() \
             WHERE community_id = $1 AND offer_code_hash = $2 AND state = 'offered' \
               AND offer_expires_at > now() \
             RETURNING",
            columns!(),
            ""
        ))
        .bind(community.as_uuid())
        .bind(redemption.code_hash.to_vec())
        .bind(redemption.peer_pubkey)
        .bind(redemption.peer_relay_url)
        .bind(redemption.peer_community_name)
        .fetch_optional(tx.conn())
        .await?;
        let connection = row.map(|row| from_row(community, &row)).transpose()?;
        tx.commit().await?;
        Ok(connection)
    }

    /// The channel scope of `peer_pubkey` (hex) when it belongs to an `active`
    /// connection in `community`, read from the writer.
    ///
    /// Admission calls this on every peer authentication and every peer HTTP
    /// request, so a disconnect is honoured from the next read on.
    #[datastore_span(name = "active_peer_connection", system = "postgresql")]
    pub async fn active_peer_connection(
        &self,
        community: CommunityId,
        peer_pubkey: &str,
    ) -> Result<Option<PeerConnectionScope>> {
        let mut conn = acquire_writer(&self.pool, WriterOperation::Authorization).await?;
        let row = sqlx::query(
            "SELECT id, channel_id FROM channel_connections \
             WHERE community_id = $1 AND peer_pubkey = $2 AND state = 'active'",
        )
        .bind(community.as_uuid())
        .bind(peer_pubkey)
        .fetch_optional(&mut *conn)
        .await?;
        row.map(|row| {
            Ok(PeerConnectionScope {
                connection_id: row.try_get("id")?,
                channel_id: row.try_get("channel_id")?,
            })
        })
        .transpose()
    }

    /// One connection row by id.
    #[datastore_span(name = "get_channel_connection", system = "postgresql")]
    pub async fn get_channel_connection(
        &self,
        community: CommunityId,
        id: Uuid,
    ) -> Result<Option<ChannelConnection>> {
        let mut conn = acquire_writer(&self.pool, WriterOperation::Authorization).await?;
        let row = sqlx::query(concat!(
            "SELECT",
            columns!(),
            "FROM channel_connections WHERE community_id = $1 AND id = $2"
        ))
        .bind(community.as_uuid())
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
        row.map(|row| from_row(community, &row)).transpose()
    }

    /// Every connection row of one channel, oldest first.
    #[datastore_span(name = "list_channel_connections", system = "postgresql")]
    pub async fn list_channel_connections(
        &self,
        community: CommunityId,
        channel_id: Uuid,
    ) -> Result<Vec<ChannelConnection>> {
        let mut conn = acquire_writer(&self.pool, WriterOperation::Authorization).await?;
        let rows = sqlx::query(concat!(
            "SELECT",
            columns!(),
            "FROM channel_connections \
             WHERE community_id = $1 AND channel_id = $2 \
             ORDER BY created_at, id"
        ))
        .bind(community.as_uuid())
        .bind(channel_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.iter().map(|row| from_row(community, row)).collect()
    }

    /// Mark a connection `disconnected` and clear any outstanding code.
    /// Returns the row as it was disconnected, or `None` when it does not
    /// exist or was already disconnected. Callers must also close the peer
    /// key's live sockets; this only stops new admissions.
    #[datastore_span(name = "disconnect_channel_connection", system = "postgresql")]
    pub async fn disconnect_channel_connection(
        &self,
        community: CommunityId,
        id: Uuid,
    ) -> Result<Option<ChannelConnection>> {
        let mut tx = crate::begin_community_write_transaction(
            &self.pool,
            community,
            WriterOperation::Authorization,
        )
        .await?;
        let row = sqlx::query(concat!(
            "UPDATE channel_connections SET \
                 state = 'disconnected', offer_code_hash = NULL, offer_expires_at = NULL, \
                 disconnected_at = now(), updated_at = now() \
             WHERE community_id = $1 AND id = $2 AND state <> 'disconnected' \
             RETURNING",
            columns!(),
            ""
        ))
        .bind(community.as_uuid())
        .bind(id)
        .fetch_optional(tx.conn())
        .await?;
        let connection = row.map(|row| from_row(community, &row)).transpose()?;
        tx.commit().await?;
        Ok(connection)
    }

    /// Move an `active` connection's pull cursor forward to
    /// `(created_at, event_id)`. A position at or behind the stored one is
    /// ignored, so a replayed batch cannot rewind it. Returns whether it moved.
    #[datastore_span(name = "advance_channel_connection_cursor", system = "postgresql")]
    pub async fn advance_channel_connection_cursor(
        &self,
        community: CommunityId,
        id: Uuid,
        created_at: i64,
        event_id: &[u8],
    ) -> Result<bool> {
        let mut tx = crate::begin_community_write_transaction(
            &self.pool,
            community,
            WriterOperation::Authorization,
        )
        .await?;
        let moved = sqlx::query(
            "UPDATE channel_connections SET \
                 cursor_created_at = $3, cursor_event_id = $4, updated_at = now() \
             WHERE community_id = $1 AND id = $2 AND state = 'active' \
               AND (cursor_created_at, COALESCE(cursor_event_id, '\\x'::bytea)) < ($3, $4)",
        )
        .bind(community.as_uuid())
        .bind(id)
        .bind(created_at)
        .bind(event_id)
        .execute(tx.conn())
        .await?
        .rows_affected()
            == 1;
        tx.commit().await?;
        Ok(moved)
    }

    /// Ids among `event_ids` that `connection_id` supplied to this community.
    /// Serving that connection omits them, so nothing echoes back.
    #[datastore_span(name = "mirrored_event_ids_from", system = "postgresql")]
    pub async fn mirrored_event_ids_from(
        &self,
        community: CommunityId,
        connection_id: Uuid,
        event_ids: &[Vec<u8>],
    ) -> Result<std::collections::HashSet<Vec<u8>>> {
        if event_ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let mut conn = acquire_writer(&self.pool, WriterOperation::SubscriptionHistory).await?;
        let rows = sqlx::query(
            "SELECT event_id FROM mirrored_events \
             WHERE community_id = $1 AND connection_id = $2 AND event_id = ANY($3)",
        )
        .bind(community.as_uuid())
        .bind(connection_id)
        .bind(event_ids)
        .fetch_all(&mut *conn)
        .await?;
        rows.iter()
            .map(|row| row.try_get::<Vec<u8>, _>("event_id").map_err(Into::into))
            .collect()
    }

    /// Record that `connection_id` supplied `event_id` from
    /// `origin_relay_url`, in its own transaction. The mirror path calls this
    /// before it stores the event, so the loop filter already omits the event
    /// when its fan-out reaches the peer's socket. Returns `false` when the
    /// event was already recorded.
    #[datastore_span(name = "record_mirrored_event", system = "postgresql")]
    pub async fn record_mirrored_event(
        &self,
        community: CommunityId,
        connection_id: Uuid,
        event_id: &[u8],
        origin_relay_url: &str,
    ) -> Result<bool> {
        let mut tx = crate::begin_community_write_transaction(
            &self.pool,
            community,
            WriterOperation::EventWrite,
        )
        .await?;
        let recorded =
            record_mirrored_event(&mut tx, connection_id, event_id, origin_relay_url).await?;
        tx.commit().await?;
        Ok(recorded)
    }

    /// The pubkeys among `pubkeys` (32-byte) that have a live event of the
    /// synced kinds (9, 7, 40003, 5) in `channel_id`: the authors a peer may
    /// read the profiles of.
    #[datastore_span(name = "channel_authors_among", system = "postgresql")]
    pub async fn channel_authors_among(
        &self,
        community: CommunityId,
        channel_id: Uuid,
        pubkeys: &[Vec<u8>],
    ) -> Result<std::collections::HashSet<Vec<u8>>> {
        if pubkeys.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let mut conn = acquire_writer(&self.pool, WriterOperation::SubscriptionHistory).await?;
        let rows = sqlx::query(
            "SELECT DISTINCT pubkey FROM events \
             WHERE community_id = $1 AND pubkey = ANY($2) AND kind IN (9, 7, 40003, 5) \
               AND channel_id = $3 AND deleted_at IS NULL",
        )
        .bind(community.as_uuid())
        .bind(pubkeys)
        .bind(channel_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.iter()
            .map(|row| row.try_get::<Vec<u8>, _>("pubkey").map_err(Into::into))
            .collect()
    }

    /// Every `active` connection on this deployment, across communities, for
    /// the mirror supervisor. Oldest first.
    #[datastore_span(name = "all_active_channel_connections", system = "postgresql")]
    pub async fn all_active_channel_connections(&self) -> Result<Vec<ChannelConnection>> {
        let mut conn = acquire_writer(&self.pool, WriterOperation::Authorization).await?;
        let rows = sqlx::query(concat!(
            "SELECT community_id,",
            columns!(),
            "FROM channel_connections WHERE state = 'active' ORDER BY created_at, id"
        ))
        .fetch_all(&mut *conn)
        .await?;
        rows.iter()
            .map(|row| {
                let community = CommunityId::from_uuid(row.try_get("community_id")?);
                from_row(community, row)
            })
            .collect()
    }
}

/// Record, inside the mirror path's admitted transaction, that
/// `connection_id` supplied `event_id` from `origin_relay_url`. Returns
/// `false` when the event was already mirrored into this community, so the
/// caller stores and fans it out at most once.
pub async fn record_mirrored_event(
    tx: &mut AdmittedTx,
    connection_id: Uuid,
    event_id: &[u8],
    origin_relay_url: &str,
) -> Result<bool> {
    let community = tx.community();
    Ok(sqlx::query(
        "INSERT INTO mirrored_events (community_id, event_id, connection_id, origin_relay_url) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (community_id, event_id) DO NOTHING",
    )
    .bind(community.as_uuid())
    .bind(event_id)
    .bind(connection_id)
    .bind(origin_relay_url)
    .execute(tx.conn())
    .await?
    .rows_affected()
        == 1)
}

#[cfg(test)]
mod postgres_tests;
