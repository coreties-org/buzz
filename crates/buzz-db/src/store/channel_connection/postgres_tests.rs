use super::*;
use chrono::Duration;

async fn fixture() -> (Db, CommunityId) {
    let db = Db::new(&crate::DbConfig {
        database_url: crate::test_support::database_url(),
        ..crate::DbConfig::default()
    })
    .await
    .unwrap();
    if std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref() != Ok("desired") {
        db.migrate().await.unwrap();
    }
    (db.clone(), community(&db).await)
}

async fn community(db: &Db) -> CommunityId {
    let community = CommunityId::from_uuid(Uuid::new_v4());
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(community.as_uuid())
        .bind(format!("connect-{}.test", community.as_uuid()))
        .execute(&db.pool)
        .await
        .unwrap();
    community
}

async fn channel(db: &Db, community: CommunityId) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO channels (community_id, id, name, created_by) VALUES ($1, $2, $3, $4)",
    )
    .bind(community.as_uuid())
    .bind(id)
    .bind(format!("shared-{id}"))
    .bind(vec![1_u8; 32])
    .execute(&db.pool)
    .await
    .unwrap();
    id
}

const LOCAL_PUBKEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LOCAL_SECRET_KEY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn key(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn code(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn offer(
    community: CommunityId,
    channel_id: Uuid,
    code_hash: [u8; 32],
) -> NewChannelConnection<'static> {
    NewChannelConnection {
        community,
        channel_id,
        role: ConnectionRole::Offerer,
        local_pubkey: LOCAL_PUBKEY,
        local_secret_key: LOCAL_SECRET_KEY,
        offer_code_hash: Some(code_hash),
        offer_expires_at: Some(Utc::now() + Duration::hours(24)),
        peer_pubkey: None,
        peer_relay_url: None,
        peer_community_name: None,
        created_by: "admin",
    }
}

fn redemption(code_hash: [u8; 32], peer: &str) -> OfferRedemption<'_> {
    OfferRedemption {
        code_hash,
        peer_pubkey: peer,
        peer_relay_url: "wss://b.example",
        peer_community_name: "B",
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn offer_is_redeemed_once_and_admits_the_peer_until_disconnect() {
    let (db, community) = fixture().await;
    let channel_id = channel(&db, community).await;
    let peer = key('c');
    let offered = db
        .create_channel_connection(offer(community, channel_id, code(1)))
        .await
        .unwrap();
    assert_eq!(offered.state, ConnectionState::Offered);
    assert_eq!(offered.role, ConnectionRole::Offerer);
    assert_eq!(
        db.active_peer_connection(community, &peer).await.unwrap(),
        None
    );

    assert!(db
        .redeem_channel_connection_offer(community, redemption(code(2), &peer))
        .await
        .unwrap()
        .is_none());
    let active = db
        .redeem_channel_connection_offer(community, redemption(code(1), &peer))
        .await
        .unwrap()
        .expect("first redemption wins");
    assert_eq!(active.state, ConnectionState::Active);
    assert_eq!(active.peer_pubkey.as_deref(), Some(peer.as_str()));
    assert_eq!(active.peer_relay_url.as_deref(), Some("wss://b.example"));
    assert_eq!(active.offer_expires_at, None);
    assert!(db
        .redeem_channel_connection_offer(community, redemption(code(1), &key('d')))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.active_peer_connection(community, &peer).await.unwrap(),
        Some(PeerConnectionScope {
            connection_id: active.id,
            channel_id
        })
    );

    let other = self::community(&db).await;
    assert_eq!(db.active_peer_connection(other, &peer).await.unwrap(), None);

    let gone = db
        .disconnect_channel_connection(community, active.id)
        .await
        .unwrap()
        .expect("disconnects");
    assert_eq!(gone.state, ConnectionState::Disconnected);
    assert!(gone.disconnected_at.is_some());
    assert_eq!(
        db.active_peer_connection(community, &peer).await.unwrap(),
        None
    );
    assert!(db
        .disconnect_channel_connection(community, active.id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn expired_or_disconnected_offers_cannot_be_redeemed() {
    let (db, community) = fixture().await;
    let channel_id = channel(&db, community).await;
    let mut expired = offer(community, channel_id, code(3));
    expired.offer_expires_at = Some(Utc::now() - Duration::seconds(1));
    db.create_channel_connection(expired).await.unwrap();
    assert!(db
        .redeem_channel_connection_offer(community, redemption(code(3), &key('c')))
        .await
        .unwrap()
        .is_none());

    let pending = db
        .create_channel_connection(offer(community, channel_id, code(4)))
        .await
        .unwrap();
    db.disconnect_channel_connection(community, pending.id)
        .await
        .unwrap()
        .expect("withdraws the offer");
    assert!(db
        .redeem_channel_connection_offer(community, redemption(code(4), &key('c')))
        .await
        .unwrap()
        .is_none());
    // A code redeemed in another community is unknown there.
    let other = self::community(&db).await;
    db.create_channel_connection(offer(community, channel_id, code(5)))
        .await
        .unwrap();
    assert!(db
        .redeem_channel_connection_offer(other, redemption(code(5), &key('c')))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn acceptor_rows_are_active_and_need_a_live_channel_in_the_community() {
    let (db, community) = fixture().await;
    let channel_id = channel(&db, community).await;
    let peer = key('e');
    let accepted = NewChannelConnection {
        role: ConnectionRole::Acceptor,
        offer_code_hash: None,
        offer_expires_at: None,
        peer_pubkey: Some(&peer),
        peer_relay_url: Some("wss://a.example"),
        peer_community_name: Some("A"),
        ..offer(community, channel_id, code(6))
    };
    let other = self::community(&db).await;
    assert!(matches!(
        db.create_channel_connection(NewChannelConnection {
            community: other,
            ..accepted
        })
        .await,
        Err(DbError::ChannelNotFound(id)) if id == channel_id
    ));
    let accepted = NewChannelConnection {
        role: ConnectionRole::Acceptor,
        offer_code_hash: None,
        offer_expires_at: None,
        peer_pubkey: Some(&peer),
        peer_relay_url: Some("wss://a.example"),
        peer_community_name: Some("A"),
        ..offer(community, channel_id, code(6))
    };
    let row = db.create_channel_connection(accepted).await.unwrap();
    assert_eq!(row.state, ConnectionState::Active);
    assert_eq!(
        db.active_peer_connection(community, &peer)
            .await
            .unwrap()
            .map(|scope| scope.channel_id),
        Some(channel_id)
    );
    assert_eq!(
        db.list_channel_connections(community, channel_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(db
        .get_channel_connection(community, row.id)
        .await
        .unwrap()
        .is_some());
    assert!(db
        .get_channel_connection(other, row.id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cursor_only_moves_forward() {
    let (db, community) = fixture().await;
    let channel_id = channel(&db, community).await;
    let peer = key('f');
    let row = db
        .create_channel_connection(NewChannelConnection {
            role: ConnectionRole::Acceptor,
            offer_code_hash: None,
            offer_expires_at: None,
            peer_pubkey: Some(&peer),
            peer_relay_url: Some("wss://a.example"),
            peer_community_name: Some("A"),
            ..offer(community, channel_id, code(7))
        })
        .await
        .unwrap();
    assert!(db
        .advance_channel_connection_cursor(community, row.id, 100, &[2; 32])
        .await
        .unwrap());
    assert!(!db
        .advance_channel_connection_cursor(community, row.id, 100, &[1; 32])
        .await
        .unwrap());
    assert!(!db
        .advance_channel_connection_cursor(community, row.id, 99, &[9; 32])
        .await
        .unwrap());
    assert!(db
        .advance_channel_connection_cursor(community, row.id, 100, &[3; 32])
        .await
        .unwrap());
    let row = db
        .get_channel_connection(community, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.cursor_created_at, row.cursor_event_id),
        (100, Some(vec![3; 32]))
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn mirrored_events_are_recorded_once_per_community() {
    let (db, community) = fixture().await;
    let connection = Uuid::new_v4();
    let record = |community, event: Vec<u8>| {
        let db = db.clone();
        async move {
            let mut tx = crate::begin_community_write_transaction(
                &db.pool,
                community,
                WriterOperation::EventWrite,
            )
            .await
            .unwrap();
            let fresh = record_mirrored_event(&mut tx, connection, &event, "wss://a.example")
                .await
                .unwrap();
            tx.commit().await.unwrap();
            fresh
        }
    };
    assert!(record(community, vec![1; 32]).await);
    assert!(!record(community, vec![1; 32]).await);
    let other = self::community(&db).await;
    assert!(record(other, vec![1; 32]).await);

    let from = db
        .mirrored_event_ids_from(community, connection, &[vec![1; 32], vec![2; 32]])
        .await
        .unwrap();
    assert_eq!(from, [vec![1_u8; 32]].into_iter().collect());
    assert!(db
        .mirrored_event_ids_from(community, Uuid::new_v4(), &[vec![1; 32]])
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn writes_are_refused_once_community_deletion_starts() {
    let (db, community) = fixture().await;
    let channel_id = channel(&db, community).await;
    let pending = db
        .create_channel_connection(offer(community, channel_id, code(8)))
        .await
        .unwrap();
    crate::test_support::quiesce_community_for_tests(&db.pool, community).await;
    for result in [
        db.create_channel_connection(offer(community, channel_id, code(9)))
            .await
            .map(|_| ()),
        db.disconnect_channel_connection(community, pending.id)
            .await
            .map(|_| ()),
        db.redeem_channel_connection_offer(community, redemption(code(8), &key('c')))
            .await
            .map(|_| ()),
    ] {
        let error = result.expect_err("quiescing community refuses writes");
        assert!(
            crate::test_support::is_admission_rejection(&error),
            "{error:?}"
        );
    }
}
