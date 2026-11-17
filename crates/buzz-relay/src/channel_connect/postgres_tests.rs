//! Postgres-backed tests for Buzz Connect scoped access: a peer connection
//! key reads its one channel (private included) over the real AUTH, frame
//! and HTTP seams, gets nothing global, cannot write, and loses access the
//! moment its connection is disconnected.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message as WsMessage;
use buzz_core::TenantContext;
use buzz_db::channel_connection::{ConnectionRole, NewChannelConnection, PeerConnectionScope};
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::connection::{AuthState, ConnectionState};
use crate::handlers::group_state_postgres_tests::{create_channel, edit_channel};
use crate::state::AppState;

struct Fixture {
    state: Arc<AppState>,
    tenant: TenantContext,
    host: String,
    member: Keys,
    peer: Keys,
    shared: Uuid,
    other: Uuid,
    connection: Uuid,
}

/// The relay's two admission regimes: an open relay admits any key, a closed
/// one only its roster.
#[derive(Clone, Copy, PartialEq)]
enum Relay {
    Open,
    Closed,
}

async fn fixture(relay: Relay) -> Fixture {
    let mut state = crate::api::bridge::postgres_tests::bridge_handler_test_state()
        .await
        .expect("local Postgres and Redis");
    if relay == Relay::Closed {
        let mut closed = (*state).clone();
        Arc::make_mut(&mut closed.config).require_relay_membership = true;
        state = Arc::new(closed);
    }
    let host = format!("connect-{}.local", Uuid::new_v4().simple());
    let community = state
        .db
        .ensure_configured_community(&host)
        .await
        .expect("ensure community")
        .id;
    let tenant = TenantContext::resolved(community, &host);
    let member = Keys::generate();
    let peer = Keys::generate();
    // The member runs the community (and, on a closed relay, is on its roster).
    state
        .db
        .add_relay_member(
            community,
            &member.public_key().to_hex(),
            "admin",
            None,
            &Keys::generate(),
        )
        .await
        .map(|write| write.outcome)
        .expect("seed relay admin");
    let shared = create_channel(&state, &tenant, &member, &[&["visibility", "private"]]).await;
    let other = create_channel(&state, &tenant, &member, &[]).await;
    // An open channel an open relay auto-joins people to on admission.
    edit_channel(&state, &tenant, &member, other, &[&["auto_join", "true"]])
        .await
        .expect("auto-join channel");
    let local = Keys::generate();
    let peer_hex = peer.public_key().to_hex();
    let connection = state
        .db
        .create_channel_connection(NewChannelConnection {
            community,
            channel_id: shared,
            role: ConnectionRole::Acceptor,
            local_pubkey: &local.public_key().to_hex(),
            local_secret_key: &local.secret_key().to_secret_hex(),
            offer_code_hash: None,
            offer_expires_at: None,
            peer_pubkey: Some(&peer_hex),
            peer_relay_url: Some("wss://a.example"),
            peer_community_name: Some("A"),
            created_by: &member.public_key().to_hex(),
        })
        .await
        .expect("connection")
        .id;
    Fixture {
        state,
        tenant,
        host,
        member,
        peer,
        shared,
        other,
        connection,
    }
}

impl Fixture {
    async fn publish(&self, kind: u16, content: &str, tags: &[&[&str]]) -> String {
        let event = EventBuilder::new(Kind::Custom(kind), content)
            .tags(
                tags.iter()
                    .map(|tag| Tag::parse(tag.iter().copied()).unwrap()),
            )
            .sign_with_keys(&self.member)
            .unwrap();
        let id = event.id.to_hex();
        let result = crate::handlers::ingest::ingest_event(
            &self.state,
            &self.tenant,
            event,
            crate::handlers::ingest::IngestAuth::Http {
                pubkey: self.member.public_key(),
                scopes: buzz_auth::Scope::all_known(),
                auth_method: crate::handlers::ingest::HttpAuthMethod::Nip98,
            },
        )
        .await
        .expect("ingest");
        assert!(result.accepted, "kind:{kind} refused: {}", result.message);
        id
    }

    async fn message(&self, channel: Uuid, content: &str) -> String {
        self.publish(9, content, &[&["h", &channel.to_string()]])
            .await
    }

    /// A pending socket, registered so revocation can reach it, then
    /// authenticated by `keys` through the production AUTH handler.
    async fn connect(&self, keys: &Keys) -> (Arc<ConnectionState>, mpsc::Receiver<WsMessage>) {
        let (send_tx, send_rx) = mpsc::channel(256);
        let (ctrl_tx, _ctrl_rx) = mpsc::channel(8);
        let cancel = tokio_util::sync::CancellationToken::new();
        let challenge = format!("connect-{}", Uuid::new_v4());
        let conn = Arc::new(ConnectionState {
            refusal_budget: Default::default(),
            conn_id: Uuid::new_v4(),
            tenant: self.tenant.clone(),
            remote_addr: "127.0.0.1:1234".parse().unwrap(),
            auth_state: std::sync::Mutex::new(AuthState::Pending {
                challenge: challenge.clone(),
                started_at: std::time::Instant::now(),
            }),
            subscriptions: Default::default(),
            send_tx,
            ctrl_tx,
            terminal_ctrl_tx: mpsc::channel(1).0,
            cancel: cancel.clone(),
            backpressure_count: Default::default(),
            grace_limit: 3,
            nip_fi_assertion: None,
            session_deadline: None,
            nip_fi_gate: crate::nip_fi_gate::SessionAdmissionGate::off_mode(cancel.clone()),
            community_control: crate::state::CommunityConnectionControl::new(cancel.clone()),
        });
        self.state.conn_manager.register(
            conn.conn_id,
            conn.send_tx.clone(),
            conn.ctrl_tx.clone(),
            mpsc::channel(1).0,
            None,
            conn.cancel.clone(),
            conn.tenant.community(),
            Arc::clone(&conn.backpressure_count),
            Arc::clone(&conn.subscriptions),
            3,
            conn.community_control.clone(),
        );
        let relay = crate::api::bridge::nip42_expected_relay_url(
            &self.state.config.relay_url,
            &self.tenant,
        );
        let auth = EventBuilder::new(Kind::Authentication, "")
            .tag(Tag::parse(["relay", &relay]).unwrap())
            .tag(Tag::parse(["challenge", &challenge]).unwrap())
            .sign_with_keys(keys)
            .unwrap();
        crate::handlers::auth::handle_auth(auth, Arc::clone(&conn), Arc::clone(&self.state)).await;
        (conn, send_rx)
    }

    async fn send(&self, conn: &Arc<ConnectionState>, frame: Value) {
        crate::connection::handle_text_message(
            frame.to_string(),
            Arc::clone(conn),
            Arc::clone(&self.state),
        )
        .await;
    }

    async fn http(&self, keys: &Keys, path: &str, body: Value) -> (u16, Value) {
        use tower::ServiceExt;
        let response = crate::router::build_router(Arc::clone(&self.state))
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", &self.host)
                    .header("content-type", "application/json")
                    .header("x-pubkey", keys.public_key().to_hex())
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

async fn frame(rx: &mut mpsc::Receiver<WsMessage>) -> Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("relay frame in time")
            .expect("connection open");
        if let WsMessage::Text(text) = message {
            return serde_json::from_str(&text).expect("json frame");
        }
    }
}

async fn no_frame(rx: &mut mpsc::Receiver<WsMessage>) {
    if let Ok(Some(message)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
        panic!("unexpected frame: {message:?}");
    }
}

/// The event ids a REQ returns before EOSE, or `None` when it is CLOSED.
async fn req(
    f: &Fixture,
    conn: &Arc<ConnectionState>,
    rx: &mut mpsc::Receiver<WsMessage>,
    sub: &str,
    filter: Value,
) -> Option<Vec<String>> {
    f.send(conn, json!(["REQ", sub, filter])).await;
    let mut ids = Vec::new();
    loop {
        let message = frame(rx).await;
        match message[0].as_str() {
            Some("EVENT") => ids.push(message[2]["id"].as_str().unwrap().to_owned()),
            Some("EOSE") => return Some(ids),
            Some("CLOSED") => {
                assert_eq!(message[1], sub, "{message}");
                return None;
            }
            _ => panic!("unexpected frame {message}"),
        }
    }
}

fn authenticated_scope(conn: &ConnectionState) -> (Option<Vec<Uuid>>, Option<Uuid>) {
    match conn.auth_state_snapshot() {
        AuthState::Authenticated(ctx) => (ctx.channel_ids, ctx.peer_connection),
        other => panic!("not authenticated: {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn peer_key_is_admitted_to_its_channel_only_open_relay() {
    peer_key_is_admitted_to_its_channel_only(Relay::Open).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn peer_key_is_admitted_to_its_channel_only_closed_relay() {
    peer_key_is_admitted_to_its_channel_only(Relay::Closed).await;
}

async fn peer_key_is_admitted_to_its_channel_only(relay: Relay) {
    let f = fixture(relay).await;
    let shared_msg = f.message(f.shared, "in the shared private channel").await;
    let other_msg = f.message(f.other, "in another open channel").await;
    f.publish(0, r#"{"name":"member"}"#, &[]).await;

    let (conn, mut rx) = f.connect(&f.peer).await;
    let ok = frame(&mut rx).await;
    assert_eq!(ok[2], true, "peer AUTH accepted: {ok}");
    assert_eq!(
        authenticated_scope(&conn),
        (Some(vec![f.shared]), Some(f.connection))
    );
    let shared = f.shared.to_string();
    let other = f.other.to_string();

    // Its channel, private and not a member of it: readable.
    assert_eq!(
        req(
            &f,
            &conn,
            &mut rx,
            "a",
            json!({"kinds": [9], "#h": [shared]})
        )
        .await,
        Some(vec![shared_msg.clone()])
    );
    // Everything else is refused, not answered empty.
    for (sub, filter) in [
        ("b", json!({"kinds": [9], "#h": [other]})),
        ("c", json!({"kinds": [9], "#h": [shared, other]})),
        ("d", json!({"kinds": [9]})),
        ("e", json!({"#h": [shared]})),
        ("f", json!({"kinds": [0]})),
        (
            "g",
            json!({"kinds": [0], "authors": [f.member.public_key().to_hex()]}),
        ),
        ("h", json!({"kinds": [39000, 39002], "#d": [shared]})),
        ("i", json!({"kinds": [9007, 9], "#h": [shared]})),
        (
            "j",
            json!({"kinds": [1059], "#p": [f.peer.public_key().to_hex()]}),
        ),
        (
            "k",
            json!({"kinds": [9], "#h": [shared], "search": "shared"}),
        ),
    ] {
        assert_eq!(
            req(&f, &conn, &mut rx, sub, filter.clone()).await,
            None,
            "{filter}"
        );
    }
    assert!(!other_msg.is_empty());

    // COUNT follows the same scope.
    f.send(&conn, json!(["COUNT", "n", {"kinds": [9], "#h": [shared]}]))
        .await;
    let count = frame(&mut rx).await;
    assert_eq!(
        (count[0].as_str(), count[2]["count"].as_u64()),
        (Some("COUNT"), Some(1))
    );
    f.send(&conn, json!(["COUNT", "m", {"kinds": [9], "#h": [other]}]))
        .await;
    assert_eq!(frame(&mut rx).await[0], "CLOSED");

    // It cannot write, even into its own channel.
    let write = EventBuilder::new(Kind::Custom(9), "from the peer key")
        .tag(Tag::parse(["h", &shared]).unwrap())
        .sign_with_keys(&f.peer)
        .unwrap();
    f.send(&conn, json!(["EVENT", write])).await;
    let refused = frame(&mut rx).await;
    assert_eq!(
        (refused[0].as_str(), &refused[2]),
        (Some("OK"), &json!(false)),
        "{refused}"
    );

    // Live fan-out on the still-open first subscription: a new message in its
    // channel arrives; nothing elsewhere does, not even global events.
    let live = f.message(f.shared, "live in the shared channel").await;
    let delivered = frame(&mut rx).await;
    assert_eq!(
        (
            delivered[0].as_str(),
            delivered[1].as_str(),
            delivered[2]["id"].as_str()
        ),
        (Some("EVENT"), Some("a"), Some(live.as_str()))
    );
    f.message(f.other, "live elsewhere").await;
    f.publish(0, r#"{"name":"member renamed"}"#, &[]).await;
    no_frame(&mut rx).await;

    // Admission joined it to nothing, though an open relay auto-joins people
    // to its auto-join channels.
    let joined = f
        .state
        .db
        .membership_pairs(
            f.tenant.community(),
            &[f.shared, f.other],
            &[f.peer.public_key().to_bytes().to_vec()],
        )
        .await
        .unwrap();
    assert!(joined.is_empty(), "{joined:?}");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn peer_key_gets_only_scoped_http_reads_open_relay() {
    peer_key_gets_only_scoped_http_reads(Relay::Open).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn peer_key_gets_only_scoped_http_reads_closed_relay() {
    peer_key_gets_only_scoped_http_reads(Relay::Closed).await;
}

async fn peer_key_gets_only_scoped_http_reads(relay: Relay) {
    let f = fixture(relay).await;
    let shared_msg = f.message(f.shared, "shared").await;
    f.message(f.other, "other").await;
    let shared = f.shared.to_string();

    let (status, body) = f
        .http(&f.peer, "/query", json!([{"kinds": [9], "#h": [shared]}]))
        .await;
    assert_eq!(status, 200, "{body}");
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [shared_msg.as_str()]);
    let (status, body) = f
        .http(&f.peer, "/count", json!([{"kinds": [9], "#h": [shared]}]))
        .await;
    assert_eq!((status, body["count"].as_u64()), (200, Some(1)), "{body}");

    for filter in [
        json!({"kinds": [9], "#h": [f.other.to_string()]}),
        json!({"kinds": [0]}),
        json!({"kinds": [9], "#h": [shared], "search": "shared"}),
        json!({"kinds": [9], "#h": [shared], "depth_limit": 3, "#e": [shared_msg]}),
        json!({"kinds": [9], "#h": [shared], "feed_types": ["activity"]}),
    ] {
        for path in ["/query", "/count"] {
            let (status, body) = f.http(&f.peer, path, json!([filter])).await;
            assert_eq!(status, 403, "{path} {filter}: {body}");
        }
    }

    // It cannot write, even into its own channel.
    let write = EventBuilder::new(Kind::Custom(9), "from the peer key")
        .tag(Tag::parse(["h", &shared]).unwrap())
        .sign_with_keys(&f.peer)
        .unwrap();
    let (status, body) = f.http(&f.peer, "/events", json!(write)).await;
    assert!(
        status != 200 || body["accepted"] == false,
        "{status}: {body}"
    );

    // Relay membership gives it exactly what it gives an unknown key: on a
    // closed relay nothing, so every other route refuses it; on an open relay
    // what any fresh key gets, which the peer could have without this key.
    let decision = |keys: Keys| {
        let f = &f;
        async move {
            crate::api::relay_members::check_relay_membership(
                &f.state,
                f.tenant.community(),
                &keys.public_key().to_bytes(),
                None,
                None,
                None,
            )
            .await
            .unwrap()
        }
    };
    let expected = match relay {
        Relay::Open => crate::api::relay_members::MembershipDecision::OpenRelay,
        Relay::Closed => crate::api::relay_members::MembershipDecision::Denied,
    };
    assert_eq!(decision(f.peer.clone()).await, expected);
    assert_eq!(decision(Keys::generate()).await, expected);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn disconnect_ends_peer_access_at_once_open_relay() {
    disconnect_ends_peer_access_at_once(Relay::Open).await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn disconnect_ends_peer_access_at_once_closed_relay() {
    disconnect_ends_peer_access_at_once(Relay::Closed).await;
}

async fn disconnect_ends_peer_access_at_once(relay: Relay) {
    let f = fixture(relay).await;
    f.message(f.shared, "before the disconnect").await;
    let (conn, mut rx) = f.connect(&f.peer).await;
    assert_eq!(frame(&mut rx).await[2], true);
    assert_eq!(
        f.state
            .db
            .active_peer_connection(f.tenant.community(), &f.peer.public_key().to_hex())
            .await
            .unwrap(),
        Some(PeerConnectionScope {
            connection_id: f.connection,
            channel_id: f.shared
        })
    );

    let ended = super::disconnect(&f.state, &f.tenant, f.connection, &"0".repeat(64))
        .await
        .unwrap()
        .expect("was active");
    assert_eq!(ended.id, f.connection);
    assert!(conn.cancel.is_cancelled(), "the live peer socket is closed");

    // The retired key is now an unknown key. A closed relay refuses it; an
    // open relay admits it like any stranger, without the channel scope, and
    // the private shared channel is closed to it.
    let shared = f.shared.to_string();
    let (again, mut again_rx) = f.connect(&f.peer).await;
    let reply = frame(&mut again_rx).await;
    match relay {
        Relay::Closed => {
            assert_eq!(reply[2], false, "{reply}");
            assert!(!matches!(
                again.auth_state_snapshot(),
                AuthState::Authenticated(_)
            ));
        }
        Relay::Open => {
            assert_eq!(reply[2], true, "{reply}");
            assert_eq!(authenticated_scope(&again), (None, None));
            assert_eq!(
                req(
                    &f,
                    &again,
                    &mut again_rx,
                    "after",
                    json!({"kinds": [9], "#h": [shared]})
                )
                .await,
                None
            );
        }
    }
    let (status, body) = f
        .http(&f.peer, "/query", json!([{"kinds": [9], "#h": [shared]}]))
        .await;
    assert!(
        status == 403 || body.as_array().is_some_and(Vec::is_empty),
        "{status}: {body}"
    );
    assert!(super::disconnect(&f.state, &f.tenant, f.connection, "")
        .await
        .unwrap()
        .is_none());
}
