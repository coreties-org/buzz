//! Buzz Connect end to end, on two relays (two routers on two ports over one
//! Postgres, each serving its own community): the handshake through the real
//! commands and the CLI, mirroring of every synced kind both ways, no echo,
//! a reply that arrives before its parent, edit/delete ownership, an agent on
//! B woken exactly once by a mention from A whose reply reaches A with its
//! agent markers, and a disconnect from one side that ends both.

use std::sync::Arc;
use std::time::Duration;

use buzz_core::channel::MemberRole;
use buzz_core::TenantContext;
use buzz_db::channel_connection::{ChannelConnection, ConnectionState};
use buzz_ws_client::{NostrWsConnection, RelayMessage};
use nostr::{EventBuilder, Filter, Keys, Kind, Tag, Timestamp};
use serde_json::json;
use uuid::Uuid;

use crate::handlers::group_state_postgres_tests::create_channel;
use crate::handlers::ingest::{ingest_event, HttpAuthMethod, IngestAuth, IngestError};
use crate::state::AppState;

struct Side {
    state: Arc<AppState>,
    tenant: TenantContext,
    url: String,
    admin: Keys,
}

/// A closed relay with its own community, served on its own port.
async fn side() -> Side {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let base = crate::api::bridge::postgres_tests::bridge_handler_test_state()
        .await
        .expect("local Postgres and Redis");
    let mut state = (*base).clone();
    let config = Arc::make_mut(&mut state.config);
    config.relay_url = format!("ws://127.0.0.1:{port}");
    config.require_relay_membership = true;
    let state = Arc::new(state);
    let host = format!("127.0.0.1:{port}");
    let community = state
        .db
        .ensure_configured_community(&host)
        .await
        .expect("community")
        .id;
    let tenant = TenantContext::resolved(community, &host);
    let admin = Keys::generate();
    member(&state, &tenant, &admin, "admin").await;
    let router = crate::router::build_router(state.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("serve")
    });
    Side {
        state,
        tenant,
        url: format!("ws://127.0.0.1:{port}"),
        admin,
    }
}

async fn member(state: &Arc<AppState>, tenant: &TenantContext, keys: &Keys, role: &str) {
    state
        .db
        .add_relay_member(
            tenant.community(),
            &keys.public_key().to_hex(),
            role,
            None,
            &Keys::generate(),
        )
        .await
        .map(|write| write.outcome)
        .expect("relay member");
}

fn signed(
    keys: &Keys,
    kind: u16,
    content: &str,
    tags: &[&[&str]],
    at: Option<i64>,
) -> nostr::Event {
    let mut builder = EventBuilder::new(Kind::Custom(kind), content).tags(
        tags.iter()
            .map(|tag| Tag::parse(tag.iter().copied()).expect("tag")),
    );
    if let Some(at) = at {
        builder = builder.custom_created_at(Timestamp::from(at as u64));
    }
    builder.sign_with_keys(keys).expect("sign")
}

impl Side {
    async fn submit(&self, keys: &Keys, event: nostr::Event) -> Result<String, IngestError> {
        ingest_event(
            &self.state,
            &self.tenant,
            event,
            IngestAuth::Http {
                pubkey: keys.public_key(),
                scopes: buzz_auth::Scope::all_known(),
                auth_method: HttpAuthMethod::Nip98,
            },
        )
        .await
        .map(|result| result.message)
    }

    async fn post(
        &self,
        keys: &Keys,
        kind: u16,
        content: &str,
        tags: &[&[&str]],
    ) -> nostr::EventId {
        self.post_at(keys, kind, content, tags, None).await
    }

    async fn post_at(
        &self,
        keys: &Keys,
        kind: u16,
        content: &str,
        tags: &[&[&str]],
        at: Option<i64>,
    ) -> nostr::EventId {
        let event = signed(keys, kind, content, tags, at);
        let id = event.id;
        self.submit(keys, event)
            .await
            .unwrap_or_else(|e| panic!("kind:{kind} refused: {e:?}"));
        id
    }

    async fn command(&self, keys: &Keys, kind: u32, tag: [&str; 2]) -> Result<String, String> {
        self.submit(keys, signed(keys, kind as u16, "", &[&tag], None))
            .await
            .map_err(|e| format!("{e:?}"))
    }

    async fn has(&self, id: nostr::EventId) -> bool {
        self.state
            .db
            .get_event_by_id(self.tenant.community(), id.as_bytes())
            .await
            .expect("read")
            .is_some()
    }

    async fn wait_for(&self, id: nostr::EventId, what: &str) {
        for _ in 0..100 {
            if self.has(id).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{what} never arrived");
    }

    async fn connection(&self, channel: Uuid) -> ChannelConnection {
        self.state
            .db
            .list_channel_connections(self.tenant.community(), channel)
            .await
            .expect("connections")
            .pop()
            .expect("a connection row")
    }

    /// Run the connection's worker, as the supervisor would.
    async fn pull(&self, channel: Uuid) -> tokio::task::JoinHandle<()> {
        tokio::spawn(super::mirror::run_connection(
            self.state.clone(),
            self.tenant.clone(),
            self.connection(channel).await,
        ))
    }

    /// The `connected` tags of the channel's latest kind 39000.
    async fn connected_tags(&self, channel: Uuid) -> Vec<Vec<String>> {
        let filter = Filter::new()
            .kind(Kind::Custom(39000))
            .identifier(channel.to_string());
        let query = crate::handlers::req::build_event_query_from_filter(
            &filter,
            &[],
            &self.state,
            self.tenant.community(),
        )
        .await;
        let rows = self.state.db.query_events(&query).await.expect("39000");
        let latest = rows
            .into_iter()
            .max_by_key(|row| row.event.created_at)
            .expect("a kind 39000");
        latest
            .event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .filter(|tag| tag.first().map(String::as_str) == Some("connected"))
            .collect()
    }

    async fn cli(&self, keys: &Keys, args: &[&str]) -> i32 {
        let http = self.url.replace("ws://", "http://");
        let secret = keys.secret_key().to_secret_hex();
        let mut argv = vec!["buzz", "--relay", &http, "--private-key", &secret];
        argv.extend_from_slice(args);
        buzz_cli::run_from_args(argv).await
    }
}

/// Mirrored events the agent's live subscription receives within `window`.
async fn received(ws: &mut NostrWsConnection, id: nostr::EventId, window: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + window;
    let mut count = 0;
    while let Some(left) = deadline.checked_duration_since(tokio::time::Instant::now()) {
        match ws.next_event(left).await {
            Ok(RelayMessage::Event { event, .. }) if event.id == id => count += 1,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    count
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn shared_channel_mirrors_both_ways_and_ends_from_either_side() {
    use buzz_core::kind::{KIND_CHANNEL_CONNECT_ACCEPT, KIND_CHANNEL_CONNECT_OFFER};
    let _ = tracing_subscriber::fmt()
        .with_env_filter("buzz_relay::channel_connect=info")
        .with_test_writer()
        .try_init();
    let a = side().await;
    let b = side().await;
    let alice = Keys::generate();
    let bob = Keys::generate();
    let carol = Keys::generate();
    let helper = Keys::generate();
    member(&a.state, &a.tenant, &alice, "member").await;
    member(&b.state, &b.tenant, &bob, "member").await;
    member(&b.state, &b.tenant, &carol, "member").await;
    member(&b.state, &b.tenant, &helper, "member").await;

    // A private channel on A, with history from before the connection: a
    // reply timestamped before its parent, and Alice's profile.
    let channel =
        create_channel(&a.state, &a.tenant, &a.admin, &[&["visibility", "private"]]).await;
    let h = channel.to_string();
    a.state
        .db
        .add_member(
            a.tenant.community(),
            channel,
            &alice.public_key().to_bytes(),
            MemberRole::Member,
            Some(&a.admin.public_key().to_bytes()),
        )
        .await
        .expect("alice joins");
    let now = chrono::Utc::now().timestamp();
    let parent = a
        .post_at(&alice, 9, "parent", &[&["h", &h]], Some(now - 50))
        .await;
    let early_reply = a
        .post_at(
            &alice,
            9,
            "reply stamped before its parent",
            &[&["h", &h], &["e", &parent.to_hex(), "", "reply"]],
            Some(now - 60),
        )
        .await;
    let alice_name = format!("Alice{}", Uuid::new_v4().simple());
    let alice_profile = a
        .post(&alice, 0, &json!({ "name": alice_name }).to_string(), &[])
        .await;

    // Only admins offer and accept.
    let refused = a
        .command(&alice, KIND_CHANNEL_CONNECT_OFFER, ["channel", &h])
        .await
        .expect_err("a member cannot offer");
    assert!(refused.contains("admin"), "{refused}");
    let link = a
        .command(&a.admin, KIND_CHANNEL_CONNECT_OFFER, ["channel", &h])
        .await
        .expect("offer");
    assert!(link.starts_with("buzz://channel-connect?"), "{link}");
    let refused = b
        .command(&carol, KIND_CHANNEL_CONNECT_ACCEPT, ["link", &link])
        .await
        .expect_err("a member cannot accept");
    assert!(refused.contains("admin"), "{refused}");

    // B's admin accepts through the CLI; the link is then spent.
    assert_eq!(
        b.cli(&b.admin, &["channels", "accept", "--link", &link])
            .await,
        0
    );
    let refused = b
        .command(&b.admin, KIND_CHANNEL_CONNECT_ACCEPT, ["link", &link])
        .await
        .expect_err("a used link");
    assert!(refused.contains("invalid, used or expired"), "{refused}");
    let copy = b
        .state
        .db
        .get_channel(b.tenant.community(), channel)
        .await
        .expect("B has the channel under A's UUID");
    assert_eq!(copy.visibility, "private");
    assert_eq!(a.connection(channel).await.state, ConnectionState::Active);
    assert_eq!(b.connection(channel).await.state, ConnectionState::Active);
    assert_eq!(
        b.connected_tags(channel).await,
        vec![vec![
            "connected".to_owned(),
            a.url.clone(),
            a.tenant.host().to_owned()
        ]]
    );
    assert_eq!(
        a.connected_tags(channel).await,
        vec![vec![
            "connected".to_owned(),
            b.url.clone(),
            b.tenant.host().to_owned()
        ]]
    );

    // B's admin adds Bob and the agent like any local member.
    for keys in [&bob, &helper] {
        b.state
            .db
            .add_member(
                b.tenant.community(),
                channel,
                &keys.public_key().to_bytes(),
                MemberRole::Member,
                Some(&b.admin.public_key().to_bytes()),
            )
            .await
            .expect("member on B");
    }
    let attestation = buzz_sdk::nip_oa::compute_auth_tag(&bob, &helper.public_key(), "")
        .expect("owner attestation");
    let auth_tag = buzz_sdk::nip_oa::parse_auth_tag(&attestation).expect("auth tag");
    let auth_parts: Vec<String> = auth_tag.as_slice().to_vec();
    let auth_refs: Vec<&str> = auth_parts.iter().map(String::as_str).collect();
    let helper_profile = b
        .post(&helper, 0, r#"{"name":"Helper","bot":true}"#, &[&auth_refs])
        .await;

    let workers = [a.pull(channel).await, b.pull(channel).await];

    // History, including the reply that sorts before its parent, and the
    // author's profile, which stays an event: no users row on B, and B's
    // people search does not find it (A's does).
    b.wait_for(parent, "the parent").await;
    b.wait_for(early_reply, "the early reply").await;
    b.wait_for(alice_profile, "Alice's profile").await;
    assert!(b
        .state
        .db
        .get_user(b.tenant.community(), &alice.public_key().to_bytes())
        .await
        .expect("users read")
        .is_none());
    let people = |side: &Side| {
        let search = side.state.search.clone();
        let community = side.tenant.community();
        let name = alice_name.clone();
        async move {
            search
                .search_profile_names(community, &name, None, 1, 20)
                .await
                .expect("people search")
                .hits
                .len()
        }
    };
    assert_eq!(people(&a).await, 1, "control: A finds Alice");
    assert_eq!(
        people(&b).await,
        0,
        "B's search must not find a remote author"
    );

    // The agent, subscribed to its own relay the way buzz-acp does (per
    // channel, mentions only), is woken once by Alice's mention.
    let mut agent = NostrWsConnection::connect_authenticated(&b.url, &helper, None)
        .await
        .expect("agent connects to B");
    let helper_hex = helper.public_key().to_hex();
    agent
        .send_raw(&json!(["REQ", "mentions", {
            "kinds": [9], "#h": [h], "#p": [helper_hex], "since": chrono::Utc::now().timestamp()
        }]))
        .await
        .expect("subscribe");
    let mention = a
        .post(
            &alice,
            9,
            "@Helper can you look?",
            &[&["h", &h], &["p", &helper_hex]],
        )
        .await;
    assert_eq!(
        received(&mut agent, mention, Duration::from_secs(5)).await,
        1
    );

    // The agent's reply, with its owner attestation, reaches A with its profile.
    let answer = b
        .post(
            &helper,
            9,
            "on it",
            &[
                &["h", &h],
                &["e", &mention.to_hex(), "", "reply"],
                &["p", &alice.public_key().to_hex()],
                &auth_refs,
            ],
        )
        .await;
    a.wait_for(answer, "the agent's reply").await;
    a.wait_for(helper_profile, "the agent's profile").await;
    let profile = a
        .state
        .db
        .get_event_by_id(a.tenant.community(), helper_profile.as_bytes())
        .await
        .expect("read")
        .expect("profile");
    assert!(profile.event.content.contains(r#""bot":true"#));
    assert!(profile
        .event
        .tags
        .iter()
        .any(|t| t.as_slice() == auth_parts.as_slice()));

    // Reactions, an edit and a delete, both ways.
    let bob_reacts = b
        .post(
            &bob,
            7,
            "+",
            &[
                &["e", &mention.to_hex()],
                &["p", &alice.public_key().to_hex()],
            ],
        )
        .await;
    let alice_reacts = a
        .post(
            &alice,
            7,
            "🎉",
            &[&["e", &answer.to_hex()], &["p", &helper_hex]],
        )
        .await;
    let edit = a
        .post(
            &alice,
            40003,
            "@Helper can you look now?",
            &[&["h", &h], &["e", &mention.to_hex()]],
        )
        .await;
    let doomed = b.post(&bob, 9, "typo", &[&["h", &h]]).await;
    a.wait_for(doomed, "Bob's message").await;
    let delete = b.post(&bob, 5, "", &[&["e", &doomed.to_hex()]]).await;
    a.wait_for(bob_reacts, "Bob's reaction").await;
    b.wait_for(alice_reacts, "Alice's reaction").await;
    b.wait_for(edit, "Alice's edit").await;
    for _ in 0..100 {
        if !a.has(doomed).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!a.has(doomed).await, "Bob's delete reaches A");
    assert!(a
        .state
        .db
        .get_event_by_id_including_deleted(a.tenant.community(), delete.as_bytes())
        .await
        .expect("read")
        .is_some());

    // No echo: neither side was ever handed back its own events.
    let supplied = |side: &Side, connection: Uuid, ids: Vec<nostr::EventId>| {
        let state = side.state.clone();
        let community = side.tenant.community();
        async move {
            state
                .db
                .mirrored_event_ids_from(
                    community,
                    connection,
                    &ids.iter()
                        .map(|id| id.as_bytes().to_vec())
                        .collect::<Vec<_>>(),
                )
                .await
                .expect("mirrored ids")
        }
    };
    let a_conn = a.connection(channel).await.id;
    let b_conn = b.connection(channel).await.id;
    assert!(
        supplied(&a, a_conn, vec![parent, mention, edit, alice_reacts])
            .await
            .is_empty()
    );
    assert!(
        supplied(&b, b_conn, vec![answer, bob_reacts, doomed, delete])
            .await
            .is_empty()
    );
    assert_eq!(
        supplied(&b, b_conn, vec![parent, mention, edit])
            .await
            .len(),
        3
    );

    // The mirror path itself: only the author edits or deletes, only the
    // shared channel, only the synced kinds.
    let mallory = Keys::generate();
    let mirror = |event: nostr::Event| {
        let state = b.state.clone();
        let tenant = b.tenant.clone();
        async move {
            ingest_event(
                &state,
                &tenant,
                event.clone(),
                IngestAuth::Mirror {
                    author: event.pubkey,
                    channel_id: channel,
                },
            )
            .await
        }
    };
    for (event, why) in [
        (
            signed(
                &mallory,
                40003,
                "forged",
                &[&["h", &h], &["e", &mention.to_hex()]],
                None,
            ),
            "an edit by someone else",
        ),
        (
            signed(&mallory, 5, "", &[&["e", &mention.to_hex()]], None),
            "a delete by someone else",
        ),
        (
            signed(
                &alice,
                9,
                "elsewhere",
                &[&["h", &Uuid::new_v4().to_string()]],
                None,
            ),
            "another channel",
        ),
        (signed(&alice, 1, "note", &[], None), "an unsynced kind"),
    ] {
        assert!(
            matches!(mirror(event).await, Err(IngestError::Rejected(_))),
            "the mirror path stored {why}"
        );
    }

    // A disconnects through the CLI; B learns it from A, both keep history.
    assert_eq!(
        a.cli(&a.admin, &["channels", "disconnect", "--channel", &h])
            .await,
        0
    );
    for _ in 0..200 {
        if b.connection(channel).await.state == ConnectionState::Disconnected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        b.connection(channel).await.state,
        ConnectionState::Disconnected
    );
    assert!(b.connected_tags(channel).await.is_empty());
    assert!(a.connected_tags(channel).await.is_empty());
    let after = a.post(&alice, 9, "after the end", &[&["h", &h]]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!b.has(after).await, "nothing crosses after a disconnect");
    assert!(b.has(mention).await && a.has(answer).await, "history stays");
    for worker in workers {
        tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .expect("both workers stop")
            .expect("worker");
    }
}
