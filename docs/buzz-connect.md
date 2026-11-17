# Buzz Connect: channels shared between communities

`draft` · prototype on the `coreties-org` fork, not proposed upstream

Buzz Connect lets two communities share one channel, the way Slack Connect
does. An admin of community A connects a channel to community B. People and
agents in both communities post, reply, react, edit and delete in it, and each
message keeps its real author. Nobody joins the other community.

This document is written before the code. It records the approved product
spec, the design decisions, the data model, the handshake protocol, exactly
what crosses the community boundary, and the security limits of the
prototype. Later sections name the phase that implements each part.

## User flow

1. An admin in A opens the channel → Members → **Connected communities** →
   **Connect another community**. Buzz shows a one-time link:
   `buzz://channel-connect?relay=<A relay url>&channel=<channel uuid>&code=<one-time code>`.
   The link is valid for 24 hours and works once.
2. An admin in B opens the link in Buzz and confirms. The channel appears in
   B's sidebar with a "shared" icon and the header "Shared with A".
3. Both sides post, reply, react, edit and delete. Every message shows its
   real author, name and avatar. People and agents from the other community
   carry a "· A" (or "· B") marker.
4. An admin on either side can **Disconnect**. Both sides keep the history up
   to that point; nothing new crosses after it.

Agents take part like people (see [Agents](#agents)).

Not in v1: more than two communities per channel, media mirroring, shared
moderation, cross-community DMs, upstreaming, and a mobile badge (mobile shows
the messages without the marker).

## Design decisions

1. **Pull mirroring.** Each relay pulls the other side's channel events over a
   normal NIP-42 WebSocket and stores them through a separate relay-internal
   *mirror path*. Signatures and authors stay intact; no bot re-posts. The rule
   that an event's `pubkey` must equal the authenticated key stays in force for
   every normal client; only the mirror path, which never takes client input,
   stores events signed by someone else.
2. **A separate keypair per connection.** Each side generates a keypair for the
   connection; it is not the relay key. The prototype keeps the private key in
   the `channel_connections` row in plaintext. It must be encrypted at rest
   (or held in a KMS) before real use.
3. **Scoped access.** When the peer relay authenticates with its connection
   key, it is admitted with `channel_ids = [that channel]`, and that scope
   *replaces* normal access rather than narrowing it. It therefore works for
   private channels the key is not a member of. The key gets no global reads,
   no search, no writes and no directory.
4. **No loops, no double push.** Every mirrored event is recorded in
   `mirrored_events`. A peer never receives back events that it supplied. Each
   mirrored event triggers local fan-out and push exactly once.
5. **What syncs:** kind 9 (messages and replies), 7 (reactions), 40003 (edits),
   5 (an author's deletes of their own events), and kind 0 of people who post
   in the channel. **What does not:** membership, moderation, canvas, typing,
   huddles, workflows. Bans stay local: B can ban a remote author on B.
6. **Remote profiles** are stored only as kind 0 events for names and avatars.
   They get no `users` row, so they do not appear in B's directory or search.
7. **Ordering.** One cursor per connection; events are applied in time order. A
   reply whose parent has not arrived yet is retried later. The ±900 s
   timestamp drift check is skipped only on the mirror path.
8. **Handshake.** Admin-only relay operations `connect-offer` (one-time code,
   24 h), `connect-accept` (B creates its copy of the channel with A's UUID,
   adding " (A)" to the name on a clash, and registers its connection key with
   A) and `disconnect`. CLI: `buzz channels connect|accept|disconnect`.
9. **Media.** Files and images posted on A sit behind A's Blossom auth and do
   not load on B in v1. B shows the link.
10. **Community isolation is broken on purpose, within bounds.** This document
    is the record of what crosses (below). The TLA+ and Tamarin models
    (`docs/spec/MultiTenantRelay.tla`, `docs/spec/MultiTenantAuth.spthy`) are
    unchanged: they model one relay's communities, and Buzz Connect does not
    change how one relay separates its own communities. They do not model a
    connection, and nothing here claims they do.

## Agents

An agent is a normal Buzz identity: its own key, a kind 0 profile with the bot
and owner-attestation markers. Its own community's admin adds it to the shared
channel on their side, with the same flow as any local member. There is no
cross-community invite of agents.

1. A mirrored event that p-tags a local member, human or agent, is fanned out
   and notified on the receiving relay **exactly once**, the same way a
   locally posted event is. An agent subscribed to its own relay is woken by
   an @mention from someone in the other community.
2. The agent's replies mirror back like any other message.
3. Remote agent profiles keep their bot and owner-attestation markers, so the
   app shows them as agents, with the "· A" marker too.
4. In the app, @mentioning a remote person or agent produces a reference
   (p-tag and readable name). It never adds them to the local roster and never
   offers to invite them.
5. Adding an agent to a shared channel is the same flow as adding any local
   member.

## Data model

Both tables are tenant-owned (`community_id` first in every key), carry no
foreign keys, triggers or functions (docs/database.md rules 1 and 2), are
written only through community admission (`begin_community_write_transaction`),
and are purged with their community (`EXPECTED_SCOPED_TABLES`,
`PURGE_SCOPED_TABLES`, `APPROVAL_FORWARD_TABLES`).

### `channel_connections`

One row per connection per side. A and B each hold their own row for the same
shared channel; the channel UUID is the same on both sides.

| Column | Meaning |
|---|---|
| `community_id`, `id` | Primary key. `id` is local to this relay. |
| `channel_id` | The shared channel (same UUID on both relays). |
| `role` | `offerer` (A) or `acceptor` (B). |
| `state` | `offered` (A only, link outstanding) → `active` → `disconnected`. |
| `peer_relay_url` | The other relay's WebSocket URL. `NULL` on A until the offer is redeemed. |
| `peer_community_name` | Display name of the other community, for "Shared with …" and the "· A" marker. |
| `local_pubkey`, `local_secret_key` | This side's connection keypair (hex). This side authenticates **at the peer** with it to pull. Plaintext in the prototype (see Security). |
| `peer_pubkey` | The peer's connection pubkey. When it authenticates **here**, it is admitted with the channel scope. Unique per community. |
| `offer_code_hash`, `offer_expires_at` | SHA-256 of the one-time code and its expiry (24 h). Cleared when redeemed. The code itself is never stored. |
| `cursor_created_at`, `cursor_event_id` | Pull cursor: the last applied peer event, by `(created_at, id)`. |
| `created_by` | Admin who created the offer or accepted it. |
| `created_at`, `updated_at`, `disconnected_at` | Timestamps. |

Admission looks a pubkey up with `state = 'active'` only; an offered or
disconnected row admits nothing.

### `mirrored_events`

One row per event this relay stored through the mirror path.

| Column | Meaning |
|---|---|
| `community_id`, `event_id` | Primary key: an event is mirrored into a community at most once. |
| `connection_id` | The connection that supplied it. |
| `origin_relay_url` | The peer relay it came from, kept after the connection row changes. |
| `received_at` | When it was stored. |
| `fanned_out_at` | When local fan-out/push ran for it; `NULL` until then. Used to make fan-out exactly once across retries and pods. |

The loop filter (decision 4) is "when serving connection *c*, omit events with
a `mirrored_events` row whose `connection_id = c`".

## Protocol

### Offer (on A)

An admin of A sends the `connect-offer` relay-admin command for a channel. A
checks the sender is a community admin or owner and the channel exists, then
creates an `offered` row with a fresh connection keypair and a random code,
stores `SHA-256(code)` with a 24 h expiry, and returns the link with the plain
code. The code exists only in the link.

### Accept (on B, then A)

An admin of B runs `connect-accept` with the link. B:

1. checks the sender is an admin or owner of B;
2. generates B's connection keypair;
3. calls A to redeem the code, presenting B's connection pubkey, B's relay URL
   and B's community name. The request is authenticated and bound to B's
   connection key (NIP-98 style: signed by that key). A redeems the code
   atomically: the row must be `offered`, unexpired, and the code unused. A
   stores B's pubkey and URL, sets the row `active`, clears the code hash, and
   answers with A's connection pubkey, A's community name and the channel's
   name, type and visibility;
4. creates its copy of the channel with A's UUID (name suffixed " (A)" when
   the name is taken on B) and an `active` row holding A's pubkey;
5. starts its mirror worker; A starts its worker once its row is `active`.

The exact transport of step 3 is fixed in phase 3 and documented here then.
A reused, expired or unknown code is refused without saying which.

### Mirroring

Each side runs one worker per `active` connection, under the leader lock so a
multi-pod relay does no double work. The worker authenticates at the peer with
NIP-42 using its `local_secret_key`, subscribes with
`{"kinds":[9,7,40003,5],"#h":[channel],"since":cursor}` (kinds are always
explicit), applies events in `(created_at, id)` order through the mirror path,
and advances the cursor durably. It reconnects with jittered, capped backoff and
stops on disconnect or revocation.

The peer serves that subscription under the connection's scope only. Kind 0 of
channel authors is fetched by a second, author-bounded read (phase 2).

### Disconnect

Either admin sends `disconnect`. That side marks its row `disconnected`, stops
its worker and closes every live socket of the peer's key on every pod
(`disconnect_pubkey_clusterwide`), so access ends at once, not at the next
reconnect. The other side learns of it when its next pull is refused and marks
its own row `disconnected`. Both keep the history they have.

## What crosses community isolation, and what does not

Buzz normally guarantees that nothing in community A is observable from B. A
connection deliberately opens one bounded path.

**Crosses, per connection, for that one channel only:**

- kind 9, 7, 40003 and 5 events in the channel, with their original
  signatures, authors, tags and content;
- kind 0 profiles of the people and agents who post in that channel, including
  bot and owner-attestation markers;
- the peer community's name and relay URL (shown as "Shared with A" and "· A");
- the channel's UUID, name, type and visibility at accept time;
- the connection pubkeys of both sides.

**Does not cross:**

- the member list of the shared channel or of either community, the
  directory, search, the channel list, other channels (including other
  channels' existence), DMs, profiles of anyone who has not posted in the
  channel, canvas, typing, huddles, workflows, moderation actions, bans,
  reports, read state, push state, media bytes;
- any write authority: the peer's key cannot publish anything. Mirrored events
  enter only through the relay-internal mirror path, which accepts only the
  synced kinds, for the shared channel, signed by their authors.

**Who learns what.** Each relay sees the other's channel events as its own
members do, and the other relay's community name and URL. An admin of either
side controls the connection for their side; neither can read the other's
members or other channels through it.

### Scoped access, as implemented (phase 1)

Code: `crates/buzz-relay/src/channel_connect.rs`; storage:
`crates/buzz-db/src/store/channel_connection.rs`.

- **Admission.** A connection key is never a relay member. Three seams
  recognise it as a peer when it matches an `active` row: WebSocket AUTH,
  `POST /query` and `POST /count`. On a closed relay they look only after
  membership refused the key, so members pay nothing extra, and every other
  route (media, git, huddles, workflows, invites, `POST /events`, the v1 API,
  …) refuses it like any non-member. On an open relay, where membership
  admits every key, those three seams look first; other routes treat the key
  like any unknown key. That grants nothing the peer relay could not get by
  authenticating with a fresh key, and the private shared channel stays
  closed there. A NIP-FI session or agent token is never treated as a peer.
- **Scope.** On the socket, `AuthContext.channel_ids = Some([channel])` and
  `AuthContext.peer_connection = Some(connection id)`. For a peer,
  `channel_ids` *replaces* the membership-derived channel set in REQ and
  COUNT instead of narrowing it, so a private channel works without a
  membership row. Admission joins the key to nothing (no default or
  open-relay auto-join).
- **Filters.** Every REQ and COUNT filter must name only the channel in a
  non-empty `#h`, must list `kinds`, all from 9, 7, 40003 and 5, and must not
  carry `search`. Anything else is refused with `CLOSED`
  (`restricted: …`), not answered empty. Over HTTP, filters may carry only
  `ids`, `authors`, `kinds`, `since`, `until`, `limit` and `#x` tags: bridge
  extensions (thread windows, feeds, snapshots, artifact reads) answer from
  the caller's own membership and are refused (403). A COUNT must be exactly
  countable in SQL.
- **Writes.** `EVENT` and artifact sync are refused on the socket
  (`OK false` / `CLOSED`, `restricted: a channel connection is read-only`);
  HTTP writes are refused by membership.
- **Live fan-out.** The socket's subscriptions are registered from those
  filters, and the fan-out access gate decides a peer connection on its own:
  it receives events of the synced kinds in its channel, member or not, and
  nothing else, whatever its subscriptions match. The channel is recorded on
  the connection-manager entry at AUTH, so this costs no database read.
- **Revocation.** `channel_connect::disconnect` marks the row
  `disconnected` and closes the key's sockets on every pod at once. The final
  admission fence re-reads the row from the writer, so a disconnect that
  races an AUTH cannot be undone. HTTP requests read the row each time. On an
  open relay the retired key afterwards authenticates like any unknown key:
  without the scope, so the private shared channel is closed to it.

Not in phase 1, by design: the loop filter (phase 2 omits events the
connection supplied, using `mirrored_events`), and the author-bounded kind 0
read for channel authors (phase 2). Until then a peer cannot read any kind 0.

Cost: one indexed read (`channel_connections` by
`(community_id, peer_pubkey)`) per WebSocket AUTH and per `/query` or
`/count` request on an open relay; on a closed relay only for keys membership
already refused. No other route reads it. A per-community cache is the
obvious next step if open relays at scale adopt this.

## Security notes

- **Plaintext connection key.** `local_secret_key` is stored in plaintext in
  the prototype. Anyone who reads the database can impersonate this side at
  the peer and read the shared channel there. Before real use: encrypt it with
  a relay-held key or move it to a KMS, and rotate on suspicion.
- **One-time code.** Only `SHA-256(code)` is stored; the code is single-use and
  expires after 24 h. Anyone holding an unredeemed link can complete the
  connection, so the link is a secret, like an invite link.
- **Bounded authority.** The peer key reads one channel's synced kinds and
  nothing else, and cannot write. Mirrored events still pass signature
  verification, the kind allowlist, the channel check and local bans on the
  receiving side; edits and deletes must be by the original author.
- **Remote authors are not members.** They have no `users` row, no roster
  entry and no access to the receiving community. Their events exist only
  inside the shared channel.
- **Formal models unchanged.** As stated in decision 10, the TLA+ and Tamarin
  models do not cover connections. The isolation proof in
  [multi-tenant-relay.md](multi-tenant-relay.md) still holds between
  communities on one relay; Buzz Connect is an explicit, documented flow
  between two relays that the proof does not speak to.

## Implementation phases

1. This document; `channel_connections` and `mirrored_events` with store
   functions; scoped admission for connection keys.
2. Mirror path and worker; loop filter; exactly-once fan-out; agents.
3. Handshake operations, CLI, `["connected", url, name]` on the channel's
   kind 39000.
4. App: connect/accept UI, shared badge, remote author markers, mentions.
5. Try-out environment with two relays.
6. End-to-end verification.
