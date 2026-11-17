# Buzz Connect demo

Two throwaway communities, each on its own box, reachable over the internet through a
cloudflared quick tunnel, for trying a shared channel ([docs/buzz-connect.md](../../docs/buzz-connect.md))
end to end. Not a production deployment: no object store (uploads and git hosting off), debug-friendly
defaults, secrets in plain files on the box.

## What a box needs

- Docker (inner Docker without outbound network on the default bridge is fine: everything uses
  `--network=host`), `cloudflared`, `curl`, `openssl`, `python3`.
- One directory with the binaries built from this branch: `buzz-relay`, `buzz-admin`, `buzz` and
  `compute_auth_tag` (`cargo build -p buzz-relay -p buzz-cli -p buzz-admin --bins` and
  `cargo build -p buzz-sdk --example compute_auth_tag`; the last lands in `target/*/examples/`).
  Point `BUZZ_BIN_DIR` at it; by default the scripts use this checkout's `target/debug`.

## Run

```bash
export BUZZ_BIN_DIR=/opt/buzz-connect/bin           # where the binaries are
deploy/connect-demo/up.sh connect-a 3100             # prints state.json
```

`up.sh <name> <port>` starts Postgres (`<port>+1`) and Redis (`<port>+2`) containers, a quick
tunnel, then the relay as a closed relay for one community at the tunnel's `wss://` URL, with a
generated admin key as its owner. It writes `~/.buzz-connect-demo/<name>/state.json`
(`relay_url`, `http_url`, `admin_pubkey`, …); the admin key is in `admin.nsec` next to it (0600, never
printed). `up.sh <name> --down` stops it all and keeps the data.

Share a channel (A's and B's admin keys are on their own boxes):

```bash
# box A
export BUZZ_PRIVATE_KEY=$(cat ~/.buzz-connect-demo/connect-a/admin.nsec) A=<A http_url>
buzz --relay $A channels create --name launch --type stream --visibility private   # → channel_id
buzz --relay $A channels connect --channel <channel_id>                            # → buzz://channel-connect?… link
# box B
export BUZZ_PRIVATE_KEY=$(cat ~/.buzz-connect-demo/connect-b/admin.nsec) B=<B http_url>
buzz --relay $B channels accept --link '<link>'
deploy/connect-demo/agent.sh connect-b <channel_id>   # B's agent, foreground; answers mentions with "pong from connect-b"
# box A
buzz --relay $A messages send --channel <channel_id> --content 'ping' --mention <agent pubkey from agent.sh>
buzz --relay $A messages get --channel <channel_id>   # the pong arrives from B
buzz --relay $A channels disconnect --channel <channel_id>
```

People join with the desktop app by adding the community URL (`relay_url`); the community is closed,
so the admin adds them first (`buzz-admin add-member --pubkey <hex>` with `relay.env` sourced).
In the app, the admin of B opens the `buzz://channel-connect` link instead of
running `channels accept`.

`agent.sh <name> <channel>` gives the agent its own key, makes it a member of *that* community
(`buzz-admin add-member`), publishes its profile with the admin's NIP-OA owner attestation (so Buzz
shows it as an agent), has the admin add it to the channel like any member, then polls the channel
and replies to every message that mentions it.

## What is ephemeral

- **Tunnel URLs change on every start.** The community is keyed by its host, so after a restart the
  relay serves a *new, empty* community at the new URL (the old one stays in the database,
  unreachable), and the other side's connection points at a URL that no longer exists: create the
  channel and connect again.
- A Cloudflare box sleeps after about 45 idle minutes unless a job runs, which stops the tunnel; it
  costs nothing while asleep. Run `up.sh` again after it wakes (new URL, see above).
- Quick tunnels have no SLA and no account; fine for a demo, not for anything else.
