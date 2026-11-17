#!/usr/bin/env bash
# Bring up one Buzz Connect demo community: Postgres + Redis (Docker, host
# network), a cloudflared quick tunnel, and the relay built from this branch,
# serving one community at the tunnel's public URL.
#
#   up.sh <name> <port>     e.g. up.sh connect-a 3100
#   up.sh <name> --down     stop the relay, tunnel and containers (data kept)
#
# Ports: relay <port>, Postgres <port>+1, Redis <port>+2, health <port>+3,
# metrics <port>+4.
# Binaries: $BUZZ_BIN_DIR (default: target/debug of this checkout) must hold
# buzz-relay, buzz-admin and buzz.
# State: $CONNECT_DEMO_DIR/<name> (default ~/.buzz-connect-demo/<name>):
# state.json (public), admin.nsec (0600, never printed), logs, pids.
set -euo pipefail

usage() { echo "usage: $0 <name> <port> | $0 <name> --down" >&2; exit 2; }
[[ $# -eq 2 ]] || usage
name=$1
[[ $name =~ ^[a-z0-9-]+$ ]] || { echo "name must be [a-z0-9-]+" >&2; exit 2; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin_dir="${BUZZ_BIN_DIR:-$here/../../target/debug}"
dir="${CONNECT_DEMO_DIR:-$HOME/.buzz-connect-demo}/$name"
pg="buzz-demo-$name-pg"
redis="buzz-demo-$name-redis"

stop_pid() {
  local file="$dir/$1.pid"
  if [[ -f $file ]]; then
    kill "$(cat "$file")" 2>/dev/null || true
    rm -f "$file"
  fi
}

if [[ $2 == --down ]]; then
  stop_pid relay
  stop_pid tunnel
  stop_pid agent
  docker stop "$pg" "$redis" >/dev/null 2>&1 || true
  echo "$name stopped (data in $dir and container $pg kept; up.sh again re-uses them)"
  exit 0
fi

port=$2
[[ $port =~ ^[0-9]+$ ]] || usage
pg_port=$((port + 1))
redis_port=$((port + 2))
for b in buzz-relay buzz-admin buzz; do
  [[ -x $bin_dir/$b ]] || { echo "missing $bin_dir/$b (set BUZZ_BIN_DIR)" >&2; exit 1; }
done
command -v cloudflared >/dev/null || { echo "cloudflared not installed" >&2; exit 1; }
mkdir -p "$dir/repos"
chmod 700 "$dir"

# Dependencies: re-use the containers (and their data) when they exist.
if ! docker start "$pg" >/dev/null 2>&1; then
  docker run -d --name "$pg" --network=host \
    -e POSTGRES_USER=buzz -e POSTGRES_PASSWORD=buzz_dev -e POSTGRES_DB=buzz \
    postgres:16 -c port="$pg_port" >/dev/null
fi
if ! docker start "$redis" >/dev/null 2>&1; then
  docker run -d --name "$redis" --network=host redis:7 --port "$redis_port" >/dev/null
fi
until docker exec "$pg" pg_isready -q -p "$pg_port" -U buzz; do sleep 1; done

# A quick tunnel gets a new URL on every start, so the relay URL follows it.
stop_pid tunnel
cloudflared tunnel --no-autoupdate --protocol http2 --url "http://127.0.0.1:$port" >"$dir/tunnel.log" 2>&1 &
echo $! >"$dir/tunnel.pid"
host=""
for _ in $(seq 60); do
  host=$(grep -aoE 'https://[a-z0-9-]+\.trycloudflare\.com' "$dir/tunnel.log" | head -1 | sed 's#https://##') || true
  [[ -n $host ]] && break
  sleep 1
done
[[ -n $host ]] || { echo "no tunnel URL, see $dir/tunnel.log" >&2; exit 1; }

# Secrets stay in the box: generated once, 0600.
umask 077
if [[ ! -f $dir/env.secret ]]; then
  {
    echo "BUZZ_RELAY_PRIVATE_KEY=$(openssl rand -hex 32)"
    echo "BUZZ_GIT_HOOK_HMAC_SECRET=$(openssl rand -hex 32)"
  } >"$dir/env.secret"
fi
if [[ ! -f $dir/admin.nsec ]]; then
  keys=$("$bin_dir/buzz-admin" generate-key)
  awk '/Secret key:/ {print $3}' <<<"$keys" >"$dir/admin.nsec"
  awk '/Public key:/ {print $3}' <<<"$keys" >"$dir/admin.pub"
fi
umask 022

export DATABASE_URL="postgres://buzz:buzz_dev@127.0.0.1:$pg_port/buzz"
export REDIS_URL="redis://127.0.0.1:$redis_port"
export RELAY_URL="wss://$host"
export BUZZ_BIND_ADDR="127.0.0.1:$port"
export BUZZ_HEALTH_PORT=$((port + 3))
export BUZZ_METRICS_PORT=$((port + 4))
export BUZZ_REQUIRE_RELAY_MEMBERSHIP=true
export RELAY_OWNER_PUBKEY="$(cat "$dir/admin.pub")"
export BUZZ_GIT_REPO_PATH="$dir/repos"
export BUZZ_MEDIA_READ_MODE=off
export BUZZ_PUSH_ENABLED=false
# No object store in the demo: git hosting and uploads are off, so skip the
# git object-store probe.
export BUZZ_GIT_CONFORMANCE_PROBE=false
export RUST_LOG="${RUST_LOG:-buzz_relay=info}"
set -a
# shellcheck disable=SC1091
source "$dir/env.secret"
set +a

# The relay's environment, for buzz-admin later (agent.sh); holds secrets.
(umask 077; export -p | grep -E ' (DATABASE_URL|REDIS_URL|RELAY_URL|RELAY_OWNER_PUBKEY|BUZZ_[A-Z_]+)=' >"$dir/relay.env")

"$bin_dir/buzz-admin" migrate >"$dir/migrate.log" 2>&1
stop_pid relay
"$bin_dir/buzz-relay" >"$dir/relay.log" 2>&1 &
echo $! >"$dir/relay.pid"
for _ in $(seq 120); do
  curl -fsS "http://127.0.0.1:$port/_liveness" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://127.0.0.1:$port/_liveness" >/dev/null || { echo "relay not live, see $dir/relay.log" >&2; exit 1; }

# The relay seeds the community for RELAY_URL's host at startup, with the
# demo admin as its owner (RELAY_OWNER_PUBKEY).
admin_hex=$RELAY_OWNER_PUBKEY

# Public tunnels take a moment to route; wait until the relay answers there.
for _ in $(seq 60); do
  curl -fsS "https://$host/_liveness" >/dev/null 2>&1 && break
  sleep 2
done

cat >"$dir/state.json" <<JSON
{
  "name": "$name",
  "relay_url": "wss://$host",
  "http_url": "https://$host",
  "local_port": $port,
  "admin_pubkey": "$admin_hex",
  "admin_key_file": "$dir/admin.nsec",
  "web_client_url": null
}
JSON
cat "$dir/state.json"
