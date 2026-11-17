#!/usr/bin/env bash
# Run a minimal agent on a demo community brought up by up.sh: its own key, a
# kind 0 carrying the admin's NIP-OA owner attestation (so Buzz shows it as an
# agent), added to <channel> by the admin like any local member, answering
# every message that mentions it with "pong from <name>".
#
#   agent.sh <name> <channel-uuid>     runs in the foreground (Ctrl-C stops)
#
# Needs buzz, buzz-admin and compute_auth_tag in $BUZZ_BIN_DIR (default: this
# checkout's target/debug, plus target/debug/examples for compute_auth_tag),
# and python3. The agent key stays in <state dir>/agent.nsec (0600).
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 <name> <channel-uuid>" >&2; exit 2; }
name=$1
channel=$2
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin_dir="${BUZZ_BIN_DIR:-$here/../../target/debug}"
dir="${CONNECT_DEMO_DIR:-$HOME/.buzz-connect-demo}/$name"
auth_tool="$bin_dir/compute_auth_tag"
[[ -x $auth_tool ]] || auth_tool="$bin_dir/examples/compute_auth_tag"
[[ -f $dir/state.json ]] || { echo "run up.sh $name first" >&2; exit 1; }
http_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_url"])' "$dir/state.json")
buzz() { "$bin_dir/buzz" --relay "$http_url" "$@"; }

umask 077
if [[ ! -f $dir/agent.nsec ]]; then
  keys=$("$bin_dir/buzz-admin" generate-key)
  awk '/Secret key:/ {print $3}' <<<"$keys" >"$dir/agent.nsec"
  awk '/Public key:/ {print $3}' <<<"$keys" >"$dir/agent.pub"
fi
umask 022
agent=$(cat "$dir/agent.pub")
admin_key=$(cat "$dir/admin.nsec")

# A member of this community (local only; it never joins the other one),
# then added to the channel by the admin, the same flow as any local member.
(set -a; source "$dir/relay.env"; "$bin_dir/buzz-admin" add-member --pubkey "$agent" --role member >/dev/null)

# The owner (the community admin) attests the agent; every event the agent
# signs carries that `auth` tag, so its profile reads as an agent's.
BUZZ_AUTH_TAG=$("$auth_tool" "$admin_key" "$agent")
export BUZZ_AUTH_TAG
export BUZZ_PRIVATE_KEY
BUZZ_PRIVATE_KEY=$(cat "$dir/agent.nsec")
buzz users set-profile --name "Pong ($name)" --about "Buzz Connect demo agent" >/dev/null

# Added to the channel by the admin.
env -u BUZZ_AUTH_TAG BUZZ_PRIVATE_KEY="$admin_key" "$bin_dir/buzz" --relay "$http_url" \
  channels add-member --channel "$channel" --pubkey "$agent" --role bot >/dev/null
echo "agent $agent (Pong ($name)) is in $channel; waiting for mentions"

echo $$ >"$dir/agent.pid"
seen="$dir/agent.answered"
touch "$seen"
since=$(date +%s)
while true; do
  buzz messages get --channel "$channel" --since "$since" --limit 50 2>/dev/null |
    python3 -c '
import json, sys
agent, seen_file = sys.argv[1], sys.argv[2]
seen = set(open(seen_file).read().split())
try:
    events = json.load(sys.stdin)
except ValueError:
    events = []
for e in events if isinstance(events, list) else []:
    if e.get("kind") != 9 or e["pubkey"] == agent or e["id"] in seen:
        continue
    if ["p", agent] in [t[:2] for t in e.get("tags", [])]:
        print(e["id"], e["pubkey"])
' "$agent" "$seen" |
    while read -r id author; do
      echo "$id" >>"$seen"
      buzz messages send --channel "$channel" --content "pong from $name" \
        --reply-to "$id" --mention "$author" >/dev/null &&
        echo "answered $id from $author"
    done
  sleep 3
done
