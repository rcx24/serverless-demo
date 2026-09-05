#!/usr/bin/env bash
# Brings the launch bridge online for a demo: starts the tunnel, discovers its
# public URL, writes it into .env as BOT_PUBLIC_URL, and runs the bot server in the
# foreground. Stop it with Ctrl-C and the tunnel is torn down with it.
#
# The tunnel URL is ephemeral (a fresh trycloudflare hostname each run), which is
# why this discovers it and writes it to .env every time -- so `serverless-demo
# demo fire` in another terminal picks up the current one via `source .env`.
#
# Usage:
#   ./scripts/demo-up.sh            # this terminal: tunnel + bot bridge
#   # then, in another terminal:
#   source .env && serverless-demo demo fire --run-id <id>
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
port="${BOT_PORT:-8787}"

[ -f .env ] || { echo "No .env found. Copy .env.example to .env and fill it in." >&2; exit 1; }
set -a; . ./.env; set +a

command -v cloudflared >/dev/null 2>&1 || {
  echo "cloudflared not found. Install it (brew install cloudflared) or use ngrok." >&2; exit 1; }

log="$(mktemp)"
echo "Starting tunnel to :$port ..."
cloudflared tunnel --url "http://localhost:$port" >"$log" 2>&1 &
tunnel_pid=$!
trap 'kill "$tunnel_pid" 2>/dev/null; rm -f "$log"; echo; echo "tunnel stopped"' EXIT

# Wait for the public URL to appear in the log.
url=""
for _ in $(seq 1 30); do
  url="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$log" | head -1 || true)"
  [ -n "$url" ] && break
  sleep 1
done
[ -n "$url" ] || { echo "Tunnel did not produce a URL. See $log" >&2; exit 1; }

# Write BOT_PUBLIC_URL into .env (replace or append), so `demo fire` picks it up.
if grep -q '^export BOT_PUBLIC_URL=' .env; then
  # portable in-place edit (BSD + GNU sed)
  sed -i.bak "s#^export BOT_PUBLIC_URL=.*#export BOT_PUBLIC_URL=$url#" .env && rm -f .env.bak
else
  printf '\nexport BOT_PUBLIC_URL=%s\n' "$url" >> .env
fi

echo "Tunnel live: $url"
echo "Wrote BOT_PUBLIC_URL to .env"
echo
echo "In another terminal:  source .env && serverless-demo demo fire --run-id <id>"
echo "Bridge running below. Ctrl-C to stop everything."
echo

export BOT_PUBLIC_URL="$url"
exec "$root/.venv/bin/serverless-demo" bot serve --port "$port"
