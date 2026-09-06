#!/usr/bin/env bash
# The whole live demo in one command: check, clean, bring the bridge online,
# generate the telemetry, drop the alert, and hold open for the button until you
# Ctrl-C.
#
#   make demo                 # or: ./scripts/demo-run.sh
#   RUN_ID=my-demo make demo  # override the auto-generated run id
#
# Cleanup is at the START (teardown clears any prior run so the fresh seed can
# mint), so on exit nothing the harness needs is removed -- the exit trap only
# stops the bot + tunnel and powers down the attacker host to stop the cost meter.
# The run's keys, orphan, and CloudTrail telemetry survive for re-showing.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
sd="$root/.venv/bin/serverless-demo"
port="${BOT_PORT:-8787}"
run_id="${RUN_ID:-demo-$(date +%Y%m%d-%H%M%S)}"

bot_pid=""
tunnel_pid=""
tunnel_log=""

say()  { printf '\n\033[1;35m== %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31merror: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  # Idempotent: runs on normal exit, on error, and on Ctrl-C.
  trap - INT TERM EXIT
  say "shutting down"
  [ -n "$bot_pid" ]    && kill "$bot_pid"    2>/dev/null && echo "  stopped the launch bridge"
  [ -n "$tunnel_pid" ] && kill "$tunnel_pid" 2>/dev/null && echo "  stopped the tunnel"
  [ -n "$tunnel_log" ] && rm -f "$tunnel_log"
  # Power down the attacker host + release the EIP. Touches no keys/telemetry, so
  # the harness and the finding stay intact.
  echo "  returning the estate to minimum cost..."
  "$sd" down >/dev/null 2>&1 && echo "  done (run \`make up\` to re-demo, or open the harness anytime)"
  exit 0
}
trap cleanup INT TERM EXIT

# --- 1. preconditions (fail fast, before the ~15-minute seed) ----------------
say "preflight"
[ -f .env ] || fail "no .env -- copy .env.example to .env and fill it in"
set -a; . ./.env; set +a
for v in SLACK_BOT_TOKEN SLACK_CHANNEL SERVERLESS_API_URL SERVERLESS_CLIENT_ID \
         SERVERLESS_CLIENT_SECRET SOC_TRIAGE_CONFIG_ID BOT_SIGNING_SECRET; do
  [ -n "${!v:-}" ] || fail "$v is not set in .env (see harness/slack/SETUP.md)"
done
command -v cloudflared >/dev/null 2>&1 || fail "cloudflared not found (brew install cloudflared)"
./scripts/check-aws-account.sh "${MGMT_ACCOUNT_ID:-429418377902}" >/dev/null \
  || fail "AWS identity is not the management account"
echo "  running verify (the estate must be sound before seeding)..."
"$sd" verify >/dev/null 2>&1 || fail "verify failed -- run \`make verify\` to see why"
echo "  ok: env, aws identity, cloudflared, estate verified"

# --- 2. clean slate ----------------------------------------------------------
say "clean slate"
"$sd" teardown >/dev/null 2>&1 && echo "  prior run cleared (or already clean)"

# --- 3. bring the launch bridge online (background) --------------------------
say "launch bridge"
tunnel_log="$(mktemp)"
cloudflared tunnel --url "http://localhost:$port" >"$tunnel_log" 2>&1 &
tunnel_pid=$!
url=""
for _ in $(seq 1 30); do
  url="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$tunnel_log" | head -1 || true)"
  [ -n "$url" ] && break
  sleep 1
done
[ -n "$url" ] || fail "tunnel did not produce a URL (see $tunnel_log)"
if grep -q '^export BOT_PUBLIC_URL=' .env; then
  sed -i.bak "s#^export BOT_PUBLIC_URL=.*#export BOT_PUBLIC_URL=$url#" .env && rm -f .env.bak
else
  printf '\nexport BOT_PUBLIC_URL=%s\n' "$url" >> .env
fi
export BOT_PUBLIC_URL="$url"
echo "  tunnel live: $url"

"$sd" bot serve --port "$port" >/tmp/serverless-demo-bot.log 2>&1 &
bot_pid=$!
for _ in $(seq 1 15); do
  curl -sf "http://localhost:$port/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://localhost:$port/health" >/dev/null 2>&1 \
  || fail "bot bridge did not come up (see /tmp/serverless-demo-bot.log)"
echo "  bridge healthy on :$port (log: /tmp/serverless-demo-bot.log)"

# --- 4. generate telemetry (foreground, ~15 min) -----------------------------
say "seed $run_id  (generating real telemetry; CloudTrail lags 5-15 min)"
"$sd" seed --run-id "$run_id" || fail "seed did not complete"

# --- 5. drop the alert -------------------------------------------------------
say "fire the alert into Slack"
"$sd" demo fire --run-id "$run_id" || fail "posting the alert failed"

# --- 6. hold -----------------------------------------------------------------
say "demo is live"
cat <<EOF
  The alert and SOAR results are in Slack. Click "Investigate in harness" to launch.
  Run id: $run_id   ·   bridge: $url

  Leave this terminal open -- the button needs the bridge.
  Ctrl-C when you are done: stops the bridge and powers the estate down.
EOF
# Wait on the bot; Ctrl-C fires the trap.
wait "$bot_pid"
