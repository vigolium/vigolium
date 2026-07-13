#!/usr/bin/env bash
# smoke-autopilot-access.sh — durable-autopilot access-control + XSS smoke test.
#
# A SMOKE TEST, not a deterministic e2e test: it runs the REAL vigolium agent
# autopilot (a live, PAID, non-deterministic LLM run) against the deliberately
# vulnerable access-lab, with credentials supplied ONLY in the natural-language
# prompt — the flow a native, unauthenticated scan cannot do. It then scores the
# run against ground truth: authenticated IDOR (V1/V2), broken access control
# (V3/V4), DOM-based XSS (V5), stored XSS (V6), and mass assignment (V7).
#
# >>> THIS COSTS MONEY <<<  It makes provider (codex/OpenAI) calls under your
# configured agent.olium credentials. Bounded by MAX_DURATION, but not free.
#
# Env knobs:
#   VIGOLIUM_BIN   vigolium binary to use            (default: vigolium on PATH)
#   TARGET         target URL                          (default: http://127.0.0.1:9899)
#   MODE           autopilot_mode: enforced|shadow    (default: enforced)
#   MODEL          olium model id (change to save/spend) (default: gpt-5.4)
#   MAX_DURATION   wall-clock cost ceiling            (default: 12m)
#   BROWSER        1 = enable agent-browser (needed for V5/V6)  (default: 1)
#   SKIP_APP       1 = don't start/stop access-lab    (reuse a running one)
#   NO_CONFIRM     1 = skip the cost confirmation
set -euo pipefail

VIGOLIUM_BIN="${VIGOLIUM_BIN:-vigolium}"
TARGET="${TARGET:-http://127.0.0.1:9899}"
MODE="${MODE:-enforced}"
MODEL="${MODEL:-gpt-5.4}"
MAX_DURATION="${MAX_DURATION:-12m}"
BROWSER="${BROWSER:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT/test/testdata/vulnerable-apps/access-lab"
OUT_DIR="$(mktemp -d)"
APP_PID=""

cleanup() {
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null || true
  # `go run` spawns a compiled child that outlives the parent kill, so if we
  # started the app, also clear anything left listening on its port.
  if [ "${SKIP_APP:-}" != "1" ]; then
    local lp
    lp=$(lsof -ti tcp:9899 2>/dev/null || true)
    [ -n "$lp" ] && kill $lp 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Best-effort read of the configured provider (the script overrides the model,
# not the provider) for the setup banner.
PROVIDER="$(sed -n '/^ *olium:/,/^[^ ]/p' "$HOME/.vigolium/vigolium-configs.yaml" 2>/dev/null | grep -m1 'provider:' | awk '{print $2}')"
[ -n "$PROVIDER" ] || PROVIDER="(agent.olium.provider from config)"

# The prompt: credentials live HERE, in natural language — the agent must read
# them, log in, hold the session, and reason about authorization / injection.
read -r -d '' INSTRUCTION <<'EOF' || true
This is an AUTHORIZED test of a deliberately vulnerable shop that I own.

Credentials (use these — provided for this authorized test):
  - Attacker account: username "wiener" password "peter" (a normal, low-privilege user, account id 1)
  - A victim account "carlos" (id 2) and an "admin" account also exist.

Log in as wiener via POST /login (JSON body {"username","password"}; it sets a `session` cookie),
then find and PROVE each of these authorization / injection bugs:

ACCESS CONTROL
  1. Horizontal IDOR/BOLA: as wiener, read OTHER users' data via GET /api/users/{id} or their
     orders via GET /api/orders/{id}. Prove it by retrieving carlos's/admin's PII or a secret order note.
  2. Vertical broken access control: as a normal user, reach admin-only functionality such as
     GET /admin/dashboard or POST /admin/promote. Prove it by retrieving admin-only content.
  3. Mass assignment: PATCH /api/me merges arbitrary JSON fields into your own account — try setting
     your own `credits` (or `role`) and confirm the change stuck via GET /api/me.

CLIENT-SIDE / STORED XSS (use the browser to confirm real script EXECUTION, not just reflection)
  4. DOM-based XSS at GET /welcome: the greeting is rendered client-side from the URL (the value is
     NOT reflected in the server HTML). Craft a payload that actually executes in the browser.
  5. Stored XSS: POST a review to /api/reviews with a script payload, then load GET /product and
     confirm the stored comment executes when the page renders it.

For each confirmed issue, report a finding with the exact request(s) and the response / execution
evidence that proves it.
EOF

# Build the exact command we will run, so the printed command == the run command.
CMD=( "$VIGOLIUM_BIN" agent autopilot
  --input "$TARGET"
  --model "$MODEL"
  --max-duration "$MAX_DURATION"
  --instruction "$INSTRUCTION"
  --json )
[ "$BROWSER" = "1" ] && CMD+=( --browser )

echo "==================== SETUP ===================="
echo "  binary        : $VIGOLIUM_BIN"
echo "  provider      : $PROVIDER"
echo "  model         : $MODEL   (override with MODEL=...)"
echo "  autopilot_mode: $MODE"
echo "  target        : $TARGET"
echo "  max-duration  : $MAX_DURATION   (cost ceiling; override MAX_DURATION=...)"
echo "  browser       : $([ "$BROWSER" = "1" ] && echo 'enabled (agent-browser)' || echo disabled)"
echo "==================== COMMAND ===================="
printf '  %q' "${CMD[@]}"; echo
echo ""
echo "  --instruction (verbatim):"
echo "$INSTRUCTION" | sed 's/^/    /'
echo "==============================================="
echo ""
echo "  !!! This starts a REAL, billable LLM autopilot run under your"
echo "  !!! agent.olium provider credentials. Ctrl-C now to abort."
if [ "${NO_CONFIRM:-}" != "1" ]; then
  read -r -p "  Proceed? [y/N] " ans || ans=""
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "aborted."; exit 1; }
fi

# 1. Select durable-autopilot mode (config-only knob; persists in your config).
"$VIGOLIUM_BIN" config set agent.olium.autopilot_mode "$MODE" >/dev/null
echo "==> set agent.olium.autopilot_mode = $MODE (persists in your config)"

# 2. Start the vulnerable app unless told to skip.
if [ "${SKIP_APP:-}" != "1" ]; then
  echo "==> starting access-lab (go run) ..."
  ( cd "$APP_DIR" && ACCESS_LAB_ADDR=":9899" go run . ) &
  APP_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "$TARGET/" >/dev/null 2>&1 && break
    sleep 1
  done
fi

# 3. Run the real autopilot. --json puts the live stream on stderr and a single
#    summary object (incl. agentic_scan_uuid) on stdout.
echo "==> running autopilot (see the COMMAND block above) ..."
SUMMARY_JSON="$OUT_DIR/summary.json"
set +e
"${CMD[@]}" >"$SUMMARY_JSON"
RUN_RC=$?
set -e
echo "==> autopilot exit: $RUN_RC"

UUID="$(grep -oE '"agentic_scan_uuid"[: ]+"[^"]+"' "$SUMMARY_JSON" | head -1 | grep -oE '[0-9a-fA-F-]{36}' || true)"
echo "==> agentic_scan_uuid: ${UUID:-<none>}"

# 4. Pull the findings for this run and score them against ground truth.
FINDINGS_JSON="$OUT_DIR/findings.json"
if [ -n "$UUID" ]; then
  "$VIGOLIUM_BIN" finding -j --agentic-scan "$UUID" >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
else
  "$VIGOLIUM_BIN" finding -j >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
fi

echo ""
echo "==================== SCORECARD ===================="
echo "  (enforced mode promotes only verifier-confirmed candidates to findings)"
score() { # name  regex
  if grep -iqE "$2" "$FINDINGS_JSON"; then echo "  CATCH  $1"; else echo "  MISS   $1"; fi
}
score "V1/V2 IDOR / BOLA (cross-user object access)"        'idor|bola|/api/users/|/api/orders/|home delivery code|carlos@access'
score "V3/V4 broken access control (admin / privesc)"       'FLAG\{broken-access-control|/admin/dashboard|/admin/promote|vertical|privilege escalat'
score "V5 DOM-based XSS (browser-only)"                      'dom.?based|dom xss|/welcome|location\.(search|hash)'
score "V6 stored XSS (multi-step + browser)"                'stored xss|/api/reviews|/product|innerhtml'
score "V7 mass assignment (multi-step logic)"               'mass.?assign|/api/me|credits|\bpatch\b'
echo "  ---"
echo "  Note: V5/V6 require the browser (BROWSER=1, agent-browser); enforced mode"
echo "  will not promote an XSS candidate without browser-confirmed execution."
echo "==================================================="
echo ""
echo "Full triage:   $VIGOLIUM_BIN finding --agentic-scan ${UUID:-<uuid>} --with-records"
echo "Summary JSON:  $SUMMARY_JSON"
echo "Findings JSON: $FINDINGS_JSON"
