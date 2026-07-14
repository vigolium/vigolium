#!/usr/bin/env bash
# smoke-autopilot.sh — durable-autopilot SMOKE test against a vulnerable target.
#
# Runs the REAL vigolium agent autopilot (a live, PAID, non-deterministic LLM
# run): it logs in with credentials and hunts the auth / access-control /
# injection bugs a native, unauthenticated scan can't reach. NOT a deterministic
# e2e test — it costs money.
#
# Pick a target with PROFILE (or set TARGET/CREDS/INSTRUCTION explicitly):
#   PROFILE=access-lab   (default) local hermetic lab, scored 7/7      :9899
#   PROFILE=ginandjuice  live PortSwigger demo (carlos/hunter2)        external
#   PROFILE=crapi        local OWASP crAPI (needs `make crapi-up`)      :8888
#   PROFILE=juiceshop    local OWASP Juice Shop (needs juiceshop-up)    :3000
#
# The run is STATELESS by default: autopilot writes into a throwaway SQLite DB
# under a temp dir (your real ~/.vigolium DB is never touched) and the follow-up
# finding queries read that same DB via `-S --db`. It also always emits the raw
# Pi-compatible transcript.jsonl and validates its format after the run.
#
# Env knobs:
#   VIGOLIUM_BIN   vigolium binary                    (default: vigolium on PATH)
#   TRANSPORT      how the run is driven: cli|rest    (default: cli)
#                  cli  = `vigolium agent autopilot` directly.
#                  rest = boot `vigolium server` and POST /api/agent/run/autopilot,
#                         then poll /api/agent/status/:id to completion — the same
#                         run driven through the REST API an operator/UI would use.
#                         (SEED_PRIOR is cli-only; the transcript check is best-effort.)
#   MODE           autopilot_mode: enforced|shadow    (default: enforced)
#   MODEL          olium model id                      (default: gpt-5.4)
#   MAX_DURATION   wall-clock cost ceiling            (default: 15m)
#   STATELESS      1 = throwaway --db, main DB untouched (default: 1; 0 = real DB)
#   SEED_PRIOR     1 = seed the DB with a native scan first, then run autopilot
#                  --no-prescan --prior-context auto to mine that prior traffic
#                  (simulates --burp-bridge-url / a Burp import). Needs STATELESS=1.
#   TARGET/CREDS/INSTRUCTION   override the profile defaults
#   CREDS          login as "user/pass" (woven into the prompt; autopilot extracts
#                  credentials + auth intent from the prompt — there is no --credentials flag)
#   SESSION_DIR    pin debug artifacts here           (--session-dir)
#   TRANSCRIPT     raw transcript.jsonl copy path     (--transcript; default: temp dir)
#   SOURCE         source tree for login discovery     (--source)
#   SKIP_APP       1 = never start/stop the local app
#   NO_CONFIRM     1 = skip the cost confirmation
set -euo pipefail

VIGOLIUM_BIN="${VIGOLIUM_BIN:-vigolium}"
PROFILE="${PROFILE:-access-lab}"
TRANSPORT="${TRANSPORT:-cli}"
MODE="${MODE:-enforced}"
MODEL="${MODEL:-gpt-5.4}"
MAX_DURATION="${MAX_DURATION:-15m}"
STATELESS="${STATELESS:-1}"

case "$TRANSPORT" in
  cli|rest) ;;
  *) echo "unknown TRANSPORT '$TRANSPORT' (cli|rest)"; exit 2;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # test/smoke-test/ -> repo root
APP_DIR="$ROOT/test/testdata/vulnerable-apps/access-lab"
OUT_DIR="$(mktemp -d)"
# Raw transcript always lands here (overridable); stateless run uses a throwaway DB.
TRANSCRIPT="${TRANSCRIPT:-$OUT_DIR/transcript.jsonl}"
if [ "$STATELESS" = "1" ]; then SCAN_DB="$OUT_DIR/scan.sqlite"; else SCAN_DB=""; fi
SEED_PRIOR="${SEED_PRIOR:-0}"
if [ "$SEED_PRIOR" = "1" ] && [ -z "$SCAN_DB" ]; then
  echo "SEED_PRIOR=1 needs a throwaway DB — set STATELESS=1 (default)"; exit 2
fi
if [ "$SEED_PRIOR" = "1" ] && [ "$TRANSPORT" = "rest" ]; then
  echo "SEED_PRIOR is cli-transport only (it uses --no-prescan --prior-context); not supported with TRANSPORT=rest"; exit 2
fi
APP_PID=""
SERVER_PID=""   # set when TRANSPORT=rest boots a local API server
MANAGE_APP=0   # 1 = this script starts/stops a local go-run app (access-lab only)
SCORE=0        # 1 = run the access-lab ground-truth scorecard

# ---- colors (auto-off when not a TTY or NO_COLOR is set) ----
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_HDR=$'\033[1;33m'; C_CMD=$'\033[1;36m'; C_IN=$'\033[0;32m'; C_RST=$'\033[0m'
else
  C_HDR=''; C_CMD=''; C_IN=''; C_RST=''
fi

# ---- profile → TARGET / CREDS / INSTRUCTION ----
case "$PROFILE" in
  access-lab)
    TARGET="${TARGET:-http://127.0.0.1:9899}"
    CREDS="${CREDS:-wiener/peter}"
    MANAGE_APP=1; SCORE=1
    read -r -d '' DEFAULT_INSTRUCTION <<'EOF' || true
This is an AUTHORIZED test of a deliberately vulnerable shop that I own.
Credentials: username "wiener" password "peter" (a normal, low-privilege user, id 1); a victim account "carlos" (id 2) and an "admin" account also exist.
Log in as wiener via POST /login (JSON {"username","password"}; sets a `session` cookie), then find and PROVE:
  1. Horizontal IDOR/BOLA on GET /api/users/{id} and GET /api/orders/{id} (read carlos's/admin's data).
  2. Vertical broken access control on GET /admin/dashboard and POST /admin/promote.
  3. Mass assignment on PATCH /api/me (set your own credits/role).
  4. DOM-based XSS on GET /welcome (confirm real browser execution).
  5. Stored XSS: POST /api/reviews then GET /product (confirm real browser execution).
Report each confirmed issue with the exact request(s) and the response/execution evidence.
EOF
    ;;
  ginandjuice)
    TARGET="${TARGET:-https://ginandjuice.shop}"
    CREDS="${CREDS:-carlos/hunter2}"
    ;;
  crapi)
    TARGET="${TARGET:-http://127.0.0.1:8888}"
    CREDS="${CREDS:-}"
    PROFILE_HINT="crAPI is an API-heavy shop. Focus on BOLA/IDOR over vehicle, order, and mechanic objects (numeric/UUID ids), mass assignment on profile/vehicle updates, and broken function-level authorization (mechanic/admin-only endpoints reachable as a normal user). The API is under /identity, /workshop, /community."
    ;;
  juiceshop)
    TARGET="${TARGET:-http://127.0.0.1:3000}"
    CREDS="${CREDS:-}"
    PROFILE_HINT="OWASP Juice Shop. Focus on basket/order IDOR (change the basket id), the admin section reachable by a normal user, broken access control on /api and /rest endpoints, and reflected/DOM XSS in product search. Confirm XSS with real browser execution."
    ;;
  *)
    echo "unknown PROFILE '$PROFILE' (access-lab|ginandjuice|crapi|juiceshop)"; exit 2;;
esac

# Generic instruction for the non-access-lab profiles (parameterized by target+creds).
if [ "$PROFILE" != "access-lab" ]; then
  CRED_USER="${CREDS%%/*}"; CRED_PASS="${CREDS#*/}"
  read -r -d '' DEFAULT_INSTRUCTION <<EOF || true
This is an AUTHORIZED security test of ${TARGET} that I am permitted to test.
Log in with username "${CRED_USER}" password "${CRED_PASS}" (register/create the session if needed), hold the authenticated
session, then hunt for high-impact bugs a normal user must not be able to trigger: broken access control / IDOR / BOLA
(read or act on OTHER users' objects), privilege escalation, mass assignment, authentication bypass, and reflected/stored/
DOM XSS (confirm REAL browser execution, not just reflection).
${PROFILE_HINT:-}
For each confirmed issue, report a finding with the exact request(s) and the response/execution evidence that proves it.
Prefer depth over breadth; stop when you have solid, reproduced findings.
EOF
fi
INSTRUCTION="${INSTRUCTION:-$DEFAULT_INSTRUCTION}"

cleanup() {
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null || true
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  if [ "$MANAGE_APP" = "1" ] && [ "${SKIP_APP:-}" != "1" ]; then
    local lp; lp=$(lsof -ti tcp:9899 2>/dev/null || true)
    [ -n "$lp" ] && kill $lp 2>/dev/null || true
  fi
}
trap cleanup EXIT

# free_port asks the kernel for a free TCP port (python3), falling back to a
# fixed high port. Used to bind the local API server under TRANSPORT=rest.
free_port() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
  else
    echo 19902
  fi
}

# dur_to_secs turns a Go-style duration ("15m", "1h30m", "45s") into seconds,
# used to size the REST status-poll deadline. Falls back to 900s.
dur_to_secs() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,re
s=sys.argv[1]; parts=re.findall(r"(\d+)([smh])",s); u={"s":1,"m":60,"h":3600}
print(sum(int(n)*u[x] for n,x in parts) or 900)' "$1" 2>/dev/null || echo 900
  else
    echo 900
  fi
}

# run_autopilot_rest boots a local `vigolium server`, launches the autopilot run
# over POST /api/agent/run/autopilot, polls /api/agent/status/:id to a terminal
# state, mirrors the final status JSON into $SUMMARY_JSON (so the shared UUID +
# findings + scorecard logic below is transport-agnostic), and best-effort pulls
# the run's transcript.jsonl artifact. Sets the global RUN_RC.
run_autopilot_rest() {
  local port url payload launch status sresp deadline prev
  port="$(free_port)"
  url="http://127.0.0.1:${port}"

  local SRV_CMD=( "$VIGOLIUM_BIN" server --no-auth --host 127.0.0.1 --service-port "$port" --no-swagger )
  [ -n "${SCAN_DB:-}" ] && SRV_CMD+=( --db "$SCAN_DB" )
  echo "==> booting API server: ${SRV_CMD[*]}"
  "${SRV_CMD[@]}" >"$OUT_DIR/server.log" 2>&1 &
  SERVER_PID=$!

  local ok=0
  for _ in $(seq 1 60); do
    curl -sf "$url/health" >/dev/null 2>&1 && { ok=1; break; }
    sleep 0.5
  done
  if [ "$ok" != "1" ]; then
    echo "  API server did not become healthy on $url"; sed 's/^/    /' "$OUT_DIR/server.log" | tail -20
    RUN_RC=1; return 1
  fi

  # Body: target as --input, instruction as the prompt, browser on (autopilot's
  # default), wall-clock cost ceiling as the timeout. Non-streaming: the launch
  # returns 202 + the run uuid and the pipeline runs in the background.
  payload="$(TARGET="$TARGET" INSTRUCTION="$INSTRUCTION" DUR="$MAX_DURATION" python3 - <<'PY'
import json, os
print(json.dumps({
  "input":   os.environ["TARGET"],
  "prompt":  os.environ["INSTRUCTION"],
  "browser": True,
  "timeout": os.environ["DUR"],
  "stream":  False,
}))
PY
)"
  launch="$(curl -s -X POST "$url/api/agent/run/autopilot" -H 'Content-Type: application/json' -d "$payload")"
  printf '%s' "$launch" >"$SUMMARY_JSON"
  UUID="$(printf '%s' "$launch" | grep -oE '[0-9a-fA-F-]{36}' | head -1 || true)"
  echo "==> launched autopilot over REST: uuid=${UUID:-<none>}"
  if [ -z "$UUID" ]; then
    echo "  no agentic_scan_uuid in launch response: $launch"; RUN_RC=1; return 1
  fi

  # Poll to a terminal state (deadline = timeout + 2min slack for pre-scan/unwind).
  # The `case` below is the sole terminal-state gate, so the poll just extracts the
  # raw status value; a non-terminal value (e.g. "queued") simply keeps looping.
  # Log only on change so a long run doesn't spam one status line per tick.
  status="running"; prev=""
  deadline=$(( $(date +%s) + $(dur_to_secs "$MAX_DURATION") + 120 ))
  while :; do
    sresp="$(curl -s "$url/api/agent/status/$UUID")"
    status="$(printf '%s' "$sresp" | grep -oE '"status"[[:space:]]*:[[:space:]]*"[a-z]+"' | head -1 | sed -E 's/.*"([a-z]+)"$/\1/')"
    [ -n "$status" ] || status=running
    if [ "$status" != "$prev" ]; then echo "  status: $status (uuid $UUID)"; fi
    prev="$status"
    case "$status" in
      completed|failed|cancelled|stopped|error) printf '%s' "$sresp" >"$SUMMARY_JSON"; break;;
    esac
    if [ "$(date +%s)" -ge "$deadline" ]; then echo "  status-poll deadline reached (last=$status)"; break; fi
    sleep 3
  done

  # Best-effort: fetch the run's transcript so the format check below can run.
  curl -sf "$url/api/agent/sessions/$UUID/artifacts/transcript.jsonl" -o "$TRANSCRIPT" 2>/dev/null || true

  RUN_RC=0
  [ "$status" = "completed" ] || RUN_RC=1
  return 0
}

# validate_transcript checks that the emitted transcript.jsonl matches the
# Pi-compatible olium schema (see test/testdata/agent-transcripts/README.md):
# valid JSONL, a `session`/`model_change`/`thinking_level_change` header trio,
# session version 3, a linear parentId chain, and at least one assistant +
# toolResult message. Prefers python3 (full checks), falls back to jq, then a
# minimal grep. Returns non-zero on a malformed transcript.
validate_transcript() {
  local path="$1"
  if [ ! -s "$path" ]; then
    echo "  transcript not written or empty: $path"
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$path" <<'PY'
import json, sys
recs, errs = [], []
with open(sys.argv[1], encoding="utf-8") as fh:
    lines = [l for l in fh.read().splitlines() if l.strip()]
if not lines:
    print("  empty transcript"); sys.exit(1)
for i, l in enumerate(lines, 1):
    try:
        recs.append(json.loads(l))
    except Exception as e:
        errs.append(f"line {i}: invalid JSON: {e}")
if [r.get("type") for r in recs[:3]] != ["session", "model_change", "thinking_level_change"]:
    errs.append(f"header trio = {[r.get('type') for r in recs[:3]]}, want session/model_change/thinking_level_change")
if recs and recs[0].get("version") != 3:
    errs.append(f"session version = {recs[0].get('version')}, want 3")
if recs and "parentId" in recs[0]:
    errs.append("session line must not carry parentId")
prev = None
for i, r in enumerate(recs, 1):
    if r.get("type") == "session":
        prev = None
        continue
    if "parentId" not in r:
        errs.append(f"line {i} ({r.get('type')}): missing parentId"); continue
    pid = r["parentId"]
    if prev is None and pid is not None:
        errs.append(f"line {i} ({r.get('type')}): parentId={pid!r}, want null (chain head)")
    elif prev is not None and pid != prev:
        errs.append(f"line {i} ({r.get('type')}): parentId={pid!r}, want {prev!r} (broken chain)")
    prev = r.get("id")
roles = {(r.get("message") or {}).get("role") for r in recs if r.get("type") == "message"}
for want in ("assistant", "toolResult"):
    if want not in roles:
        errs.append(f"no {want} message present")
if errs:
    print("\n".join("  - " + e for e in errs)); sys.exit(1)
print(f"  {len(lines)} lines, header trio + version 3, linear parentId chain, roles={sorted(r for r in roles if r)}")
PY
    return $?
  elif command -v jq >/dev/null 2>&1; then
    if ! jq -e . "$path" >/dev/null 2>&1; then
      echo "  invalid JSONL (jq parse failed)"; return 1
    fi
    local first; first="$(head -1 "$path" | jq -r '"\(.type) v\(.version)"' 2>/dev/null)"
    [ "$first" = "session v3" ] || { echo "  first line = '$first', want 'session v3'"; return 1; }
    echo "  $(grep -c . "$path") lines, valid JSONL, session header v3 (jq check; install python3 for full checks)"
    return 0
  else
    if grep -q '"type":"session"' "$path" && grep -q '"version":3' "$path"; then
      echo "  session header present ($(grep -c . "$path") lines; install python3/jq for full checks)"
      return 0
    fi
    echo "  session header missing"; return 1
  fi
}

PROVIDER="$(sed -n '/^ *olium:/,/^[^ ]/p' "$HOME/.vigolium/vigolium-configs.yaml" 2>/dev/null | grep -m1 'provider:' | awk '{print $2}')"
[ -n "$PROVIDER" ] || PROVIDER="(agent.olium.provider from config)"

# ---- build the exact command (printed == run) ----
CMD=( "$VIGOLIUM_BIN" agent autopilot
  --input "$TARGET"
  --model "$MODEL"
  --max-duration "$MAX_DURATION"
  --prompt "$INSTRUCTION"
  --json )
# Browser is always on for autopilot; credentials + auth intent are taken from
# the prompt (the instruction below already contains the login + credentials).
[ -n "${SOURCE:-}" ] && CMD+=( --source "$SOURCE" )
[ -n "${SCAN_DB:-}" ] && CMD+=( --db "$SCAN_DB" )
# SEED_PRIOR: skip the fresh pre-scan and instead front-load the traffic the seed
# scan already put in the DB — this is what mining Burp-bridge traffic looks like.
[ "$SEED_PRIOR" = "1" ] && CMD+=( --no-prescan --prior-context auto )
[ -n "${SESSION_DIR:-}" ] && CMD+=( --session-dir "$SESSION_DIR" )
[ -n "${TRANSCRIPT:-}" ] && CMD+=( --transcript "$TRANSCRIPT" )

printf "%s==================== SETUP ====================%s\n" "$C_HDR" "$C_RST"
printf "  profile       : %s\n" "$PROFILE"
printf "  binary        : %s\n" "$VIGOLIUM_BIN"
printf "  transport     : %s\n" "$([ "$TRANSPORT" = "rest" ] && echo 'rest (boot vigolium server → POST /api/agent/run/autopilot → poll status)' || echo 'cli (vigolium agent autopilot)')"
printf "  provider      : %s\n" "$PROVIDER"
printf "  model         : %s   (override MODEL=...)\n" "$MODEL"
printf "  autopilot_mode: %s\n" "$MODE"
printf "  target        : %s\n" "$TARGET"
printf "  max-duration  : %s   (cost ceiling; override MAX_DURATION=...)\n" "$MAX_DURATION"
printf "  browser       : %s\n" "always on (agent-browser)"
printf "  stateless db  : %s\n" "$([ -n "$SCAN_DB" ] && echo "$SCAN_DB (throwaway; main DB untouched)" || echo 'off (writes to your real DB)')"
printf "  seed prior    : %s\n" "$([ "$SEED_PRIOR" = "1" ] && echo 'on — seed a scan, then autopilot --no-prescan --prior-context auto (simulates --burp-bridge-url)' || echo off)"
printf "  transcript    : %s\n" "$TRANSCRIPT"

printf "%s==================== COMMAND (raw) ====================%s\n" "$C_HDR" "$C_RST"
if [ "$TRANSPORT" = "rest" ]; then
  printf "%s%s server --no-auth --service-port <free>%s%s\n" "$C_CMD" "$VIGOLIUM_BIN" "$([ -n "${SCAN_DB:-}" ] && echo " --db $SCAN_DB")" "$C_RST"
  printf "%s  curl -X POST <server>/api/agent/run/autopilot -d '{input,prompt,browser,timeout}'%s\n" "$C_CMD" "$C_RST"
  printf "%s  curl <server>/api/agent/status/<uuid>   # polled to a terminal state%s\n" "$C_CMD" "$C_RST"
else
  printf "%s" "$C_CMD"; printf '%q ' "${CMD[@]}"; printf "%s\n" "$C_RST"
fi

printf "%s==================== INPUT (what the agent receives) ====================%s\n" "$C_HDR" "$C_RST"
printf "  --input       : %s%s%s\n" "$C_IN" "$TARGET" "$C_RST"
[ -n "${CREDS:-}" ] && printf "  credentials   : %s%s%s   (in the prompt below; autopilot extracts them)\n" "$C_IN" "$CREDS" "$C_RST"
printf "  --prompt      :\n"
printf '%s\n' "$INSTRUCTION" | sed "s/^/    ${C_IN}/;s/\$/${C_RST}/"
printf "%s=======================================================================%s\n\n" "$C_HDR" "$C_RST"

echo "  !!! This starts a REAL, billable LLM autopilot run under your"
echo "  !!! agent.olium provider credentials. Ctrl-C now to abort."
if [ "${NO_CONFIRM:-}" != "1" ]; then
  read -r -p "  Proceed? [y/N] " ans || ans=""
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "aborted."; exit 1; }
fi

"$VIGOLIUM_BIN" config set agent.olium.autopilot_mode "$MODE" >/dev/null
echo "==> set agent.olium.autopilot_mode = $MODE (persists in your config)"

if [ "$MANAGE_APP" = "1" ] && [ "${SKIP_APP:-}" != "1" ]; then
  echo "==> starting access-lab (go run) ..."
  ( cd "$APP_DIR" && ACCESS_LAB_ADDR=":9899" go run . ) &
  APP_PID=$!
  for _ in $(seq 1 30); do curl -sf "$TARGET/" >/dev/null 2>&1 && break; sleep 1; done
fi

# SEED_PRIOR: populate the throwaway DB with a native scan BEFORE autopilot, so
# the run has prior traffic to mine (standing in for a --burp-bridge-url import;
# the DB-population outcome is identical). Best-effort — a partial scan still
# leaves traffic the prior-context brief can surface.
if [ "$SEED_PRIOR" = "1" ]; then
  echo "==> seeding prior traffic into $SCAN_DB (simulates a --burp-bridge-url import) ..."
  "$VIGOLIUM_BIN" scan -t "$TARGET" --db "$SCAN_DB" \
    --only discovery,spidering,dynamic-assessment --scanning-max-duration 3m >/dev/null 2>&1 \
    || echo "  (seed scan returned non-zero — continuing; the DB may still hold partial traffic)"
  echo "==> seed done — the record count is reported by the 'Prior context:' line below"
fi

echo "==> running autopilot (see the COMMAND block above) ..."
SUMMARY_JSON="$OUT_DIR/summary.json"
STDERR_LOG="$OUT_DIR/autopilot-stderr.log"
: >"$STDERR_LOG"
RUN_RC=0
if [ "$TRANSPORT" = "rest" ]; then
  # Drive the run through the REST API (boots vigolium server, POSTs the run,
  # polls to completion). run_autopilot_rest sets RUN_RC + $SUMMARY_JSON.
  set +e
  run_autopilot_rest
  set -e
else
  set +e
  # Tee stderr (the --json live stream + our progress lines) to a log so we can
  # assert on it after the run, while still showing it live.
  "${CMD[@]}" >"$SUMMARY_JSON" 2> >(tee "$STDERR_LOG" >&2)
  RUN_RC=$?
  set -e
fi
echo "==> autopilot exit: $RUN_RC"

# The rest transport already parsed UUID from the launch response; only the cli
# path needs to mine it out of the summary JSON here.
if [ -z "${UUID:-}" ]; then
  UUID="$(grep -oE '"agentic_scan_uuid"[: ]+"[^"]+"' "$SUMMARY_JSON" | head -1 | grep -oE '[0-9a-fA-F-]{36}' || true)"
fi
echo "==> agentic_scan_uuid: ${UUID:-<none>}"

# Validate the raw transcript format (the whole point of --transcript here).
echo ""
printf "%s==================== TRANSCRIPT ====================%s\n" "$C_HDR" "$C_RST"
echo "==> raw transcript: $TRANSCRIPT"
if validate_transcript "$TRANSCRIPT"; then
  TRANSCRIPT_OK=1
  echo "  FORMAT OK  (Pi-compatible olium transcript)"
else
  TRANSCRIPT_OK=0
  echo "  FORMAT FAIL  (see errors above)"
fi
printf "%s===================================================%s\n" "$C_HDR" "$C_RST"

# SEED_PRIOR: assert autopilot front-loaded the seeded traffic (the "Prior
# context:" line prints when the brief fires) and that the fresh pre-scan was
# skipped (--no-prescan). This is the observable proof the --burp-bridge-url /
# prior-context path worked end-to-end.
if [ "$SEED_PRIOR" = "1" ]; then
  echo ""
  printf "%s==================== PRIOR CONTEXT ====================%s\n" "$C_HDR" "$C_RST"
  if grep -q "Prior context:" "$STDERR_LOG" 2>/dev/null; then
    PRIOR_OK=1
    grep -m1 "Prior context:" "$STDERR_LOG" | sed 's/^[[:space:]]*/  /'
    echo "  PRIOR-CONTEXT OK  (autopilot mined the seeded traffic instead of starting cold)"
  else
    PRIOR_OK=0
    echo "  PRIOR-CONTEXT FAIL  (no 'Prior context:' line — the brief did not fire)"
  fi
  if grep -q "Pre-scan:" "$STDERR_LOG" 2>/dev/null; then
    echo "  NOTE: a fresh pre-scan ran despite --no-prescan (unexpected)"
  else
    echo "  pre-scan skipped (--no-prescan)"
  fi
  printf "%s======================================================%s\n" "$C_HDR" "$C_RST"
fi

# Findings read from the throwaway DB under -S when stateless (main DB untouched).
FIND_DB=()
[ -n "${SCAN_DB:-}" ] && FIND_DB=( -S --db "$SCAN_DB" )
FINDINGS_JSON="$OUT_DIR/findings.json"
if [ -n "$UUID" ]; then
  "$VIGOLIUM_BIN" finding -j ${FIND_DB[@]+"${FIND_DB[@]}"} --agentic-scan "$UUID" >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
else
  "$VIGOLIUM_BIN" finding -j ${FIND_DB[@]+"${FIND_DB[@]}"} >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
fi

if [ "$SCORE" = "1" ]; then
  echo ""
  printf "%s==================== SCORECARD ====================%s\n" "$C_HDR" "$C_RST"
  echo "  (enforced mode promotes only verifier-confirmed candidates to findings)"
  score() { if grep -iqE "$2" "$FINDINGS_JSON"; then echo "  CATCH  $1"; else echo "  MISS   $1"; fi; }
  score "V1/V2 IDOR / BOLA (cross-user object access)"  'idor|bola|/api/users/|/api/orders/|home delivery code|carlos@access'
  score "V3/V4 broken access control (admin / privesc)" 'FLAG\{broken-access-control|/admin/dashboard|/admin/promote|vertical|privilege escalat'
  score "V5 DOM-based XSS (browser-only)"                'dom.?based|dom xss|/welcome|location\.(search|hash)'
  score "V6 stored XSS (multi-step + browser)"           'stored xss|/api/reviews|/product|innerhtml'
  score "V7 mass assignment (multi-step logic)"          'mass.?assign|/api/me|credits|\bpatch\b'
  printf "%s==================================================%s\n" "$C_HDR" "$C_RST"
else
  echo ""
  echo "==> findings for this run:"
  "$VIGOLIUM_BIN" finding ${FIND_DB[@]+"${FIND_DB[@]}"} --agentic-scan "${UUID:-none}" 2>/dev/null | head -40 || true
fi

echo ""
echo "Full triage:   $VIGOLIUM_BIN finding ${FIND_DB[@]+"${FIND_DB[@]}"} --agentic-scan ${UUID:-<uuid>} --with-records"
echo "Summary JSON:  $SUMMARY_JSON"
echo "Findings JSON: $FINDINGS_JSON"
echo "Transcript:    $TRANSCRIPT   (rendered replay: $VIGOLIUM_BIN log ${UUID:-<uuid>})"

# Surface a malformed transcript as a non-zero exit even when the run itself
# succeeded — the format is a contract other tools parse against. Under
# TRANSPORT=rest the transcript is pulled best-effort from the session-artifact
# API, so a missing one is a warning rather than a hard failure there.
if [ "${TRANSCRIPT_OK:-1}" != "1" ]; then
  if [ "$TRANSPORT" = "rest" ]; then
    echo "==> transcript not retrievable/valid over the REST artifact API (best-effort under TRANSPORT=rest) — continuing"
  else
    echo "==> transcript FORMAT check FAILED"
    exit 1
  fi
fi

# Under SEED_PRIOR, the prior-context brief firing is the whole point — fail if
# it didn't.
if [ "$SEED_PRIOR" = "1" ] && [ "${PRIOR_OK:-1}" != "1" ]; then
  echo "==> prior-context check FAILED (autopilot did not front-load the seeded traffic)"
  exit 1
fi
