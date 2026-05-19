#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test/smoke-test-scripts/smoke-autopilot-juiceshop-auth.sh
#
# Smoke test for `vigolium agent autopilot --credentials --auth-required`
# against a local OWASP Juice Shop. Verifies the autopilot auth-preflight
# pipeline (pkg/agent/autopilot_auth.go) end-to-end:
#
#   1. Boots juice-shop at http://127.0.0.1:3000
#   2. Clones juice-shop source so source-analysis has a login flow to find
#   3. Runs `vigolium agent autopilot` with a pinned --scan-uuid, plus
#      --credentials "admin@juice-sh.op/admin123" and --auth-required
#   4. Asserts `vigolium agent session <uuid>` reports the three signals
#      from printSessionAuth() (pkg/cli/agent_session.go:850-911):
#        • a "Session Auth" header line
#        • a "Hydrated:" line  (proves HTTP login flow ran)
#        • a "Headers:" line   (proves at least one header hydrated)
#   5. Asserts <sessions_dir>/<run_uuid>/session-config.json exists with a
#      non-empty sessions[] array
#
# Provider: codex-oauth (~/.codex/auth.json) — no fallback. The user's
# canonical agent backend.
#
# Cost: one autopilot run with --intensity quick. Archon-lite (3-phase) runs
# automatically because the CLI only routes through AutopilotPipelineRunner —
# and therefore through prepareAutopilotAuth — when audit is enabled (see
# pkg/cli/agent_autopilot_olium.go:138). Passing --archon=off would silently
# fall through to the direct autopilot.Run path, which ignores --credentials
# and --auth-required entirely.
#
# Cleanup: removes the temporary source clone. Leaves juice-shop running so
# re-runs are fast — tear it down with `make juiceshop-down` when finished.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configurable knobs ──────────────────────────────────────────────────────
JUICESHOP_URL="${JUICESHOP_URL:-http://127.0.0.1:3000}"
JUICESHOP_READY_TIMEOUT_S="${JUICESHOP_READY_TIMEOUT_S:-120}"
JUICESHOP_SOURCE_REPO="${JUICESHOP_SOURCE_REPO:-https://github.com/juice-shop/juice-shop}"
AUTOPILOT_TIMEOUT_S="${AUTOPILOT_TIMEOUT_S:-1500}"  # 25 min hard cap on the CLI invocation
AUTOPILOT_CREDS="${AUTOPILOT_CREDS:-admin@juice-sh.op/admin123}"
SESSIONS_DIR_DEFAULT="$HOME/.vigolium/agent-sessions"

# Resolve the vigolium binary. Prefer the local build, fall back to PATH.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VIGOLIUM_BIN="${VIGOLIUM_BIN:-$REPO_ROOT/bin/vigolium}"
if [[ ! -x "$VIGOLIUM_BIN" ]]; then
    if command -v vigolium >/dev/null 2>&1; then
        VIGOLIUM_BIN="$(command -v vigolium)"
    fi
fi

# ── Logging helpers (stderr — keep stdout clean for any capture) ────────────
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_RED=$'\033[31m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_CYAN=$'\033[36m'

log()    { printf '%s[*]%s %s\n'   "$C_CYAN"   "$C_RESET" "$*" >&2; }
ok()     { printf '%s[OK]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*" >&2; }
warn()   { printf '%s[!]%s %s\n'   "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()    { printf '%s[ERR]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
header() { printf '\n%s═══ %s ═══%s\n' "$C_BOLD" "$*" "$C_RESET" >&2; }

# ── Cleanup ─────────────────────────────────────────────────────────────────
SOURCE_DIR=""
AUTOPILOT_LOG=""
RUN_UUID=""

cleanup() {
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        if [[ -n "$AUTOPILOT_LOG" && -f "$AUTOPILOT_LOG" ]]; then
            warn "autopilot log tail (last 50 lines): $AUTOPILOT_LOG"
            tail -n 50 "$AUTOPILOT_LOG" >&2 || true
        fi
        if [[ -n "$RUN_UUID" ]]; then
            warn "to inspect: $VIGOLIUM_BIN log $RUN_UUID --full"
            warn "             $VIGOLIUM_BIN agent session $RUN_UUID"
        fi
    fi
    if [[ -n "$SOURCE_DIR" && -d "$SOURCE_DIR" ]]; then
        rm -rf "$SOURCE_DIR"
    fi
    exit $rc
}
trap cleanup EXIT INT TERM

# ── Pre-flight ──────────────────────────────────────────────────────────────
header "Pre-flight checks"

for cmd in git curl jq uuidgen docker; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "missing required command: $cmd"
        exit 1
    fi
done

# Pick a `timeout` binary (GNU coreutils). macOS ships without one by default;
# Homebrew coreutils provides `timeout` (when gnubin is on PATH) or `gtimeout`.
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
else
    warn "no timeout/gtimeout on PATH — autopilot will run without a hard time cap"
    warn "  (install via: brew install coreutils)"
fi

if [[ ! -x "$VIGOLIUM_BIN" ]]; then
    err "vigolium binary not found at $VIGOLIUM_BIN"
    err "run 'make build' first, or set VIGOLIUM_BIN=/path/to/vigolium"
    exit 1
fi
ok "vigolium binary: $VIGOLIUM_BIN"

# Provider gate: codex-oauth only. We don't silently fall back to other
# providers — the user's default is codex.
if [[ ! -f "$HOME/.codex/auth.json" ]]; then
    err "no codex-oauth credentials at ~/.codex/auth.json"
    err "this smoke runs against the default provider (codex-oauth); log in via codex first"
    exit 1
fi
ok "codex-oauth credentials present"

# Resolve sessions_dir from `vigolium config ls` so the on-disk assertion
# uses the user's actual setting, not just the default.
SESSIONS_DIR_RAW="$("$VIGOLIUM_BIN" config ls 2>/dev/null \
    | awk -F' *= *' '$1=="agent.sessions_dir" { print $2 }' \
    | tr -d '[:space:]' || true)"
if [[ -z "$SESSIONS_DIR_RAW" ]]; then
    SESSIONS_DIR_RAW="$SESSIONS_DIR_DEFAULT"
fi
# Expand leading ~ to $HOME.
SESSIONS_DIR="${SESSIONS_DIR_RAW/#\~/$HOME}"
ok "agent sessions dir: $SESSIONS_DIR"

# ── Boot juice-shop ─────────────────────────────────────────────────────────
header "Booting juice-shop"

if curl -fsS --max-time 5 "$JUICESHOP_URL/" >/dev/null 2>&1; then
    ok "juice-shop already running at $JUICESHOP_URL"
else
    log "starting juice-shop via 'make juiceshop-up'"
    (cd "$REPO_ROOT" && make juiceshop-up >/dev/null)
    log "waiting for $JUICESHOP_URL/ to respond (timeout: ${JUICESHOP_READY_TIMEOUT_S}s)"
    deadline=$(( $(date +%s) + JUICESHOP_READY_TIMEOUT_S ))
    until curl -fsS --max-time 5 "$JUICESHOP_URL/" >/dev/null 2>&1; do
        if (( $(date +%s) >= deadline )); then
            err "juice-shop did not become ready within ${JUICESHOP_READY_TIMEOUT_S}s"
            exit 1
        fi
        sleep 2
    done
    ok "juice-shop ready at $JUICESHOP_URL"
fi

# ── Clone juice-shop source ─────────────────────────────────────────────────
header "Cloning juice-shop source (depth 1)"

SOURCE_DIR="$(mktemp -d -t vigolium-smoke-juiceshop.XXXXXX)"
log "source dir: $SOURCE_DIR"
git clone --depth 1 --quiet "$JUICESHOP_SOURCE_REPO" "$SOURCE_DIR" 2>&1 \
    | sed 's/^/    /' >&2 || {
    err "git clone failed"
    exit 1
}
ok "cloned $JUICESHOP_SOURCE_REPO"

# ── Run autopilot with pinned UUID ──────────────────────────────────────────
header "Running autopilot with --credentials + --auth-required"

RUN_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
AUTOPILOT_LOG="$(mktemp -t vigolium-smoke-autopilot.XXXXXX.log)"
log "pinned run UUID: $RUN_UUID"
log "autopilot log:   $AUTOPILOT_LOG"

# We pin the run UUID via the global --scan-uuid flag (root.go:223), then the
# autopilot uses it as the session-dir name (agent_autopilot_olium.go:56-91)
# and the AgenticScan parent UUID. That makes the session lookup deterministic.
#
# Intensity 'quick' caps total timeout at 1h and max-commands at 30. We don't
# pass --archon=off: that flag would skip the AutopilotPipelineRunner path
# (agent_autopilot_olium.go:138) which is the *only* path that calls
# prepareAutopilotAuth — i.e. the only path that wires --credentials and
# --auth-required (autopilot_auth.go:137-141) into the run. Archon-lite runs
# its 3-phase audit in front of the operator; that adds a few minutes but is
# the cost of exercising the auth preflight via the CLI.
autopilot_cmd=()
if [[ -n "$TIMEOUT_BIN" ]]; then
    autopilot_cmd+=("$TIMEOUT_BIN" "$AUTOPILOT_TIMEOUT_S")
fi
autopilot_cmd+=(
    "$VIGOLIUM_BIN"
    --scan-uuid "$RUN_UUID"
    agent autopilot
    --target "$JUICESHOP_URL"
    --source "$SOURCE_DIR"
    --credentials "$AUTOPILOT_CREDS"
    --auth-required
    --intensity quick
    "Verify the prepared session works against one protected endpoint, then stop."
)

set +e
"${autopilot_cmd[@]}" >"$AUTOPILOT_LOG" 2>&1
AUTOPILOT_RC=$?
set -e

if [[ $AUTOPILOT_RC -eq 124 ]]; then
    err "autopilot timed out after ${AUTOPILOT_TIMEOUT_S}s"
    exit 1
elif [[ $AUTOPILOT_RC -ne 0 ]]; then
    err "autopilot exited with status $AUTOPILOT_RC"
    exit 1
fi
ok "autopilot finished (exit 0)"

# ── Assertion 1: session-config.json on disk ────────────────────────────────
header "Assertion: session-config.json"

SESSION_DIR="$SESSIONS_DIR/$RUN_UUID"
SESSION_CONFIG="$SESSION_DIR/session-config.json"

if [[ ! -d "$SESSION_DIR" ]]; then
    err "session dir missing: $SESSION_DIR"
    exit 1
fi
ok "session dir present: $SESSION_DIR"

if [[ ! -s "$SESSION_CONFIG" ]]; then
    err "session-config.json missing or empty: $SESSION_CONFIG"
    exit 1
fi

SESSION_COUNT="$(jq -r '(.sessions // []) | length' "$SESSION_CONFIG" 2>/dev/null || echo "0")"
if [[ "$SESSION_COUNT" -lt 1 ]]; then
    err "session-config.json has no sessions[] entries"
    err "contents:"
    cat "$SESSION_CONFIG" >&2 || true
    exit 1
fi
ok "session-config.json has $SESSION_COUNT session entr$( [[ $SESSION_COUNT -eq 1 ]] && echo y || echo ies)"

# ── Assertion 2: agent session <uuid> reports the three signals ─────────────
header "Assertion: vigolium agent session $RUN_UUID"

# printSessionAuth writes to stderr (pkg/cli/agent_session.go:860 etc.), so
# fold stderr into stdout for grepping.
SESSION_OUTPUT="$("$VIGOLIUM_BIN" agent session "$RUN_UUID" 2>&1 || true)"

missing_signals=()
for signal in "Session Auth" "Hydrated:" "Headers:"; do
    if ! grep -qF "$signal" <<<"$SESSION_OUTPUT"; then
        missing_signals+=("$signal")
    fi
done

if (( ${#missing_signals[@]} > 0 )); then
    err "missing signals from 'agent session $RUN_UUID': ${missing_signals[*]}"
    err "full session output:"
    sed 's/^/    /' <<<"$SESSION_OUTPUT" >&2
    exit 1
fi
ok "all three signals present (Session Auth, Hydrated:, Headers:)"

# ── Done ────────────────────────────────────────────────────────────────────
header "Smoke complete"
ok "auth preflight verified end-to-end for run $RUN_UUID"
log "inspect with: $VIGOLIUM_BIN agent session $RUN_UUID"
log "session dir:  $SESSION_DIR"
log "tear down:    make juiceshop-down"
