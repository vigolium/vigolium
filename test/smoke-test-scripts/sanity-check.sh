#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test/smoke-test-scripts/sanity-check.sh
#
# End-to-end smoke test for the REST API + GCS storage upload flow documented
# in docs/api-references/scan-with-storage.md.
#
# Exercises three real targets, two scan_uuid pinning checks, and BYOK
# (bring-your-own-key) coverage across the CLI + REST surfaces:
#   • Phase 1: Native scan          → http://ginandjuice.shop/
#   • Phase 2: Agent audit          → https://github.com/erev0s/VAmPI    (LLM)
#                                     POST /api/agent/run/audit with driver=archon
#                                     — equivalent to the legacy /agent/run/archon
#   • Phase 3: Agent autopilot      → https://github.com/juice-shop/juice-shop
#                                     against https://preview.owasp-juice.shop/  (LLM)
#   • Phase 4: Pinned scan_uuid     → dry_run pre-create + attach native scan
#                                     under the same UUID, see docs/api-references/
#                                     scan-with-storage.md#pinning-scan-uuids-cross-node-sync
#   • Phase 5: 409 conflict guard   → reuse a pinned UUID under a different
#                                     project, expect HTTP 409
#   • Phase 6: Serverless-mode      → clone VAmPI, upload tarball to GCS, run
#                                     `vigolium agent audit --source gs://...`
#                                     mirroring the Cloud Run Job dispatch  (LLM)
#   • Phase 7: BYOK validation      → 4 negative cases (REST + CLI) confirming
#                                     ValidateAuthOverride fires before any
#                                     subprocess work — no LLM cost
#   • Phase 8: BYOK REST happy      → 8a oauth_cred_file (codex), 8b api_key
#                                     (anthropic|openai), 8c oauth_token
#                                     (VIGOLIUM_CLAUDE_OAUTH_TOKEN, claude).
#                                     Each sub-phase skips when its cred
#                                     isn't in env.                         (LLM)
#   • Phase 9: BYOK CLI happy       → vigolium agent audit --oauth-cred-file
#                                     against VAmPI git URL                 (LLM)
#   • Phase 10: BYOK piolium        → REST driver=piolium with oauth_cred_file,
#                                     exercises auth.json staging at
#                                     pkg/agent/audit_pi_byok.go            (LLM)
#   • Phase 11: BYOK driver=both    → REST driver=both with oauth_token,
#                                     thread BYOK through both child runs   (LLM)
#
# For scan phases (1-3) we verify:
#   1. The scan completes (status == completed).
#   2. Findings are produced (native) / session artifacts exist (agent).
#   3. The result bundle is downloadable from GCS via
#      GET /api/storage/results/:id and is a valid tar.gz with the expected
#      contents.
#
# Agent phases are skipped cleanly if no LLM provider is configured.
#
# Env knobs:
#   PHASES="all"        run every phase (default)
#   PHASES="3"          run only Phase 3 (or any comma-separated subset, e.g. "2,3,6")
#   KEEP_HOME=1         preserve $VIGOLIUM_HOME_DIR on exit (sessions, sqlite DB,
#                       runtime.log) so failures can be inspected
#   KEEP_BUCKET=1       skip the cleanup-time `gcloud storage rm` of the bucket
#                       prefix this run wrote to
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Required environment ─────────────────────────────────────────────────────
# Credentials must be exported by the caller (e.g. via ~/.zshrc); this script
# does NOT carry hardcoded values. Pre-flight below will fail loudly if any of
# VIGOLIUM_API_KEY / VIGOLIUM_STORAGE_{BUCKET_NAME,ACCESS_KEY,SECRET_KEY,REGION}
# is missing. The canonical shared dev values live in
# vigolium-ops/cloudrun/setup-infra.sh.

# Targets
NATIVE_TARGET="${NATIVE_TARGET:-http://ginandjuice.shop/}"
ARCHON_SOURCE="${ARCHON_SOURCE:-https://github.com/erev0s/VAmPI}"
AUTOPILOT_SOURCE="${AUTOPILOT_SOURCE:-https://github.com/juice-shop/juice-shop}"
AUTOPILOT_TARGET="${AUTOPILOT_TARGET:-https://preview.owasp-juice.shop/}"

# Polling timeouts (seconds)
NATIVE_TIMEOUT_S="${NATIVE_TIMEOUT_S:-600}"     # 10 min
ARCHON_TIMEOUT_S="${ARCHON_TIMEOUT_S:-1800}"    # 30 min
AUTOPILOT_TIMEOUT_S="${AUTOPILOT_TIMEOUT_S:-1800}" # 30 min

# ── Logging helpers ─────────────────────────────────────────────────────────
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_RED=$'\033[31m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_CYAN=$'\033[36m'

# All log helpers write to stderr so command-substitution callers (e.g.
# `STATUS="$(wait_until_terminal ...)"`) capture only the function's stdout
# data, not its chatter.
log()    { printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$*" >&2; }
ok()     { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
warn()   { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()    { printf '%s[ERR]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
header() { printf '\n%s═══ %s ═══%s\n' "$C_BOLD" "$*" "$C_RESET" >&2; }

# Per-phase result tracking. PENDING = not executed (filtered out via PHASES).
NATIVE_RESULT="PENDING"
ARCHON_RESULT="PENDING"
AUTOPILOT_RESULT="PENDING"
PINNED_RESULT="PENDING"
CONFLICT_RESULT="PENDING"
SERVERLESS_RESULT="PENDING"
# BYOK phases (7-11). Phase 7 has 4 sub-cases collapsed into one PASS/FAIL.
# Phase 8 splits into 8a/8b/8c so per-cred-type results survive into the
# summary even when the operator's env only has one cred type populated.
BYOK_NEG_RESULT="PENDING"
BYOK_8A_RESULT="PENDING"
BYOK_8B_RESULT="PENDING"
BYOK_8C_RESULT="PENDING"
BYOK_CLI_RESULT="PENDING"
BYOK_PIOLIUM_RESULT="PENDING"
BYOK_BOTH_RESULT="PENDING"

# Phase selection: PHASES="all" (default) runs every phase; "1,3,6" runs that
# subset. Useful for iterating on a single phase without paying for the rest.
PHASES_FLAG="${PHASES:-all}"
should_run() {
    [[ "$PHASES_FLAG" == "all" ]] || [[ ",${PHASES_FLAG}," == *",$1,"* ]]
}

# KEEP_HOME=1 preserves $VIGOLIUM_HOME_DIR (config, sqlite DB, session dirs)
# on exit so a failed run can be inspected with `vigolium agent session` etc.
# The bucket prefix is still cleaned up unless KEEP_BUCKET=1.
KEEP_HOME="${KEEP_HOME:-0}"
KEEP_BUCKET="${KEEP_BUCKET:-0}"

# ── Pre-flight ──────────────────────────────────────────────────────────────
header "Pre-flight checks"

# Hydrate operator env from ~/.zshrc when invoked from a non-interactive
# shell (CI runners, cron, `bash sanity-check.sh` from a fresh subshell).
# The user's BYOK creds (VIGOLIUM_CLAUDE_OAUTH_TOKEN, ANTHROPIC_API_KEY,
# OPENAI_API_KEY) and the storage env vars typically live in ~/.zshrc.
# Best-effort: zsh-only syntax errors in rc are swallowed so an interactive
# prompt or a malformed rc step can't abort the smoke. Only sets vars that
# are still empty, so caller-exported overrides win.
if [[ -f "$HOME/.zshrc" ]] && command -v zsh >/dev/null 2>&1; then
    log "hydrating env from ~/.zshrc (zsh subprocess, best-effort)"
    eval "$(zsh -c '
        emulate -L zsh
        source ~/.zshrc >/dev/null 2>&1
        for v in VIGOLIUM_API_KEY VIGOLIUM_STORAGE_BUCKET_NAME VIGOLIUM_STORAGE_ACCESS_KEY \
                 VIGOLIUM_STORAGE_SECRET_KEY VIGOLIUM_STORAGE_REGION \
                 VIGOLIUM_CLAUDE_OAUTH_TOKEN ANTHROPIC_API_KEY OPENAI_API_KEY \
                 CLAUDE_CODE_OAUTH_TOKEN; do
            val=${(P)v}
            [[ -n $val ]] && printf "export %s=%q\n" "$v" "$val"
        done
    ' 2>/dev/null)" || true
fi

for cmd in vigolium curl jq tar gzip uuidgen python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "missing required command: $cmd"
        exit 1
    fi
done
ok "tools present: vigolium, curl, jq, tar, gzip, uuidgen, python3"

missing_env=()
for v in VIGOLIUM_API_KEY VIGOLIUM_STORAGE_BUCKET_NAME VIGOLIUM_STORAGE_ACCESS_KEY VIGOLIUM_STORAGE_SECRET_KEY VIGOLIUM_STORAGE_REGION; do
    if [[ -z "${!v:-}" ]]; then
        missing_env+=("$v")
    fi
done
if (( ${#missing_env[@]} > 0 )); then
    err "missing required env var(s): ${missing_env[*]}"
    err "export them in your shell profile (e.g. ~/.zshrc); see vigolium-ops/cloudrun/setup-infra.sh for the canonical dev values"
    exit 1
fi
ok "GCS bucket: $VIGOLIUM_STORAGE_BUCKET_NAME (region: $VIGOLIUM_STORAGE_REGION)"

# Per-cred-type BYOK detection. Each cred is detected independently so the
# Phase 8a/8b/8c, 10, and 11 sub-phases can skip cleanly when their specific
# cred type isn't in the operator's env. HAS_LLM (legacy single flag) is
# derived from any of these being set — Phases 2/3/6 only need to know
# SOMETHING is configured.
#
# Sources:
#   BYOK_CODEX_CRED   ← $HOME/.codex/auth.json (codex oauth_cred_file path)
#   BYOK_ANTHROPIC_KEY ← $ANTHROPIC_API_KEY
#   BYOK_OPENAI_KEY    ← $OPENAI_API_KEY
#   BYOK_CLAUDE_OAUTH  ← $VIGOLIUM_CLAUDE_OAUTH_TOKEN (Phase 8c + 11)
BYOK_CODEX_CRED=""
BYOK_ANTHROPIC_KEY=""
BYOK_OPENAI_KEY=""
BYOK_CLAUDE_OAUTH=""
[[ -f "$HOME/.codex/auth.json" ]] && BYOK_CODEX_CRED="$HOME/.codex/auth.json"
[[ -n "${ANTHROPIC_API_KEY:-}" ]] && BYOK_ANTHROPIC_KEY="$ANTHROPIC_API_KEY"
[[ -n "${OPENAI_API_KEY:-}" ]] && BYOK_OPENAI_KEY="$OPENAI_API_KEY"
[[ -n "${VIGOLIUM_CLAUDE_OAUTH_TOKEN:-}" ]] && BYOK_CLAUDE_OAUTH="$VIGOLIUM_CLAUDE_OAUTH_TOKEN"

HAS_LLM=0
LLM_REASON=""
if [[ -n "$BYOK_CODEX_CRED" ]]; then
    HAS_LLM=1
    LLM_REASON="codex auth at ~/.codex/auth.json"
elif [[ -n "$BYOK_ANTHROPIC_KEY" ]]; then
    HAS_LLM=1
    LLM_REASON="ANTHROPIC_API_KEY set"
elif [[ -n "$BYOK_OPENAI_KEY" ]]; then
    HAS_LLM=1
    LLM_REASON="OPENAI_API_KEY set"
elif [[ -n "$BYOK_CLAUDE_OAUTH" ]]; then
    HAS_LLM=1
    LLM_REASON="VIGOLIUM_CLAUDE_OAUTH_TOKEN set"
fi
if [[ $HAS_LLM -eq 1 ]]; then
    ok "LLM provider available: $LLM_REASON"
else
    warn "no LLM provider detected — archon, autopilot, BYOK phases will be skipped"
fi

# Print the BYOK matrix so the operator can predict which sub-phases will run.
# Length only, never values — protects against accidental token leakage in CI logs.
log "BYOK creds detected (length only, never values):"
printf '    codex auth.json:             %s\n' "${BYOK_CODEX_CRED:-<unset>}" >&2
if [[ -n "$BYOK_ANTHROPIC_KEY" ]]; then
    printf '    ANTHROPIC_API_KEY:           set (%d chars)\n' "${#BYOK_ANTHROPIC_KEY}" >&2
else
    printf '    ANTHROPIC_API_KEY:           <unset>\n' >&2
fi
if [[ -n "$BYOK_OPENAI_KEY" ]]; then
    printf '    OPENAI_API_KEY:              set (%d chars)\n' "${#BYOK_OPENAI_KEY}" >&2
else
    printf '    OPENAI_API_KEY:              <unset>\n' >&2
fi
if [[ -n "$BYOK_CLAUDE_OAUTH" ]]; then
    printf '    VIGOLIUM_CLAUDE_OAUTH_TOKEN: set (%d chars)\n' "${#BYOK_CLAUDE_OAUTH}" >&2
else
    printf '    VIGOLIUM_CLAUDE_OAUTH_TOKEN: <unset>\n' >&2
fi

# Per-run project UUID — segregates this run's bucket prefix from any others
PROJECT_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
ok "project UUID: $PROJECT_UUID"

# ── Boot a local vigolium server with isolated config ───────────────────────
header "Booting local vigolium server"

VIGOLIUM_HOME_DIR="$(mktemp -d -t vigolium-sanity.XXXXXX)"
SERVER_LOG="$VIGOLIUM_HOME_DIR/server.log"
RESULTS_DIR="$VIGOLIUM_HOME_DIR/results"
mkdir -p "$RESULTS_DIR"

# Save the real HOME so we can mirror in LLM credentials below — we'll
# override HOME for the spawned vigolium processes to isolate config + DB.
REAL_HOME="$HOME"

# The olium engine reads codex credentials from $HOME/.codex/auth.json.
# Since we override HOME for isolation, mirror the real codex auth (and the
# claude config dir, in case it's used) into the tmp HOME via symlink so
# agent runs can authenticate.
if [[ -f "$REAL_HOME/.codex/auth.json" ]]; then
    mkdir -p "$VIGOLIUM_HOME_DIR/.codex"
    ln -sf "$REAL_HOME/.codex/auth.json" "$VIGOLIUM_HOME_DIR/.codex/auth.json"
fi
if [[ -d "$REAL_HOME/.claude" ]]; then
    ln -sfn "$REAL_HOME/.claude" "$VIGOLIUM_HOME_DIR/.claude"
fi
# gcloud auth lives at ~/.config/gcloud — mirror it so Phase 6's
# `gcloud storage cp` (and the cleanup-time `gcloud storage rm`) can
# authenticate under the overridden HOME.
if [[ -d "$REAL_HOME/.config/gcloud" ]]; then
    mkdir -p "$VIGOLIUM_HOME_DIR/.config"
    ln -sfn "$REAL_HOME/.config/gcloud" "$VIGOLIUM_HOME_DIR/.config/gcloud"
fi

SERVER_PID=""

cleanup() {
    local rc=$?
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log "stopping server (pid $SERVER_PID)"
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "${VIGOLIUM_HOME_DIR:-}" && -d "$VIGOLIUM_HOME_DIR" ]]; then
        # Surface tail of server log on failure for quick debugging.
        if [[ $rc -ne 0 && -f "$SERVER_LOG" ]]; then
            warn "server log tail (last 40 lines):"
            tail -n 40 "$SERVER_LOG" >&2 || true
        fi
        if [[ "$KEEP_HOME" == "1" ]]; then
            warn "KEEP_HOME=1 → preserving $VIGOLIUM_HOME_DIR for inspection"
            warn "  (sessions, sqlite DB, runtime.log all live under this dir)"
        else
            rm -rf "$VIGOLIUM_HOME_DIR"
        fi
    fi
    if [[ "$KEEP_BUCKET" != "1" ]] && command -v gcloud >/dev/null 2>&1; then
        # Best-effort: clean up the bucket prefix this run wrote to.
        gcloud storage rm -r "gs://${VIGOLIUM_STORAGE_BUCKET_NAME}/${PROJECT_UUID}/" >/dev/null 2>&1 || true
    fi
    exit $rc
}
trap cleanup EXIT INT TERM

# Use HOME isolation — vigolium reads ~/.vigolium/vigolium-configs.yaml,
# the SQLite DB defaults under that dir, and session dirs land there too.
export HOME="$VIGOLIUM_HOME_DIR"

log "VIGOLIUM_HOME: $VIGOLIUM_HOME_DIR"

# Initialize fresh config + DB + bootstrap presets.
vigolium init >/dev/null 2>&1

# Configure storage + auth via `vigolium config set`.
vigolium config set server.auth_api_key "$VIGOLIUM_API_KEY" >/dev/null
vigolium config set storage.enabled true >/dev/null
vigolium config set storage.driver gcs >/dev/null
vigolium config set storage.bucket "$VIGOLIUM_STORAGE_BUCKET_NAME" >/dev/null
vigolium config set storage.region "$VIGOLIUM_STORAGE_REGION" >/dev/null
vigolium config set storage.access_key "$VIGOLIUM_STORAGE_ACCESS_KEY" >/dev/null
vigolium config set storage.secret_key "$VIGOLIUM_STORAGE_SECRET_KEY" >/dev/null
vigolium config set storage.use_ssl true >/dev/null
# Disable OAST so the native scan doesn't wait on out-of-band callbacks (the
# default oast.pro server adds 30+s of latency per probe and a grace_period
# drain at scan end). Keeps Phase 1 deterministic.
vigolium config set oast.enabled false >/dev/null
ok "config written: storage.enabled=true driver=gcs bucket=$VIGOLIUM_STORAGE_BUCKET_NAME oast.enabled=false"

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
BASE="http://127.0.0.1:$PORT"
log "starting server on $BASE (logs: $SERVER_LOG)"

vigolium server --host 127.0.0.1 --service-port "$PORT" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for /health
for _ in $(seq 1 60); do
    if curl -fsS "$BASE/health" >/dev/null 2>&1; then
        ok "server up (pid $SERVER_PID)"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "server exited during startup; see $SERVER_LOG"
        exit 1
    fi
    sleep 0.5
done
if ! curl -fsS "$BASE/health" >/dev/null 2>&1; then
    err "server did not become healthy within 30s"
    exit 1
fi

# Curl wrapper with auth + project header. --max-time guards against the
# server hanging on a stuck endpoint (we hit one of those in autopilot post-run).
api() {
    local method="$1"; shift
    local path="$1"; shift
    curl -fsS --max-time 15 -X "$method" "$BASE$path" \
        -H "Authorization: Bearer $VIGOLIUM_API_KEY" \
        -H "X-Project-UUID: $PROJECT_UUID" \
        "$@"
}

# Download a result bundle and verify it's a tar.gz containing the expected entries.
verify_bundle() {
    local id="$1"; shift
    local label="$1"; shift
    # Remaining args = required tar entries (basename match).
    local out="$RESULTS_DIR/${label}-${id}.tar.gz"

    if ! curl -fsS --max-time 60 -o "$out" "$BASE/api/storage/results/$id" \
            -H "Authorization: Bearer $VIGOLIUM_API_KEY" \
            -H "X-Project-UUID: $PROJECT_UUID"; then
        err "$label: GET /api/storage/results/$id failed"
        return 1
    fi

    if ! gzip -t "$out" 2>/dev/null; then
        err "$label: bundle is not a valid gzip ($out)"
        return 1
    fi

    local listing
    listing="$(tar tzf "$out")"
    local missing=()
    for entry in "$@"; do
        if ! grep -q -E "(^|/)${entry}(\$|[[:space:]])" <<<"$listing"; then
            missing+=("$entry")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "$label: bundle missing entries: ${missing[*]}"
        printf 'bundle listing:\n%s\n' "$listing" >&2
        return 1
    fi

    local size
    size="$(wc -c <"$out" | tr -d ' ')"
    ok "$label: bundle OK ($out, $size bytes, $(wc -l <<<"$listing" | tr -d ' ') entries)"
}

# Poll an endpoint until jq filter '.status' returns one of the terminal values.
# Args: timeout_s, interval_s, url, label
wait_until_terminal() {
    local timeout_s="$1"; shift
    local interval_s="$1"; shift
    local url="$1"; shift
    local label="$1"; shift
    local deadline=$(( $(date +%s) + timeout_s ))
    local last_status=""
    while (( $(date +%s) < deadline )); do
        local body status
        body="$(curl -fsS --max-time 15 "$url" \
            -H "Authorization: Bearer $VIGOLIUM_API_KEY" \
            -H "X-Project-UUID: $PROJECT_UUID" 2>/dev/null || echo '{}')"
        status="$(jq -r '.status // empty' <<<"$body")"
        if [[ "$status" != "$last_status" ]]; then
            log "$label: status=$status"
            last_status="$status"
        fi
        case "$status" in
            completed|failed|cancelled) echo "$status"; return 0 ;;
        esac
        sleep "$interval_s"
    done
    err "$label: timed out after ${timeout_s}s (last status: ${last_status:-<none>})"
    echo "timeout"
    return 1
}

# Run an /api/agent/run/audit request and verify completion + storage_url +
# bundle in one shot. Used by Phase 8/10/11 (and could fold Phase 2 too, but
# leaving Phase 2 inline keeps the diff bounded). Args:
#   $1  label (also used as bundle-verify label)
#   $2  request body JSON (already constructed by jq -n)
#   $3  timeout seconds for the polling loop
#   $4… required tar.gz entries to verify
# Returns 0 on full success, 1 on any failure (with err logged).
run_audit_and_verify() {
    local label="$1"; shift
    local body="$1"; shift
    local timeout_s="$1"; shift

    local resp run_id
    resp="$(api POST /api/agent/run/audit -H 'Content-Type: application/json' -d "$body" || true)"
    run_id="$(jq -r '.agentic_scan_uuid // .run_id // empty' <<<"$resp")"
    if [[ -z "$run_id" ]]; then
        err "$label: no agentic_scan_uuid in response: $resp"
        return 1
    fi
    ok "$label: run started: $run_id"

    local status
    status="$(wait_until_terminal "$timeout_s" 10 "$BASE/api/agent/status/$run_id" "$label" || true)"
    if [[ "$status" != "completed" ]]; then
        err "$label: ended with status: $status — fetching session logs"
        api GET "/api/agent/sessions/$run_id/logs" 2>/dev/null | tail -n 30 >&2 || true
        return 1
    fi

    local expected="gs://${PROJECT_UUID}/agentic-scans/${run_id}/results.tar.gz"
    local storage_url=""
    local i
    for i in $(seq 1 30); do
        local session
        session="$(api GET "/api/agent/sessions/$run_id" 2>/dev/null || echo '{}')"
        storage_url="$(jq -r '.storage_url // empty' <<<"$session")"
        [[ -n "$storage_url" ]] && break
        sleep 2
    done
    if [[ "$storage_url" != "$expected" ]]; then
        err "$label: storage_url mismatch — got: '$storage_url' want: '$expected'"
        return 1
    fi
    ok "$label: storage_url: $storage_url"

    if ! verify_bundle "$run_id" "$label" "$@"; then
        return 1
    fi
    return 0
}

# ── Phase 1: Native scan against ginandjuice.shop ───────────────────────────
if should_run 1; then
header "Phase 1: Native scan → $NATIVE_TARGET"

NATIVE_BODY=$(jq -n \
    --arg t "$NATIVE_TARGET" \
    '{
       targets: [$t],
       strategy: "lite",
       modules: ["software-version-header","security-headers-missing","permissions-policy-detect"],
       scanning_max_duration: "60s",
       upload_results: true
     }')

NATIVE_RESP="$(api POST /api/scans/run -H 'Content-Type: application/json' -d "$NATIVE_BODY")"
NATIVE_SCAN_ID="$(jq -r '.scan_uuid // .scan_id // empty' <<<"$NATIVE_RESP")"
if [[ -z "$NATIVE_SCAN_ID" ]]; then
    err "no scan_uuid in response: $NATIVE_RESP"
    NATIVE_RESULT="FAIL"
else
    ok "scan started: $NATIVE_SCAN_ID"

    NATIVE_STATUS="$(wait_until_terminal "$NATIVE_TIMEOUT_S" 5 "$BASE/api/scans/$NATIVE_SCAN_ID" "native scan" || true)"

    if [[ "$NATIVE_STATUS" == "completed" ]]; then
        # Findings count — query both by scan_uuid and project-wide.
        FINDINGS_BY_SCAN="$(api GET "/api/findings?scan_uuid=$NATIVE_SCAN_ID&limit=1")"
        FINDINGS_BY_SCAN_TOTAL="$(jq -r '.total // 0' <<<"$FINDINGS_BY_SCAN")"
        FINDINGS_PROJECT="$(api GET "/api/findings?limit=1")"
        FINDINGS_PROJECT_TOTAL="$(jq -r '.total // 0' <<<"$FINDINGS_PROJECT")"
        if (( FINDINGS_PROJECT_TOTAL > 0 )); then
            ok "findings: ${FINDINGS_PROJECT_TOTAL} project-wide (${FINDINGS_BY_SCAN_TOTAL} linked to this scan_uuid)"
        else
            warn "findings: 0 — ginandjuice.shop usually fires several; check the runtime.log"
        fi

        # storage_url shape on the scan row — the upload runs in a goroutine
        # after the scan's status flips to completed, so poll briefly for it
        # to populate.
        EXPECTED_PREFIX="gs://${PROJECT_UUID}/native-scans/${NATIVE_SCAN_ID}/results.tar.gz"
        STORAGE_URL=""
        for _ in $(seq 1 30); do
            SCAN_ROW="$(api GET "/api/scans/$NATIVE_SCAN_ID")"
            STORAGE_URL="$(jq -r '.storage_url // empty' <<<"$SCAN_ROW")"
            [[ -n "$STORAGE_URL" ]] && break
            sleep 2
        done
        if [[ "$STORAGE_URL" == "$EXPECTED_PREFIX" ]]; then
            ok "storage_url: $STORAGE_URL"
        else
            err "storage_url mismatch — got: '$STORAGE_URL' want: '$EXPECTED_PREFIX'"
            NATIVE_RESULT="FAIL"
        fi

        # Bundle download + entries (per scan-with-storage.md:96 — runtime.log only for API runs)
        if verify_bundle "$NATIVE_SCAN_ID" "native" "runtime.log"; then
            [[ "$NATIVE_RESULT" != "FAIL" ]] && NATIVE_RESULT="PASS"
        else
            NATIVE_RESULT="FAIL"
        fi
    else
        err "native scan ended with status: $NATIVE_STATUS"
        NATIVE_RESULT="FAIL"
    fi
fi

fi  # end Phase 1

# ── Phase 2: Agent audit (driver=archon) → VAmPI ────────────────────────────
if should_run 2; then
header "Phase 2: Agent audit (driver=archon) → $ARCHON_SOURCE"

if [[ $HAS_LLM -eq 0 ]]; then
    warn "skipped (no LLM provider)"
    ARCHON_RESULT="SKIP"
else
    # driver=archon makes /agent/run/audit equivalent to the legacy
    # /agent/run/archon — same auditRunPlan, same uploadAgenticResults,
    # same artifact set. agent=codex matches the codex auth we detected
    # in pre-flight; without it, archon defaults to claude which fails
    # with "Not logged in".
    ARCHON_BODY=$(jq -n \
        --arg src "$ARCHON_SOURCE" \
        '{source:$src, driver:"archon", mode:"lite", agent:"codex", upload_results:true}')

    ARCHON_RESP="$(api POST /api/agent/run/audit -H 'Content-Type: application/json' -d "$ARCHON_BODY" || true)"
    ARCHON_RUN_ID="$(jq -r '.agentic_scan_uuid // .run_id // empty' <<<"$ARCHON_RESP")"
    if [[ -z "$ARCHON_RUN_ID" ]]; then
        err "no agentic_scan_uuid in response: $ARCHON_RESP"
        ARCHON_RESULT="FAIL"
    else
        ok "archon run started: $ARCHON_RUN_ID"
        ARCHON_STATUS="$(wait_until_terminal "$ARCHON_TIMEOUT_S" 10 "$BASE/api/agent/status/$ARCHON_RUN_ID" "archon" || true)"

        if [[ "$ARCHON_STATUS" == "completed" ]]; then
            # storage_url shape via /api/agent/sessions/:id (poll briefly —
            # upload races the status flip).
            ARCHON_EXPECTED="gs://${PROJECT_UUID}/agentic-scans/${ARCHON_RUN_ID}/results.tar.gz"
            ARCHON_STORAGE_URL=""
            for _ in $(seq 1 30); do
                ARCHON_SESSION="$(api GET "/api/agent/sessions/$ARCHON_RUN_ID")"
                ARCHON_STORAGE_URL="$(jq -r '.storage_url // empty' <<<"$ARCHON_SESSION")"
                [[ -n "$ARCHON_STORAGE_URL" ]] && break
                sleep 2
            done
            if [[ "$ARCHON_STORAGE_URL" == "$ARCHON_EXPECTED" ]]; then
                ok "storage_url: $ARCHON_STORAGE_URL"
            else
                err "storage_url mismatch — got: '$ARCHON_STORAGE_URL' want: '$ARCHON_EXPECTED'"
                ARCHON_RESULT="FAIL"
            fi

            # Bundle entries per scan-with-storage.md:222. Note: audit-stream.jsonl
            # is only produced by the claude platform (claudestream); on codex
            # the bundle has runtime.log + archon-audit-output.md only.
            if verify_bundle "$ARCHON_RUN_ID" "archon" "runtime.log" "archon-audit-output.md"; then
                [[ "$ARCHON_RESULT" != "FAIL" ]] && ARCHON_RESULT="PASS"
            else
                ARCHON_RESULT="FAIL"
            fi
        else
            err "archon ended with status: $ARCHON_STATUS — fetching session logs"
            api GET "/api/agent/sessions/$ARCHON_RUN_ID/logs" 2>/dev/null | tail -n 30 >&2 || true
            ARCHON_RESULT="FAIL"
        fi
    fi
fi

fi  # end Phase 2

# ── Phase 3: Agent autopilot → juice-shop source + preview target ──────────
if should_run 3; then
header "Phase 3: Agent autopilot → $AUTOPILOT_TARGET (source: $AUTOPILOT_SOURCE)"

if [[ $HAS_LLM -eq 0 ]]; then
    warn "skipped (no LLM provider)"
    AUTOPILOT_RESULT="SKIP"
else
    # juice-shop is a 156-record Express app; without a tight instruction the
    # autopilot burns through `quick`'s 30-turn cap before converging (we hit
    # `autopilot engine: exceeded max turns (30)` on the unscoped run). Mirror
    # smoke-autopilot-juiceshop-auth.sh's pattern: scope the agent to a single
    # spot-check so the smoke confirms the wiring rather than a full audit.
    AUTOPILOT_BODY=$(jq -n \
        --arg t "$AUTOPILOT_TARGET" \
        --arg s "$AUTOPILOT_SOURCE" \
        --arg i "Spot-check one endpoint to confirm the autopilot harness is wired (target reachable, source loaded, scanner dispatch works), then stop. No deep enumeration." \
        '{target:$t, source:$s, intensity:"quick", instruction:$i, upload_results:true}')

    AUTOPILOT_RESP="$(api POST /api/agent/run/autopilot -H 'Content-Type: application/json' -d "$AUTOPILOT_BODY" || true)"
    AUTOPILOT_RUN_ID="$(jq -r '.agentic_scan_uuid // .run_id // empty' <<<"$AUTOPILOT_RESP")"
    if [[ -z "$AUTOPILOT_RUN_ID" ]]; then
        err "no agentic_scan_uuid in response: $AUTOPILOT_RESP"
        AUTOPILOT_RESULT="FAIL"
    else
        ok "autopilot run started: $AUTOPILOT_RUN_ID"
        AUTOPILOT_STATUS="$(wait_until_terminal "$AUTOPILOT_TIMEOUT_S" 10 "$BASE/api/agent/status/$AUTOPILOT_RUN_ID" "autopilot" || true)"

        if [[ "$AUTOPILOT_STATUS" == "completed" ]]; then
            AUTOPILOT_EXPECTED="gs://${PROJECT_UUID}/agentic-scans/${AUTOPILOT_RUN_ID}/results.tar.gz"
            AUTOPILOT_STORAGE_URL=""
            for _ in $(seq 1 30); do
                AUTOPILOT_SESSION="$(api GET "/api/agent/sessions/$AUTOPILOT_RUN_ID")"
                AUTOPILOT_STORAGE_URL="$(jq -r '.storage_url // empty' <<<"$AUTOPILOT_SESSION")"
                [[ -n "$AUTOPILOT_STORAGE_URL" ]] && break
                sleep 2
            done
            if [[ "$AUTOPILOT_STORAGE_URL" == "$AUTOPILOT_EXPECTED" ]]; then
                ok "storage_url: $AUTOPILOT_STORAGE_URL"
            else
                err "storage_url mismatch — got: '$AUTOPILOT_STORAGE_URL' want: '$AUTOPILOT_EXPECTED'"
                AUTOPILOT_RESULT="FAIL"
            fi

            if verify_bundle "$AUTOPILOT_RUN_ID" "autopilot" "runtime.log"; then
                [[ "$AUTOPILOT_RESULT" != "FAIL" ]] && AUTOPILOT_RESULT="PASS"
            else
                AUTOPILOT_RESULT="FAIL"
            fi
        else
            err "autopilot ended with status: $AUTOPILOT_STATUS — fetching session logs"
            api GET "/api/agent/sessions/$AUTOPILOT_RUN_ID/logs" 2>/dev/null | tail -n 30 >&2 || true
            AUTOPILOT_RESULT="FAIL"
        fi
    fi
fi

fi  # end Phase 3

# ── Phase 4: Pinned scan_uuid (dry_run pre-create + attach) ─────────────────
# Exercises the cross-node dispatch pattern from
# docs/api-references/scan-with-storage.md#pinning-scan-uuids-cross-node-sync:
# pre-create a placeholder row via dry_run, then run the real scan against the
# same UUID and confirm the bundle key, DB row, and response all key off the
# pinned value.
if should_run 4; then
header "Phase 4: Pinned scan_uuid → dry_run + attach → $NATIVE_TARGET"

PINNED_SCAN_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
log "pinned scan UUID: $PINNED_SCAN_UUID"

DRY_BODY=$(jq -n \
    --arg t "$NATIVE_TARGET" \
    --arg u "$PINNED_SCAN_UUID" \
    '{targets:[$t], scan_uuid:$u, dry_run:true}')

DRY_RESP="$(api POST /api/scans/run -H 'Content-Type: application/json' -d "$DRY_BODY" || true)"
DRY_UUID="$(jq -r '.scan_uuid // .scan_id // empty' <<<"$DRY_RESP")"
DRY_STATUS="$(jq -r '.status // empty' <<<"$DRY_RESP")"
if [[ "$DRY_UUID" != "$PINNED_SCAN_UUID" ]]; then
    err "dry_run: scan_uuid echo mismatch — got '$DRY_UUID' want '$PINNED_SCAN_UUID' (resp: $DRY_RESP)"
    PINNED_RESULT="FAIL"
elif [[ "$DRY_STATUS" != "dry_run" ]]; then
    err "dry_run: status mismatch — got '$DRY_STATUS' want 'dry_run' (resp: $DRY_RESP)"
    PINNED_RESULT="FAIL"
else
    ok "dry_run pre-create OK (status=dry_run, scan_uuid=$PINNED_SCAN_UUID)"

    # Confirm the placeholder row is queryable.
    PRE_ROW="$(api GET "/api/scans/$PINNED_SCAN_UUID" || true)"
    PRE_UUID="$(jq -r '.scan_uuid // .uuid // empty' <<<"$PRE_ROW")"
    if [[ "$PRE_UUID" != "$PINNED_SCAN_UUID" ]]; then
        err "GET /api/scans/$PINNED_SCAN_UUID did not return placeholder row (got: $PRE_ROW)"
        PINNED_RESULT="FAIL"
    else
        ok "placeholder row visible via GET /api/scans/$PINNED_SCAN_UUID"

        # Real run against the same UUID — should attach to the placeholder.
        REAL_BODY=$(jq -n \
            --arg t "$NATIVE_TARGET" \
            --arg u "$PINNED_SCAN_UUID" \
            '{
               targets:[$t],
               strategy:"lite",
               modules:["software-version-header","security-headers-missing","permissions-policy-detect"],
               scanning_max_duration:"60s",
               scan_uuid:$u,
               upload_results:true
             }')

        REAL_RESP="$(api POST /api/scans/run -H 'Content-Type: application/json' -d "$REAL_BODY" || true)"
        REAL_UUID="$(jq -r '.scan_uuid // .scan_id // empty' <<<"$REAL_RESP")"
        if [[ "$REAL_UUID" != "$PINNED_SCAN_UUID" ]]; then
            err "attach: scan_uuid echo mismatch — got '$REAL_UUID' want '$PINNED_SCAN_UUID' (resp: $REAL_RESP)"
            PINNED_RESULT="FAIL"
        else
            ok "attach scan started against same UUID: $PINNED_SCAN_UUID"

            PINNED_STATUS="$(wait_until_terminal "$NATIVE_TIMEOUT_S" 5 "$BASE/api/scans/$PINNED_SCAN_UUID" "pinned native scan" || true)"

            if [[ "$PINNED_STATUS" == "completed" ]]; then
                PINNED_EXPECTED="gs://${PROJECT_UUID}/native-scans/${PINNED_SCAN_UUID}/results.tar.gz"
                PINNED_STORAGE_URL=""
                for _ in $(seq 1 30); do
                    PINNED_ROW="$(api GET "/api/scans/$PINNED_SCAN_UUID")"
                    PINNED_STORAGE_URL="$(jq -r '.storage_url // empty' <<<"$PINNED_ROW")"
                    [[ -n "$PINNED_STORAGE_URL" ]] && break
                    sleep 2
                done
                if [[ "$PINNED_STORAGE_URL" == "$PINNED_EXPECTED" ]]; then
                    ok "storage_url uses pinned UUID: $PINNED_STORAGE_URL"
                else
                    err "storage_url mismatch — got: '$PINNED_STORAGE_URL' want: '$PINNED_EXPECTED'"
                    PINNED_RESULT="FAIL"
                fi

                if verify_bundle "$PINNED_SCAN_UUID" "pinned" "runtime.log"; then
                    [[ "$PINNED_RESULT" != "FAIL" ]] && PINNED_RESULT="PASS"
                else
                    PINNED_RESULT="FAIL"
                fi
            else
                err "pinned native scan ended with status: $PINNED_STATUS"
                PINNED_RESULT="FAIL"
            fi
        fi
    fi
fi

fi  # end Phase 4

# ── Phase 5: 409 cross-project conflict guard ───────────────────────────────
# Reusing a pinned UUID under a different project_uuid must fail with HTTP 409,
# never silently overwrite (see scan-with-storage.md#get-or-create-semantics).
if should_run 5; then
header "Phase 5: 409 cross-project conflict guard"

CONFLICT_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
OTHER_PROJECT_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
CONFLICT_BODY=$(jq -n \
    --arg t "$NATIVE_TARGET" \
    --arg u "$CONFLICT_UUID" \
    '{targets:[$t], scan_uuid:$u, dry_run:true}')

# Pre-create under the main project.
if ! api POST /api/scans/run -H 'Content-Type: application/json' -d "$CONFLICT_BODY" >/dev/null 2>&1; then
    err "conflict setup: failed to pre-create $CONFLICT_UUID under main project"
    CONFLICT_RESULT="FAIL"
else
    ok "pre-created $CONFLICT_UUID under project $PROJECT_UUID"

    # Re-POST under a different project — server must reject with 409.
    CONFLICT_RESP_FILE="$VIGOLIUM_HOME_DIR/conflict-resp.json"
    CONFLICT_CODE="$(curl -sS -o "$CONFLICT_RESP_FILE" -w '%{http_code}' --max-time 15 \
        -X POST "$BASE/api/scans/run" \
        -H "Authorization: Bearer $VIGOLIUM_API_KEY" \
        -H "X-Project-UUID: $OTHER_PROJECT_UUID" \
        -H "Content-Type: application/json" \
        -d "$CONFLICT_BODY" 2>/dev/null || echo "000")"
    if [[ "$CONFLICT_CODE" == "409" ]]; then
        ok "got expected HTTP 409 for cross-project UUID reuse"
        CONFLICT_RESULT="PASS"
    else
        err "expected HTTP 409, got $CONFLICT_CODE — body: $(cat "$CONFLICT_RESP_FILE" 2>/dev/null || echo '<empty>')"
        CONFLICT_RESULT="FAIL"
    fi
fi

fi  # end Phase 5

# ── Phase 6: Serverless-mode simulation (CLI + gs:// source) ────────────────
# Mirrors how the Cloud Run Job dispatcher (src/lib/cloudrunJob.ts:58-64)
# invokes the agent: clone source → tar.gz → upload to GCS → run
# `vigolium agent audit --source gs://...` against that archive. Exercises
# storage.ResolveGCSSource (handlers_agent_audit_runner.go:126-134) and the
# equivalent CLI path in pkg/cli/agent_audit.go.
#
# Production dispatch leaves --driver at its default ("both"); we pin to
# "archon" here to keep verification deterministic on smoke hosts that may
# not have the pi CLI registered. --agent codex matches the codex-oauth
# detected in pre-flight; the CLI default ("claude") would fail.
if should_run 6; then
header "Phase 6: Serverless-mode (CLI + gs:// source) → $ARCHON_SOURCE"

if [[ $HAS_LLM -eq 0 ]]; then
    warn "skipped (no LLM provider)"
    SERVERLESS_RESULT="SKIP"
elif ! command -v gcloud >/dev/null 2>&1; then
    warn "skipped (gcloud not on PATH — needed to upload the source tarball)"
    SERVERLESS_RESULT="SKIP"
else
    # Pick a `timeout` binary if available (macOS doesn't ship one).
    SERVERLESS_TIMEOUT_BIN=""
    if command -v timeout >/dev/null 2>&1; then
        SERVERLESS_TIMEOUT_BIN="timeout"
    elif command -v gtimeout >/dev/null 2>&1; then
        SERVERLESS_TIMEOUT_BIN="gtimeout"
    fi

    SERVERLESS_SCAN_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
    SERVERLESS_CLONE_DIR="$VIGOLIUM_HOME_DIR/serverless-src"
    SERVERLESS_TGZ="$VIGOLIUM_HOME_DIR/serverless-source.tar.gz"
    SERVERLESS_KEY="sources/${SERVERLESS_SCAN_UUID}.tar.gz"
    # vigolium gs:// URIs are project-relative (gs://<project-uuid>/<key>);
    # the bucket comes from storage config. The full GCS path is what we
    # pass to gcloud for the actual upload.
    SERVERLESS_GS_URI="gs://${PROJECT_UUID}/${SERVERLESS_KEY}"
    SERVERLESS_GS_FULL="gs://${VIGOLIUM_STORAGE_BUCKET_NAME}/${PROJECT_UUID}/${SERVERLESS_KEY}"

    log "pinned scan UUID: $SERVERLESS_SCAN_UUID"
    log "cloning $ARCHON_SOURCE (depth 1)"
    mkdir -p "$SERVERLESS_CLONE_DIR"
    if ! git clone --depth 1 --quiet "$ARCHON_SOURCE" "$SERVERLESS_CLONE_DIR/vampi" 2>/dev/null; then
        err "git clone failed"
        SERVERLESS_RESULT="FAIL"
    elif ! tar -czf "$SERVERLESS_TGZ" -C "$SERVERLESS_CLONE_DIR" vampi; then
        err "tar -czf failed"
        SERVERLESS_RESULT="FAIL"
    elif ! gcloud storage cp "$SERVERLESS_TGZ" "$SERVERLESS_GS_FULL" >/dev/null 2>"$VIGOLIUM_HOME_DIR/gcloud-cp.err"; then
        err "gcloud storage cp failed (target: $SERVERLESS_GS_FULL)"
        if [[ -s "$VIGOLIUM_HOME_DIR/gcloud-cp.err" ]]; then
            sed 's/^/    /' "$VIGOLIUM_HOME_DIR/gcloud-cp.err" >&2 || true
        fi
        SERVERLESS_RESULT="FAIL"
    else
        ok "source archive uploaded → $SERVERLESS_GS_FULL"
        log "running CLI audit (intensity=balanced, driver=archon, agent=codex)"

        SERVERLESS_LOG="$VIGOLIUM_HOME_DIR/serverless-audit.log"
        cli_cmd=()
        if [[ -n "$SERVERLESS_TIMEOUT_BIN" ]]; then
            cli_cmd+=("$SERVERLESS_TIMEOUT_BIN" "$ARCHON_TIMEOUT_S")
        fi
        cli_cmd+=(
            vigolium agent audit
            --project-uuid "$PROJECT_UUID"
            --scan-uuid "$SERVERLESS_SCAN_UUID"
            --source "$SERVERLESS_GS_URI"
            --driver archon
            --agent codex
            --intensity balanced
            --upload-results
        )

        set +e
        "${cli_cmd[@]}" >"$SERVERLESS_LOG" 2>&1
        SERVERLESS_RC=$?
        set -e

        if [[ $SERVERLESS_RC -eq 124 ]]; then
            err "audit CLI timed out after ${ARCHON_TIMEOUT_S}s (log: $SERVERLESS_LOG)"
            SERVERLESS_RESULT="FAIL"
        elif [[ $SERVERLESS_RC -ne 0 ]]; then
            err "audit CLI exited $SERVERLESS_RC (log tail follows)"
            tail -n 30 "$SERVERLESS_LOG" >&2 || true
            SERVERLESS_RESULT="FAIL"
        else
            ok "audit CLI completed (log: $SERVERLESS_LOG)"

            # CLI shares the SQLite DB with the running server, so we can
            # verify storage_url + bundle via the same /api/agent/sessions
            # and /api/storage/results endpoints used by Phase 2.
            SERVERLESS_EXPECTED="gs://${PROJECT_UUID}/agentic-scans/${SERVERLESS_SCAN_UUID}/results.tar.gz"
            SERVERLESS_STORAGE_URL=""
            for _ in $(seq 1 30); do
                SERVERLESS_SESSION="$(api GET "/api/agent/sessions/$SERVERLESS_SCAN_UUID" 2>/dev/null || echo '{}')"
                SERVERLESS_STORAGE_URL="$(jq -r '.storage_url // empty' <<<"$SERVERLESS_SESSION")"
                [[ -n "$SERVERLESS_STORAGE_URL" ]] && break
                sleep 2
            done
            if [[ "$SERVERLESS_STORAGE_URL" == "$SERVERLESS_EXPECTED" ]]; then
                ok "storage_url: $SERVERLESS_STORAGE_URL"
            else
                err "storage_url mismatch — got: '$SERVERLESS_STORAGE_URL' want: '$SERVERLESS_EXPECTED'"
                SERVERLESS_RESULT="FAIL"
            fi

            if verify_bundle "$SERVERLESS_SCAN_UUID" "serverless" "runtime.log" "archon-audit-output.md"; then
                [[ "$SERVERLESS_RESULT" != "FAIL" ]] && SERVERLESS_RESULT="PASS"
            else
                SERVERLESS_RESULT="FAIL"
            fi
        fi
    fi

    rm -rf "$SERVERLESS_CLONE_DIR"
    [[ -f "$SERVERLESS_TGZ" ]] && rm -f "$SERVERLESS_TGZ"
fi

fi  # end Phase 6

# ── Phase 7: BYOK validation negatives (no LLM cost) ────────────────────────
# The shared validator (pkg/agent/auth_override.go:ValidateAuthOverride) is
# called from both the CLI (resolveAuditAuthOverride) and REST
# (resolveAuditRequestAuthOverride). Phase 7 confirms the validator fires on
# both paths before any LLM round-trip. Cheap — every sub-case errors out
# before subprocess work.
if should_run 7; then
header "Phase 7: BYOK validation negatives (no LLM cost)"

NEG_PASS=0
NEG_FAIL=0

# 7a: REST — api_key + oauth_cred_file simultaneously → 400, "at most one".
# Default driver=both so we don't 503 on a missing single-driver runtime;
# validation runs after the per-driver availability probe regardless.
NEG7A_BODY=$(jq -n --arg src "$ARCHON_SOURCE" \
    '{source:$src, agent:"claude", api_key:"fake-key-A", oauth_cred_file:"/tmp/fake.json"}')
NEG7A_RESP="$VIGOLIUM_HOME_DIR/neg7a-resp.json"
NEG7A_CODE="$(curl -sS -o "$NEG7A_RESP" -w '%{http_code}' --max-time 15 \
    -X POST "$BASE/api/agent/run/audit" \
    -H "Authorization: Bearer $VIGOLIUM_API_KEY" \
    -H "X-Project-UUID: $PROJECT_UUID" \
    -H "Content-Type: application/json" \
    -d "$NEG7A_BODY" 2>/dev/null || echo "000")"
if [[ "$NEG7A_CODE" == "400" ]] && grep -q "at most one" "$NEG7A_RESP" 2>/dev/null; then
    ok "7a: REST api_key + oauth_cred_file → 400 'at most one'"
    NEG_PASS=$((NEG_PASS+1))
else
    err "7a: expected 400 with 'at most one' — got $NEG7A_CODE — body: $(cat "$NEG7A_RESP" 2>/dev/null || echo '<empty>')"
    NEG_FAIL=$((NEG_FAIL+1))
fi

# 7b: REST — oauth_token + agent=codex → 400, mentions "claude".
NEG7B_BODY=$(jq -n --arg src "$ARCHON_SOURCE" \
    '{source:$src, agent:"codex", oauth_token:"fake-token-B"}')
NEG7B_RESP="$VIGOLIUM_HOME_DIR/neg7b-resp.json"
NEG7B_CODE="$(curl -sS -o "$NEG7B_RESP" -w '%{http_code}' --max-time 15 \
    -X POST "$BASE/api/agent/run/audit" \
    -H "Authorization: Bearer $VIGOLIUM_API_KEY" \
    -H "X-Project-UUID: $PROJECT_UUID" \
    -H "Content-Type: application/json" \
    -d "$NEG7B_BODY" 2>/dev/null || echo "000")"
if [[ "$NEG7B_CODE" == "400" ]] && grep -qi "claude" "$NEG7B_RESP" 2>/dev/null; then
    ok "7b: REST oauth_token + agent=codex → 400 mentions 'claude'"
    NEG_PASS=$((NEG_PASS+1))
else
    err "7b: expected 400 mentioning 'claude' — got $NEG7B_CODE — body: $(cat "$NEG7B_RESP" 2>/dev/null || echo '<empty>')"
    NEG_FAIL=$((NEG_FAIL+1))
fi

# 7c: CLI — --api-key + --oauth-token together → non-zero exit, "at most one".
# Source=. so the flag-validation step is reached before any FS/git work.
# Literal values (not $ENV / @path) — those forms are the resolver's, not
# the validator's.
NEG7C_LOG="$VIGOLIUM_HOME_DIR/neg7c.log"
set +e
vigolium agent audit --driver=archon --source=. \
    --api-key=fake-key-C --oauth-token=fake-token-C \
    --no-stream >"$NEG7C_LOG" 2>&1
NEG7C_RC=$?
set -e
if [[ $NEG7C_RC -ne 0 ]] && grep -q "at most one" "$NEG7C_LOG"; then
    ok "7c: CLI --api-key + --oauth-token rejected (rc=$NEG7C_RC)"
    NEG_PASS=$((NEG_PASS+1))
else
    err "7c: expected non-zero exit with 'at most one' — rc=$NEG7C_RC, log tail:"
    tail -n 10 "$NEG7C_LOG" >&2 || true
    NEG_FAIL=$((NEG_FAIL+1))
fi

# 7d: CLI — --oauth-token + --archon-provider=openai-codex-oauth → reject.
# The provider override resolves to agent="codex" via ResolveAuthAgent,
# then ValidateAuthOverride enforces oauth_token-needs-claude.
NEG7D_LOG="$VIGOLIUM_HOME_DIR/neg7d.log"
set +e
vigolium agent audit --driver=archon --source=. \
    --oauth-token=fake-token-D --archon-provider=openai-codex-oauth \
    --no-stream >"$NEG7D_LOG" 2>&1
NEG7D_RC=$?
set -e
if [[ $NEG7D_RC -ne 0 ]] && grep -qi "claude" "$NEG7D_LOG"; then
    ok "7d: CLI --oauth-token + openai-codex-oauth rejected (rc=$NEG7D_RC)"
    NEG_PASS=$((NEG_PASS+1))
else
    err "7d: expected non-zero exit mentioning 'claude' — rc=$NEG7D_RC, log tail:"
    tail -n 10 "$NEG7D_LOG" >&2 || true
    NEG_FAIL=$((NEG_FAIL+1))
fi

if [[ $NEG_FAIL -eq 0 ]]; then
    BYOK_NEG_RESULT="PASS"
    ok "Phase 7: ${NEG_PASS}/4 negatives passed"
else
    BYOK_NEG_RESULT="FAIL"
    err "Phase 7: ${NEG_PASS}/4 passed, ${NEG_FAIL} failed"
fi

fi  # end Phase 7

# ── Phase 8: REST BYOK happy paths (driver=archon) ──────────────────────────
# Three sub-phases, one per cred type. Each runs an archon audit against
# VAmPI with the cred supplied in the JSON body, then reuses Phase 2's
# completion + bundle verification. Each sub-phase skips cleanly when its
# specific cred isn't in the operator's env, so a typical CI env (one cred
# type) only pays for one extra LLM round-trip.
if should_run 8; then
header "Phase 8: REST BYOK happy paths → $ARCHON_SOURCE"

# 8a: oauth_cred_file (codex auth.json). Most realistic — pre-flight already
# detected ~/.codex/auth.json; this proves the explicit BYOK passthrough
# still works when the body names the path.
if [[ -z "$BYOK_CODEX_CRED" ]]; then
    warn "8a (REST oauth_cred_file): skipped (no ~/.codex/auth.json)"
    BYOK_8A_RESULT="SKIP"
else
    BODY_8A=$(jq -n --arg src "$ARCHON_SOURCE" --arg p "$BYOK_CODEX_CRED" \
        '{source:$src, driver:"archon", mode:"lite", agent:"codex", oauth_cred_file:$p, upload_results:true}')
    if run_audit_and_verify "byok-8a-codex-cred-file" "$BODY_8A" "$ARCHON_TIMEOUT_S" \
            "runtime.log" "archon-audit-output.md"; then
        BYOK_8A_RESULT="PASS"
    else
        BYOK_8A_RESULT="FAIL"
    fi
fi

# 8b: api_key — anthropic→claude preferred (cleaner provider semantics);
# fall back to openai→codex if only OPENAI_API_KEY is set.
# Bundle artifact names differ by archon platform (per Phase 2 docstring +
# scan-with-storage.md:222): codex produces archon-audit-output.md; claude
# produces audit-stream.jsonl (claudestream). runtime.log is on both.
if [[ -n "$BYOK_ANTHROPIC_KEY" ]]; then
    BODY_8B=$(jq -n --arg src "$ARCHON_SOURCE" --arg k "$BYOK_ANTHROPIC_KEY" \
        '{source:$src, driver:"archon", mode:"lite", agent:"claude", api_key:$k, upload_results:true}')
    if run_audit_and_verify "byok-8b-claude-api-key" "$BODY_8B" "$ARCHON_TIMEOUT_S" \
            "runtime.log" "audit-stream.jsonl"; then
        BYOK_8B_RESULT="PASS"
    else
        BYOK_8B_RESULT="FAIL"
    fi
elif [[ -n "$BYOK_OPENAI_KEY" ]]; then
    BODY_8B=$(jq -n --arg src "$ARCHON_SOURCE" --arg k "$BYOK_OPENAI_KEY" \
        '{source:$src, driver:"archon", mode:"lite", agent:"codex", api_key:$k, upload_results:true}')
    if run_audit_and_verify "byok-8b-codex-api-key" "$BODY_8B" "$ARCHON_TIMEOUT_S" \
            "runtime.log" "archon-audit-output.md"; then
        BYOK_8B_RESULT="PASS"
    else
        BYOK_8B_RESULT="FAIL"
    fi
else
    warn "8b (REST api_key): skipped (no ANTHROPIC_API_KEY or OPENAI_API_KEY)"
    BYOK_8B_RESULT="SKIP"
fi

# 8c: oauth_token (claude only, sourced from $VIGOLIUM_CLAUDE_OAUTH_TOKEN).
# Claude bundle has audit-stream.jsonl, not archon-audit-output.md.
if [[ -z "$BYOK_CLAUDE_OAUTH" ]]; then
    warn "8c (REST oauth_token): skipped (VIGOLIUM_CLAUDE_OAUTH_TOKEN unset)"
    BYOK_8C_RESULT="SKIP"
else
    BODY_8C=$(jq -n --arg src "$ARCHON_SOURCE" --arg t "$BYOK_CLAUDE_OAUTH" \
        '{source:$src, driver:"archon", mode:"lite", agent:"claude", oauth_token:$t, upload_results:true}')
    if run_audit_and_verify "byok-8c-claude-oauth-token" "$BODY_8C" "$ARCHON_TIMEOUT_S" \
            "runtime.log" "audit-stream.jsonl"; then
        BYOK_8C_RESULT="PASS"
    else
        BYOK_8C_RESULT="FAIL"
    fi
fi

fi  # end Phase 8

# ── Phase 9: CLI BYOK happy path (--oauth-cred-file literal path) ───────────
# Mirrors Phase 6's CLI invocation but with explicit --oauth-cred-file so
# the BYOK flag passthrough into archon's CLI args (--oauth-cred-file) is
# exercised end-to-end. Uses --intensity quick to keep the run short since
# Phase 6 already covers the full balanced path.
if should_run 9; then
header "Phase 9: CLI BYOK → $ARCHON_SOURCE (--oauth-cred-file literal)"

if [[ -z "$BYOK_CODEX_CRED" ]]; then
    warn "skipped (no ~/.codex/auth.json)"
    BYOK_CLI_RESULT="SKIP"
else
    # Pick `timeout` if available (macOS doesn't ship one).
    BYOK_CLI_TIMEOUT_BIN=""
    if command -v timeout >/dev/null 2>&1; then
        BYOK_CLI_TIMEOUT_BIN="timeout"
    elif command -v gtimeout >/dev/null 2>&1; then
        BYOK_CLI_TIMEOUT_BIN="gtimeout"
    fi

    BYOK_CLI_SCAN_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
    BYOK_CLI_LOG="$VIGOLIUM_HOME_DIR/byok-cli-audit.log"
    log "pinned scan UUID: $BYOK_CLI_SCAN_UUID"
    log "running CLI audit with --oauth-cred-file $BYOK_CODEX_CRED (intensity=quick)"

    cli_cmd=()
    if [[ -n "$BYOK_CLI_TIMEOUT_BIN" ]]; then
        cli_cmd+=("$BYOK_CLI_TIMEOUT_BIN" "$ARCHON_TIMEOUT_S")
    fi
    cli_cmd+=(
        vigolium agent audit
        --project-uuid "$PROJECT_UUID"
        --scan-uuid "$BYOK_CLI_SCAN_UUID"
        --source "$ARCHON_SOURCE"
        --driver archon
        --archon-provider openai-codex-oauth
        --oauth-cred-file "$BYOK_CODEX_CRED"
        --intensity quick
        --upload-results
        --no-stream
    )

    set +e
    "${cli_cmd[@]}" >"$BYOK_CLI_LOG" 2>&1
    BYOK_CLI_RC=$?
    set -e

    if [[ $BYOK_CLI_RC -eq 124 ]]; then
        err "CLI audit timed out after ${ARCHON_TIMEOUT_S}s (log: $BYOK_CLI_LOG)"
        BYOK_CLI_RESULT="FAIL"
    elif [[ $BYOK_CLI_RC -ne 0 ]]; then
        err "CLI audit exited $BYOK_CLI_RC (log tail follows)"
        tail -n 30 "$BYOK_CLI_LOG" >&2 || true
        BYOK_CLI_RESULT="FAIL"
    else
        ok "CLI audit completed (log: $BYOK_CLI_LOG)"

        BYOK_CLI_EXPECTED="gs://${PROJECT_UUID}/agentic-scans/${BYOK_CLI_SCAN_UUID}/results.tar.gz"
        BYOK_CLI_STORAGE_URL=""
        for _ in $(seq 1 30); do
            BYOK_CLI_SESSION="$(api GET "/api/agent/sessions/$BYOK_CLI_SCAN_UUID" 2>/dev/null || echo '{}')"
            BYOK_CLI_STORAGE_URL="$(jq -r '.storage_url // empty' <<<"$BYOK_CLI_SESSION")"
            [[ -n "$BYOK_CLI_STORAGE_URL" ]] && break
            sleep 2
        done
        if [[ "$BYOK_CLI_STORAGE_URL" == "$BYOK_CLI_EXPECTED" ]]; then
            ok "storage_url: $BYOK_CLI_STORAGE_URL"
        else
            err "storage_url mismatch — got: '$BYOK_CLI_STORAGE_URL' want: '$BYOK_CLI_EXPECTED'"
            BYOK_CLI_RESULT="FAIL"
        fi

        if verify_bundle "$BYOK_CLI_SCAN_UUID" "byok-cli" "runtime.log" "archon-audit-output.md"; then
            [[ "$BYOK_CLI_RESULT" != "FAIL" ]] && BYOK_CLI_RESULT="PASS"
        else
            BYOK_CLI_RESULT="FAIL"
        fi
    fi
fi

fi  # end Phase 9

# ── Phase 10: REST piolium BYOK (auth.json staging) ─────────────────────────
# Exercises pkg/agent/audit_pi_byok.go: the codex cred file is staged at
# <pi-agent-dir>/auth.json with backup-and-restore + per-dir lock for the
# duration of the run. Beyond the standard completion/bundle verify, we
# best-effort confirm the .vigolium-auth.lock didn't leak after cleanup.
if should_run 10; then
header "Phase 10: REST piolium BYOK → $ARCHON_SOURCE (auth.json staging)"

if [[ -z "$BYOK_CODEX_CRED" ]]; then
    warn "skipped (no ~/.codex/auth.json)"
    BYOK_PIOLIUM_RESULT="SKIP"
elif ! command -v pi >/dev/null 2>&1; then
    warn "skipped (pi CLI not in PATH)"
    BYOK_PIOLIUM_RESULT="SKIP"
else
    BODY_10=$(jq -n --arg src "$ARCHON_SOURCE" --arg p "$BYOK_CODEX_CRED" \
        '{source:$src, driver:"piolium", mode:"lite", agent:"codex", oauth_cred_file:$p, upload_results:true}')
    if run_audit_and_verify "byok-10-piolium" "$BODY_10" "$ARCHON_TIMEOUT_S" \
            "runtime.log"; then
        BYOK_PIOLIUM_RESULT="PASS"
    else
        BYOK_PIOLIUM_RESULT="FAIL"
    fi

    # Best-effort post-run lock check. The lock lives at
    # <pi-agent-dir>/.vigolium-auth.lock; we don't know piolium's resolved
    # agent dir without coupling to its internals, so we sweep the two
    # documented locations (system install + ~/.piolium opt-in).
    LOCK_LEAK=""
    for d in /opt/piolium/agent "$HOME/.piolium/agent"; do
        [[ -e "$d/.vigolium-auth.lock" ]] && LOCK_LEAK="$d/.vigolium-auth.lock"
    done
    if [[ -n "$LOCK_LEAK" ]]; then
        err "10: post-run lock leaked at $LOCK_LEAK — staging cleanup missed it"
        BYOK_PIOLIUM_RESULT="FAIL"
    else
        ok "10: no leftover .vigolium-auth.lock in known pi-agent-dir paths"
    fi
fi

fi  # end Phase 10

# ── Phase 11: REST driver=both BYOK (oauth_token, claude) ──────────────────
# Threads a single AuthOverride through both child runs. archon receives
# --oauth-token <value>; piolium gets CLAUDE_CODE_OAUTH_TOKEN injected on
# the pi subprocess (PiAuthEnv at pkg/agent/auth_override.go:96). Skipped
# if the env var is missing or pi isn't in PATH (driver=both needs both
# runtimes for the BYOK thread-through to be a meaningful test).
if should_run 11; then
header "Phase 11: REST driver=both BYOK (oauth_token from VIGOLIUM_CLAUDE_OAUTH_TOKEN)"

if [[ -z "$BYOK_CLAUDE_OAUTH" ]]; then
    warn "skipped (VIGOLIUM_CLAUDE_OAUTH_TOKEN unset)"
    BYOK_BOTH_RESULT="SKIP"
elif ! command -v pi >/dev/null 2>&1; then
    warn "skipped (pi CLI not in PATH — driver=both needs both runtimes)"
    BYOK_BOTH_RESULT="SKIP"
else
    # Doubled timeout: archon then piolium run sequentially under one parent.
    BOTH_TIMEOUT_S=$((ARCHON_TIMEOUT_S * 2))
    BODY_11=$(jq -n --arg src "$ARCHON_SOURCE" --arg t "$BYOK_CLAUDE_OAUTH" \
        '{source:$src, driver:"both", mode:"lite", agent:"claude", oauth_token:$t, upload_results:true}')
    if run_audit_and_verify "byok-11-both" "$BODY_11" "$BOTH_TIMEOUT_S" \
            "runtime.log"; then
        BYOK_BOTH_RESULT="PASS"
    else
        BYOK_BOTH_RESULT="FAIL"
    fi
fi

fi  # end Phase 11

# ── Summary ─────────────────────────────────────────────────────────────────
header "Summary"

mark() {
    case "$1" in
        PASS)    printf '%s✓ PASS%s' "$C_GREEN" "$C_RESET" ;;
        FAIL)    printf '%s✗ FAIL%s' "$C_RED" "$C_RESET" ;;
        SKIP)    printf '%s∼ SKIP%s' "$C_YELLOW" "$C_RESET" ;;
        PENDING) printf '%s· not run%s' "$C_YELLOW" "$C_RESET" ;;
        *)       printf '? %s' "$1" ;;
    esac
}

if [[ "$PHASES_FLAG" != "all" ]]; then
    log "PHASES=$PHASES_FLAG (other phases marked '· not run')"
fi

printf '  %s  Native scan        → %s\n'  "$(mark "$NATIVE_RESULT")"   "$NATIVE_TARGET"
printf '  %s  Agent audit (archon) → %s\n'  "$(mark "$ARCHON_RESULT")"   "$ARCHON_SOURCE"
printf '  %s  Agent autopilot    → %s\n'  "$(mark "$AUTOPILOT_RESULT")" "$AUTOPILOT_TARGET"
printf '  %s  Pinned scan_uuid   → dry_run + attach (UUID: %s)\n' "$(mark "$PINNED_RESULT")"   "${PINNED_SCAN_UUID:-<not started>}"
printf '  %s  409 conflict guard → cross-project UUID reuse\n'    "$(mark "$CONFLICT_RESULT")"
printf '  %s  Serverless audit   → CLI + gs:// source (UUID: %s)\n' "$(mark "$SERVERLESS_RESULT")" "${SERVERLESS_SCAN_UUID:-<not started>}"
printf '  %s  BYOK negatives     → 7a/b REST + 7c/d CLI (no LLM)\n' "$(mark "$BYOK_NEG_RESULT")"
printf '  %s  BYOK REST archon   → oauth_cred_file (codex)\n' "$(mark "$BYOK_8A_RESULT")"
printf '  %s  BYOK REST archon   → api_key (anthropic|openai)\n' "$(mark "$BYOK_8B_RESULT")"
printf '  %s  BYOK REST archon   → oauth_token (VIGOLIUM_CLAUDE_OAUTH_TOKEN)\n' "$(mark "$BYOK_8C_RESULT")"
printf '  %s  BYOK CLI archon    → --oauth-cred-file (codex)\n' "$(mark "$BYOK_CLI_RESULT")"
printf '  %s  BYOK REST piolium  → oauth_cred_file → auth.json staging\n' "$(mark "$BYOK_PIOLIUM_RESULT")"
printf '  %s  BYOK REST both     → oauth_token threaded through both drivers\n' "$(mark "$BYOK_BOTH_RESULT")"
printf '\n  Project UUID: %s\n' "$PROJECT_UUID"
printf '  Bucket:       gs://%s/%s/\n' "$VIGOLIUM_STORAGE_BUCKET_NAME" "$PROJECT_UUID"

if [[ "$NATIVE_RESULT" == "FAIL" || "$ARCHON_RESULT" == "FAIL" || "$AUTOPILOT_RESULT" == "FAIL" \
   || "$PINNED_RESULT" == "FAIL" || "$CONFLICT_RESULT" == "FAIL" \
   || "$SERVERLESS_RESULT" == "FAIL" \
   || "$BYOK_NEG_RESULT" == "FAIL" \
   || "$BYOK_8A_RESULT" == "FAIL" || "$BYOK_8B_RESULT" == "FAIL" || "$BYOK_8C_RESULT" == "FAIL" \
   || "$BYOK_CLI_RESULT" == "FAIL" || "$BYOK_PIOLIUM_RESULT" == "FAIL" \
   || "$BYOK_BOTH_RESULT" == "FAIL" ]]; then
    err "sanity-check failed"
    exit 1
fi

ok "sanity-check complete"
