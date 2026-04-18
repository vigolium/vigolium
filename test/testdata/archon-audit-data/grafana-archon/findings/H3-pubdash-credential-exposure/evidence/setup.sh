#!/usr/bin/env bash
# setup.sh — Provision Grafana 12.4.2 for H3 PoC
# Used by exploit.sh independently; poc.sh self-provisions.

set -euo pipefail

CONTAINER_NAME="h3-grafana-poc"
GRAFANA_PORT=13002
GRAFANA_IMAGE="grafana/grafana:latest"   # 12.4.2 as of 2026-04-11

echo "[setup] Stopping any existing container..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

echo "[setup] Starting $GRAFANA_IMAGE on port $GRAFANA_PORT..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${GRAFANA_PORT}:3000" \
  -e "GF_SECURITY_ADMIN_PASSWORD=admin" \
  "$GRAFANA_IMAGE"

echo "[setup] Waiting for Grafana to be ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${GRAFANA_PORT}/api/health" >/dev/null 2>&1; then
    echo "[setup] Grafana ready (attempt $i)."
    break
  fi
  echo "[setup]   attempt $i/30..."
  sleep 2
done

curl -sf "http://localhost:${GRAFANA_PORT}/api/health" | python3 -m json.tool
echo "[setup] Done."
