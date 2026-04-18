#!/usr/bin/env bash
# setup.sh — Provision a Grafana instance with auth proxy enabled and empty whitelist
# Reproduces: H6 — proxy-auth-empty-allowlist
set -euo pipefail

CONTAINER_NAME="grafana-h6-poc"
GRAFANA_PORT=3001

echo "[*] Stopping any existing container..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

echo "[*] Starting Grafana with auth.proxy enabled and whitelist empty..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${GRAFANA_PORT}:3000" \
  -e GF_AUTH_PROXY_ENABLED=true \
  -e GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER \
  -e GF_AUTH_PROXY_AUTO_SIGN_UP=true \
  -e GF_AUTH_PROXY_WHITELIST="" \
  -e GF_LOG_LEVEL=warn \
  grafana/grafana:11.4.0

echo "[*] Waiting for Grafana to be ready..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${GRAFANA_PORT}/api/health" >/dev/null 2>&1; then
    echo "[+] Grafana is up."
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "[-] Grafana did not start in time." >&2
    exit 1
  fi
done

echo "[+] Setup complete. Grafana running on port ${GRAFANA_PORT}."
