#!/usr/bin/env bash
# Quick deploy script — pull latest, rebuild, restart
# Usage: bash scripts/deploy.sh

set -euo pipefail

APP_NAME="vigolium-console"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$APP_DIR"

echo "[*] Pulling latest changes..."
git pull --ff-only

echo "[*] Installing dependencies..."
bun install

echo "[*] Building..."
bun run build:prod

# Restart via systemd if available, otherwise just inform
if systemctl is-active --quiet "$APP_NAME" 2>/dev/null; then
  echo "[*] Restarting service..."
  sudo systemctl restart "$APP_NAME"
  echo "[+] Deployed and restarted."
else
  echo "[+] Build complete. Start with: bun run start"
fi
