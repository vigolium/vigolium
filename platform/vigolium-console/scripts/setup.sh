#!/usr/bin/env bash
# Setup script for Vigolium Console on a fresh VPS (Ubuntu/Debian)
# Usage: bash scripts/setup.sh
#
# What it does:
#   1. Installs system dependencies (Node.js 22, Bun, Caddy)
#   2. Installs project dependencies
#   3. Creates .env from .env.example if missing
#   4. Builds the Next.js app
#   5. Sets up a systemd service for the app
#   6. Optionally configures Caddy as a reverse proxy

set -euo pipefail

APP_NAME="vigolium-console"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_PORT=5002
APP_USER="${USER:-$(whoami)}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
CADDY_FILE="/etc/caddy/Caddyfile"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID}"
  elif [[ "$(uname)" == "Darwin" ]]; then
    OS_ID="macos"
  else
    error "Unsupported OS. This script supports Ubuntu, Debian, and macOS."
  fi
}

# ── Install system packages ──────────────────────────────────────────────────
install_deps_linux() {
  info "Updating package lists..."
  sudo apt-get update -qq

  info "Installing base dependencies..."
  sudo apt-get install -y -qq curl unzip git ca-certificates gnupg

  # Node.js 22 via NodeSource
  if ! command -v node &>/dev/null || [[ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]]; then
    info "Installing Node.js 22..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y -qq nodejs
  else
    info "Node.js $(node -v) already installed."
  fi

  # Bun
  if ! command -v bun &>/dev/null; then
    info "Installing Bun..."
    curl -fsSL https://bun.sh/install | bash
    export BUN_INSTALL="$HOME/.bun"
    export PATH="$BUN_INSTALL/bin:$PATH"
  else
    info "Bun $(bun --version) already installed."
  fi

  # Caddy
  if ! command -v caddy &>/dev/null; then
    info "Installing Caddy..."
    sudo apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null || true
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq caddy
  else
    info "Caddy $(caddy version) already installed."
  fi
}

install_deps_macos() {
  if ! command -v brew &>/dev/null; then
    error "Homebrew is required on macOS. Install it from https://brew.sh"
  fi

  if ! command -v node &>/dev/null; then
    info "Installing Node.js..."
    brew install node
  fi

  if ! command -v bun &>/dev/null; then
    info "Installing Bun..."
    brew install oven-sh/bun/bun
  fi

  info "Skipping Caddy and systemd setup on macOS (use 'bun run start' directly)."
}

# ── Project setup ─────────────────────────────────────────────────────────────
setup_project() {
  cd "$APP_DIR"

  # .env
  if [[ ! -f .env ]]; then
    info "Creating .env from .env.example..."
    cp .env.example .env
    # Default to skip-auth for self-hosted
    sed -i.bak 's/^VIGOLIUM_SKIP_AUTH=false/VIGOLIUM_SKIP_AUTH=true/' .env && rm -f .env.bak
    warn "Edit .env to configure your scan server and other settings."
  else
    info ".env already exists, skipping."
  fi

  # Install dependencies
  info "Installing project dependencies..."
  bun install

  # Build
  info "Building the application..."
  bun run build
}

# ── Systemd service ──────────────────────────────────────────────────────────
setup_systemd() {
  if [[ "$OS_ID" == "macos" ]]; then
    return
  fi

  info "Creating systemd service..."

  # Resolve bun path
  BUN_BIN="$(which bun)"

  sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Vigolium Console
After=network.target

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${BUN_BIN} run start
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production
EnvironmentFile=${APP_DIR}/.env

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable "$APP_NAME"
  info "Systemd service created. Start with: sudo systemctl start ${APP_NAME}"
}

# ── Caddy reverse proxy ─────────────────────────────────────────────────────
setup_caddy() {
  if [[ "$OS_ID" == "macos" ]]; then
    return
  fi

  echo ""
  read -rp "Configure Caddy reverse proxy? (y/N): " SETUP_CADDY
  if [[ "${SETUP_CADDY,,}" != "y" ]]; then
    info "Skipping Caddy setup."
    return
  fi

  read -rp "Enter your domain (e.g., console.example.com): " DOMAIN
  if [[ -z "$DOMAIN" ]]; then
    warn "No domain provided, skipping Caddy setup."
    return
  fi

  info "Configuring Caddy for ${DOMAIN}..."
  sudo tee "$CADDY_FILE" >/dev/null <<EOF
${DOMAIN} {
	reverse_proxy localhost:${APP_PORT}
}
EOF

  sudo systemctl restart caddy
  info "Caddy configured. HTTPS will be provisioned automatically for ${DOMAIN}."
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo "========================================="
  echo "  Vigolium Console — Server Setup"
  echo "========================================="
  echo ""

  detect_os

  case "$OS_ID" in
    ubuntu|debian) install_deps_linux ;;
    macos)         install_deps_macos ;;
    *)             error "Unsupported OS: ${OS_ID}" ;;
  esac

  setup_project
  setup_systemd
  setup_caddy

  echo ""
  info "Setup complete!"
  echo ""
  echo "  Next steps:"
  echo "    1. Edit .env with your configuration"
  echo "    2. Start the app:"
  if [[ "$OS_ID" != "macos" ]]; then
    echo "       sudo systemctl start ${APP_NAME}"
    echo "       sudo systemctl status ${APP_NAME}"
  else
    echo "       bun run start"
  fi
  echo ""
}

main "$@"
