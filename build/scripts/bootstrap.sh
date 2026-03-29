#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Vigolium VPS Initialization Script
# =============================================================================
# Sets up a fresh Ubuntu/Debian VPS for running Vigolium with:
#   - System dependencies (git, sqlite3, etc.)
#   - Vigolium binary installation
#   - Vigolium server as a systemd service
#   - Cloudflare Tunnel for secure HTTPS access
#
# Tested on: Ubuntu 22.04/24.04, Debian 12 (Hetzner, DigitalOcean)
#
# Usage:
#   curl -sfL <url>/bootstrap.sh | bash
#   # with flags
#   curl -sfL <url>/bootstrap.sh | bash -s -- --full
#   # or
#   bash bootstrap.sh [OPTIONS]
#
# Options:
#   --domain <domain>         Domain for Cloudflare Tunnel (e.g. vigolium.example.com)
#   --tunnel-name <name>      Cloudflare tunnel name (default: vigolium)
#   --skip-cloudflare         Skip Cloudflare Tunnel setup
#   --full                    Install full image deps (Chromium, Python, SAST tools)
#   --with-agent              Install Claude Code CLI for agent mode
#   --with-browser            Install agent-browser (headless browser for agent mode)
#   --port <port>             Vigolium server port (default: 9002)
#   --cloudflare-only          Only set up Cloudflare Tunnel (skip Vigolium install)
#   --harden                  Block all ports except SSH (22), disable SSH password login
#   --help                    Show this help message
# =============================================================================

# --- Configuration -----------------------------------------------------------
VIGOLIUM_HOME="${VIGOLIUM_HOME:-$HOME/.vigolium}"
VIGOLIUM_PORT=9002
TUNNEL_NAME="vigolium"
TUNNEL_DOMAIN=""
SKIP_CLOUDFLARE=false
INSTALL_FULL=false
INSTALL_AGENT=false
INSTALL_BROWSER=false
CLOUDFLARE_ONLY=false
HARDEN=false
INSTALL_WARNINGS=()  # Collect non-fatal install warnings for summary

# --- Colors ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Helpers -----------------------------------------------------------------
log()     { echo -e "${BLUE}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
step()    { echo -e "\n${CYAN}${BOLD}==> $1${NC}"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

need_root() {
    if [[ $EUID -ne 0 ]]; then
        if command_exists sudo; then
            SUDO="sudo"
        else
            error "This script must be run as root or with sudo available"
        fi
    else
        SUDO=""
    fi
}

# --- Parse Arguments ---------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                TUNNEL_DOMAIN="$2"; shift 2 ;;
            --tunnel-name)
                TUNNEL_NAME="$2"; shift 2 ;;
            --skip-cloudflare)
                SKIP_CLOUDFLARE=true; shift ;;
            --cloudflare-only)
                CLOUDFLARE_ONLY=true; shift ;;
            --full)
                INSTALL_FULL=true; shift ;;
            --with-agent)
                INSTALL_AGENT=true; shift ;;
            --with-browser)
                INSTALL_BROWSER=true; shift ;;
            --harden)
                HARDEN=true; shift ;;
            --port)
                VIGOLIUM_PORT="$2"; shift 2 ;;
            --help|-h)
                head -30 "$0" | tail -17
                exit 0 ;;
            *)
                warn "Unknown option: $1"; shift ;;
        esac
    done
}

# =============================================================================
# Phase 1: System Setup
# =============================================================================
install_system_deps() {
    step "Installing system dependencies"

    $SUDO apt-get update -qq

    # Base packages (always needed)
    local packages=(
        curl wget git ca-certificates gnupg lsb-release
        jq unzip dumb-init
        # SQLite tools for DB inspection
        sqlite3
        # For healthchecks
        netcat-openbsd
    )

    if [[ "$INSTALL_FULL" == true ]]; then
        packages+=(
            chromium
            python3 python3-pip python3-venv
            fonts-liberation
        )
    fi

    $SUDO apt-get install -y --no-install-recommends "${packages[@]}"
    success "System dependencies installed"

    # Full mode: install SAST tools
    if [[ "$INSTALL_FULL" == true ]]; then
        step "Installing SAST tools (full mode)"

        # Detect if pip needs --break-system-packages (PEP 668, Python 3.11+)
        local pip_flags="--no-cache-dir"
        if pip install --break-system-packages --help >/dev/null 2>&1; then
            pip_flags="--break-system-packages --no-cache-dir"
        fi

        # ast-grep
        if ! command_exists ast-grep; then
            if pip install $pip_flags ast-grep-cli 2>&1; then
                success "ast-grep installed"
            else
                INSTALL_WARNINGS+=("ast-grep-cli failed to install via pip. Install manually: pip install ast-grep-cli")
                warn "ast-grep-cli installation failed (see summary below)"
            fi
        fi

        # semgrep
        if ! command_exists semgrep; then
            if pip install $pip_flags semgrep 2>&1; then
                success "semgrep installed"
            else
                INSTALL_WARNINGS+=("semgrep failed to install via pip. Install manually: pip install semgrep")
                warn "semgrep installation failed (see summary below)"
            fi
        fi

        # CodeQL
        if ! command_exists codeql; then
            log "Installing CodeQL..."
            local codeql_version="2.21.3"
            local codeql_arch
            case "$(uname -m)" in
                x86_64)  codeql_arch="linux64" ;;
                aarch64|arm64) codeql_arch="linux-arm64" ;;
                *) warn "Unsupported architecture for CodeQL: $(uname -m)"; codeql_arch="" ;;
            esac
            if [[ -n "$codeql_arch" ]]; then
                local codeql_url="https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-${codeql_arch}.tar.gz"
                local codeql_install_dir="/opt/codeql"
                $SUDO mkdir -p "$codeql_install_dir"
                if curl -fsSL "$codeql_url" | $SUDO tar -xz -C "$codeql_install_dir" --strip-components=1; then
                    $SUDO ln -sf "$codeql_install_dir/codeql" /usr/local/bin/codeql
                    success "CodeQL installed: $(codeql --version 2>/dev/null | head -1 || echo 'OK')"
                else
                    INSTALL_WARNINGS+=("CodeQL failed to install. Install manually: https://github.com/github/codeql-action/releases")
                    warn "CodeQL installation failed (see summary below)"
                fi
            fi
        else
            success "CodeQL already installed: $(codeql --version 2>/dev/null | head -1)"
        fi

        # osv-scanner
        if ! command_exists osv-scanner; then
            log "Installing osv-scanner..."
            local osv_arch
            case "$(uname -m)" in
                x86_64)  osv_arch="amd64" ;;
                aarch64|arm64) osv_arch="arm64" ;;
                *) warn "Unsupported architecture for osv-scanner: $(uname -m)"; osv_arch="" ;;
            esac
            if [[ -n "$osv_arch" ]]; then
                local osv_url="https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${osv_arch}"
                if curl -fsSL -o /tmp/osv-scanner "$osv_url"; then
                    chmod +x /tmp/osv-scanner
                    $SUDO mv /tmp/osv-scanner /usr/local/bin/osv-scanner
                    success "osv-scanner installed: $(osv-scanner --version 2>/dev/null | head -1 || echo 'OK')"
                else
                    INSTALL_WARNINGS+=("osv-scanner failed to install. Install manually: https://github.com/google/osv-scanner/releases")
                    warn "osv-scanner installation failed (see summary below)"
                fi
            fi
        else
            success "osv-scanner already installed: $(osv-scanner --version 2>/dev/null | head -1)"
        fi

        # Detect Chromium binary (varies by distro: chromium, chromium-browser, google-chrome)
        local chromium_bin=""
        for bin in chromium chromium-browser google-chrome google-chrome-stable; do
            if command_exists "$bin"; then
                chromium_bin="$(command -v "$bin")"
                break
            fi
        done
        if [[ -n "$chromium_bin" ]]; then
            success "Chromium path: $chromium_bin"
        else
            warn "Chromium not found in PATH. You may need to install it manually or set CHROME_PATH."
        fi
    fi
}

# =============================================================================
# Phase 1b: Install Nuclei Templates (always — KnownIssueScan is a core phase)
# =============================================================================
install_nuclei_templates() {
    step "Installing nuclei templates for KnownIssueScan"

    local templates_dir="$HOME/nuclei-templates"
    if [[ -d "$templates_dir" ]]; then
        success "Nuclei templates already exist at $templates_dir"
        return
    fi

    log "Cloning nuclei-templates (shallow)..."
    if git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$templates_dir"; then
        success "Nuclei templates installed at $templates_dir"
    else
        warn "Failed to clone nuclei-templates. KnownIssueScan may not work until templates are installed manually:"
        log "  git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates"
    fi
}

# =============================================================================
# Phase 2: Install Vigolium Binary
# =============================================================================
install_vigolium() {
    step "Installing Vigolium"

    # Use the existing install.sh script logic inline
    local bin_dir="$HOME/.local/bin"
    mkdir -p "$bin_dir" "$VIGOLIUM_HOME"

    # Detect platform
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64)  local platform="linux_amd64" ;;
        aarch64|arm64) local platform="linux_arm64" ;;
        *) error "Unsupported architecture: $arch" ;;
    esac

    # Download via the existing install script if available, otherwise direct download
    local install_script="$(dirname "$0")/install.sh"
    if [[ -f "$install_script" ]]; then
        log "Using local install.sh"
        bash "$install_script"
    else
        log "Downloading install script..."
        curl -sfL https://raw.githubusercontent.com/vigolium/vigolium/main/build/scripts/install.sh | bash
    fi

    # Ensure binary is on PATH
    export PATH="$bin_dir:$PATH"

    if command_exists vigolium; then
        success "Vigolium installed: $(vigolium version 2>/dev/null | head -1 || echo 'OK')"
    else
        error "Vigolium binary not found after installation"
    fi
}

# =============================================================================
# Phase 3: Configure Vigolium
# =============================================================================
configure_vigolium() {
    step "Configuring Vigolium"

    local config_file="$VIGOLIUM_HOME/vigolium-configs.yaml"

    if [[ -f "$config_file" ]]; then
        warn "Config already exists at $config_file — skipping (not overwriting)"
        return
    fi

    # Generate API key
    local api_key
    api_key=$(openssl rand -hex 24 2>/dev/null || head -c 48 /dev/urandom | xxd -p | tr -d '\n' | head -c 48)

    cat > "$config_file" <<YAML
# Vigolium Configuration — generated by bootstrap.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)

server:
  auth_api_key: "${api_key}"
  service_port: ${VIGOLIUM_PORT}
  cors_allowed_origins: "reflect-origin"
  enable_metrics: true

database:
  enabled: true
  driver: sqlite
  sqlite:
    path: ${VIGOLIUM_HOME}/database-vgnm.sqlite
    busy_timeout: 15000
    journal_mode: WAL
    synchronous: NORMAL
    cache_size: 10000

scanning_strategy:
  default_strategy: 'balanced'

scanning_pace:
  concurrency: 50
  rate_limit: 100
  max_per_host: 10
  max_duration: 1h

oast:
  enabled: true

audit:
  max_findings_per_module: 15
  extensions:
    enabled: false
    extension_dir: ${VIGOLIUM_HOME}/extensions/
YAML

    chmod 600 "$config_file"
    success "Config written to $config_file"
    log "API Key: ${BOLD}${api_key}${NC}"
    log "Save this key — you'll need it for API requests and the Cloudflare tunnel"
}

# =============================================================================
# Phase 4: Create systemd Service
# =============================================================================
create_systemd_service() {
    step "Creating systemd service"

    local service_file="/etc/systemd/system/vigolium.service"
    local bin_path="$HOME/.local/bin/vigolium"

    # Resolve actual binary path
    if command_exists vigolium; then
        bin_path="$(command -v vigolium)"
    fi

    # Stop existing service before overwriting
    if [[ -f "$service_file" ]]; then
        log "Existing vigolium.service found — updating"
        $SUDO systemctl stop vigolium 2>/dev/null || true
    fi

    $SUDO tee "$service_file" > /dev/null <<EOF
[Unit]
Description=Vigolium Scanner Server
Documentation=https://github.com/vigolium/vigolium
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
Group=${USER}
ExecStart=${bin_path} server
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Environment
Environment=HOME=${HOME}
Environment=PATH=${HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin
WorkingDirectory=${HOME}

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${VIGOLIUM_HOME}
PrivateTmp=true

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload
    $SUDO systemctl enable vigolium
    $SUDO systemctl start vigolium

    # Wait for service to come up
    sleep 2
    if $SUDO systemctl is-active --quiet vigolium; then
        success "Vigolium service started on port ${VIGOLIUM_PORT}"
    else
        warn "Service may not have started yet. Check: systemctl status vigolium"
    fi
}

# =============================================================================
# Phase 5: Install & Configure Cloudflare Tunnel
# =============================================================================
install_cloudflared() {
    if [[ "$SKIP_CLOUDFLARE" == true ]]; then
        log "Skipping Cloudflare Tunnel setup (--skip-cloudflare)"
        return
    fi

    step "Installing cloudflared"

    if command_exists cloudflared; then
        success "cloudflared already installed: $(cloudflared --version)"
    else
        # Install cloudflared from official repo
        curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
            | $SUDO tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null

        echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
            | $SUDO tee /etc/apt/sources.list.d/cloudflared.list

        $SUDO apt-get update -qq
        $SUDO apt-get install -y cloudflared
        success "cloudflared installed: $(cloudflared --version)"
    fi
}

configure_cloudflare_tunnel() {
    if [[ "$SKIP_CLOUDFLARE" == true ]]; then
        return
    fi

    step "Configuring Cloudflare Tunnel"

    # Check if already authenticated
    local cred_dir="$HOME/.cloudflared"
    mkdir -p "$cred_dir"

    if [[ ! -f "$cred_dir/cert.pem" ]]; then
        log ""
        log "${BOLD}Cloudflare authentication required.${NC}"
        log "A browser URL will be printed below. Open it to authorize."
        log "On a headless server, copy the URL and open it on your local machine."
        log ""
        cloudflared tunnel login
        success "Cloudflare authenticated"
    else
        success "Cloudflare already authenticated"
    fi

    # Check if tunnel already exists
    local tunnel_id=""
    if cloudflared tunnel list 2>/dev/null | grep -q "$TUNNEL_NAME"; then
        tunnel_id=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}')
        log "Tunnel '${TUNNEL_NAME}' already exists (ID: ${tunnel_id})"
    else
        log "Creating tunnel: ${TUNNEL_NAME}"
        cloudflared tunnel create "$TUNNEL_NAME"
        tunnel_id=$(cloudflared tunnel list 2>/dev/null | grep "$TUNNEL_NAME" | awk '{print $1}')
        success "Tunnel created (ID: ${tunnel_id})"
    fi

    if [[ -z "$tunnel_id" ]]; then
        error "Failed to get tunnel ID. Run 'cloudflared tunnel list' to debug."
    fi

    # Write tunnel config
    local tunnel_config="$cred_dir/config.yml"
    cat > "$tunnel_config" <<YAML
# Cloudflare Tunnel config — generated by bootstrap.sh
tunnel: ${tunnel_id}
credentials-file: ${cred_dir}/${tunnel_id}.json

ingress:
  # Vigolium API server
  - hostname: ${TUNNEL_DOMAIN:-${TUNNEL_NAME}.example.com}
    service: http://localhost:${VIGOLIUM_PORT}
    originRequest:
      noTLSVerify: true
      connectTimeout: 30s
      # Pass original IP to Vigolium
      httpHostHeader: ${TUNNEL_DOMAIN:-${TUNNEL_NAME}.example.com}

  # Catch-all (required by cloudflared)
  - service: http_status:404
YAML

    success "Tunnel config written to $tunnel_config"

    # Set up DNS route if domain was provided
    if [[ -n "$TUNNEL_DOMAIN" ]]; then
        log "Creating DNS route: ${TUNNEL_DOMAIN} -> tunnel ${TUNNEL_NAME}"
        cloudflared tunnel route dns "$TUNNEL_NAME" "$TUNNEL_DOMAIN" 2>/dev/null || \
            warn "DNS route may already exist or requires manual setup in Cloudflare dashboard"
    else
        warn "No --domain specified. You'll need to add a DNS route manually:"
        log "  cloudflared tunnel route dns ${TUNNEL_NAME} your-subdomain.yourdomain.com"
    fi

    # Create or update systemd service for cloudflared
    step "Configuring cloudflared systemd service"

    local cf_service="/etc/systemd/system/cloudflared-tunnel.service"
    local cf_existed=false
    if [[ -f "$cf_service" ]]; then
        cf_existed=true
        log "Existing cloudflared-tunnel.service found — updating"
        $SUDO systemctl stop cloudflared-tunnel 2>/dev/null || true
    fi

    $SUDO tee "$cf_service" > /dev/null <<EOF
[Unit]
Description=Cloudflare Tunnel for Vigolium
After=network-online.target vigolium.service
Wants=network-online.target

[Service]
Type=simple
User=${USER}
ExecStart=$(command -v cloudflared) tunnel --config ${tunnel_config} run ${TUNNEL_NAME}
Restart=on-failure
RestartSec=5
TimeoutStopSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cloudflared-vigolium

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload
    $SUDO systemctl enable cloudflared-tunnel
    $SUDO systemctl start cloudflared-tunnel

    sleep 2
    if $SUDO systemctl is-active --quiet cloudflared-tunnel; then
        if [[ "$cf_existed" == true ]]; then
            success "Cloudflare tunnel restarted with updated config"
        else
            success "Cloudflare tunnel running"
        fi
    else
        warn "Tunnel service may not have started. Check: systemctl status cloudflared-tunnel"
    fi
}

# =============================================================================
# Phase 6: Claude Code CLI for Agent Mode (optional)
# =============================================================================
install_agent_deps() {
    if [[ "$INSTALL_AGENT" != true ]]; then
        return
    fi

    step "Installing agent mode dependencies"

    # Node.js (needed for Claude Code CLI)
    if ! command_exists node; then
        log "Installing Node.js 22 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | $SUDO -E bash -
        $SUDO apt-get install -y nodejs
        success "Node.js installed: $(node --version)"
    fi

    # Claude Code CLI
    if ! command_exists claude; then
        log "Installing Claude Code CLI..."
        if npm install -g @anthropic-ai/claude-code 2>&1; then
            success "Claude Code CLI installed"
        else
            INSTALL_WARNINGS+=("Claude Code CLI failed to install via npm. Install manually: npm install -g @anthropic-ai/claude-code")
            warn "Claude Code CLI installation failed (see summary below)"
        fi
    fi

    log ""
    log "For agent mode, set your API key:"
    log "  export ANTHROPIC_API_KEY='sk-ant-...'"
    log "  # Add to ~/.bashrc or ~/.profile to persist"

}

# =============================================================================
# Phase 6b: Agent Browser (optional)
# =============================================================================
install_agent_browser() {
    if [[ "$INSTALL_BROWSER" != true ]]; then
        return
    fi

    step "Installing agent-browser"

    # Node.js is required
    if ! command_exists node; then
        log "Installing Node.js 22 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | $SUDO -E bash -
        $SUDO apt-get install -y nodejs
        success "Node.js installed: $(node --version)"
    fi

    if command_exists agent-browser; then
        success "agent-browser already installed"
    else
        log "Installing agent-browser via npm..."
        if npm install -g agent-browser 2>&1; then
            success "agent-browser npm package installed"
        else
            INSTALL_WARNINGS+=("agent-browser failed to install via npm. Install manually: npm install -g agent-browser")
            warn "agent-browser installation failed (see summary below)"
            return
        fi
    fi

    # Install browser binary (Chromium for Playwright)
    log "Installing agent-browser Chromium..."
    if agent-browser install 2>&1; then
        success "agent-browser ready"
    else
        INSTALL_WARNINGS+=("agent-browser Chromium install failed. Run manually: agent-browser install")
        warn "agent-browser Chromium installation failed (see summary below)"
    fi
}

# =============================================================================
# Phase 7: Firewall Setup
# =============================================================================
configure_firewall() {
    step "Configuring firewall"

    if command_exists ufw; then
        if [[ "$HARDEN" == true ]]; then
            # Hardened mode — deny all incoming, allow only SSH
            $SUDO ufw default deny incoming 2>/dev/null || true
            $SUDO ufw default allow outgoing 2>/dev/null || true
            $SUDO ufw allow 22/tcp comment "SSH" 2>/dev/null || true
            log "All incoming ports blocked except SSH (22)"
        else
            # Allow SSH (always)
            $SUDO ufw allow 22/tcp comment "SSH" 2>/dev/null || true

            if [[ "$SKIP_CLOUDFLARE" == true ]]; then
                # Direct access mode — open Vigolium port
                $SUDO ufw allow "${VIGOLIUM_PORT}/tcp" comment "Vigolium API" 2>/dev/null || true
                log "Port ${VIGOLIUM_PORT} opened for direct access"
            else
                # Cloudflare tunnel mode — only allow localhost access to Vigolium
                # The tunnel connects locally, no need to expose the port
                $SUDO ufw deny "${VIGOLIUM_PORT}/tcp" comment "Vigolium - tunnel only" 2>/dev/null || true
                log "Port ${VIGOLIUM_PORT} blocked externally (Cloudflare tunnel handles access)"
            fi
        fi

        # Enable if not already
        if ! $SUDO ufw status | grep -q "Status: active"; then
            $SUDO ufw --force enable
        fi

        success "Firewall configured"
    else
        warn "ufw not found — configure your firewall manually"
    fi
}

# =============================================================================
# Phase 7b: Harden SSH (optional)
# =============================================================================
harden_ssh() {
    if [[ "$HARDEN" != true ]]; then
        return
    fi

    step "Hardening SSH — disabling password authentication"

    local sshd_config="/etc/ssh/sshd_config"
    local sshd_drop="/etc/ssh/sshd_config.d/99-vigolium-harden.conf"

    # Check that at least one authorized_keys file exists to avoid lockout
    local has_keys=false
    if [[ -f "$HOME/.ssh/authorized_keys" ]] && [[ -s "$HOME/.ssh/authorized_keys" ]]; then
        has_keys=true
    fi

    if [[ "$has_keys" != true ]]; then
        warn "No SSH authorized_keys found for user ${USER}."
        warn "Skipping SSH hardening to avoid lockout. Add your public key first:"
        log "  ssh-copy-id ${USER}@<this-server>"
        return
    fi

    # Use a drop-in config if sshd_config.d is supported, otherwise patch main config
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        $SUDO tee "$sshd_drop" > /dev/null <<'EOF'
# Vigolium SSH hardening — generated by bootstrap.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
EOF
        success "SSH drop-in config written to $sshd_drop"
    else
        # Patch main sshd_config in place
        for directive in PasswordAuthentication KbdInteractiveAuthentication ChallengeResponseAuthentication; do
            if grep -qE "^#?${directive}" "$sshd_config"; then
                $SUDO sed -i "s/^#*${directive}.*/${directive} no/" "$sshd_config"
            else
                echo "${directive} no" | $SUDO tee -a "$sshd_config" > /dev/null
            fi
        done
        if grep -qE "^#?PermitRootLogin" "$sshd_config"; then
            $SUDO sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$sshd_config"
        else
            echo "PermitRootLogin prohibit-password" | $SUDO tee -a "$sshd_config" > /dev/null
        fi
        success "SSH config updated in $sshd_config"
    fi

    # Validate config before restarting
    if $SUDO sshd -t 2>/dev/null; then
        $SUDO systemctl restart sshd 2>/dev/null || $SUDO systemctl restart ssh 2>/dev/null || true
        success "SSH service restarted — password login disabled"
    else
        warn "sshd config validation failed — SSH was NOT restarted. Check config manually."
    fi
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    local config_file="$VIGOLIUM_HOME/vigolium-configs.yaml"
    local api_key=""
    if [[ -f "$config_file" ]]; then
        api_key=$(grep 'auth_api_key:' "$config_file" | awk '{print $2}' | tr -d '"')
    fi

    # Print any deferred install warnings
    if [[ ${#INSTALL_WARNINGS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}${BOLD}============================================================${NC}"
        echo -e "${YELLOW}${BOLD}  Some optional tools failed to install${NC}"
        echo -e "${YELLOW}${BOLD}============================================================${NC}"
        for w in "${INSTALL_WARNINGS[@]}"; do
            echo -e "  ${YELLOW}•${NC} $w"
        done
        echo -e "${YELLOW}${BOLD}============================================================${NC}"
    fi

    echo ""
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}  Vigolium VPS Setup Complete${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo ""
    echo -e "  ${BOLD}Service Status${NC}"
    echo -e "    vigolium:           $($SUDO systemctl is-active vigolium 2>/dev/null || echo 'not running')"
    if [[ "$SKIP_CLOUDFLARE" != true ]]; then
        echo -e "    cloudflared-tunnel: $($SUDO systemctl is-active cloudflared-tunnel 2>/dev/null || echo 'not running')"
    fi
    if [[ "$HARDEN" == true ]]; then
        echo ""
        echo -e "  ${BOLD}Hardening${NC}"
        echo -e "    Firewall:       deny all incoming except SSH (22)"
        echo -e "    SSH password:   disabled"
    fi
    echo ""
    echo -e "  ${BOLD}Access${NC}"
    if [[ -n "$TUNNEL_DOMAIN" && "$SKIP_CLOUDFLARE" != true ]]; then
        echo -e "    URL:      ${CYAN}https://${TUNNEL_DOMAIN}${NC}"
        echo -e "    API Docs: ${CYAN}https://${TUNNEL_DOMAIN}/api/swagger${NC}"
    else
        echo -e "    Local:    ${CYAN}http://localhost:${VIGOLIUM_PORT}${NC}"
        echo -e "    API Docs: ${CYAN}http://localhost:${VIGOLIUM_PORT}/api/swagger${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}API Key${NC}"
    if [[ -n "$api_key" ]]; then
        echo -e "    ${api_key}"
    fi
    echo -e "    Auth header: ${CYAN}Authorization: Bearer <api-key>${NC}"
    echo ""
    echo -e "  ${BOLD}Files${NC}"
    echo -e "    Config:   ${VIGOLIUM_HOME}/vigolium-configs.yaml"
    echo -e "    Database: ${VIGOLIUM_HOME}/database-vgnm.sqlite"
    echo -e "    Logs:     journalctl -u vigolium -f"
    echo ""
    echo -e "  ${BOLD}Useful Commands${NC}"
    echo -e "    systemctl status vigolium          # Check service status"
    echo -e "    journalctl -u vigolium -f          # Tail logs"
    echo -e "    systemctl restart vigolium         # Restart after config change"
    echo -e "    vigolium health                    # Validate setup"
    echo -e "    vigolium scan -t https://target    # Run a scan"
    if [[ "$SKIP_CLOUDFLARE" != true ]]; then
        echo -e "    systemctl status cloudflared-tunnel"
        echo -e "    journalctl -u cloudflared-tunnel -f"
    fi
    echo ""
    echo -e "  ${BOLD}Manual systemd Setup${NC} (if not using this script)"
    echo -e "    # Create the service file:"
    echo -e "    sudo tee /etc/systemd/system/vigolium.service > /dev/null <<'SVC'"
    echo -e "    [Unit]"
    echo -e "    Description=Vigolium Scanner Server"
    echo -e "    After=network-online.target"
    echo -e "    Wants=network-online.target"
    echo -e ""
    echo -e "    [Service]"
    echo -e "    Type=simple"
    echo -e "    User=${USER}"
    echo -e "    ExecStart=$(command -v vigolium 2>/dev/null || echo '/usr/local/bin/vigolium') server"
    echo -e "    Restart=on-failure"
    echo -e "    RestartSec=5"
    echo -e "    Environment=HOME=${HOME}"
    echo -e "    Environment=PATH=${HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin"
    echo -e "    WorkingDirectory=${HOME}"
    echo -e "    LimitNOFILE=65535"
    echo -e ""
    echo -e "    [Install]"
    echo -e "    WantedBy=multi-user.target"
    echo -e "    SVC"
    echo -e ""
    echo -e "    sudo systemctl daemon-reload"
    echo -e "    sudo systemctl enable --now vigolium"
    echo ""
    echo -e "  ${BOLD}Quick Test${NC}"
    echo -e "    curl -s -H 'Authorization: Bearer ${api_key}' http://localhost:${VIGOLIUM_PORT}/api/health | jq ."
    if [[ -n "$TUNNEL_DOMAIN" && "$SKIP_CLOUDFLARE" != true ]]; then
        echo -e "    curl -s -H 'Authorization: Bearer ${api_key}' https://${TUNNEL_DOMAIN}/api/health | jq ."
    fi
    echo ""
    echo -e "${GREEN}${BOLD}============================================================${NC}"
}

# =============================================================================
# Main
# =============================================================================
main() {
    parse_args "$@"

    echo -e "${BOLD}"
    echo "  ╦  ╦╦╔═╗╔═╗╦  ╦╦ ╦╔╦╗"
    echo "  ╚╗╔╝║║ ╦║ ║║  ║║ ║║║║"
    echo "   ╚╝ ╩╚═╝╚═╝╩═╝╩╚═╝╩ ╩"
    echo -e "${NC}"
    echo -e "  VPS Initialization Script"
    echo ""

    need_root

    if [[ "$CLOUDFLARE_ONLY" == true ]]; then
        # Standalone Cloudflare Tunnel setup for existing VPS
        step "Cloudflare-only mode — skipping Vigolium installation"

        # Verify Vigolium is already running
        if ! command_exists vigolium; then
            warn "Vigolium binary not found in PATH"
            log "Make sure Vigolium is installed and 'vigolium server' is running on port ${VIGOLIUM_PORT}"
        fi
        if curl -sf "http://localhost:${VIGOLIUM_PORT}/api/health" >/dev/null 2>&1; then
            success "Vigolium server detected on port ${VIGOLIUM_PORT}"
        else
            warn "Vigolium server not responding on port ${VIGOLIUM_PORT}"
            log "Continuing with tunnel setup — make sure the server is running before testing"
        fi

        # Only install cloudflared and configure the tunnel
        SKIP_CLOUDFLARE=false
        install_cloudflared
        configure_cloudflare_tunnel
        configure_firewall
        harden_ssh
        print_summary
    else
        # Full VPS initialization
        install_system_deps
        install_nuclei_templates
        install_vigolium
        configure_vigolium
        create_systemd_service
        install_cloudflared
        configure_cloudflare_tunnel
        install_agent_deps
        install_agent_browser
        configure_firewall
        harden_ssh
        print_summary
    fi
}

main "$@"
