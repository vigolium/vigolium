# Vigolium Ansible Deployment

Two playbooks for deploying Vigolium to a fresh Ubuntu/Debian server.

| Playbook | What it deploys | Use case |
|----------|----------------|----------|
| `playbook.yml` | Scanner + Console + Caddy (full stack) | Production with web UI, HTTPS via Cloudflare |
| `playbook-scanner.yml` | Scanner only | Headless API server, no UI |

## Prerequisites

### On your local machine

1. **Ansible** (2.15+)

   ```bash
   # macOS
   brew install ansible

   # Ubuntu/Debian
   pip install ansible

   # Verify
   ansible --version
   ```

2. **Required Ansible collections**

   ```bash
   ansible-galaxy collection install community.general ansible.posix
   ```

3. **A pre-built Vigolium binary** — build it before deploying:

   ```bash
   # From the repo root
   make build-linux          # builds to build/dist/
   # Or for all platforms:
   make build-all
   ```

   The playbook expects the binary at `build/dist/vigolium_linux_amd64_v1/vigolium` by default. For ARM64 servers, change `vigolium_binary_src` in `inventory/group_vars/all.yml`.

### On the target server

- **OS**: Ubuntu 22.04, Ubuntu 24.04, or Debian 12
- **Access**: Root SSH access (or a sudo user)
- **Minimum specs**: 2 vCPU, 4 GB RAM, 40 GB disk (CodeQL bundle alone is ~2 GB)

### Accounts (full-stack only)

| Service | What you need | Where to get it |
|---------|--------------|-----------------|
| Cloudflare | API token with **DNS Edit** permission on your zone | Cloudflare dashboard > My Profile > API Tokens |
| WorkOS | API key + Client ID | workos.com/dashboard |
| GitHub | OAuth App client ID + secret | github.com/settings/developers |
| Stripe | Secret key + Webhook secret | dashboard.stripe.com/apikeys |

---

## Quick Start: Scanner Only

The simplest deployment. No TLS, no web UI — just the scanner API on port 9002.

### 1. Configure your server

```bash
cd build/infra
```

Edit `inventory/hosts.yml`:

```yaml
all:
  hosts:
    vigolium-server:
      ansible_host: 203.0.113.10        # Your server IP
      ansible_user: root
```

### 2. Create the vault

```bash
ansible-vault create inventory/group_vars/vault.yml
```

Enter a vault password, then add:

```yaml
vault_vigolium_api_key: "pick-a-strong-api-key-here"
```

Save and close.

### 3. Deploy

```bash
ansible-playbook playbook-scanner.yml --ask-vault-pass
```

### 4. Verify

```bash
curl -s -H "Authorization: Bearer pick-a-strong-api-key-here" \
  http://203.0.113.10:9002/health
```

---

## Quick Start: Full Stack

Scanner + Next.js Console + Caddy with automatic HTTPS.

### 1. Configure your server

Edit `inventory/hosts.yml` with your server IP (same as above).

### 2. Create the vault

```bash
ansible-vault create inventory/group_vars/vault.yml
```

Contents:

```yaml
vault_vigolium_api_key: "pick-a-strong-api-key-here"
vault_cloudflare_api_token: "your-cloudflare-dns-edit-token"
```

### 3. Prepare the console .env

```bash
cp roles/vigolium-console/files/console.env.example \
   roles/vigolium-console/files/console.env
```

Edit `console.env` with your WorkOS, Stripe, and GitHub credentials. Then encrypt it:

```bash
ansible-vault encrypt roles/vigolium-console/files/console.env
```

Use the same vault password as step 2.

### 4. Set your domain

Edit `inventory/group_vars/all.yml`:

```yaml
vigolium_domain: "scan.yourdomain.com"
```

Make sure a DNS A record exists in Cloudflare pointing `scan.yourdomain.com` to your server IP. Caddy will obtain the TLS certificate automatically via Cloudflare DNS-01 challenge.

### 5. Deploy

```bash
ansible-playbook playbook.yml --ask-vault-pass
```

### 6. Verify

```bash
curl -s https://scan.yourdomain.com/health
```

Open `https://scan.yourdomain.com` in your browser to access the console.

---

## Configuration Reference

All variables are in `inventory/group_vars/all.yml`.

### Core settings

| Variable | Default | Description |
|----------|---------|-------------|
| `vigolium_domain` | `scan.example.com` | Public domain (full-stack only) |
| `vigolium_server_port` | `9002` | Scanner API port |
| `vigolium_console_port` | `5002` | Console port |
| `vigolium_api_key` | from vault | Bearer token for API auth |
| `vigolium_binary_src` | `../../build/dist/vigolium_linux_amd64_v1/vigolium` | Path to pre-built binary |
| `vigolium_user` | `vigolium` | System user that runs everything |
| `vigolium_home` | `/opt/vigolium` | Home directory |

### Dependency toggles

| Variable | Default | What it installs |
|----------|---------|-----------------|
| `install_chromium` | `true` | Chromium + fonts (headless browser for crawling) |
| `install_semgrep` | `true` | Python 3, semgrep, ast-grep (SAST tools) |
| `install_codeql` | `true` | CodeQL bundle (~2 GB, static analysis) |
| `install_claude_code` | `true` | Bun + Claude Code CLI (agent mode) |
| `install_nuclei_templates` | `true` | nuclei-templates repo (KnownIssueScan phase) |

Set any to `false` to skip. For example, to deploy without CodeQL:

```bash
ansible-playbook playbook-scanner.yml --ask-vault-pass \
  -e install_codeql=false
```

### Scanning defaults

| Variable | Default | Description |
|----------|---------|-------------|
| `vigolium_concurrency` | `50` | Concurrent scan workers |
| `vigolium_rate_limit` | `100` | Max requests/second |
| `vigolium_max_per_host` | `10` | Max concurrent requests per host |
| `vigolium_max_duration` | `1h` | Max scan duration |

---

## Partial Deploys

Use tags to update only what changed:

```bash
# Update just the scanner binary
ansible-playbook playbook.yml --tags scanner --ask-vault-pass

# Update just the console (rebuild Next.js)
ansible-playbook playbook.yml --tags console --ask-vault-pass

# Update just the dependencies
ansible-playbook playbook.yml --tags deps --ask-vault-pass

# Update just Caddy config
ansible-playbook playbook.yml --tags caddy --ask-vault-pass

# Update system packages + firewall only
ansible-playbook playbook.yml --tags common --ask-vault-pass
```

---

## Architecture

### Full stack (`playbook.yml`)

```
Internet
  │
  :443 ──→ Caddy (auto-TLS via Cloudflare DNS-01)
              │
              └── /* ──→ Next.js :5002 (cloud mode)
                           │
                           └── /api/proxy/* ──→ Vigolium :9002 (127.0.0.1)
                                                  │
                                                  └── SQLite
```

Three systemd services:
- `vigolium` — scanner on 127.0.0.1:9002 (not exposed)
- `vigolium-console` — Next.js on 127.0.0.1:5002 (not exposed)
- `caddy` — reverse proxy on :443 (public)

### Scanner only (`playbook-scanner.yml`)

```
Internet
  │
  :9002 ──→ Vigolium (0.0.0.0:9002)
               │
               └── SQLite
```

One systemd service:
- `vigolium` — scanner on 0.0.0.0:9002 (exposed directly)

---

## Systemd Services

```bash
# Check status
systemctl status vigolium
systemctl status vigolium-console    # full-stack only
systemctl status caddy               # full-stack only

# View logs
journalctl -u vigolium -f
journalctl -u vigolium-console -f
journalctl -u caddy -f

# Restart after manual config changes
systemctl restart vigolium
systemctl restart vigolium-console
systemctl reload caddy               # Caddy supports zero-downtime reload
```

---

## File Locations on the Server

| Path | Description |
|------|-------------|
| `/usr/local/bin/vigolium` | Scanner binary |
| `/opt/vigolium/.vigolium/vigolium-configs.yaml` | Scanner config |
| `/opt/vigolium/.vigolium/database-vgnm.sqlite` | SQLite database |
| `/opt/vigolium/.vigolium/extensions/` | Custom JS extensions |
| `/opt/vigolium/.vigolium/agent-sessions/` | Agent session artifacts |
| `/opt/vigolium/nuclei-templates/` | Nuclei templates |
| `/opt/vigolium/console/` | Console source + build (full-stack) |
| `/opt/vigolium/console/.env.local` | Console secrets (full-stack) |
| `/etc/caddy/Caddyfile` | Caddy config (full-stack) |
| `/opt/codeql/` | CodeQL bundle |

---

## Vault Management

```bash
# Edit existing vault
ansible-vault edit inventory/group_vars/vault.yml

# Edit encrypted console .env
ansible-vault edit roles/vigolium-console/files/console.env

# Re-encrypt with a new password
ansible-vault rekey inventory/group_vars/vault.yml
ansible-vault rekey roles/vigolium-console/files/console.env
```

---

## Troubleshooting

**Playbook fails at "Build Caddy with Cloudflare DNS plugin"**
- This compiles Caddy from source with Go. Needs ~1 GB RAM.
- On low-memory VPS, add a swap file first: `fallocate -l 2G /swapfile && mkswap /swapfile && swapon /swapfile`

**Caddy can't obtain TLS certificate**
- Check that your Cloudflare API token has `Zone:DNS:Edit` permission on the correct zone.
- Check that the DNS A record exists and points to the server IP.
- Check Caddy logs: `journalctl -u caddy -f`

**Console returns 502**
- The scanner might not be running: `systemctl status vigolium`
- Check the console can reach the scanner: `curl http://127.0.0.1:9002/health` from the server.

**Agent mode not working**
- Set the Anthropic API key: add `Environment=ANTHROPIC_API_KEY=sk-ant-...` to `/etc/systemd/system/vigolium.service`, then `systemctl daemon-reload && systemctl restart vigolium`.
- Or set it in the scanner config under the `agent` section.

**CodeQL installation fails**
- The bundle is ~2 GB. On slow connections it may time out.
- Skip it with `-e install_codeql=false` and install manually later.
