# Scanner-Only Deployment (No Vault)

Deploy Vigolium scanner to a fresh Ubuntu/Debian server without Ansible Vault.

## Prerequisites

**Local machine:**
```bash
brew install ansible                    # macOS
ansible-galaxy collection install community.general ansible.posix
make build-linux                        # from repo root → build/dist/
```

**Target server:** Ubuntu 22.04/24.04 or Debian 12, root SSH access, 2+ vCPU, 4 GB RAM.

## One-Liner Deploy

No files to edit — pass everything on the command line:

```bash
cd build/infra

ansible-playbook playbook-scanner.yml \
  -i "89.167.95.127," \
  -u root \
  -e vault_vigolium_api_key="your-api-key-here"
```

The trailing comma after the IP is required — it tells Ansible this is a host, not a file path.

Skip heavy deps to speed things up:

```bash
ansible-playbook playbook-scanner.yml \
  -i "89.167.95.127," \
  -u root \
  -e vault_vigolium_api_key="your-api-key-here" \
  -e install_codeql=false \
  -e install_semgrep=false
```

---

## Setup (file-based)

```bash
cd build/infra
```

### 1. Set your server IP

Edit `inventory/hosts.yml`:

```yaml
all:
  hosts:
    vigolium-server:
      ansible_host: 203.0.113.10       # ← your server IP
      ansible_user: root
```

### 2. Set your API key (plaintext, no vault)

Create `inventory/group_vars/vault.yml` as a **plain YAML file** (not encrypted):

```yaml
vault_vigolium_api_key: "pick-a-strong-api-key-here"
```

### 3. Deploy

```bash
ansible-playbook playbook-scanner.yml
```

No `--ask-vault-pass` needed since the file isn't encrypted.

### 4. Verify

```bash
curl -s -H "Authorization: Bearer pick-a-strong-api-key-here" \
  http://203.0.113.10:9002/health
```

## Customization

### Change bind address

Pass it at deploy time:

```bash
ansible-playbook playbook-scanner.yml -e vigolium_server_host=127.0.0.1
```

Or on the server directly:

```bash
vigolium server --host 127.0.0.1 --service-port 9002
```

Default for scanner-only: `0.0.0.0` (all interfaces).

### Skip heavy dependencies

```bash
# Skip CodeQL (~2 GB), semgrep, or Claude Code to save time/disk
ansible-playbook playbook-scanner.yml \
  -e install_codeql=false \
  -e install_semgrep=false \
  -e install_claude_code=false
```

| Flag | Default | What it installs |
|------|---------|-----------------|
| `install_chromium` | `true` | Chromium for headless crawling |
| `install_semgrep` | `true` | Python 3, semgrep, ast-grep |
| `install_codeql` | `true` | CodeQL bundle (~2 GB) |
| `install_claude_code` | `true` | Bun + Claude Code CLI |
| `install_nuclei_templates` | `true` | nuclei-templates repo |

### Tune scanning performance

Edit `inventory/group_vars/all.yml` or pass via `-e`:

```bash
ansible-playbook playbook-scanner.yml \
  -e vigolium_concurrency=100 \
  -e vigolium_rate_limit=200
```

| Variable | Default | Description |
|----------|---------|-------------|
| `vigolium_concurrency` | `50` | Concurrent scan workers |
| `vigolium_rate_limit` | `100` | Max requests/second |
| `vigolium_max_per_host` | `10` | Per-host concurrency cap |
| `vigolium_max_duration` | `1h` | Max scan duration |

### ARM64 servers

Edit `inventory/group_vars/all.yml`:

```yaml
vigolium_binary_src: "../../build/dist/vigolium_linux_arm64_v8.0/vigolium"
```

## Update the binary only

```bash
make build-linux                        # rebuild
ansible-playbook playbook-scanner.yml --tags scanner
```

## Server management

```bash
systemctl status vigolium               # check status
journalctl -u vigolium -f               # tail logs
systemctl restart vigolium              # restart after config changes
```

## Key files on the server

| Path | Description |
|------|-------------|
| `/usr/local/bin/vigolium` | Scanner binary |
| `/opt/vigolium/.vigolium/vigolium-configs.yaml` | Config |
| `/opt/vigolium/.vigolium/database-vgnm.sqlite` | SQLite DB |
| `/opt/vigolium/.vigolium/extensions/` | JS extensions |
| `/opt/vigolium/.vigolium/agent-sessions/` | Agent sessions |

## Troubleshooting

**Agent mode not working** — Set the Anthropic key in the systemd service:
```bash
# Add to /etc/systemd/system/vigolium.service under [Service]:
Environment=ANTHROPIC_API_KEY=sk-ant-...
systemctl daemon-reload && systemctl restart vigolium
```

**CodeQL install fails** — It's ~2 GB. Skip with `-e install_codeql=false`.
