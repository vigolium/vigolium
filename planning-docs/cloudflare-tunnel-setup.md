# Cloudflare Tunnel Setup for Vigolium

Guide for exposing a Vigolium server running on a VPS (Hetzner, DigitalOcean, etc.) to the internet via Cloudflare Tunnel with full SSL, without opening any ports.

## Prerequisites

- A VPS with Vigolium already installed and running (`vigolium server` on port 9002)
- A Cloudflare account (free tier is fine)
- A domain with its DNS managed by Cloudflare (nameservers pointed to Cloudflare)

## How It Works

```
Browser/Client
    │
    │  HTTPS (TLS terminated by Cloudflare)
    ▼
Cloudflare Edge (nearest PoP)
    │
    │  Encrypted tunnel (QUIC/HTTP2)
    ▼
cloudflared daemon on your VPS
    │
    │  http://localhost:9002
    ▼
Vigolium Server
```

- No ports need to be open on your VPS (not even 443 or 80)
- Cloudflare handles SSL certificates automatically — no Let's Encrypt, no renewals
- Traffic between Cloudflare edge and your VPS is encrypted through the tunnel
- You get Cloudflare's DDoS protection, WAF, and caching for free

---

## Step 1: Install cloudflared on the VPS

SSH into your VPS and install the `cloudflared` daemon.

### Option A: APT (Debian/Ubuntu — recommended)

```bash
# Add Cloudflare GPG key
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
    | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null

# Add repository
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/cloudflared.list

# Install
sudo apt-get update && sudo apt-get install -y cloudflared
```

### Option B: Direct binary download

```bash
# For x86_64
curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

# For ARM64 (Hetzner CAX / ARM droplets)
curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 \
    -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared
```

### Verify

```bash
cloudflared --version
# cloudflared version 2024.x.x
```

---

## Step 2: Authenticate with Cloudflare

```bash
cloudflared tunnel login
```

This prints a URL like:

```
Please open the following URL and log in with your Cloudflare account:
https://dash.cloudflare.com/argotunnel?aud=...&callback=...
```

**On a headless VPS:** Copy the URL and open it in a browser on your local machine. Select the domain you want to use. After authorization, a certificate is saved at `~/.cloudflared/cert.pem`.

Verify:
```bash
ls ~/.cloudflared/cert.pem
# Should exist
```

---

## Step 3: Create a Named Tunnel

```bash
cloudflared tunnel create vigolium
```

Output:
```
Tunnel credentials written to /home/user/.cloudflared/<TUNNEL_UUID>.json.
Created tunnel vigolium with id <TUNNEL_UUID>
```

Note the **tunnel UUID** — you'll need it for the config. You can always retrieve it later:

```bash
cloudflared tunnel list
# ID                                   NAME       CREATED
# a1b2c3d4-e5f6-7890-abcd-ef1234567890 vigolium   2026-03-29T...
```

---

## Step 4: Create the Tunnel Config

Create `~/.cloudflared/config.yml`:

```yaml
tunnel: <TUNNEL_UUID>
credentials-file: /home/<your-user>/.cloudflared/<TUNNEL_UUID>.json

ingress:
  # Route your domain to the local Vigolium server
  - hostname: vigolium.yourdomain.com
    service: http://localhost:9002
    originRequest:
      connectTimeout: 30s
      noTLSVerify: true

  # Catch-all rule (required — must be last)
  - service: http_status:404
```

Replace:
- `<TUNNEL_UUID>` with the UUID from step 3
- `/home/<your-user>/` with your actual home path
- `vigolium.yourdomain.com` with your chosen subdomain

### Multiple subdomains (optional)

You can route multiple subdomains through one tunnel:

```yaml
tunnel: <TUNNEL_UUID>
credentials-file: /home/<your-user>/.cloudflared/<TUNNEL_UUID>.json

ingress:
  # Main API
  - hostname: vigolium.yourdomain.com
    service: http://localhost:9002

  # Prometheus metrics on a separate subdomain
  - hostname: metrics.yourdomain.com
    service: http://localhost:9002
    path: /metrics

  # Catch-all
  - service: http_status:404
```

### Validate the config

```bash
cloudflared tunnel ingress validate
# OK
```

---

## Step 5: Create DNS Route

Route your subdomain to the tunnel. This creates a CNAME record in your Cloudflare DNS zone.

```bash
cloudflared tunnel route dns vigolium vigolium.yourdomain.com
```

This adds: `vigolium.yourdomain.com  CNAME  <TUNNEL_UUID>.cfargotunnel.com`

You can verify in the Cloudflare dashboard under DNS > Records for your domain.

---

## Step 6: Test the Tunnel (Manual Run)

Before daemonizing, test manually to ensure everything works:

```bash
cloudflared tunnel --config ~/.cloudflared/config.yml run vigolium
```

You should see:
```
INF Starting tunnel tunnelID=<UUID>
INF Connection registered connIndex=0 ...
INF Connection registered connIndex=1 ...
INF Connection registered connIndex=2 ...
INF Connection registered connIndex=3 ...
```

From your local machine, test:
```bash
# Health check (no auth needed)
curl -s https://vigolium.yourdomain.com/api/health | jq .

# Authenticated request
curl -s -H "Authorization: Bearer <your-api-key>" \
    https://vigolium.yourdomain.com/api/scans | jq .
```

Press `Ctrl+C` to stop the manual run once verified.

---

## Step 7: Run as a systemd Service

Create the service file so the tunnel starts on boot and auto-restarts on failure.

```bash
sudo tee /etc/systemd/system/cloudflared-tunnel.service > /dev/null <<'EOF'
[Unit]
Description=Cloudflare Tunnel for Vigolium
After=network-online.target vigolium.service
Wants=network-online.target

[Service]
Type=simple
User=<your-user>
ExecStart=/usr/local/bin/cloudflared tunnel --config /home/<your-user>/.cloudflared/config.yml run vigolium
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
```

Replace `<your-user>` with your actual username. If you installed via APT, the binary path is `/usr/bin/cloudflared` instead.

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cloudflared-tunnel
sudo systemctl start cloudflared-tunnel
```

Check status:
```bash
sudo systemctl status cloudflared-tunnel
# ● cloudflared-tunnel.service - Cloudflare Tunnel for Vigolium
#    Active: active (running) ...

journalctl -u cloudflared-tunnel -f
# Shows live connection logs
```

---

## Step 8: Lock Down the VPS Firewall

Since all traffic goes through the tunnel, you don't need any ports open except SSH:

```bash
# Reset to deny all incoming
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (don't lock yourself out!)
sudo ufw allow 22/tcp comment "SSH"

# DO NOT open 9002 — the tunnel connects locally
# If you need direct LAN access for debugging:
# sudo ufw allow from 10.0.0.0/8 to any port 9002 comment "Vigolium LAN"

sudo ufw --force enable
sudo ufw status verbose
```

Result: the only way to reach Vigolium is through the Cloudflare tunnel. Port 9002 is not exposed to the internet.

---

## Step 9: Add Cloudflare Access (Zero Trust) — Optional but Recommended

Cloudflare Access adds an authentication layer in front of your tunnel. Users must authenticate before reaching Vigolium. Free for up to 50 users.

### 9a: Set up in the dashboard

1. Go to **Cloudflare Zero Trust** dashboard: https://one.dash.cloudflare.com
2. Navigate to **Access > Applications > Add an application**
3. Choose **Self-hosted**
4. Configure:
   - **Application name:** Vigolium
   - **Session duration:** 24 hours
   - **Application domain:** `vigolium.yourdomain.com`
5. Add a policy:
   - **Policy name:** Allowed Users
   - **Action:** Allow
   - **Include rule:** Emails ending in `@yourdomain.com` (or specific emails)
6. Save

Now visitors to `https://vigolium.yourdomain.com` see a Cloudflare login page before reaching Vigolium.

### 9b: Bypass Access for API calls

If you call the Vigolium API from scripts/CI, you don't want to go through browser-based auth. Create a **Service Token**:

1. **Zero Trust > Access > Service Auth > Create Service Token**
2. Note the `CF-Access-Client-Id` and `CF-Access-Client-Secret`
3. In your Access application, add a second policy:
   - **Policy name:** Service Token
   - **Action:** Service Auth
   - **Include rule:** Service Token = (the one you created)

API calls then authenticate with headers:

```bash
curl -s \
    -H "CF-Access-Client-Id: <client-id>" \
    -H "CF-Access-Client-Secret: <client-secret>" \
    -H "Authorization: Bearer <vigolium-api-key>" \
    https://vigolium.yourdomain.com/api/health | jq .
```

This gives you two layers of auth: Cloudflare Access (network level) + Vigolium API key (application level).

---

## Managing the Tunnel

### Common Commands

```bash
# List all tunnels
cloudflared tunnel list

# Check tunnel status/connections
cloudflared tunnel info vigolium

# Delete a tunnel (stop service first)
sudo systemctl stop cloudflared-tunnel
cloudflared tunnel delete vigolium

# Rotate tunnel credentials
cloudflared tunnel token --cred-file ~/.cloudflared/<UUID>.json vigolium
```

### Service Management

```bash
# Restart after config changes
sudo systemctl restart cloudflared-tunnel

# View logs
journalctl -u cloudflared-tunnel -f
journalctl -u cloudflared-tunnel --since "1 hour ago"

# Restart both services after Vigolium config change
sudo systemctl restart vigolium
sudo systemctl restart cloudflared-tunnel
```

### Health Monitoring

Simple cron-based health check:

```bash
# Add to crontab: crontab -e
*/5 * * * * curl -sf https://vigolium.yourdomain.com/api/health > /dev/null || systemctl restart cloudflared-tunnel
```

Or use Cloudflare's built-in health checks in the tunnel dashboard.

---

## Troubleshooting

### Tunnel connects but site returns 502

Vigolium server isn't running or isn't on the expected port.

```bash
# Check Vigolium is running
systemctl status vigolium
curl -s http://localhost:9002/api/health

# Check configured port matches
grep service_port ~/.vigolium/vigolium-configs.yaml
```

### "failed to connect to origin" in cloudflared logs

```bash
# Check the service URL in config.yml matches
cat ~/.cloudflared/config.yml | grep service

# Verify Vigolium is listening
ss -tlnp | grep 9002
```

### DNS not resolving

```bash
# Check the CNAME was created
dig vigolium.yourdomain.com CNAME

# Should return: <UUID>.cfargotunnel.com
# If not, re-run:
cloudflared tunnel route dns vigolium vigolium.yourdomain.com
```

### "ERR  error="Tunnel credentials file ... not found"

The credentials JSON file is missing or the path in `config.yml` is wrong.

```bash
# List credential files
ls ~/.cloudflared/*.json

# Match the UUID in config.yml to the actual file
grep credentials-file ~/.cloudflared/config.yml
```

### Tunnel works but Cloudflare Access blocks API calls

You need a service token policy. See Step 9b above.

### Connection drops / instability

```bash
# Check cloudflared logs for reconnection events
journalctl -u cloudflared-tunnel --since "30 min ago" | grep -E "ERR|reconnect|failed"

# Update cloudflared to latest
sudo apt-get update && sudo apt-get upgrade cloudflared
```

---

## Architecture: What's Running on the VPS

```
┌─────────────────────────────────────────────┐
│  VPS (Hetzner / DigitalOcean)               │
│                                             │
│  ┌──────────────────────┐                   │
│  │ vigolium.service     │                   │
│  │  vigolium server     │ ◄── port 9002     │
│  │  (API + scanner)     │     (localhost)    │
│  │  SQLite DB           │                   │
│  └──────────────────────┘                   │
│           ▲                                 │
│           │ http://localhost:9002            │
│           │                                 │
│  ┌──────────────────────┐                   │
│  │ cloudflared-tunnel   │                   │
│  │  .service            │ ◄── outbound only │
│  │  (Cloudflare Tunnel) │     (no open      │
│  └──────────────────────┘      ports)       │
│           │                                 │
│           │ Encrypted tunnel (outbound)     │
├───────────┼─────────────────────────────────┤
│  Firewall │  UFW: allow 22/tcp only         │
└───────────┼─────────────────────────────────┘
            │
            ▼
┌───────────────────────────┐
│  Cloudflare Edge          │
│  - SSL termination        │
│  - DDoS protection        │
│  - Access (Zero Trust)    │
│  - WAF rules              │
│  - Caching                │
│                           │
│  vigolium.yourdomain.com  │
└───────────────────────────┘
            ▲
            │ HTTPS
            │
        Browsers / API clients
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Install cloudflared | `sudo apt install cloudflared` |
| Login to Cloudflare | `cloudflared tunnel login` |
| Create tunnel | `cloudflared tunnel create vigolium` |
| Route DNS | `cloudflared tunnel route dns vigolium sub.domain.com` |
| Test manually | `cloudflared tunnel run vigolium` |
| Start service | `sudo systemctl start cloudflared-tunnel` |
| View logs | `journalctl -u cloudflared-tunnel -f` |
| Restart both | `sudo systemctl restart vigolium cloudflared-tunnel` |
| List tunnels | `cloudflared tunnel list` |
| Delete tunnel | `cloudflared tunnel delete vigolium` |

---

## Cost

| Component | Cost |
|-----------|------|
| Cloudflare Tunnel | **Free** (unlimited bandwidth) |
| Cloudflare SSL | **Free** (auto-managed certs) |
| Cloudflare Access | **Free** (up to 50 users) |
| Cloudflare WAF | **Free** (basic rules on free plan) |
| Domain on Cloudflare DNS | **Free** (bring your own domain) |

The entire tunnel + SSL + access control stack costs $0/month.
