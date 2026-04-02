# Self-Hosted Setup Guide

Deploy Vigolium Console on your own VPS or server. This guide covers the automated setup script and manual installation steps.

## Prerequisites

- A VPS or server running **Ubuntu 22.04+** or **Debian 12+** (1 GB RAM minimum, 2 GB recommended)
- A running [Vigolium Scan Server](https://github.com/user/vigolium) accessible from the VPS
- A domain name pointed to your server (optional, for HTTPS)

## Quick Start

Clone the repo and run the setup script:

```bash
git clone https://github.com/user/vigolium-console.git
cd vigolium-console
bun run setup
```

> If Bun is not yet installed, run the setup script directly:
>
> ```bash
> bash scripts/setup.sh
> ```

The setup script will:

1. Install Node.js 22, Bun, and Caddy
2. Run `bun install` to install project dependencies
3. Create `.env` from `.env.example` with auth bypass enabled
4. Build the Next.js production bundle
5. Create a systemd service (`vigolium-console`) for auto-start
6. Optionally configure Caddy as a reverse proxy with automatic HTTPS

After setup completes, configure your environment and start the service:

```bash
nano .env                                    # set VIGOLIUM_SCAN_SERVER, etc.
sudo systemctl start vigolium-console        # start the app
sudo systemctl status vigolium-console       # verify it's running
```

The console will be available at `http://<your-server-ip>:5002`.

---

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure the values. The most important ones:

| Variable | Required | Description |
|---|---|---|
| `VIGOLIUM_SCAN_SERVER` | Yes | URL of the Vigolium scan server (e.g., `http://localhost:9002`) |
| `VIGOLIUM_SKIP_AUTH` | No | Set to `true` to bypass WorkOS auth and billing (default for self-hosted) |
| `VIGOLIUM_AUTH_API_KEY` | No | API key for scan server auth (not needed if scan server has no auth) |

### Auth & Billing (Optional)

If you want user authentication and billing, set `VIGOLIUM_SKIP_AUTH=false` and configure:

| Variable | Description |
|---|---|
| `WORKOS_API_KEY` | WorkOS API key |
| `WORKOS_CLIENT_ID` | WorkOS client ID |
| `WORKOS_COOKIE_PASSWORD` | 32+ character random string for session cookie encryption |
| `NEXT_PUBLIC_WORKOS_REDIRECT_URI` | OAuth callback URL (e.g., `https://console.example.com/callback`) |
| `STRIPE_SECRET_KEY` | Stripe secret key for billing |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |

### GitHub Integration (Optional)

For source repo cloning via GitHub:

| Variable | Description |
|---|---|
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |

---

## Reverse Proxy with Caddy

The setup script can configure Caddy for you. If you skipped it during setup or want to configure it manually:

```bash
sudo nano /etc/caddy/Caddyfile
```

Add your domain:

```caddyfile
console.example.com {
    reverse_proxy localhost:5002
}
```

Restart Caddy to apply:

```bash
sudo systemctl restart caddy
```

Caddy will automatically provision and renew an HTTPS certificate via Let's Encrypt. Make sure ports **80** and **443** are open in your firewall.

### Using Nginx Instead

If you prefer Nginx:

```nginx
server {
    listen 80;
    server_name console.example.com;

    location / {
        proxy_pass http://localhost:5002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Then use Certbot for HTTPS:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d console.example.com
```

---

## Managing the Service

The setup script creates a systemd service called `vigolium-console`.

```bash
# Start / stop / restart
sudo systemctl start vigolium-console
sudo systemctl stop vigolium-console
sudo systemctl restart vigolium-console

# Check status
sudo systemctl status vigolium-console

# View logs
sudo journalctl -u vigolium-console -f

# Disable auto-start on boot
sudo systemctl disable vigolium-console
```

---

## Updating

Pull the latest changes and redeploy:

```bash
bun run deploy
```

This runs `scripts/deploy.sh`, which will:

1. `git pull --ff-only`
2. `bun install`
3. Rebuild the app (`bun run build:prod`)
4. Restart the systemd service (if running)

---

## Manual Installation

If you prefer not to use the setup script:

### 1. Install Node.js 22 and Bun

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
curl -fsSL https://bun.sh/install | bash
source ~/.bashrc
```

### 2. Clone and build

```bash
git clone https://github.com/user/vigolium-console.git
cd vigolium-console
cp .env.example .env
nano .env                  # configure your settings
bun install
bun run build
```

### 3. Run with PM2 (alternative to systemd)

```bash
npm install -g pm2
pm2 start "bun run start" --name vigolium-console
pm2 save
pm2 startup                # auto-start on reboot
```

### 4. Run directly

```bash
NODE_ENV=production bun run start
```

---

## Resource Requirements

| Setup | RAM Usage (approx.) | Notes |
|---|---|---|
| Console only | ~200-350 MB | Next.js production server |
| Console + Caddy | ~250-400 MB | Add ~50 MB for Caddy |
| Console + Scan Server | ~500 MB - 1 GB+ | Depends on scan workload |

A **1 GB VPS** can comfortably run the console alone. If running the scan server on the same machine, use at least **2 GB**.

---

## Troubleshooting

### App won't start

Check logs for errors:

```bash
sudo journalctl -u vigolium-console -n 50 --no-pager
```

Common issues:
- **Port 5002 already in use**: Another process is using the port. Find it with `sudo lsof -i :5002`.
- **Missing .env**: Make sure `.env` exists and `VIGOLIUM_SCAN_SERVER` is set.
- **Build errors**: Run `bun run build` manually to see detailed output.

### Can't connect to scan server

- Verify the scan server is running: `curl http://localhost:9002/health`
- If the scan server is on a different host, make sure the firewall allows the connection.
- Check `VIGOLIUM_SCAN_SERVER` in `.env` matches the actual scan server address.

### Caddy HTTPS not working

- Ensure your domain's DNS A record points to the server's IP.
- Ports 80 and 443 must be open: `sudo ufw allow 80,443/tcp`
- Check Caddy logs: `sudo journalctl -u caddy -f`

### Out of memory

If the build process gets killed on a low-RAM VPS, add swap space:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

Then retry `bun run build`.
