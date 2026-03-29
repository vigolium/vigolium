---
name: agent-browser
description: >-
  Browser automation via agent-browser CLI for login capture, auth flows, and
  browser-based interaction. Invoke for login form filling, cookie extraction,
  session capture, OAuth flows, SPA authentication, and bridging browser state
  to vigolium scanning.
metadata:
  version: "1.0.0"
  domain: browser-automation
  role: operator
  scope: usage
---

# agent-browser CLI

Operator's guide for the `agent-browser` CLI tool. Automates browser interactions for login capture, auth flows, and session extraction. Captured cookies and tokens feed directly into vigolium scans.

## Core Workflow

All browser automation follows the **snapshot-ref-action** loop:

1. **Open** a URL to load it in the browser
2. **Snapshot** the page to get an accessibility tree with `@e` element refs
3. **Act** on elements using their refs (click, fill, type, press)
4. **Re-snapshot** after each action to see the updated state

```bash
# 1. Open
agent-browser open https://example.com/login

# 2. Snapshot (JSON mode returns structured accessibility tree)
agent-browser snapshot --json

# 3. Act using @e refs from the snapshot
agent-browser fill @e15 "admin@example.com"
agent-browser fill @e18 "password123"
agent-browser click @e22

# 4. Re-snapshot to verify result
agent-browser snapshot --json
```

The `--json` flag on `snapshot` returns a structured accessibility tree where every interactive element has an `@e<N>` ref. Use these refs as stable selectors for all interaction commands.

## When to Use

- **Login forms**: Capture cookies and tokens from form-based authentication
- **SPAs**: Navigate JavaScript-heavy apps that require a real browser
- **Multi-step auth**: Handle MFA pages, CAPTCHA interstitials, consent screens
- **OAuth flows**: Follow redirect chains and capture final tokens
- **Cookie extraction**: Pull authenticated session cookies for use in vigolium scans

## Reference Guide

Load detailed reference based on what you need:

| Topic | Reference | Load When |
|-------|-----------|-----------|
| Auth workflows | `references/auth-workflows.md` | Login flows, OAuth, JWT capture, cookie extraction |
| State management | `references/state-management.md` | Sessions, profiles, state files, auth vault, cleanup |
| Commands reference | `references/commands-reference.md` | Full command index with flags and examples |

## Auth Capture Recipe

Step-by-step: capture authenticated session from a login form and feed it to vigolium.

```bash
# Step 1: Open the login page
agent-browser open https://example.com/login --session-name myapp

# Step 2: Snapshot to find form elements
agent-browser snapshot --json --session-name myapp
# Output includes: @e15 textbox "Email", @e18 textbox "Password", @e22 button "Sign In"

# Step 3: Fill and submit the form
agent-browser fill @e15 "admin@example.com" --session-name myapp
agent-browser fill @e18 "s3cretP@ss" --session-name myapp
agent-browser click @e22 --session-name myapp

# Step 4: Wait for redirect after login
agent-browser wait --url "*/dashboard*" --session-name myapp

# Step 5: Extract cookies
agent-browser cookies --session-name myapp --json
# Output: [{"name":"session_id","value":"abc123","domain":"example.com",...}]

# Step 6: Feed to vigolium
vigolium scan -t https://example.com \
  --header "Cookie: session_id=abc123; csrf_token=xyz789"
```

## Auth Vault

Pre-store encrypted credentials for reuse across sessions. The vault uses AES-256-GCM encryption.

```bash
# Save credentials (prompts for password or reads from env)
agent-browser auth save myapp \
  --url https://example.com/login \
  --username admin@example.com \
  --password-env MYAPP_PASSWORD

# Login using stored credentials (replays the saved flow)
agent-browser auth login myapp --session-name myapp

# List saved auth entries
agent-browser auth list
```

## Key Flags

| Flag | Description |
|------|-------------|
| `--session-name` | Named session: cookies and localStorage persist across commands |
| `--json` | Structured JSON output (for snapshot, cookies, storage, etc.) |
| `--profile` | Full Chrome user data directory for persistent browser state |
| `--annotate` | Overlay element refs on screenshots for visual debugging |
| `--state` | Path to a state file for save/load operations |
| `--timeout` | Max wait time for commands (default: 30s) |
| `--headless` | Run in headless mode (default: true) |
| `--auto-connect` | Attach to an already-running Chrome instance |

## Bridging to Vigolium

After capturing auth state with `agent-browser`, pass it to vigolium for authenticated scanning.

### Option 1: Inline Cookie Header

```bash
# Extract cookies as a header string
COOKIES=$(agent-browser cookies --session-name myapp --format header)
vigolium scan -t https://example.com --header "Cookie: $COOKIES"
```

### Option 2: Auth Config YAML

Generate a vigolium auth-config file from captured browser state:

```yaml
# auth-config.yaml
sessions:
  - name: browser_session
    role: primary
    headers:
      Cookie: "session_id=abc123; csrf_token=xyz789"
```

```bash
vigolium scan -t https://example.com --auth-config auth-config.yaml
```

### Option 3: Token from localStorage

```bash
# Extract JWT from localStorage
TOKEN=$(agent-browser storage local get --key auth_token --session-name myapp)
vigolium scan -t https://example.com --header "Authorization: Bearer $TOKEN"
```

## Quick Examples

```bash
# Screenshot with annotated element refs
agent-browser screenshot --annotate -o login-page.png

# Execute JavaScript in the page
agent-browser eval "document.title"

# Wait for a specific element to appear
agent-browser wait "#dashboard-content" --timeout 10s

# Batch multiple commands in one call
agent-browser batch --json '[
  {"cmd": "open", "args": ["https://example.com/login"]},
  {"cmd": "snapshot", "args": ["--json"]},
  {"cmd": "fill", "args": ["@e15", "admin"]},
  {"cmd": "fill", "args": ["@e18", "password"]},
  {"cmd": "click", "args": ["@e22"]}
]'

# Network interception (mock API responses)
agent-browser network route "*/api/feature-flags" --body '{"debug":true}'
```
