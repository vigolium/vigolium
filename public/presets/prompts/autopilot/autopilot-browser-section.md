## Browser Automation (agent-browser)

The `agent-browser` CLI tool is available via the Bash tool for browser-based interaction. Use it when the target requires JavaScript execution, complex login flows, or inspection of SPAs behind authentication walls.

### Core Loop

1. **Open** a URL in the headless browser
2. **Snapshot** the page to see current state and interactive elements
3. **Interact** with elements using their `@ref` identifiers
4. **Re-snapshot** to observe the result

```bash
agent-browser open <url> --session-name <name>
agent-browser snapshot --json --session-name <name>
agent-browser click @ref=42 --session-name <name>
agent-browser fill @ref=15 "admin@example.com" --session-name <name>
agent-browser snapshot --json --session-name <name>
```

### When to Use

- Target requires authentication through a web form (username/password, MFA, OAuth redirects)
- Login flow involves JavaScript-rendered forms or multi-step wizards
- SPA endpoints are only visible after login and client-side routing
- You need to extract cookies or tokens that are set by JavaScript after login
- Standard curl-based login does not work (CSRF tokens, JS challenges)

### Auth Capture

After successfully logging in through the browser, extract session credentials:

```bash
# Extract cookies
agent-browser cookies --json --session-name <name>

# Check localStorage for JWT or bearer tokens
agent-browser storage local --json --session-name <name>
```

Use captured credentials with vigolium scanning:

```bash
# Direct header injection
vigolium scan -t <url> --header "Cookie: session_id=abc123"

# Or write an auth-config.yaml for reuse
```

**auth-config.yaml format:**

```yaml
sessions:
  - type: cookie
    headers:
      Cookie: "session_id=abc123"
```

```yaml
sessions:
  - type: bearer
    headers:
      Authorization: "Bearer eyJhbG..."
```

### Auth Vault

If pre-stored credentials exist in the auth vault, use them directly:

```bash
# List available stored credentials
agent-browser auth list

# Login with stored credentials
agent-browser auth login <name> --session-name <name>
```

### Important Rules

- **Always use `--session-name`** to persist browser state across commands. Without it, each command starts a fresh session.
- **Always use `--json`** for snapshot, cookies, and storage commands so output is machine-parseable.
- **Verify auth works before scanning** — after capturing cookies or tokens, run a quick curl request to an authenticated endpoint to confirm the session is valid.
- **Save browser state** with `agent-browser state save --session-name <name>` after login so the session can be restored later without re-authenticating.
- Do not use the browser for scanning — it is for authentication and reconnaissance only. Once you have credentials, switch to vigolium scan commands with the captured headers.
