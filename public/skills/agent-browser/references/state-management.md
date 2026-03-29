# State Management

How `agent-browser` persists browser state across commands: sessions, profiles, state files, auth vault, and cleanup.

## Session Persistence

Named sessions keep cookies and localStorage alive across multiple commands. Use `--session-name` on every command that should share state.

```bash
# All commands in the same session share cookies/localStorage
agent-browser open https://example.com/login --session-name myapp
agent-browser fill @e10 "user" --session-name myapp
agent-browser click @e15 --session-name myapp
agent-browser cookies --session-name myapp   # sees cookies set during login

# Without --session-name, each command gets a fresh ephemeral session
agent-browser open https://example.com   # no state carried over
```

### Session Listing

```bash
# List active sessions
agent-browser session list

# Output:
# NAME       CREATED              LAST_USED            COOKIES  PAGES
# myapp      2026-03-29 10:15:00  2026-03-29 10:18:32  4        1
# staging    2026-03-28 14:00:00  2026-03-28 14:12:05  2        0
```

Sessions persist until explicitly closed or cleaned up. Each session maintains its own cookie jar, localStorage, and sessionStorage.

## Profile Persistence

Profiles use a full Chrome user data directory. This preserves everything a real Chrome session would: cookies, localStorage, IndexedDB, cached credentials, service workers, and browser history.

```bash
# Use a named profile (stored in agent-browser's data directory)
agent-browser open https://example.com --profile work

# Use a custom directory
agent-browser open https://example.com --profile /path/to/chrome-profile

# Profile survives across CLI invocations and system restarts
```

Profiles are heavier than sessions. Use sessions for quick cookie/token capture. Use profiles when you need full browser state persistence (e.g., staying logged into complex SPAs over days).

## State Files

Export and import portable JSON snapshots of browser state. Useful for sharing captured auth state across machines or CI environments.

### Save State

```bash
# Save current session state to a JSON file
agent-browser state save --session-name myapp --state auth-state.json

# State file includes:
# - All cookies (with domain, path, expiry, httpOnly, secure flags)
# - localStorage entries (per origin)
# - sessionStorage entries (per origin)
# - Current URL
```

### Load State

```bash
# Restore state into a new session
agent-browser state load --state auth-state.json --session-name restored

# Now this session has all the cookies and storage from the snapshot
agent-browser cookies --session-name restored --json
```

### List and Inspect

```bash
# List saved state files
agent-browser state list

# Show contents of a state file without loading it
agent-browser state show --state auth-state.json
```

### CI/CD Usage

```bash
# In CI: load pre-captured auth state and scan
agent-browser state load --state ci-auth-state.json --session-name ci
COOKIES=$(agent-browser cookies --session-name ci --format header)
vigolium scan -t https://staging.example.com --header "Cookie: $COOKIES"
```

## Auth Vault

Encrypted credential storage using AES-256-GCM. Stores login flows (URL, username, selectors, steps) so they can be replayed without exposing plaintext passwords in scripts.

### Save Credentials

```bash
# Interactive (prompts for password)
agent-browser auth save myapp --url https://example.com/login --username admin

# From environment variable
agent-browser auth save myapp \
  --url https://example.com/login \
  --username admin \
  --password-env MYAPP_PASSWORD

# With custom selectors (if defaults do not work)
agent-browser auth save myapp \
  --url https://example.com/login \
  --username admin \
  --username-selector "#email-field" \
  --password-selector "#pass-field" \
  --submit-selector "#login-btn"
```

### Replay Login

```bash
# Login using stored credentials
agent-browser auth login myapp --session-name myapp

# This replays the saved flow:
# 1. Opens the stored URL
# 2. Fills username/password into detected or specified fields
# 3. Clicks submit
# 4. Waits for redirect/success indicator
```

### Manage Vault Entries

```bash
# List all saved auth entries
agent-browser auth list

# Output:
# NAME       URL                              USERNAME
# myapp      https://example.com/login        admin
# staging    https://staging.example.com/login  testuser

# Delete an entry
agent-browser auth delete myapp
```

### Vault Encryption

The vault master key is derived from a passphrase. Set it via:

- `AGENT_BROWSER_VAULT_KEY` environment variable
- `--vault-key` flag
- Interactive prompt (if neither is set)

The vault file is stored at `~/.agent-browser/vault.enc` by default.

## Import from Running Chrome

Attach to an already-running Chrome instance to capture its state. Useful when you have already logged in manually.

```bash
# Chrome must be started with remote debugging enabled:
# google-chrome --remote-debugging-port=9222

# Connect and capture state
agent-browser open https://example.com --auto-connect --session-name captured

# Extract cookies from the running browser
agent-browser cookies --auto-connect --session-name captured --json

# Save the state for later use
agent-browser state save --session-name captured --state manual-login.json
```

## Cleanup

```bash
# Close a specific session
agent-browser close --session-name myapp

# Clean up old state files
agent-browser state clean --older-than 7d

# Clean up all sessions
agent-browser state clean --all

# Clean up only expired sessions (no recent activity)
agent-browser state clean --expired
```

State file age is based on last modification time. The `--older-than` flag accepts durations: `1h`, `7d`, `30d`, etc.
