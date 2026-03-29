# Vigolium API Reference — Diagnostics

## GET /api/diagnostics — System Readiness Check

Returns a diagnostic report checking database connectivity, agent backend availability, third-party tools, and directory configuration. Useful for verifying the scanner is ready to operate before starting scans.

**Auth:** Viewer (requires Bearer token)

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9002/api/diagnostics | jq .
```

```json
{
  "status": "degraded",
  "timestamp": "2026-03-29T03:40:08+08:00",
  "database": {
    "status": "ok",
    "message": "driver=sqlite"
  },
  "queue": {
    "status": "ok",
    "message": "depth=0"
  },
  "agent": {
    "status": "ok",
    "name": "claude",
    "binary": "/opt/homebrew/bin/claude",
    "protocol": "sdk"
  },
  "browser": {
    "status": "warning",
    "message": "disabled in config"
  },
  "tools": {
    "ast-grep": {
      "status": "ok",
      "path": "/opt/homebrew/bin/ast-grep"
    },
    "chromium": {
      "status": "ok",
      "path": "/opt/homebrew/bin/chromium"
    }
  },
  "templates_dir": {
    "status": "ok",
    "message": "path=~/.vigolium/prompts, templates=38"
  },
  "sessions_dir": {
    "status": "ok",
    "message": "path=~/.vigolium/agent-sessions, writable=true"
  }
}
```

### Top-Level Status

| Value | Meaning |
|---|---|
| `ready` | All checks passed |
| `degraded` | Some non-critical checks failed (e.g., optional tool missing, browser disabled) |
| `not_ready` | Critical checks failed (database or agent unavailable) |

### Check Statuses

Each individual check returns one of: `ok`, `warning`, `error`.

### Checks Performed

| Check | Critical | Description |
|---|---|---|
| `database` | Yes | Pings the database with a 2s timeout |
| `agent` | Yes | Resolves the default agent backend, verifies binary is in PATH |
| `queue` | No | Reports queue depth and error counts |
| `browser` | No | Checks `agent-browser` binary if enabled in config |
| `tools.ast-grep` | No | Checks `ast-grep` is in PATH (used for SAST/route extraction) |
| `tools.chromium` | No | Checks for chromium/chrome binary (fallbacks: `chromium-browser`, `google-chrome`, `google-chrome-stable`) |
| `templates_dir` | No | Verifies prompt templates directory exists and contains `.md` files |
| `sessions_dir` | No | Verifies agent sessions directory exists and is writable |

### CLI Equivalent

The same checks are available via the CLI without a running server:

```bash
# Colored console output
vigolium doctor

# JSON output
vigolium doctor --json
```

The CLI version omits the `queue` check since the queue is only available when the server is running.
