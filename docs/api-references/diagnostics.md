# Vigolium API Reference — Diagnostics

## GET /api/diagnostics — System Readiness Check

Returns a diagnostic report checking database connectivity, agent provider readiness, third-party tools, and directory configuration. Useful for verifying the scanner is ready to operate before starting scans.

**Auth:** Viewer (requires Bearer token)

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9002/api/diagnostics | jq .
```

```json
{
  "status": "ready",
  "timestamp": "2026-07-14T23:46:20+08:00",
  "database": {
    "status": "ok",
    "message": "driver=sqlite, schema=ok"
  },
  "initialized": {
    "status": "ok",
    "message": "path=~/.vigolium/initialized, version=v0.3.2"
  },
  "queue": {
    "status": "ok",
    "message": "depth=0"
  },
  "agent": {
    "status": "ok",
    "name": "olium",
    "protocol": "openai-compatible"
  },
  "browser": {
    "status": "ok",
    "message": "/opt/homebrew/bin/agent-browser"
  },
  "embedded_binaries": {
    "jstangle": { "status": "ok", "message": "protocol=v2, probe=ok" },
    "vigolium-audit": { "status": "ok", "message": "runtime=darwin/arm64, list=ok" }
  },
  "audit": {
    "status": "ok",
    "message": "mode=balanced, embedded binary ok"
  },
  "piolium": {
    "status": "ok",
    "message": "pi + piolium extension loaded"
  },
  "tools": {
    "chromium": {
      "status": "ok",
      "path": "/opt/homebrew/bin/chromium"
    },
    "claude": { "status": "ok", "path": "/usr/local/bin/claude" },
    "codex": { "status": "ok", "path": "/usr/local/bin/codex" },
    "pi": { "status": "ok", "path": "/usr/local/bin/pi" }
  },
  "templates_dir": {
    "status": "ok",
    "message": "path=~/.vigolium/prompts, templates=29"
  },
  "sessions_dir": {
    "status": "ok",
    "message": "path=~/.vigolium/agent-sessions, writable=true"
  },
  "nuclei_templates": {
    "status": "ok",
    "message": "path=~/nuclei-templates"
  }
}
```

Fields whose integration is disabled may be omitted. `details` and `tip`
arrays/strings provide diagnostic evidence and remediation guidance when
available.

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
| `initialized` | No | Reports the first-run initialization marker and version |
| `agent` | Yes | Resolves the configured olium provider and confirms credentials are available |
| `queue` | No | Reports queue depth and error counts |
| `browser` | No | Checks `agent-browser` binary if enabled in config |
| `embedded_binaries` | No | Probes embedded JSTangle and Vigolium Audit runtimes |
| `audit` / `piolium` | No | Checks the configured Audit path and Piolium extension |
| `tools.*` | No | Resolves Chromium, agent-browser, Claude, Codex, Pi, Bun, and npm |
| `templates_dir` | No | Verifies prompt templates directory exists and contains `.md` files |
| `sessions_dir` | No | Verifies agent sessions directory exists and is writable |
| `nuclei_templates` | No | Verifies the configured Nuclei template directory |

### CLI Equivalent

The same checks are available via the CLI without a running server:

```bash
# Colored console output
vigolium doctor

# JSON output
vigolium doctor --json
```

The CLI version omits the `queue` check since the queue is only available when the server is running.
