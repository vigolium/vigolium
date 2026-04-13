# Vigolium API Reference — Agent

## Overview

The agent API provides three run modes that mirror the `vigolium agent` CLI subcommands, plus session history and status endpoints:

| Endpoint                         | CLI Equivalent              | Description                              |
|----------------------------------|-----------------------------|------------------------------------------|
| `POST /api/agent/run/query`      | `vigolium agent query`      | Single-shot prompt execution             |
| `POST /api/agent/run/autopilot`  | `vigolium agent autopilot`  | Autonomous AI-driven scanning session    |
| `POST /api/agent/run/swarm`      | `vigolium agent swarm`      | AI-guided multi-phase vulnerability swarm|
| `GET /api/agent/status/list`     | —                           | List runs with in-memory status          |
| `GET /api/agent/status/:id`      | —                           | Get run status by ID                     |
| `GET /api/agent/sessions`        | `vigolium agent sessions`   | Paginated session history from DB        |
| `GET /api/agent/sessions/:id`    | —                           | Full session detail with debug fields    |
| `GET /api/agent/sessions/:id/logs`| —                          | Raw console `run.log` (plain text or SSE tail)|

All run modes share a global concurrency lock — only one agent run can be active at a time. Attempting to start a second run returns `409 Conflict`.

---

## POST /api/agent/run/query — Single-Shot Agent Run

Starts an AI agent run with a prompt template, file, or inline prompt. Returns `202 Accepted` (async) or an SSE stream when `stream: true`.

**Request body:**

| Field              | Type     | Required | Description                                                    |
|--------------------|----------|----------|----------------------------------------------------------------|
| `agent`            | string   | No       | Agent backend name (e.g. `claude`, `opencode`, `codex`)        |
| `prompt_template`  | string   | No*      | Name of a prompt template (from `~/.vigolium/prompts/`)        |
| `prompt_file`      | string   | No*      | Path to a prompt file on disk                                  |
| `prompt`           | string   | No*      | Inline prompt text                                             |
| `source`           | string   | No       | Path to source code for context (JSON field: `source`)         |
| `files`            | string[] | No       | Specific files to include as context                           |
| `append`           | string   | No       | Additional text appended to the prompt                         |
| `instruction`      | string   | No       | Custom instruction appended to the prompt                      |
| `source_label`     | string   | No       | Source label for findings (JSON field: `source_label`)          |
| `scan_uuid`        | string   | No       | Link results to a specific scan UUID                           |
| `stream`           | bool     | No       | If `true`, returns an SSE stream instead of 202 async response |

\* At least one of `prompt_template`, `prompt_file`, or `prompt` is required.

```bash
# Run with a prompt template
curl -s -X POST http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "claude",
    "prompt_template": "code-review",
    "source": "/home/user/src/my-app"
  }' | jq .

# Run with an inline prompt
curl -s -X POST http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Analyze the authentication flow for vulnerabilities",
    "source": "/home/user/src/my-app",
    "files": ["src/auth/login.py", "src/auth/session.py"]
  }' | jq .
```

**Response (202):**

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "query run started"
}
```

---

## POST /api/agent/run/autopilot — Autonomous Scanning Session

Launches an AI agent that autonomously discovers, scans, and triages vulnerabilities using vigolium CLI commands. When `source` is provided, archon-audit runs first, native context and planning artifacts are prepared, and then the autonomous operator session starts.

**Request body:**

| Field              | Type     | Required | Description                                                    |
|--------------------|----------|----------|----------------------------------------------------------------|
| `prompt`           | string   | No       | Natural language scan prompt (parsed into target/source/focus when explicit fields are empty) |
| `intensity`        | string   | No       | Scan intensity preset: `"quick"`, `"balanced"` (default), or `"deep"`. Bundles `max_commands`, `timeout`, `archon_mode`, and `browser` settings |
| `target`           | string   | No*      | Target URL to scan (derived from `input` if not set)           |
| `input`            | string   | No       | Raw input (curl, raw HTTP, Burp XML, URL) — target extracted automatically |
| `agent`            | string   | No       | Agent backend name (default from config)                       |
| `source`           | string   | No       | Path to source code, git URL (with optional OAuth token), or archive file (`.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`) |
| `files`            | string[] | No       | Specific files to include (relative to `source`). Auto-populated from `diff` when not set |
| `diff`             | string   | No       | Focus on changed code: GitHub PR URL (`github.com/.../pull/123`), git ref range (`main...branch`), or `HEAD~N` |
| `last_commits`     | int      | No       | Focus on last N commits (shorthand for `diff: "HEAD~N"`)       |
| `focus`            | string   | No       | Focus area hint (e.g. `"API injection"`, `"auth bypass"`)      |
| `instruction`      | string   | No       | Custom instruction appended to the prompt                      |
| `timeout`          | string   | No       | Go duration string (default `"6h"`)                            |
| `max_commands`     | int      | No       | Max CLI commands the agent can execute (default `100`)         |
| `dry_run`          | bool     | No       | Render the prompt without executing the agent                  |
| `stream`           | bool     | No       | If `true`, returns an SSE stream                               |
| `scan_uuid`        | string   | No       | Link results to a specific scan UUID                           |
| `project_uuid`     | string   | No       | Scope results to a project (falls back to `X-Project-UUID` header) |
| `no_archon`        | bool     | No       | Disable automatic archon-audit (enabled by default when `source` is set) |
| `archon_mode`      | string   | No       | Archon audit mode: `"lite"` (default, 3-phase), `"scan"` (6-phase), or `"deep"` (11-phase) |
| `archon`           | string   | No       | **DEPRECATED** — use `no_archon` + `archon_mode` instead. Legacy values: `"lite"`, `"scan"`, `"deep"`, `"off"` |

\* At least one of `target`, `input`, `source`, `diff`, or `prompt` is required.

**Source resolution:** The `source` field accepts local paths, git URLs (HTTPS or SSH), git URLs with embedded OAuth tokens (`https://oauth2:TOKEN@github.com/...`), and archive files. Git repos are cloned with `--depth 1` and archives are extracted into the session directory. OAuth tokens are stripped from logs.

**Diff resolution:** When `diff` is set, the changed file list auto-populates `files` and the patch content is included in the agent prompt. For PR URLs without `source`, the repo is auto-cloned. GitHub PRs use the GitHub REST API directly (no `gh` CLI required). OAuth tokens embedded in the URL (`https://oauth2:TOKEN@github.com/...`) are extracted and passed as `Authorization: Bearer` header. The `GITHUB_TOKEN` env var is used as a fallback.

**Quick scan (CI/PR review)** — lite archon, diff-focused, tight limits:

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "intensity": "quick",
    "diff": "https://github.com/org/repo/pull/42"
  }' | jq .
```

**Balanced scan (routine assessment)** — scan-mode archon, standard limits (`"balanced"` is the default when `intensity` is omitted):

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "focus": "authentication bypass",
    "stream": true
  }'
```

**Deep scan (thorough pentest)** — deep archon, browser, extended timeout:

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "intensity": "deep",
    "instruction": "Test all API endpoints. Focus on IDOR, auth bypass, and injection.",
    "stream": true
  }'
```

**Diff-focused scan (PR review without pre-cloned source):**

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://staging.example.com",
    "diff": "https://github.com/org/repo/pull/123",
    "archon_mode": "lite",
    "max_commands": 25,
    "timeout": "15m"
  }' | jq .
```

**Private repo with OAuth token:**

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "https://oauth2:ghp_token123@github.com/org/private-repo.git",
    "archon_mode": "scan"
  }' | jq .
```

**Basic scan (no source):**

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "agent": "claude",
    "focus": "API injection"
  }' | jq .
```

**Response (202):**

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "autopilot run started"
}
```

---

## POST /api/agent/run/swarm — AI-Guided Vulnerability Swarm

Launches an AI-guided multi-phase vulnerability swarm. The master agent analyzes inputs, selects scanner modules, generates custom JS extensions, executes scans, and triages results. The swarm phases are:

1. **Normalize** — Parse and normalize inputs (native, no AI)
2. **Source Analysis** — AI agents extract routes, auth flows, and extensions from source code *(conditional, requires source path)*
3. **Code Audit** — AI security code audit *(conditional, requires `code_audit: true`)*
4. **SAST** — Static analysis route extraction and secret detection *(conditional, requires source path)*
5. **Discovery** — Content discovery and spidering *(conditional, requires discover flag)*
6. **Plan** — Master agent analyzes targets, selects modules, generates quick checks and extensions
7. **Extension** — Validate, merge, and write JS extensions to disk (native)
8. **Scan** — Execute scanner modules with agent-selected filters and extensions (native)
9. **Triage** — AI agent reviews findings, confirms or marks as false positive
10. **Rescan** — Targeted re-scanning based on triage follow-ups *(conditional, triggered by triage)*

AI agents are called at phases 2, 3, 6, and 9. When inputs exceed 5 records, the master agent runs in parallel batches (max 5 records per batch) with plan merging.

**Request body:**

*Prompt:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `prompt`               | string   | No       | Natural language scan prompt (parsed into structured fields when explicit fields are empty) |
| `intensity`            | string   | No       | Scan intensity preset: `"quick"`, `"balanced"` (default), or `"deep"`. Bundles `discover`, `triage`, `code_audit`, `max_iterations`, `archon`, concurrency, and duration settings |

*Inputs:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `input`                | string   | No*      | Single input (URL, curl command, raw HTTP, Burp XML, or record UUID)  |
| `inputs`               | string[] | No*      | Multiple inputs                                                       |
| `http_request_base64`  | string   | No*      | Base64-encoded raw HTTP request (ingested into DB, UUID used as input)|
| `http_response_base64` | string   | No       | Base64-encoded raw HTTP response (attached to the request above)      |
| `url`                  | string   | No       | URL hint for parsing the base64 request                               |

\* At least one of `input`, `inputs`, `http_request_base64`, `source`, `diff`, or `prompt` is required.

*Source analysis:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `source`               | string   | No       | Path to source code, git URL, or archive file for route discovery     |
| `files`                | string[] | No       | Specific source files to include (relative to `source`). Auto-populated from `diff` when not set |
| `diff`                 | string   | No       | Focus on changed code: PR URL, git ref range, or `HEAD~N`            |
| `last_commits`         | int      | No       | Focus on last N commits (shorthand for `diff: "HEAD~N"`)             |
| `source_analysis_only` | bool     | No       | Run only the source analysis phase and exit                           |
| `skip_sast`            | bool     | No       | Skip native SAST tools (ast-grep, osv-scanner) during source analysis       |

*Scanning parameters:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `vuln_type`            | string   | No       | Vulnerability type focus (e.g. `"sqli"`, `"xss"`)                     |
| `focus`                | string   | No       | Broad focus area hint (e.g. `"API injection"`, `"auth bypass"`)       |
| `instruction`          | string   | No       | Custom instruction appended to agent prompts                          |
| `module_names`         | string[] | No       | Explicit module IDs to use                                            |
| `only_phase`           | string   | No       | Isolate a single phase                                                |
| `skip_phases`          | string[] | No       | Skip specific phases                                                  |
| `start_from`           | string   | No       | Resume from a specific phase (e.g. `"plan"`, `"triage"`)              |
| `max_iterations`       | int      | No       | Max triage→rescan rounds (default `3`)                                |
| `discover`             | bool     | No       | Run discovery+spidering before master agent planning                  |
| `code_audit`           | bool     | No       | Enable AI security code audit phase (requires `source`)               |
| `triage`               | bool     | No       | Enable AI triage and rescan phases (disabled by default)              |
| `profile`              | string   | No       | Scanning profile name (e.g. `"light"`, `"thorough"`)                  |

*Agent selection:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `agent`                | string   | No       | Agent backend name (default from config)                              |

*Concurrency tuning:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `batch_concurrency`    | int      | No       | Max parallel master agent batches (0 = auto, scales with CPU)         |
| `max_master_retries`   | int      | No       | Max master agent retries on parse failure (default `3`)               |
| `sa_max_concurrency`   | int      | No       | Max parallel source analysis sub-agents (default `3`)                 |
| `max_plan_records`     | int      | No       | Max records sent to plan agent (0 = default `10`)                     |
| `master_batch_size`    | int      | No       | Max records per master agent batch (0 = default `5`)                  |
| `probe_concurrency`    | int      | No       | Max parallel probe requests (0 = default `10`)                        |
| `probe_timeout`        | string   | No       | Per-request probe timeout as Go duration (0 = default `10s`)          |
| `max_probe_body`       | int      | No       | Max response body size in bytes during probing (0 = default 2MB)      |

*Output control:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `dry_run`              | bool     | No       | Render prompts without executing agents                               |
| `show_prompt`          | bool     | No       | Include rendered prompts in output                                    |
| `stream`               | bool     | No       | If `true`, returns an SSE stream with phase events                    |
| `timeout`              | string   | No       | Go duration string (default `"15m"`)                                  |

*Project/scan scoping:*

| Field                  | Type     | Required | Description                                                           |
|------------------------|----------|----------|-----------------------------------------------------------------------|
| `project_uuid`         | string   | No       | Scope results to a project (falls back to `X-Project-UUID` header)    |
| `scan_uuid`            | string   | No       | Link results to a specific scan UUID                                  |
| `archon`               | string   | No       | Run background archon-audit: `"lite"` (3-phase), `"scan"` (6-phase), `"deep"` (11-phase), `"off"` to disable. Requires `source` |

**Source resolution:** The `source` field accepts local paths, git URLs (with optional OAuth token), and archive files (`.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`). The legacy `source_path` JSON key is still accepted for backward compatibility.

**Diff resolution:** When `diff` is set, the changed file list auto-populates `files` and focuses the source analysis phase on the changed code. GitHub PRs use the GitHub REST API directly. OAuth tokens embedded in the URL or the `GITHUB_TOKEN` env var are used for authentication.

**Intensity presets:**

```bash
# Quick scan — fast CI/CD pipeline check
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com/api/users?id=1",
    "intensity": "quick"
  }' | jq .

# Deep scan — full discovery, triage, browser, extended duration
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "intensity": "deep",
    "stream": true
  }'
```

**Basic examples:**

```bash
# Swarm a single URL
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com/api/search?q=test",
    "agent": "claude"
  }' | jq .

# Swarm a curl command (auto-detected)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "curl -X POST -H '\''Content-Type: application/json'\'' -d '\''{\"user\":\"admin\",\"pass\":\"secret\"}'\'' https://example.com/api/login"
  }' | jq .

# Swarm with multiple inputs (e.g. an auth flow)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [
      "https://example.com/api/users",
      "https://example.com/api/products?id=1",
      "https://example.com/api/login"
    ],
    "vuln_type": "sqli",
    "focus": "API injection",
    "max_iterations": 2
  }' | jq .

# Swarm a base64-encoded HTTP request (e.g. exported from Burp Suite)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "http_request_base64": "R0VUIC9hcGkvc2VhcmNoP3E9dGVzdCBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NCg0K",
    "http_response_base64": "SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0Key...",
    "url": "https://example.com"
  }' | jq .

# Swarm a record already stored in the database
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }' | jq .
```

**Diff-focused scanning:**

```bash
# Swarm focused on a GitHub PR diff (auto-fetches changed files via GitHub API)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "diff": "https://github.com/org/repo/pull/42"
  }' | jq .

# Swarm focused on last 5 commits
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "last_commits": 5
  }' | jq .

# Swarm with diff on a git ref range
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "diff": "main...feature-branch"
  }' | jq .

# Swarm with PR diff + private repo token (auto-clones, token used for GitHub API)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "http://localhost:3000",
    "diff": "https://oauth2:ghp_token@github.com/org/private-repo/pull/7",
    "archon": "lite"
  }' | jq .
```

**Source-aware scanning:**

```bash
# Source-aware swarm — discovers routes from source code, then scans
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "agent": "claude"
  }' | jq .

# Source-aware with specific files (faster, focused analysis)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "files": ["routes/api.js", "controllers/auth.js", "middleware/session.js"]
  }' | jq .

# Only run source analysis (no scanning) — useful for route extraction
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "source_analysis_only": true
  }' | jq .

# Source-aware with code audit + SAST + discovery — full pipeline
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "discover": true,
    "code_audit": true,
    "instruction": "Focus on business logic flaws in the payment flow",
    "profile": "thorough"
  }' | jq .

# Source-aware but skip SAST tools (only AI source analysis)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "skip_sast": true
  }' | jq .

# Source-aware with background archon-audit (parallel deep code audit)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "discover": true,
    "archon": "lite"
  }' | jq .

# Full 11-phase archon-audit with comprehensive scan
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "discover": true,
    "code_audit": true,
    "archon": "deep"
  }' | jq .
```

**Scanning control:**

```bash
# Use specific scanner modules only
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com/api/users?id=1",
    "module_names": ["sqli-error-based", "sqli-blind-time", "sqli-blind-boolean"]
  }' | jq .

# Skip specific phases (e.g. skip triage for raw scan results)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "skip_phases": ["triage", "native-rescan"]
  }' | jq .

# Resume from a specific phase (e.g. re-run triage after reviewing plan)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "start_from": "triage",
    "max_iterations": 1
  }' | jq .

# Run only the planning phase (isolate plan generation)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com/api/search?q=test",
    "only_phase": "plan"
  }' | jq .

# Run with discovery+spidering before the master agent plans
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "discover": true,
    "profile": "light"
  }' | jq .
```

**Advanced configuration:**

```bash
# Concurrency tuning for large input sets (>5 records trigger batching)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": [
      "https://example.com/api/users",
      "https://example.com/api/orders",
      "https://example.com/api/products",
      "https://example.com/api/payments",
      "https://example.com/api/auth",
      "https://example.com/api/settings",
      "https://example.com/api/files",
      "https://example.com/api/admin"
    ],
    "batch_concurrency": 4,
    "max_master_retries": 5,
    "max_iterations": 2
  }' | jq .

# Dry run — render all prompts without executing agents
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com/api/search?q=test",
    "dry_run": true,
    "show_prompt": true
  }' | jq .

# SSE streaming with project scoping
curl -N -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: proj-123" \
  -d '{
    "input": "https://example.com",
    "stream": true,
    "timeout": "30m",
    "project_uuid": "proj-123"
  }'
```

**Response (202):**

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "swarm run started"
}
```

---

## Natural Language Prompts

The autopilot and swarm endpoints accept a `prompt` field for natural language scan requests. When `prompt` is provided and no explicit input fields are set (`target`, `input`, `source`), the prompt is parsed by an AI intent extractor that returns structured parameters.

The intent extractor recognizes: target URLs, source code paths, vulnerability focus areas, custom instructions, discovery mode, code audit mode, and archon audit level (`"lite"`, `"scan"`, or `"deep"`).

**Extracted fields:**

| Intent Field   | Maps To (Autopilot) | Maps To (Swarm)  | Description                                           |
|----------------|----------------------|-------------------|-------------------------------------------------------|
| `target`       | `target`             | `input`           | Target URL                                            |
| `source_path`  | `source`             | `source`          | Filesystem path to source code                        |
| `focus`        | `focus`              | `focus`           | Vulnerability focus area                              |
| `instruction`  | `instruction`        | `instruction`     | Remaining guidance                                    |
| `discover`     | —                    | `discover`        | Inferred when both target and source are present      |
| `code_audit`   | —                    | `code_audit`      | Inferred when source-only (no target)                 |
| `archon`       | `archon_mode`        | `archon`          | `"lite"`, `"scan"`, or `"deep"` when archon/audit agent is mentioned |

**Autopilot with natural language prompt:**

```bash
# Prompt-based autopilot — intent parser extracts target, source, and audit agent
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "scan VAmPI source at ~/src/VAmPI on localhost:3005 with an audit agent"
  }' | jq .

# Dry run — preview extracted intent without launching a scan
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "scan VAmPI source at ~/src/VAmPI on localhost:3005 with full audit agent",
    "dry_run": true
  }' | jq .
```

**Swarm with natural language prompt:**

```bash
# Prompt-based swarm — extracts target, source, discover, and audit agent
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "scan source at ~/src/VAmPI on localhost:3005 with audit agent"
  }' | jq .

# Source-only prompt — triggers code audit mode
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "audit the source code at ~/src/my-app with full audit agent"
  }' | jq .

# Dry run — verify intent extraction
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "scan source at ~/src/VAmPI on localhost:3005 with audit agent",
    "dry_run": true
  }' | jq .
```

**Dry run response (intent preview):**

```json
{
  "intent": {
    "apps": [
      {
        "target": "http://localhost:3005",
        "source_path": "~/src/VAmPI",
        "discover": true,
        "archon": "lite"
      }
    ],
    "raw": "scan source at ~/src/VAmPI on localhost:3005 with audit agent"
  }
}
```

> **Note:** Explicit fields always take precedence. If you pass both `prompt` and `target`/`input`/`source`, the prompt is ignored and explicit fields are used directly. The `archon` field from intent extraction is only applied when `archon`/`archon_mode` is not already set in the request body.

---

## SSE Streaming

All run endpoints support `"stream": true`, which returns a `text/event-stream` (Server-Sent Events) response. Each event is a JSON object on a `data:` line.

**Event types:**

| Type    | Description                                                        | Modes              |
|---------|--------------------------------------------------------------------|---------------------|
| `chunk` | Incremental text output from the agent                             | All                 |
| `phase` | Phase transition (includes `phase` field)                          | Swarm only          |
| `done`  | Final event with the complete result object                        | All                 |
| `error` | Agent run failed; includes `error` message                         | All                 |

**Example SSE stream (query/autopilot):**

```
data: {"type":"chunk","text":"Analyzing authentication flow..."}

data: {"type":"chunk","text":" found potential issue in session handling."}

data: {"type":"done","result":{"agent_name":"claude","findings":[...],"saved_count":3}}

```

**Example SSE stream (swarm):**

```
data: {"type":"phase","phase":"native-normalize"}

data: {"type":"phase","phase":"plan"}

data: {"type":"chunk","text":"Analyzing targets for attack strategy..."}

data: {"type":"phase","phase":"native-extension"}

data: {"type":"phase","phase":"native-scan"}

data: {"type":"phase","phase":"triage"}

data: {"type":"chunk","text":"Reviewing findings..."}

data: {"type":"done","swarm_result":{"total_findings":5,"confirmed":3,"false_positives":2,"iterations":2,"severity_counts":{"high":2,"medium":3}}}

```

---

## GET /api/agent/status/list — List Agent Runs

Returns all agent runs with their current status.

```bash
curl -s http://localhost:9002/api/agent/status/list | jq .
```

```json
[
  {
    "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
    "mode": "query",
    "status": "completed",
    "agent_name": "claude",
    "template_id": "code-review",
    "finding_count": 3,
    "saved_count": 3,
    "completed_at": "2026-02-16T15:10:00Z"
  },
  {
    "run_id": "agt-661f9511-f3ac-52e5-b827-557766551111",
    "mode": "swarm",
    "status": "running",
    "current_phase": "native-scan",
    "phases_run": ["native-normalize", "plan", "native-extension"]
  }
]
```

---

## GET /api/agent/status/:id — Agent Run Status

Returns the status of a specific agent run. The response includes a `mode` field and mode-specific fields.

```bash
curl -s http://localhost:9002/api/agent/status/agt-550e8400-e29b-41d4-a716-446655440000 | jq .
```

**Response fields:**

| Field              | Type     | Description                                                |
|--------------------|----------|------------------------------------------------------------|
| `run_id`           | string   | Unique run identifier                                      |
| `mode`             | string   | Run mode: `"query"`, `"autopilot"`, or `"swarm"`           |
| `status`           | string   | `"running"`, `"completed"`, or `"failed"`                  |
| `agent_name`       | string   | Agent backend used                                         |
| `template_id`      | string   | Prompt template ID (query mode)                            |
| `finding_count`    | int      | Number of findings produced                                |
| `record_count`     | int      | Number of HTTP records produced (query/autopilot)          |
| `saved_count`      | int      | Number of records saved to DB (query/autopilot)            |
| `error`            | string   | Error message (failed runs only)                           |
| `completed_at`     | string   | ISO 8601 completion timestamp                              |
| `result`           | object   | Full agent result (query/autopilot, completed runs only)   |
| `current_phase`    | string   | Currently executing phase (swarm, running only)            |
| `phases_run`       | string[] | Completed phases (swarm only)                              |
| `swarm_result`     | object   | Full swarm result (swarm, completed runs only)             |

**Query/autopilot completed run:**

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "mode": "query",
  "status": "completed",
  "agent_name": "claude",
  "template_id": "code-review",
  "finding_count": 3,
  "record_count": 0,
  "saved_count": 3,
  "completed_at": "2026-02-16T15:10:00Z",
  "result": {
    "agent_name": "claude",
    "template_id": "code-review",
    "findings": [],
    "http_records": [],
    "saved_count": 3,
    "raw_output": "..."
  }
}
```

**Swarm completed run:**

```json
{
  "run_id": "agt-772a0622-g4bd-63f6-c938-668877662222",
  "mode": "swarm",
  "status": "completed",
  "finding_count": 5,
  "completed_at": "2026-02-16T16:30:00Z",
  "phases_run": ["native-normalize", "plan", "native-extension", "native-scan", "triage"],
  "swarm_result": {
    "swarm_plan": {
      "module_tags": ["xss", "sqli"],
      "focus_areas": ["authentication", "API endpoints"]
    },
    "triage_results": [
      {
        "confirmed": [{"title": "Reflected XSS in search", "url": "/search?q=..."}],
        "false_positives": [{"title": "Potential SQLi", "reason": "parameterized query"}],
        "verdict": "done"
      }
    ],
    "total_findings": 5,
    "confirmed": 3,
    "false_positives": 2,
    "iterations": 1,
    "severity_counts": {"high": 2, "medium": 3},
    "total_records": 3,
    "duration": "2m15s"
  }
}
```

**Failed run:**

```json
{
  "run_id": "agt-661f9511-f3ac-52e5-b827-557766551111",
  "mode": "autopilot",
  "status": "failed",
  "error": "agent process exited with code 1",
  "completed_at": "2026-02-16T15:08:00Z"
}
```

---

## GET /api/agent/sessions — List Agent Sessions

Returns a paginated list of agent sessions from the database. Unlike `/api/agent/status/list` (which includes in-memory running state), this endpoint returns persisted historical sessions with structured metadata — but without the large debug fields (`prompt_sent`, `agent_raw_output`, etc.) to keep responses lightweight.

**Query parameters:**

| Parameter | Type   | Default | Description                                      |
|-----------|--------|---------|--------------------------------------------------|
| `mode`    | string | —       | Filter by mode: `query`, `autopilot`, `swarm`    |
| `limit`   | int    | `50`    | Page size (max `500`)                            |
| `offset`  | int    | `0`     | Offset for pagination                            |

**Headers:**

| Header           | Description                                |
|------------------|--------------------------------------------|
| `X-Project-UUID` | Scope to a specific project (optional)     |

```bash
# List all sessions
curl -s http://localhost:9002/api/agent/sessions | jq .

# Filter by mode with pagination
curl -s "http://localhost:9002/api/agent/sessions?mode=swarm&limit=10&offset=0" | jq .
```

**Response (200):**

```json
{
  "project_uuid": "default",
  "data": [
    {
      "uuid": "agt-550e8400-e29b-41d4-a716-446655440000",
      "mode": "swarm",
      "status": "completed",
      "agent_name": "claude",
      "template_id": "",
      "target_url": "https://example.com",
      "input_type": "url",
      "current_phase": "triage",
      "phases_run": ["native-normalize", "plan", "native-extension", "native-scan", "triage"],
      "finding_count": 5,
      "record_count": 3,
      "saved_count": 3,
      "duration_ms": 135000,
      "started_at": "2026-02-16T15:00:00Z",
      "completed_at": "2026-02-16T15:02:15Z",
      "created_at": "2026-02-16T15:00:00Z"
    },
    {
      "uuid": "agt-661f9511-f3ac-52e5-b827-557766551111",
      "mode": "query",
      "status": "completed",
      "agent_name": "claude",
      "template_id": "code-review",
      "finding_count": 3,
      "saved_count": 3,
      "duration_ms": 18500,
      "started_at": "2026-02-16T14:50:00Z",
      "completed_at": "2026-02-16T14:50:18Z",
      "created_at": "2026-02-16T14:50:00Z"
    }
  ],
  "total": 24,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

## GET /api/agent/sessions/:id — Agent Session Detail

Returns the full detail of a single agent session, including the large debug fields omitted from the list endpoint: `prompt_sent`, `agent_raw_output`, `attack_plan`, `triage_result`, and `result_json`.

```bash
curl -s http://localhost:9002/api/agent/sessions/agt-550e8400-e29b-41d4-a716-446655440000 | jq .
```

**Response fields (in addition to all list fields):**

| Field              | Type     | Description                                            |
|--------------------|----------|--------------------------------------------------------|
| `input_raw`        | string   | Raw input provided to the agent run                    |
| `module_names`     | string[] | Scanner modules used or selected                       |
| `session_id`       | string   | Session ID (for autopilot resume)                      |
| `prompt_sent`      | string   | Full prompt text sent to the agent                     |
| `agent_raw_output` | string   | Complete raw output from the agent                     |
| `attack_plan`      | string   | JSON attack plan (swarm mode)                          |
| `triage_result`    | string   | JSON triage result (swarm mode)                        |
| `result_json`      | string   | Full result object as JSON                             |

**Response (200):**

```json
{
  "uuid": "agt-550e8400-e29b-41d4-a716-446655440000",
  "mode": "swarm",
  "status": "completed",
  "agent_name": "claude",
  "target_url": "https://example.com",
  "input_type": "url",
  "current_phase": "triage",
  "phases_run": ["native-normalize", "plan", "native-extension", "native-scan", "triage"],
  "finding_count": 5,
  "record_count": 3,
  "saved_count": 3,
  "duration_ms": 135000,
  "started_at": "2026-02-16T15:00:00Z",
  "completed_at": "2026-02-16T15:02:15Z",
  "created_at": "2026-02-16T15:00:00Z",
  "input_raw": "https://example.com/api/search?q=test",
  "module_names": ["xss-reflected", "sqli-error"],
  "session_id": "",
  "prompt_sent": "You are a security scanning agent...",
  "agent_raw_output": "I'll analyze the target for vulnerabilities...",
  "attack_plan": "{\"module_tags\":[\"xss\",\"sqli\"],\"focus_areas\":[\"auth\"]}",
  "triage_result": "{\"confirmed\":3,\"false_positives\":2}",
  "result_json": "{...}"
}
```

**Error responses:**

| Status | Condition                |
|--------|--------------------------|
| `400`  | Missing session ID       |
| `404`  | Session not found        |
| `503`  | Database not configured  |

---

## GET /api/agent/sessions/:id/logs — Agent Session Console Logs

Returns the raw `run.log` file for a session — the same live console stream the CLI user sees when running `vigolium agent autopilot/swarm/query`. ANSI colors are preserved by default so browser terminal emulators (xterm.js, etc.) render it exactly like the CLI. Works while the run is in progress *and* after it finishes.

The endpoint operates in two modes, selected via the `Accept` header:

- **Plain text** (default, any Accept except `text/event-stream`): `text/plain; charset=utf-8` dump of the entire `run.log` at request time.
- **Server-Sent Events** (`Accept: text/event-stream`): tails the file and emits each new byte range as a `chunk` event. Exits with a `done` event when the run reaches a terminal status (`completed`, `failed`, `cancelled`, `timeout`, `error`), the client disconnects, or a 2-hour safety backstop fires.

**Query parameters:**

| Name    | Type    | Description                                                                 |
|---------|---------|-----------------------------------------------------------------------------|
| `strip` | bool    | If truthy (`1`, `true`, `yes`, `y`, `on`), strip ANSI escape sequences server-side. Default: false (preserve ANSI). |

**Examples:**

```bash
# Plain text dump (ANSI preserved — pipe into less -R or an xterm widget)
curl -s http://localhost:9002/api/agent/sessions/agt-550e8400-.../logs

# Plain text, ANSI stripped for a clean terminal / log tool
curl -s 'http://localhost:9002/api/agent/sessions/agt-550e8400-.../logs?strip=1'

# Live tail via SSE
curl -N -H 'Accept: text/event-stream' \
  http://localhost:9002/api/agent/sessions/agt-550e8400-.../logs

# Live tail with stripped chunks
curl -N -H 'Accept: text/event-stream' \
  'http://localhost:9002/api/agent/sessions/agt-550e8400-.../logs?strip=1'
```

**SSE event shape** (reuses the streaming-run `sseEvent` type):

```json
{"type":"chunk","text":"◆ Phase [source-analysis] - analyze source code...\n"}
{"type":"chunk","text":"❯ source-analysis │ routes discovered count=42\n"}
{"type":"done"}
```

On a read error the stream emits `{"type":"error","error":"..."}` and closes.

**Notes:**

- The endpoint reads `run.log` from the session directory recorded on the DB row (`session_dir`). For rows created before that field was persisted, it falls back to `<sessions_dir>/<run_id>/run.log`.
- All three agent modes (query, autopilot, swarm) write `run.log` when started via the REST API, so the endpoint works uniformly across modes.
- Structured data (findings, attack plan, triage result, final raw output blob) still lives on `GET /api/agent/sessions/:id` — this endpoint is the *unstructured* console stream only.
- When ANSI stripping is enabled on the SSE path, an escape sequence that happens to span a read boundary may leak through as a cosmetic artifact. The plain-text path is not affected.

**Error responses:**

| Status | Condition                                  |
|--------|--------------------------------------------|
| `400`  | Missing session ID                         |
| `404`  | Session not found, or `run.log` missing    |
| `500`  | Failed to read `run.log` from disk         |
| `503`  | Database not configured                    |

---

## POST /api/agent/chat/completions — OpenAI-Compatible Chat Completions

Accepts an OpenAI-compatible Chat Completions request and returns an OpenAI-compatible response. This allows any OpenAI-compatible client or tool to use Vigolium agents by changing the base URL.

The `model` field maps to agent names in config. If `model` matches a configured agent name (e.g. `"claude"`, `"opencode"`, `"codex"`), that agent is used. Unrecognized model names fall back to the default agent.

This endpoint is **synchronous** — it blocks until the agent completes. It shares the concurrency lock with the run endpoints (returns `409 Conflict` if an agent is already running).

**Request body:**

| Field      | Type   | Required | Description                                      |
|------------|--------|----------|--------------------------------------------------|
| `model`    | string | Yes      | Agent name or any string (falls back to default) |
| `messages` | array  | Yes      | Array of `{role, content}` message objects       |

```bash
curl -s -X POST http://localhost:9002/api/agent/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "model": "claude",
    "messages": [
      { "role": "user", "content": "What are common JWT vulnerabilities?" }
    ]
  }' | jq .
```

**Response (200):**

```json
{
  "id": "chatcmpl-550e8400-e29b-41d4-a716-446655440000",
  "object": "chat.completion",
  "created": 1708531200,
  "model": "claude",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Common JWT vulnerabilities include..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 150,
    "completion_tokens": 200,
    "total_tokens": 350
  }
}
```

**Using with OpenAI-compatible clients:**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:9002/api/agent",
    api_key="<api-key>",
)
response = client.chat.completions.create(
    model="claude",
    messages=[{"role": "user", "content": "Explain CSRF attacks"}],
)
print(response.choices[0].message.content)
```

See [Agent Mode](../agents/agent-mode.md) for full agent documentation.
