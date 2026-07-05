# Agent Commands Reference

Complete flag reference for `agent`, `agent query`, `agent autopilot`, `agent swarm`, `agent olium`, `agent audit`, and `agent session` commands. (The former `agent archon` command has been folded into `agent audit` — drive the vigolium-audit harness with `vigolium agent audit --driver=audit`.)

All agent dispatch is routed through the in-process **olium** engine — there are no subprocess SDK backends. Provider selection happens via `agent.olium.provider` in `vigolium-configs.yaml` or per-run flags (`--provider`, `--model`, `--oauth-cred`, `--oauth-token`, `--llm-api-key`, `--gcp-project`, `--gcp-location`).

## Table of Contents

- [agent](#agent)
- [agent query](#agent-query)
- [agent autopilot](#agent-autopilot)
- [agent swarm](#agent-swarm)
- [agent olium](#agent-olium)
- [agent audit](#agent-audit)
- [agent session](#agent-session)
- [Intensity Presets](#intensity-presets)
- [Prompt Templates](#prompt-templates)
- [Agent Configuration](#agent-configuration)
- [Output Schemas](#output-schemas)

---

## agent

**Usage:** `vigolium agent [flags]`

Run an agentic scan using the in-process olium engine for intelligent vulnerability scanning with native scan support.

The parent command only supports `--list-templates` and `--list-agents` flags — all execution requires a subcommand.

### Available Subcommands

| Subcommand | Description |
|------------|-------------|
| `query` | Single-shot prompt execution (template-based or inline) |
| `autopilot` | Agentic scan: autonomous AI-driven vulnerability scanning |
| `swarm` | AI-guided vulnerability scanning (targeted or full-scope with `--discover`) |
| `olium` | Interactive olium TUI / one-shot prompt (also exposed as top-level `vigolium olium` / `ol`) |
| `piolium` | Foreground audit driven by the user's installed piolium Pi extension |
| `audit` | Unified driver dispatcher — drives the embedded vigolium-audit harness and/or piolium under a single AgenticScan (`--driver=auto\|both\|audit\|piolium`) |
| `session` | List or inspect agent run sessions |

### agent flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list-templates` | — | bool | `false` | List available prompt templates |
| `--list-agents` | — | bool | `false` | List the olium providers available for agent runs |

### Examples

```bash
# List available templates
vigolium agent --list-templates

# List configured backends
vigolium agent --list-agents
```

---

## agent query

**Usage:** `vigolium agent query [prompt] [flags]`

Send a freeform prompt to an AI agent without templates or structured output. Prompt can be passed as positional argument, via `--prompt/-p`, or piped through `--stdin`.

### agent query flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent-label` | — | string | — | Label recorded on the AgenticScan DB row (agent dispatch always uses olium). The deprecated `--agent` alias maps to this. |
| `--max-duration` | — | duration | `5m` | Maximum time for agent execution (0 = no limit). Deprecated alias: `--agent-timeout` |
| `--append` | — | string | — | Append extra text to the rendered prompt |
| `--dry-run` | — | bool | `false` | Print the rendered prompt without executing |
| `--files` | — | []string | — | Specific files to include (relative to `--source`) |
| `--instruction` | — | string | — | Custom instruction to guide the agent (appended to prompt) |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--output` | — | string | — | Write agent output to this file |
| `--prompt` | `-p` | string | — | Prompt text to send to the agent |
| `--prompt-file` | — | string | — | Path to a prompt template file |
| `--prompt-template` | — | string | — | Prompt template ID (e.g. `security-code-review`) |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--source` | — | string | — | Path to source code repository |
| `--source-label` | — | string | — | Label for records ingested from agent output (e.g. `agent-review`) |
| `--stdin` | — | bool | `false` | Read prompt from stdin |
| `--upload-results` | — | bool | `false` | Upload session bundle to cloud storage after completion (requires storage config) |
| `--provider` | — | string | — | Olium provider override: `openai-compatible` \| `openai-codex-oauth` \| `anthropic-api-key` \| `anthropic-oauth` \| `openai-api-key` \| `anthropic-cli` \| `anthropic-vertex` \| `google-vertex` (falls back to `agent.olium.provider`) |
| `--model` | — | string | — | Olium model id override (falls back to `agent.olium.model`) |
| `--oauth-cred` | — | string | — | Olium OAuth/SA credential file (openai-codex-oauth or google-vertex; falls back to `agent.olium.oauth_cred_path` or `$GOOGLE_APPLICATION_CREDENTIALS`) |
| `--oauth-token` | — | string | — | Claude Code OAuth bearer token (`anthropic-oauth`; falls back to `agent.olium.oauth_token` or `$ANTHROPIC_API_KEY`) |
| `--llm-api-key` | — | string | — | API key for key-based providers (falls back to `agent.olium.llm_api_key` or provider env var) |
| `--gcp-project` | — | string | — | GCP project for `google-vertex` (else `$GOOGLE_CLOUD_PROJECT`, then YAML, then SA file's project_id) |
| `--gcp-location` | — | string | — | GCP region for `google-vertex` (else `$GOOGLE_CLOUD_LOCATION`, then YAML, then `us-central1`) |

### Examples

```bash
# Positional argument prompt
vigolium agent query 'review this code for vulnerabilities'

# Named prompt flag
vigolium agent query --prompt 'analyze the authentication flow'

# Pipe prompt from stdin
echo "check for SQL injection in the login handler" | vigolium agent query --stdin

# With specific agent
vigolium agent query --agent claude 'find XSS vulnerabilities'

# With source code context
vigolium agent query 'explain the auth flow' --source ./src

# With timeout
vigolium agent query --max-duration 10m 'comprehensive security review'

# Security code review with template
vigolium agent query --prompt-template security-code-review --source ./src

# Endpoint discovery
vigolium agent query --prompt-template endpoint-discovery --source ./src

# Custom prompt file
vigolium agent query --prompt-file custom-prompt.md --source ./src

# Append instructions to prompt
vigolium agent query --prompt-template security-code-review --source ./src \
  --append "Focus on authentication and authorization issues"

# Specific files only
vigolium agent query --prompt-template security-code-review --source ./src \
  --files "src/auth.go,src/middleware.go"

# Dry run (preview prompt)
vigolium agent query --prompt-template security-code-review --source ./src --dry-run

# Save output
vigolium agent query --prompt-template security-code-review --source ./src \
  --output review-results.json
```

---

## agent autopilot

**Usage:** `vigolium agent autopilot [prompt] [flags]`

Launch an AI agent that autonomously discovers, scans, and triages vulnerabilities by driving the vigolium CLI. The operator runs through the in-process olium engine with full coding-agent tools (Read, Grep, Glob, Bash, Edit, Write).

Autopilot runs a **single autonomous operator session**. When `--source` is set, an audit harness runs first, the whitebox context is prepared natively, and then one operator agent handles recon, validation, scanning, exploit attempts, and reporting.

**Audit-harness auto-pick:** when neither `--audit` nor `--piolium` is explicitly set, autopilot picks **piolium** if `pi` + the piolium Pi extension are installed, otherwise falls back to the embedded **vigolium-audit** at lite. Force piolium with `--piolium <mode>` (auto-disables vigolium-audit for the run); force vigolium-audit with `--audit <mode>`; disable both with `--audit=off`.

### Positional prompt

A positional natural-language prompt is parsed by the AI to extract target URLs, source paths, and focus areas — an alternative to setting `--target`/`--source` explicitly.

```bash
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
vigolium agent autopilot "test auth bypass on https://app.example.com"
```

Use `--dry-run` to preview what the parser extracts without executing.

### Supported `--input` types (auto-detected)

| Type | Example |
|------|---------|
| URL | `https://example.com/api/login` |
| Curl | `curl -X POST https://example.com/api -d '{"user":"admin"}'` |
| Raw HTTP | `POST /api HTTP/1.1\r\nHost: example.com\r\n...` |
| Burp XML | `<?xml...><items>...</items>` |
| Base64 | Base64-encoded raw HTTP (Burp base64 export) |

When input is piped via stdin, it is automatically read (no `--input` needed). The target URL is extracted from the input when `--target` is not provided.

### agent autopilot flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (derived from `--input` if not set) |
| `--input` | — | string | — | Raw input (curl command, raw HTTP, Burp XML, URL, base64). Reads from stdin if piped |
| `--record-uuid` | — | string | — | Use an HTTP record from the database as the seed input (looked up by UUID) |
| `--source` | — | string | — | Path to application source code for source-aware scanning |
| `--files` | — | []string | — | Specific files to include (relative to `--source`) |
| `--focus` | — | string | — | Focus area hint (e.g. `API injection`, `auth bypass`) |
| `--focus-routes` | — | []string | — | Protected or browser-focused routes to prioritize after auth |
| `--audit` | — | string | `lite` | vigolium-audit mode run before the operator: `lite` (3-phase), `balanced` (9-phase), `deep` (12-phase), `mock`, or `off` to disable. Default `lite` when `--source` is set |
| `--piolium` | — | string | — | Piolium audit mode: `lite`, `balanced`, `deep`, `longshot`, etc. Empty triggers auto-pick (piolium when `pi` is installed, else vigolium-audit). Setting `--piolium` explicitly forces piolium and turns `--audit` off |
| `--diff` | — | string | — | Focus on changed code: PR URL, git ref range (`main...branch`), or `HEAD~N` |
| `--last-commits` | — | int | `0` | Focus on last N commits (shorthand for `--diff HEAD~N`) |
| `--max-duration` | — | duration | `6h` | Maximum wall-clock duration for the autopilot session |
| `--intensity` | — | string | `balanced` | Scan intensity preset: `quick`, `balanced`, or `deep` — sets the operator command budget, audit mode, browser, and pre-scan strategy (see [Intensity Presets](#intensity-presets)) |
| `--triage` | — | bool | `false` | After the scan completes, run an AI triage pass over the findings (confirm real issues vs false positives, written back to finding status) |
| `--no-prescan` | — | bool | `false` | Skip the native pre-scan that seeds http_records before the operator agent (target-only runs; no-op when `--source` is set) |
| `--no-preflight-discovery` | — | bool | `false` | Skip the pre-flight discovery + OpenAPI/Swagger ingestion pass that seeds http_records |
| `--no-post-halt-verify` | — | bool | `false` | Skip the post-halt coverage verification re-entry (operator halts → coverage probe → re-prompt when new routes turn up) |
| `--post-halt-gap-threshold` | — | int | `0` | Min new (method, URL) routes the post-halt probe must turn up before the agent is re-entered (0 = built-in default, 5) |
| `--plan-file` | — | string | — | Path to a plan file mixing free-text guidance and raw HTTP request(s); owns the instruction + seed input (mutually exclusive with `--input`/`--instruction`/`--instruction-file`) |
| `--instruction` | — | string | — | Custom instruction to guide the agent (appended to prompt) |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--browser` | — | bool | `false` | Enable agent-browser for browser-based interactions |
| `--headed` | — | bool | `false` | Show the browser window during in-process probes (requires `--browser`; sets `VIGOLIUM_BROWSER_HEADED=1` for the run) |
| `--credentials` | — | string | — | Credentials for auth preflight (e.g. `admin/admin123, compare user/user123`) |
| `--auth-required` | — | bool | `false` | Require auth/session preparation before the autonomous operator starts |
| `--requires-browser` | — | bool | `false` | Require browser-assisted auth/setup instead of HTTP-only preflight |
| `--browser-start-url` | — | string | — | Explicit browser/login start URL for auth preflight |
| `--dry-run` | — | bool | `false` | Render the system prompt without launching the agent |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--disable-guardrail` | — | bool | `false` | Skip the prompt-safety classifier on the natural-language prompt (use only when refusing a known-good prompt) |
| `--provider` | — | string | — | Olium provider override: `openai-compatible` \| `openai-codex-oauth` \| `anthropic-api-key` \| `anthropic-oauth` \| `openai-api-key` \| `anthropic-cli` \| `anthropic-vertex` \| `google-vertex` |
| `--model` | — | string | — | Olium model id override (falls back to `agent.olium.model`) |
| `--system-prompt` | — | string | — | Replace the built-in autopilot system prompt with this value (full replace; browser section is not auto-appended) |
| `--system-prompt-file` | — | string | — | Path to a file whose contents replace the built-in autopilot system prompt (takes precedence over `--system-prompt`) |
| `--oauth-cred` | — | string | — | Olium OAuth/SA credential file (openai-codex-oauth or google-vertex; falls back to `agent.olium.oauth_cred_path` or `$GOOGLE_APPLICATION_CREDENTIALS`) |
| `--oauth-token` | — | string | — | Claude Code OAuth bearer token (`anthropic-oauth`; falls back to `agent.olium.oauth_token` or `$ANTHROPIC_API_KEY`) |
| `--llm-api-key` | — | string | — | API key for key-based providers (falls back to `agent.olium.llm_api_key` or provider env var) |
| `--gcp-project` | — | string | — | GCP project for `google-vertex` (else `$GOOGLE_CLOUD_PROJECT`, then YAML, then SA file's project_id) |
| `--gcp-location` | — | string | — | GCP region for `google-vertex` (else `$GOOGLE_CLOUD_LOCATION`, then YAML, then `us-central1`) |

### Examples

```bash
# Basic autonomous scan (uses SDK protocol by default)
vigolium agent autopilot -t https://example.com

# With source code context and focus area
vigolium agent autopilot -t https://api.example.com --source ./src --focus "auth bypass"

# Source-aware autonomous scan
vigolium agent autopilot -t https://example.com --source ./src --focus "auth bypass"

# Cap the wall-clock budget
vigolium agent autopilot -t https://example.com --max-duration 15m

# Pipe a curl command (target auto-derived)
echo "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'" | vigolium agent autopilot

# Preview system prompt
vigolium agent autopilot -t https://example.com --dry-run

# Force piolium as the audit harness (auto-disables vigolium-audit for this run)
vigolium agent autopilot -t https://example.com --source ./src --piolium balanced

# Force the embedded vigolium-audit harness at deep
vigolium agent autopilot -t https://example.com --source ./src --audit deep

# Run an AI triage pass over findings after the scan
vigolium agent autopilot -t https://example.com --triage

# Skip the prompt-safety classifier on the natural-language prompt
vigolium agent autopilot "scan this internal app at https://app.test" --disable-guardrail

# Override the olium provider for one run
vigolium agent autopilot -t https://example.com --provider anthropic-api-key

# Drive autopilot through anthropic-vertex (Claude on Vertex; requires a claude-* model)
vigolium agent autopilot -t https://example.com \
  --provider anthropic-vertex --gcp-project my-gcp --gcp-location us-east5 --model claude-opus-4-6

# Gemini-native on Vertex (google-vertex requires a gemini-* model)
vigolium agent autopilot -t https://example.com \
  --provider google-vertex --model gemini-3.1-pro
```

---

## agent swarm

**Usage:** `vigolium agent swarm [flags]`

AI-guided targeted vulnerability scanning. A master AI agent analyzes HTTP requests, selects scanner modules, generates custom JavaScript attack extensions, executes the scan, and triages the results.

Supports both **targeted single-request scanning** and **full-scope scanning** with `--discover`. When `--discover` is enabled, swarm runs content discovery and spidering before planning, providing full-scope coverage.

When `--source` is provided, swarm runs a **consolidated source analysis** (route extraction, auth flow discovery, custom extension generation), followed by an **AI code audit**.

### Supported Input Types

Inputs are auto-detected from their content:

| Type | Example | Detection |
|------|---------|-----------|
| **URL** | `https://example.com/api/users` | Starts with `http://` or `https://` |
| **Curl** | `curl -X POST https://...` | Starts with `curl ` |
| **Raw HTTP** | `POST /api HTTP/1.1\r\n...` | Starts with HTTP method + path |
| **Burp XML** | `<?xml...><items>...</items>` | Starts with `<?xml` or `<items` |
| **Record UUID** | `550e8400-e29b-...` | Matches UUID format (8-4-4-4-12 hex) |

### Positional prompt

Like autopilot, swarm accepts a positional natural-language prompt that the AI parses to extract target URLs, source paths, and focus areas.

```bash
vigolium agent swarm "scan VAmPI source at ~/src/VAmPI on localhost:3005"
vigolium agent swarm "scan all source code from ~/src/crAPI, ~/src/DVWA"
```

### agent swarm flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (required when `--source` is used) |
| `--input` | — | string | — | Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped |
| `--record-uuid` | — | []string | — | HTTP record UUID from database (repeatable, or comma-separated) |
| `--all-records` | — | bool | `false` | Use every HTTP record in the active project as input |
| `--records-from` | — | string | — | Filter ingested HTTP records by spec (e.g. `host=example.com,status=200,method=GET,path=/api,since=2026-04-01`) |
| `--source` | — | string | — | Path to application source code for route discovery |
| `--files` | — | []string | — | Specific source files to include (relative to `--source`) |
| `--vuln-type` | — | string | — | Vulnerability type focus (e.g. sqli, xss, ssrf) |
| `--focus` | — | string | — | Focus area hint for the agent (e.g. `API injection`, `auth bypass`) |
| `--modules` | `-m` | []string | — | Explicit module names to include |
| `--max-iterations` | — | int | `3` | Maximum triage-rescan iterations (alias `--max-rescan-rounds`) |
| `--agent-label` | — | string | — | Label recorded on the AgenticScan DB row (deprecated alias `--agent`) |
| `--dry-run` | — | bool | `false` | Render prompts without executing |
| `--show-prompt` | — | bool | `false` | Print rendered prompts to stderr before executing |
| `--source-analysis-only` | — | bool | `false` | Run only the source analysis phase and exit |
| `--max-duration` | — | duration | `12h` | Maximum swarm duration (0 = unlimited; deprecated alias `--swarm-duration`) |
| `--profile` | — | string | — | Scanning profile to use |
| `--only` | — | string | — | Run only this scanning phase (discovery, spidering, spa, dynamic-assessment, external-harvest) |
| `--skip` | — | []string | — | Skip specific phases (discovery, spidering, spa, dynamic-assessment, external-harvest, triage, rescan) |
| `--start-from` | — | string | — | Resume from a specific phase (native-normalize, source-analysis, code-audit, native-discover, native-recon, plan, native-extension, native-scan, triage) |
| `--instruction` | — | string | — | Custom instruction to guide the agent (appended to prompts) |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--discover` | — | bool | `false` | Run discovery+spidering before master agent planning to expand attack surface |
| `--code-audit` | — | bool | auto | Enable AI security code audit phase (on by default when `--source` is provided; `--code-audit=false` to disable) |
| `--triage` | — | bool | `false` | Enable AI triage and rescan phases (disabled by default) |
| `--with-extensions` | — | bool | `false` | Force the extension agent to run even when the planner decides built-in modules are sufficient |
| `--batch-concurrency` | — | int | `0` | Max parallel master agent batches (0 = auto, scales with CPU count) |
| `--max-master-retries` | — | int | `3` | Max master agent retries on parse failure |
| `--sub-agent-concurrency` | — | int | `3` | Max parallel source analysis sub-agents (routes, auth, extensions) |
| `--max-plan-records` | — | int | `10` | Max records sent to plan agent (selects most interesting; 0 = no limit) |
| `--master-batch-size` | — | int | `0` | Max records per master agent batch (0 = default 5) |
| `--probe-concurrency` | — | int | `0` | Max parallel probe requests (0 = default 10) |
| `--probe-timeout` | — | duration | `0` | Per-request probe timeout (0 = default 10s) |
| `--max-probe-body` | — | int | `0` | Max response body size in bytes during probing (0 = default 2MB) |
| `--browser` | — | bool | `false` | Enable agent-browser for browser-based auth capture and interaction |
| `--browser-auth` | — | bool | `false` | Run browser-based auth phase before discovery (requires `--browser`) |
| `--credentials` | — | string | — | Credentials for browser auth phase (e.g. `username=admin,password=secret`) |
| `--audit` | — | string | — | Run background vigolium-audit in parallel: `lite` (default if flag is bare), `balanced`, `deep`. Requires `--source` |
| `--piolium` | — | string | — | Run background piolium audit (Pi runtime): `lite`, `balanced`, `deep`, `longshot`, etc. Requires `--source`. Empty triggers auto-pick when `--audit` is also empty (piolium when `pi` is installed, else nothing) |
| `--diff` | — | string | — | Focus on changed code: PR URL, git ref range (`main...branch`), or `HEAD~N` |
| `--last-commits` | — | int | `0` | Focus on last N commits (shorthand for `--diff HEAD~N`) |
| `--intensity` | — | string | `balanced` | Scan intensity preset: `quick`, `balanced`, or `deep` (see [Intensity Presets](#intensity-presets)) |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--disable-guardrail` | — | bool | `false` | Skip the prompt-safety classifier on the natural-language prompt (use only when refusing a known-good prompt) |

At least one input is required: `--target`, `--input`, `--record-uuid`, `--all-records`, `--records-from`, `--source`, or piped stdin. `--source` requires `--target` for hostname filtering. `--browser-auth` requires `--browser`. `--audit` and `--piolium` both require `--source`. The same olium provider override flags from `agent query` (`--provider`, `--model`, `--oauth-cred`, `--oauth-token`, `--llm-api-key`, `--gcp-project`, `--gcp-location`, `--system`) are also accepted on swarm.

### Swarm Phases

```
Phase 1:    native-normalize    (Go)       — Parse input(s) into HttpRequestResponse objects, save to DB
Phase 2:    source-analysis     (AI)       — Extract routes, auth config, JS extensions from source (conditional: --source)
Phase 3:    code-audit          (AI)       — Deep AI security code audit for business logic flaws (conditional: --source, on by default)
Phase 4:    native-discover     (Go)       — Content discovery + spidering (conditional: --discover)
Phase 5:    plan                (AI)       — Master agent analyzes requests, selects modules, generates extensions
Phase 6:    native-extension    (Go)       — Write generated JS extensions to temp directory
Phase 7:    native-scan         (Go)       — Dynamic assessment with selected modules + extensions
Phase 8:    triage              (AI)       — Agent reviews extension-generated findings (conditional: --triage)
Phase 9:    rescan              (Go, loop) — Targeted rescan from triage follow-ups (conditional: --triage)
```

Phases 2-3 are automatically skipped when `--source` is not provided. Phase 4 is skipped unless `--discover` is passed. Phases 8-9 are skipped unless `--triage` is enabled.

### Swarm Output Schemas

**SwarmPlan** (plan phase output):

The master agent produces a plan with three tiers of custom checks (lightest first):

```json
{
  "module_tags": ["sqli", "injection"],
  "module_ids": ["sqli-error-based"],
  "quick_checks": [
    {
      "id": "ssti-jinja2",
      "severity": "high",
      "scan": "per_insertion_point",
      "payloads": ["{{7*7}}", "${7*7}"],
      "match": {"body_contains": "49"}
    }
  ],
  "snippets": [
    {
      "id": "idor-check",
      "severity": "high",
      "scan": "per_request",
      "body": "var related = vigolium.db.records.getRelated(ctx.record.uuid);\nvar cmp = vigolium.db.compareResponses(related);\nif (!cmp.all_similar) return [{url: ctx.request.url, matched: 'Response variance', name: 'Potential IDOR'}];\nreturn null;"
    }
  ],
  "extensions": [
    {
      "filename": "custom-json-sqli.js",
      "code": "module.exports = { id: 'custom-json-sqli', ... };",
      "reason": "JSON body with user_id parameter susceptible to SQL injection"
    }
  ],
  "focus_areas": ["SQL injection in JSON body parameters"],
  "notes": "Target uses JSON API with direct DB queries"
}
```

**Custom check tiers** (prefer the lightest format that works):

| Tier | Format | When to use |
|------|--------|-------------|
| `quick_checks` | Declarative JSON (payloads + match) | Simple "send payload, check response" patterns — zero JS |
| `snippets` | JS function body only | Need `vigolium.*` API access but no boilerplate |
| `extensions` | Full JS module | Complex multi-step logic, multiple helpers, state management |

**SwarmResult** (final output):

```json
{
  "swarm_plan": { "..." },
  "triage_results": [ "..." ],
  "total_findings": 5,
  "total_records": 3,
  "severity_counts": {"critical": 1, "high": 2, "medium": 2, "low": 0},
  "confirmed": 3,
  "false_positives": 2,
  "iterations": 2,
  "duration": "3m45s",
  "agentic_scan_uuid": "...",
  "session_id": "...",
  "session_dir": "~/.vigolium/agent-sessions/<uuid>"
}
```

### Examples

```bash
# Target a URL
vigolium agent swarm -t https://example.com/api/users

# Full-scope scan with discovery
vigolium agent swarm -t https://example.com --discover

# Analyze a curl command
vigolium agent swarm --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"

# Pipe raw HTTP request from stdin
echo -e "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test" | vigolium agent swarm --input -

# Scan a record from the database
vigolium agent swarm --record-uuid 550e8400-e29b-41d4-a716-446655440000

# Focus on a specific vulnerability type
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Source-aware swarm (route extraction + code audit + SAST + scanning)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app

# Source-aware with specific files
vigolium agent swarm -t http://localhost:8080 --source ./backend \
  --files src/routes/api.js,src/models/user.js

# Full-scope source-aware scan (discovery + source analysis + SAST + scanning)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/express-app --discover

# Source analysis only (extract routes, no scan)
vigolium agent swarm -t http://localhost:3000 --source ./src --source-analysis-only

# Skip SAST tools during source analysis
vigolium agent swarm -t http://localhost:3000 --source ./src --skip-sast

# Disable code audit (still runs source analysis + SAST)
vigolium agent swarm -t http://localhost:3000 --source ./src --code-audit=false

# Enable triage and rescan loop
vigolium agent swarm -t https://example.com/api/users --triage --max-iterations 5

# Pull all HTTP records from the active project as input
vigolium agent swarm --all-records

# Filter HTTP records by host/status/method/path/since
vigolium agent swarm --records-from "host=example.com,status=200,method=GET,path=/api,since=2026-04-01"

# Pull multiple specific records (repeatable / comma-separated)
vigolium agent swarm --record-uuid 550e8400-...,7c9b1a2d-...

# Run a background vigolium-audit harness in parallel (requires --source)
vigolium agent swarm -t http://localhost:3000 --source ./src --audit deep

# Run piolium as the background audit harness instead of vigolium-audit
vigolium agent swarm -t http://localhost:3000 --source ./src --piolium balanced

# Force the extension agent to run even when the planner picks built-in modules
vigolium agent swarm -t https://example.com/api --with-extensions

# Tune master-agent batching and probing
vigolium agent swarm --all-records --master-batch-size 10 --batch-concurrency 4 \
  --probe-concurrency 20 --probe-timeout 15s --max-plan-records 25

# Custom instructions to guide the agent
vigolium agent swarm -t https://example.com/api/users --instruction "Focus on GraphQL parsing"

# Instructions from a file
vigolium agent swarm -t https://example.com/api/users --instruction-file custom-hints.txt

# Resume from a specific phase
vigolium agent swarm -t https://example.com --start-from plan

# Show rendered prompts during execution
vigolium agent swarm -t https://example.com/api/users --show-prompt

# Specify modules explicitly
vigolium agent swarm -t https://example.com/api/search -m xss-reflected,xss-stored

# Control scanning phases
vigolium agent swarm -t https://example.com --only dynamic-assessment
vigolium agent swarm -t https://example.com --skip discovery,spidering

# Preview master agent prompt
vigolium agent swarm -t https://example.com/api/users --dry-run

# With specific agent backend
vigolium agent swarm -t https://example.com/api/users --agent codex
```

---

## agent olium

**Usage:** `vigolium agent olium [prompt...] [flags]`

**Aliases (top-level):** `vigolium olium`, `vigolium ol`

Launch the in-process olium agent — interactive TUI by default, or one-shot mode when `-p`/`--prompt` is set. Powers every other `agent *` subcommand under the hood; this command exposes it directly for ad-hoc prompts and provider debugging.

### agent olium flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--provider` | — | string | from config | Provider: `openai-compatible` \| `openai-codex-oauth` \| `anthropic-api-key` \| `anthropic-oauth` \| `openai-api-key` \| `anthropic-cli` \| `anthropic-vertex` \| `google-vertex` |
| `--model` | — | string | provider default | Model id (provider-specific default if empty) |
| `--oauth-cred` | — | string | from config | Path to OAuth/SA credential file (openai-codex-oauth: `~/.codex/auth.json`; anthropic-vertex / google-vertex: SA JSON or `$GOOGLE_APPLICATION_CREDENTIALS`) |
| `--oauth-token` | — | string | from config | Claude Code OAuth bearer token (`anthropic-oauth`; falls back to `agent.olium.oauth_token` or `$ANTHROPIC_API_KEY`) |
| `--llm-api-key` | — | string | from config | API key for key-based providers (anthropic-api-key, openai-api-key); falls back to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` env |
| `--claude-bin` | — | string | `claude` | Path to the `claude` binary (anthropic-cli provider) |
| `--gcp-project` | — | string | — | GCP project for `google-vertex` (else `$GOOGLE_CLOUD_PROJECT`, then YAML, then SA file's project_id) |
| `--gcp-location` | — | string | — | GCP region for `google-vertex` (else `$GOOGLE_CLOUD_LOCATION`, then YAML, then `us-central1`) |
| `--system` | — | string | — | Override system prompt |
| `--prompt` | `-p` | string | — | Run one prompt non-interactively and stream to stdout (skips the TUI). Pass `-` to read the prompt from stdin |
| `--stdin` | — | bool | `false` | Force reading prompt from stdin |

When piped (stdin is not a TTY), olium auto-detects piped input and seeds the TUI with it. Use `-p -` for the conventional headless "read prompt from stdin" form.

### Examples

```bash
# Interactive TUI
vigolium olium

# Seed the TUI with a positional prompt
vigolium ol "explain the entitlement check in pkg/cli/server.go"

# One-shot prompt, stream to stdout (headless)
vigolium olium -p "summarize the agent autopilot intensity presets"

# One-shot prompt from stdin
echo "review this snippet for SSRF" | vigolium olium -p -

# Anthropic via API key
vigolium olium --provider anthropic-api-key --llm-api-key $ANTHROPIC_API_KEY

# Claude via Claude Code OAuth bearer token
vigolium olium --provider anthropic-oauth --oauth-token "$(cat ~/.config/claude-token)"

# Anthropic Claude on Vertex (anthropic-vertex requires a claude-* model)
vigolium olium --provider anthropic-vertex \
  --oauth-cred ~/secrets/gcp-sa.json \
  --gcp-project my-gcp --gcp-location us-east5 --model claude-opus-4-6

# Gemini-native on Vertex (google-vertex requires a gemini-* model)
vigolium olium --provider google-vertex --model gemini-3.1-pro

# Local OpenAI-compatible endpoint (default provider — e.g. Ollama at localhost:11434)
vigolium olium --provider openai-compatible --model gemma4:latest

# Local claude CLI
vigolium olium --provider anthropic-cli --claude-bin /usr/local/bin/claude
```

---

## agent audit --driver=piolium (piolium driver)

**Usage:** `vigolium agent audit --driver=piolium [flags]`

Foreground audit driven by the user's installed **piolium** Pi extension. Drives `pi --mode json -p /piolium-<mode>` against a resolved source tree, syncs audit artifacts into the vigolium agent session directory, and imports findings into the database. Same `audit-state.json` schema as vigolium-audit (so the same parsing/reporting tooling applies), tagged separately in the DB.

**Requires:** `pi` in PATH (install: `npm i -g @earendil-works/pi-coding-agent`) plus `piolium` registered in `~/.pi/agent/settings.json` (`pi install git:git@github.com:vigolium/piolium.git`). Run `vigolium doctor` if unsure.

### piolium driver flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--intensity` | — | string | `balanced` | Audit intensity preset: `quick` (lite + shallow clone), `balanced` (default), `deep` (deep + full clone history). Explicit `--mode` / `--commit-depth` always override |
| `--mode` | — | string | (from intensity) | Audit mode override: `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`, `diff`, `longshot`, `status`, `smoke` |
| `--source` | — | string | `.` | Source: local directory, git URL, `gs://<project>/<key>` archive, or local archive (`.zip / .tar.gz / .tar.bz2 / .tar.xz`) |
| `--commit-depth` | — | int | `1` | `git clone --depth` value when `--source` is a git URL (0 = full history) |
| `--no-stream` | — | bool | `false` | Don't echo agent output to the console (still written to `{session}/runtime.log`) |
| `--upload-results` | — | bool | `false` | Upload session bundle to cloud storage after completion (requires storage config) |
| `--pi-provider` | — | string | — | Override pi's `defaultProvider` for this run (e.g. `vertex-anthropic`, `google-vertex`) |
| `--pi-model` | — | string | — | Override pi's `defaultModel` for this run (e.g. `claude-opus-4-6`, `gemini-3.1-pro`) |
| `--no-preflight` | — | bool | `false` | Skip the pre-audit pi roundtrip check (auth + model availability) |
| `--preflight-timeout` | — | duration | `30s` | Pi preflight timeout (e.g. `30s`, `1m`) |
| `--plm-scan-limit` | — | int | `0` | [piolium] Cap commit-history scan to N commits (0 = piolium default) |
| `--plm-scan-since` | — | string | — | [piolium] Cap commit-history scan to a `git --since` window (e.g. `"60 days ago"`) |
| `--plm-phase-retries` | — | int | `0` | [piolium] Per-phase retry count (0 = piolium default) |
| `--plm-command-retries` | — | int | `0` | [piolium] Per-command retry count (0 = piolium default) |
| `--plm-longshot-limit` | — | int | `0` | [piolium] Max files hunted in `longshot` mode (0 = piolium default) |
| `--plm-longshot-timeout` | — | int | `0` | [piolium] Per-file kill timer in `longshot` mode in ms (0 = piolium default) |
| `--plm-longshot-langs` | — | string | — | [piolium] Longshot language allowlist (comma-separated, e.g. `python,go`) |

### Audit modes

| Mode | Phases | Description |
|------|-------:|-------------|
| `lite` | 4 | Quick recon, secrets, fast SAST |
| `balanced` | 9 | Default audit path with PoCs and report |
| `deep` | 17 | Full audit |
| `revisit` | — | Anti-anchored second pass over an existing audit |
| `confirm` | — | Confirm existing findings live or with tests |
| `merge` | — | Merge and dedupe result trees from prior runs |
| `diff` | — | Scan changed files since an audited commit |
| `longshot` | — | Hail-mary file-by-file vulnerability hunt |
| `status` | — | Read-only progress check on an existing run (no agent launched) |
| `smoke` | — | Verify runner/provider wiring |

### Examples

```bash
# Balanced 9-phase audit of a local repo
vigolium agent audit --driver=piolium --mode balanced --source .

# Quick lite audit of a remote git URL (auto-clones)
vigolium agent audit --driver=piolium --mode lite --source https://github.com/org/repo

# Hail-mary file-by-file vulnerability hunt over Python+Go files only
vigolium agent audit --driver=piolium --mode longshot --source ./src \
  --plm-longshot-langs python,go --plm-longshot-limit 200

# Use a specific Pi provider/model for this run
vigolium agent audit --driver=piolium --pi-provider vertex-anthropic --pi-model claude-opus-4-6 --source .

# Full clone history via intensity preset
vigolium agent audit --driver=piolium --intensity deep --source https://github.com/org/repo

# Cap commit-history scan to last 60 days
vigolium agent audit --driver=piolium --mode balanced --source . --plm-scan-since "60 days ago"

# Resume / re-audit an existing tree
vigolium agent audit --driver=piolium --mode revisit --source ./prior-piolium-tree

# Read-only progress check on an in-progress run
vigolium agent audit --driver=piolium --mode status --source ./in-progress-piolium

# Skip preflight
vigolium agent audit --driver=piolium --mode balanced --source . --no-preflight
```

To run piolium and the vigolium-audit harness back-to-back on the same source, use `vigolium agent audit` instead — that command dispatches both drivers (or just one with `--driver=audit|piolium`) under a single AgenticScan.

---

## agent audit

**Usage:** `vigolium agent audit [flags]`

Unified driver dispatcher: drives the embedded **vigolium-audit** harness (driver name `audit`) and/or **piolium** against the same source tree under a **single parent AgenticScan UUID**. There is no separate `agent archon` command — the vigolium-audit leg is reached here via `--driver=audit`.

Default `--driver=auto` preflights the resolved coding-agent CLI (claude or codex) on PATH: if present it runs the vigolium-audit harness and **only falls back to piolium when that CLI is missing** (a clean audit run never consults piolium; a mid-run audit failure surfaces directly rather than silently retrying). `--driver=both` runs audit then piolium unconditionally. After the participating drivers finish, a project-wide post-pass findings dedup collapses duplicates. Per-driver child rows + session subdirs (`{session}/audit/`, `{session}/piolium/`) keep them separated on disk and in the DB while still scoring as one logical audit.

If one driver fails under `--driver=both`, the other still runs — the parent run reports per-driver status. Source resolution (git clone / gs:// download / archive extraction) happens **once** for both drivers.

### agent audit flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--driver` | — | string | `auto` | Audit driver: `auto` (audit; fall back to piolium only when claude/codex CLI is missing), `both` (audit then piolium, unconditional), `audit`, or `piolium` |
| `--intensity` | — | string | `balanced` | Audit intensity preset: `quick` (→ `lite`), `balanced` (→ `balanced`), `deep` (→ chain `deep,confirm`) |
| `--mode` | — | string | (from intensity) | Single mode override. Shared (allowed under `auto`/`both`): `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`. Driver-specific (require `--driver=audit\|piolium`): audit = `reinvest`/`refresh`/`mock`/`diff`/`status`, piolium = `longshot`/`smoke`/`diff`/`status` |
| `--modes` | — | string | — | Run a chain of modes back-to-back, comma-separated (e.g. `deep,refresh,confirm`). Overrides `--mode`/`--intensity`; stops on the first non-complete mode. Audit runs the chain natively; piolium chains via sequential runs collapsed into one row; under `auto`/`both`, modes a driver can't run are skipped on that leg |
| `--list-modes` | — | bool | `false` | Print the vigolium-audit mode graph (phases, time estimate, descriptions) and exit |
| `--source` | — | string | `.` | Source: local directory, git URL, `gs://<project>/<key>` archive, or local archive (`.zip / .tar.gz / .tar.bz2 / .tar.xz`) |
| `--interactive` | `-i` | bool | `false` | Drop into the coding agent with the audit harness installed and drive it yourself (audit-only). Skips streaming, the AgenticScan row, and findings import — results land in `<source>/vigolium-results/`; import them afterward. Not valid with `--driver=piolium` |
| `--commit-depth` | — | int | `1` | `git clone --depth` value when `--source` is a git URL (0 = full history; deep intensity uses 0) |
| `--no-stream` | — | bool | `false` | Don't echo agent output to the console (still written to `{session}/<driver>/runtime.log`) |
| `--show-thinking` | — | bool | `false` | Render the agent's internal thinking blocks in the live stream (audit; verbose, off by default) |
| `--keep-raw` | — | bool | `false` | [audit] Keep raw scanner output / draft findings under `<source>/vigolium-results/` (overrides deep/confirm auto-prune). No effect on the piolium leg |
| `--upload-results` | — | bool | `false` | Upload parent session bundle to cloud storage after completion (only when **all** participating drivers succeed) |
| `--no-dedup` | — | bool | `false` | Skip the post-pass project-wide findings dedup that runs after the audit completes |
| `--provider` | — | string | `""` | [audit] Olium provider hint that selects the audit leg's agent: `anthropic-*` → claude, `openai-*` → codex (also forwards that provider's BYOK auth). Empty inherits `agent.olium.provider` |
| `--agent` | — | string | `""` | [audit] Coding agent for the audit leg: `claude` or `codex`. Overrides the agent implied by `--provider` while keeping its auth (warns under `--driver=piolium`) |
| `--api-key` | — | string | — | BYOK API key (literal, `$ENV_NAME`, or `@path`). claude→`ANTHROPIC_API_KEY`, codex→`OPENAI_API_KEY`. Mutually exclusive with `--oauth-token`/`--oauth-cred-file` |
| `--oauth-token` | — | string | — | BYOK Anthropic OAuth bearer token (claude only; from `claude setup-token`). Mutually exclusive with `--api-key`/`--oauth-cred-file` |
| `--oauth-cred-file` | — | string | — | BYOK OAuth credential file (codex `~/.codex/auth.json` shape). Mutually exclusive with `--api-key`/`--oauth-token` |
| `--pi-provider` | — | string | — | [piolium] Override pi's `defaultProvider` (e.g. `vertex-anthropic`, `google-vertex`) |
| `--pi-model` | — | string | — | [piolium] Override pi's `defaultModel` |
| `--no-preflight` | — | bool | `false` | Skip the pre-audit roundtrip checks for both drivers |
| `--preflight-timeout` | — | duration | `30s` | Per-driver preflight timeout |
| `--plm-scan-limit` / `--plm-scan-since` / `--plm-phase-retries` / `--plm-command-retries` / `--plm-longshot-limit` / `--plm-longshot-timeout` / `--plm-longshot-langs` | — | — | — | [piolium] passthroughs — same semantics as `vigolium agent audit --driver=piolium`. Ignored when `--driver=audit` |

### Driver availability

- `--driver=audit` and the harness/CLI is missing → **hard error** (so you don't waste a git clone).
- `--driver=piolium` and the piolium runtime is missing → **hard error**.
- `--driver=auto`: audit runs when its claude/codex CLI is on PATH; otherwise it silently falls back to piolium (only then is piolium's availability reported).
- `--driver=both` and one runtime is missing → warn, drop the missing driver, run the other; **both** missing → hard error with both reasons.

### Examples

```bash
# Default: run vigolium-audit, fall back to piolium only if claude/codex CLI is missing
vigolium agent audit --source .

# Run both drivers back-to-back, unconditionally
vigolium agent audit --driver=both --source .

# Force a single driver
vigolium agent audit --driver=audit --source .
vigolium agent audit --driver=piolium --source ./src

# Driver-specific modes (require forcing the driver)
vigolium agent audit --driver=piolium --source . --mode longshot
vigolium agent audit --driver=audit   --source . --mode mock

# Chain modes back-to-back (audit runs them natively)
vigolium agent audit --driver=audit --source . --modes deep,refresh,confirm

# List the audit mode graph and exit
vigolium agent audit --list-modes

# Interactive: drive the audit yourself, then import the on-disk results
vigolium agent audit -i --source ./src
vigolium import ./src/vigolium-results --format html -o audit-report.html

# Audit from a gs:// archive (downloaded + extracted once, shared by both drivers)
vigolium agent audit --source gs://my-project/snapshots/app.tar.gz

# Skip the post-pass project-wide findings dedup
vigolium agent audit --source . --no-dedup

# Pin the audit leg's agent + provider (anthropic-* → claude, openai-* → codex)
vigolium agent audit --source . --provider anthropic-oauth
vigolium agent audit --source . --agent codex

# BYOK auth for the run
vigolium agent audit --source . --oauth-token "$(cat ~/.config/claude-token)"

# Override piolium's Pi defaults
vigolium agent audit --driver=piolium --source . --pi-provider google-vertex --pi-model gemini-3.1-pro

# Pass piolium-only knobs through (ignored on the audit leg)
vigolium agent audit --driver=piolium --source . --plm-scan-since "30 days ago" --plm-longshot-langs python
```

---

## agent session

**Usage:** `vigolium agent session [uuid] [flags]`

**Aliases:** `session`, `sessions`

List or inspect agent run sessions. Without arguments, lists all agent run sessions. With a UUID argument, shows detailed session information.

### agent session flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `50` | Maximum number of records to display |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--mode` | — | string | — | Filter by mode (query, autopilot, swarm, audit, piolium) |
| `--tail` | — | int | `50` | Number of raw output lines to show in detail view (0 = none, -1 = all) |
| `--full` | — | bool | `false` | Show full raw output (shortcut for `--tail -1`) |
| `--tui` / `--no-tui` | — | bool | — | Enable / force-disable interactive TUI picker |

### Detail view

When given a session UUID, `agent session <uuid>` prints: basic info (mode, agent, target, source, parent run), timing, results (findings, records, phases run, current phase), input, prompt, audit stats (for audit/piolium modes), attack/swarm plan, session auth configs, token usage, triage results, errors, module names, session directory listing, extensions, a tail of raw output, and any child runs spawned by the session.

### Examples

```bash
# List all agent sessions
vigolium agent session

# List with pagination
vigolium agent session -n 20 -o 40

# Filter by mode
vigolium agent session --mode swarm
vigolium agent session --mode audit

# Show details for a specific session (last 50 lines of output)
vigolium agent session 550e8400-e29b-41d4-a716-446655440000

# Full raw output
vigolium agent session <uuid> --full

# Interactive picker
vigolium agent session --tui
```

---

## Intensity Presets

`agent autopilot`, `agent swarm`, `agent audit` all accept `--intensity {quick|balanced|deep}` to bundle multiple defaults into a single flag. Explicit flags always override the preset. The preset is applied even when `--intensity` is not passed (`balanced` is the implicit default).

### Autopilot intensity

`Command Budget` is the internal operator command cap (there is no `--max-commands` flag). `Audit Mode` is the vigolium-audit / piolium harness mode run before the operator when `--source` is set.

| Preset | Command Budget | Timeout | Audit Mode | Browser |
|--------|---------------:|--------:|------------|:-------:|
| `quick` | 150 | 1h | `lite` | on |
| `balanced` (default) | 500 | 6h | `balanced` | on |
| `deep` | 1500 | 12h | `deep` | on |

### Swarm intensity

| Preset | Discover | Triage | Code Audit | Browser | Auth | Duration | Max Iterations |
|--------|:--------:|:------:|:----------:|:-------:|:----:|---------:|---------------:|
| `quick` | on | off | off | on | off | 2h | 1 |
| `balanced` (default) | on | on | on | on | off | 12h | 3 |
| `deep` | on | on | on | on | on | 24h | 5 |

Note: Code Audit only takes effect when `--source` is given; Auth only takes effect when the browser is enabled.

### Audit / Piolium intensity

| Preset | Mode(s) | Clone depth | Notes |
|--------|---------|-------------|-------|
| `quick` | `lite` | shallow (depth 1) | Fast triage |
| `balanced` (default) | `balanced` | shallow (depth 1) | Standard audit |
| `deep` | `deep,confirm` (chain) | full history (depth 0) | Full audit + PoC confirmation pass; commit archaeology |

Pass `--mode` (single) or `--modes` (chain) explicitly to invoke operational modes (`revisit`, `confirm`, `merge`, `diff`, `status`, plus piolium's `longshot`/`smoke` and audit's `reinvest`/`refresh`/`mock`) that aren't part of the intensity ladder.

Example — use a preset, then override one setting:

```bash
vigolium agent swarm -t https://example.com --source ./src --intensity deep --triage=false
vigolium agent autopilot -t https://example.com --intensity deep --max-duration 4h
```

---

## Prompt Templates

Prompt templates are Markdown files with YAML frontmatter stored in:
- `~/.vigolium/prompts/` (user-defined)
- Embedded in the binary (`public/presets/prompts/`)

### Template Discovery

```bash
# List all available templates
vigolium agent --list-templates

# Output: ID, NAME, OUTPUT_SCHEMA, SOURCE, DESCRIPTION
```

### Template Frontmatter

Templates use YAML frontmatter with fields like:
- `name`: Display name
- `description`: What the template does
- `output_schema`: Expected output format (`findings`, `http_records`, `attack_plan`, `triage_result`, `source_analysis`)
- Variables: Populated from database context (findings, HTTP records, module registry, scan stats)

### Built-in Templates

**SAST / Code Review:**
- `security-code-review` — Comprehensive security code review
- `injection-sinks` — Find injection sinks in source code
- `auth-bypass` — Identify authentication bypass vectors
- `secret-detection` — Detect hardcoded secrets and credentials
- `nextjs-security-audit` — Next.js-specific security review
- `react-xss-audit` — React XSS vulnerability audit
- `auth-session-review` — Auth and session management review
- `cors-csrf-review` — CORS and CSRF configuration audit
- `build-config-audit` — Build and deployment config review

**Analysis / Dynamic:**
- `endpoint-discovery` — Discover API endpoints from source code
- `api-input-gen` — Generate API test inputs
- `curl-command-gen` — Generate cURL commands for testing
- `attack-surface-mapper` — Map application attack surface
- `interactive-scan` — Interactive scan template
- `targeted-retest` — Re-test specific findings

**Autopilot:**
- `autopilot-system` — System prompt for autonomous mode

**Swarm:**
- `agent-swarm-master` — Master agent prompt for swarm planning

---

## Agent Configuration

Every agent invocation is routed through the in-process **olium** runtime —
there are no external subprocess backends. Configure the provider under
`agent.olium` in `vigolium-configs.yaml`:

```yaml
agent:
  default_agent: olium
  templates_dir: ~/.vigolium/prompts/
  sessions_dir: ~/.vigolium/agent-sessions/
  stream: true

  olium:
    provider: openai-compatible    # openai-compatible | openai-codex-oauth | anthropic-api-key | anthropic-oauth | openai-api-key | anthropic-cli | anthropic-vertex | google-vertex
    model: gemma4:latest           # empty = provider default
    oauth_cred_path: ~/.codex/auth.json
    oauth_token: ""                # anthropic-oauth bearer (or $ANTHROPIC_API_KEY)
    llm_api_key: ""                # supports ${ENV_VAR}
    google_cloud_project: ""       # anthropic-vertex / google-vertex; else $GOOGLE_CLOUD_PROJECT, then SA file's project_id
    google_cloud_location: ""      # anthropic-vertex / google-vertex; else $GOOGLE_CLOUD_LOCATION, then us-central1
    custom_provider:               # openai-compatible knobs (default points at a local Ollama)
      base_url: http://localhost:11434/v1
      model_id: gemma4:latest
      api_key: ""
    reasoning_effort: medium
    system_prompt: ""
    max_tokens: 1000000
    temperature: 0.0
    max_turns: 32
    max_concurrent: 4
    call_timeout_sec: 600
    cache_size: 1024
```

### Providers

| Provider | Auth | Description |
|----------|------|-------------|
| `openai-compatible` | `custom_provider.api_key` (optional) | Any OpenAI Chat-Completions-compatible endpoint via `custom_provider.base_url` / `model_id`. **Default** (points at a local Ollama at `http://localhost:11434/v1`, model `gemma4:latest`). |
| `openai-codex-oauth` | `~/.codex/auth.json` (via `codex login`) | OpenAI Codex via ChatGPT subscription. |
| `anthropic-api-key` | `llm_api_key` or `$ANTHROPIC_API_KEY` | Anthropic Claude via Messages API. |
| `anthropic-oauth` | `oauth_token` or `$ANTHROPIC_API_KEY` (bearer minted by `claude setup-token`) | Anthropic Claude via Claude Code OAuth bearer token. |
| `openai-api-key` | `llm_api_key` or `$OPENAI_API_KEY` | OpenAI Chat Completions API. |
| `anthropic-cli` | `claude` binary in PATH | Shells out to the local `claude` CLI for Claude Max subscribers. |
| `anthropic-vertex` | `oauth_cred_path` (GCP service-account JSON) or `$GOOGLE_APPLICATION_CREDENTIALS` | Anthropic Claude on GCP Vertex AI. Requires a `claude-*` model (e.g. `claude-opus-4-6`). Project/location resolve `$GOOGLE_CLOUD_PROJECT`/`$GOOGLE_CLOUD_LOCATION` > `--gcp-project`/`--gcp-location` > YAML > SA file's `project_id` / `us-central1`. |
| `google-vertex` | `oauth_cred_path` (GCP service-account JSON) or `$GOOGLE_APPLICATION_CREDENTIALS` | Gemini-native on GCP Vertex AI. Requires a `gemini-*` model (e.g. `gemini-3.1-pro`). Same project/location resolution as `anthropic-vertex`. |

### Per-run overrides

These flags map onto `agent.olium.*` for one run only — they're accepted on `agent query`, `agent autopilot`, `agent swarm`, `agent olium`, and the top-level `vigolium olium` / `ol` alias:

- `--provider` — selects the olium provider
- `--model` — overrides the model id
- `--oauth-cred` — OAuth/SA credential path (openai-codex-oauth, anthropic-vertex, or google-vertex)
- `--oauth-token` — Claude Code OAuth bearer (anthropic-oauth)
- `--llm-api-key` — API key for key-based providers
- `--gcp-project` — GCP project for `anthropic-vertex` / `google-vertex`
- `--gcp-location` — GCP region for `anthropic-vertex` / `google-vertex`
- `--system-prompt` / `--system-prompt-file` — full-replace system prompt (autopilot)
- `--system` — replace system prompt (`agent olium` TUI only)

### Listing Agents

```bash
vigolium agent --list-agents
```

Prints the configured olium providers as a table (PROVIDER, MODEL, AUTH, DESCRIPTION, ACTIVE), with the active default marked. Use `--json` for machine-readable output.

---

## Output Schemas

Agent output is parsed into structured schemas:

### findings

Used for code review and security analysis. Each finding has:
- `title`, `description`, `severity`, `confidence`
- `file`, `line`, `cwe`
- Findings are saved to the database

### http_records

Used for endpoint discovery and scan target generation. Each record has:
- `url`, `method`, `headers`, `body`
- Records can be scanned by subsequent commands

### attack_plan

Used by the swarm plan phase. Contains:
- `module_tags`, `module_ids` — which modules to run
- `focus_areas`, `skip_paths` — scanning guidance
- `endpoints` — prioritized targets with rationale

### triage_result

Used by swarm triage phase. Contains:
- `confirmed` — validated findings with reasons
- `false_positives` — dismissed findings with reasons
- `follow_up_scans` — additional targets for rescan
- `verdict` — `"done"` or `"rescan"` to control the loop

### source_analysis

Used by swarm source analysis phase. Contains:
- `http_records` — extracted routes as HTTP requests with method, URL, headers, body
- `session_config` — login flow and auth configuration (sessions with extract rules)
- `extensions` — custom JavaScript scanner extensions generated from identified sinks
