# Agentic Scanning

## Overview

Vigolium's agent mode uses AI to drive vulnerability scanning. The main subcommands are: **Query** for single-shot analysis, **Swarm** for AI-planned targeted scanning, **Autopilot** for fully autonomous assessments, **Audit** for multi-phase source-code audit, and **Olium** for direct interactive TUI access to the engine.

## Prerequisites

All AI dispatch runs through the in-process **olium** engine. Provider selection lives under `agent.olium.*` in `~/.vigolium/vigolium-configs.yaml`; the default provider is `openai-codex-oauth`. Inspect the current configuration:

```bash
vigolium config ls agent
```

Per-invocation provider overrides for olium-backed commands are CLI flags only: `--provider`, `--model`, `--llm-api-key`, `--oauth-cred`, `--oauth-token`. The standalone `vigolium agent audit` (and the audit leg of `vigolium agent audit`) instead picks its coding agent with `--provider <olium-provider>` (resolves the agent **and** that provider's BYOK auth: `anthropic-*` → claude, `openai-*` → codex) or `--agent {claude|codex}` (a pure agent selector that overrides the provider-implied agent while keeping its resolved auth).

## Query: Single-Shot Analysis

Query runs a single AI prompt and returns structured output. No network scanning -- useful for code review, endpoint discovery, and secret detection.

### With a Built-in Template

```bash
vigolium agent query --prompt-template security-code-review --source ./app
```

List available templates:

```bash
vigolium agent --list-templates
```

### With an Inline Prompt

```bash
vigolium agent query -p "Find all API endpoints that accept user input without validation" --source ./app
```

### With Specific Files

```bash
vigolium agent query \
  --prompt-template security-code-review \
  --source ./app \
  --files src/auth/login.go,src/auth/session.go
```

### Saving Output

```bash
vigolium agent query \
  --prompt-template endpoint-discovery \
  --source ./app \
  --output endpoints.json
```

## Swarm: AI-Planned Targeted Scanning

Swarm is the primary agentic scan mode. A master AI agent analyzes your input, selects scanner modules, generates custom JavaScript extensions, and executes the scan.

### Scanning a Specific Request

Pass a target request via `--input` (accepts URLs, curl commands, raw HTTP, Burp XML, or base64):

```bash
# From a URL
vigolium agent swarm \
  --input "https://example.com/api/users?id=1" \
  -t https://example.com

# From a curl command
vigolium agent swarm \
  --input "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' https://example.com/api/login" \
  -t https://example.com

# From a file
vigolium agent swarm \
  --input @request.txt \
  -t https://example.com
```

### Intensity Presets

The `--intensity` flag bundles multiple settings into a single preset — works for both swarm and autopilot:

```bash
# Quick — discovery + browser, no triage, 2h cap
vigolium agent swarm --input "https://example.com/api/users?id=1" --intensity quick

# Deep — discovery, triage, browser + auth, extended duration
vigolium agent swarm -t https://example.com --source ./app --intensity deep

# Deep autopilot — 300 commands, 12h timeout, deep audit, browser
vigolium agent autopilot -t https://example.com --source ./app --intensity deep
```

Explicit flags always override intensity presets.

### Full-Scope Scanning with Discovery

Add `--discover` to run content discovery and spidering before the AI planning phase:

```bash
vigolium agent swarm \
  --discover \
  -t https://example.com
```

### Source-Aware Scanning

Provide application source code for deeper analysis. The AI agent analyzes routes, auth flows, and generates targeted extensions:

```bash
vigolium agent swarm \
  --source ./app \
  -t https://example.com \
  --discover
```

For a deep AI-driven code audit on top of scanning:

```bash
vigolium agent swarm \
  --source ./app \
  -t https://example.com \
  --code-audit
```

### Focusing on a Vulnerability Type

```bash
vigolium agent swarm \
  --input "https://example.com/api/users?id=1" \
  -t https://example.com \
  --vuln-type sqli
```

### Enabling Triage

By default, swarm outputs raw findings. Add `--triage` for AI-powered true/false positive classification with automatic rescan:

```bash
vigolium agent swarm \
  --input "https://example.com/api/users?id=1" \
  -t https://example.com \
  --triage \
  --max-iterations 3
```

### Swarm Phases

The swarm pipeline runs these phases in order:

| Phase | Type | Description |
|-------|------|-------------|
| `native-normalize` | Native | Parse and normalize input |
| `auth` | AI/Native | Browser-based login (requires `--browser-auth` + `--browser`) |
| `source-analysis` | AI | Route extraction from source code (if `--source`) |
| `code-audit` | AI | Deep security code audit (if `--code-audit`) |
| `native-discover` | Native | Discovery + spidering (if `--discover`) |
| `plan` | AI | Master agent plans the attack |
| `native-extension` | Native | Write generated JS extensions |
| `native-scan` | Native | Execute the planned scan |
| `triage` | AI | Classify findings (if `--triage`) |
| `native-rescan` | Native | Targeted rescan on follow-ups |

Skip or start from a specific phase:

```bash
# Skip source analysis
vigolium agent swarm -t https://example.com --skip source-analysis

# Resume from the plan phase
vigolium agent swarm -t https://example.com --start-from plan
```

## Autopilot: Autonomous Assessment

Autopilot opens a single long-running LLM session with full bash/file/web tools plus `report_finding` and `halt_scan`. The agent decides what to scan, runs scans via `bash`, inspects results, writes findings as it confirms them, and halts on its own.

```bash
vigolium agent autopilot -t https://example.com
```

### Flow

1. **Prepare** - resolve target, source, diff, and session artifacts
2. **Audit (optional)** - when `--source` is set, run an vigolium-audit pass first; findings flow into the operator's context
3. **Operator session** - one olium engine loop with bash/read/write/edit/grep/glob/web_fetch tools plus `report_finding` and `halt_scan`
4. **Halt** - the agent halts itself, hits `--max-commands`, or runs out the `--timeout`

### With Source Code

```bash
vigolium agent autopilot -t https://example.com --source ./app
```

### With a Focus Area

```bash
vigolium agent autopilot -t https://example.com --focus "authentication bypass"
```

### Resuming a Session

Autopilot supports checkpointing. If interrupted, resume from where it left off:

```bash
vigolium agent autopilot --resume ~/.vigolium/agent-sessions/<uuid>
```

### Timeout and Limits

```bash
vigolium agent autopilot -t https://example.com \
  --timeout 2h \
  --max-commands 50
```

## Session Management

All agent runs create session directories under `~/.vigolium/agent-sessions/`. Browse past sessions:

```bash
# List all sessions
vigolium agent session

# Filter by mode
vigolium agent session --mode swarm

# View a specific session
vigolium agent session <uuid>
```

## Custom Instructions

Append custom guidance to any agent prompt:

```bash
vigolium agent swarm \
  -t https://example.com \
  --instruction "Focus on the /api/v2 endpoints. The app uses JWT auth with RS256."
```

Or load from a file:

```bash
vigolium agent swarm \
  -t https://example.com \
  --instruction-file context.md
```

## Dry Run and Prompt Inspection

Preview the rendered prompt without executing:

```bash
vigolium agent swarm --dry-run \
  --input "https://example.com/api/users?id=1" \
  -t https://example.com
```

Print the prompt to stderr while executing:

```bash
vigolium agent swarm --show-prompt \
  --input "https://example.com/api/users?id=1" \
  -t https://example.com
```

## Choosing the Right Mode

| Mode | AI Calls | Best For |
|------|----------|----------|
| **Query** | 1 | Code review, endpoint discovery, CI checks |
| **Swarm** | 2-10+ | Targeted scanning where AI plans and the native scanner executes |
| **Autopilot** | Many (turns) | Open-ended autonomous assessment when target/scope is fuzzy |
| **Audit** | Many (multi-phase) | Deep AI source-code audit |

The agentic-scan modes (`swarm`, `autopilot`, `audit`) all support the `--intensity` flag (`quick`, `balanced`, `deep`) to control scan depth, duration, and resource usage with a single setting.
