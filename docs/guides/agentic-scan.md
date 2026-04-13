# Agentic Scanning

## Overview

Vigolium's agent mode uses AI to drive vulnerability scanning. There are three execution modes with increasing autonomy: **Query** for single-shot analysis, **Swarm** for AI-planned targeted scanning, and **Autopilot** for fully autonomous multi-class assessments. A fourth command, **Pipeline**, is a convenience alias for `swarm --discover`.

## Prerequisites

Agent mode requires an AI backend. The default backend is Claude (via the Agent SDK). Verify it's available:

```bash
vigolium agent --list-agents
```

To use a different backend, pass `--agent <name>` (e.g., `--agent codex`, `--agent opencode`).

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
# Quick — fast CI/CD scan, minimal phases
vigolium agent swarm --input "https://example.com/api/users?id=1" --intensity quick

# Deep — full discovery, triage, browser, extended duration
vigolium agent swarm -t https://example.com --source ./app --intensity deep

# Deep autopilot — 300 commands, 12h timeout, deep archon, browser
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
| `source-analysis` | AI | Route extraction from source code (if `--source`) |
| `code-audit` | AI | Deep security code audit (if `--code-audit`) |
| `native-sast` | Native | Static analysis (if `--source`) |
| `sast-review` | AI | Validate SAST findings |
| `native-discover` | Native | Discovery + spidering (if `--discover`) |
| `plan` | AI | Master agent plans the attack |
| `native-extension` | Native | Write generated JS extensions |
| `native-scan` | Native | Execute the planned scan |
| `triage` | AI | Classify findings (if `--triage`) |
| `native-rescan` | Native | Targeted rescan on follow-ups |

Skip or start from a specific phase:

```bash
# Skip source analysis and SAST
vigolium agent swarm -t https://example.com --skip source-analysis --skip native-sast

# Resume from the plan phase
vigolium agent swarm -t https://example.com --start-from plan
```

## Autopilot: Autonomous Assessment

Autopilot uses an Archon-first workflow and then launches a single autonomous operator session over prepared context:

```bash
vigolium agent autopilot -t https://example.com
```

### Flow

1. **Prepare** - resolve target, source, diff, and session artifacts
2. **Archon** - when source is present, run whitebox analysis first
3. **Plan** - build native context, priorities, and budgets
4. **Execute** - let the operator agent recon, validate, and report
5. **Verify** - keep only findings backed by artifacts and evidence

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
| **Swarm** | 2-4+ | Targeted request scanning, focused testing |
| **Pipeline** | 5-6+ | Full-scope structured scanning |
| **Autopilot** | Many (parallel) | Deep autonomous assessment, multi-class testing |

All agent modes support the `--intensity` flag (`quick`, `balanced`, `deep`) to control scan depth, duration, and resource usage with a single setting.
