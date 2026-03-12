# Whitebox + Agent Scanning

Agent-enhanced scanning uses AI coding agents (Claude, Codex, Gemini, OpenCode) to analyze source code, discover vulnerabilities, and generate test targets.

## Prerequisites

1. An AI agent backend installed and accessible (e.g., Claude Code, Codex CLI, Gemini CLI)
2. Agent configured in `vigolium-configs.yaml` (or use built-in defaults)

## Quick Start

```bash
# One-shot security code review (local repo)
vigolium agent --prompt-template security-code-review --repo ./my-app

# Discover endpoints from source code
vigolium agent --prompt-template endpoint-discovery --repo ./my-app
```

> **Tip:** Use `--repo` for local paths. For `vigolium scan`, you can also use `--source-url` or `--repo-url` with a Git URL to have Vigolium clone the repository automatically.

## Agent Configuration

Configure agent backends in `vigolium-configs.yaml`:

```yaml
agent:
  default_agent: claude          # Default backend to use
  templates_dir: ~/.vigolium/prompts/  # Custom template directory
  sessions_dir: ~/.vigolium/agent-sessions/  # Agent run session artifacts
  stream: true                   # Stream agent output in real-time

  backends:
    claude:
      command: npx
      args: ["-y", "@zed-industries/claude-agent-acp@latest"]
      description: "Anthropic Claude Code (ACP)"
      protocol: acp

    claude-cli:
      command: claude
      args: ["--dangerously-skip-permissions", "-p"]
      description: "Anthropic Claude Code (pipe mode)"
      protocol: pipe

    codex:
      command: codex
      args: ["app-server"]
      description: "OpenAI Codex CLI (ACP)"
      protocol: acp

    gemini:
      command: gemini
      args: ["--experimental-acp"]
      description: "Google Gemini CLI (ACP)"
      protocol: acp

    gemini-cli:
      command: gemini
      args: ["-p"]
      description: "Google Gemini CLI (pipe mode)"
      protocol: pipe

    opencode:
      command: npx
      args: ["-y", "opencode-acp"]
      description: "OpenCode agent (ACP)"
      protocol: acp
```

### Protocols

| Protocol | Description |
|----------|-------------|
| `acp` | Agent Communication Protocol — structured bidirectional communication, agents can use filesystem tools natively |
| `pipe` | Classic stdin/stdout — prompt piped to stdin, output read from stdout |

ACP is the preferred protocol for modern AI coding agents. Use pipe mode as a fallback.

## Prompt Templates

Templates define what the agent analyzes and how results are structured.

### Built-in Templates

| Template ID | Output Schema | Description |
|-------------|---------------|-------------|
| `security-code-review` | `findings` | Comprehensive security review of source code |
| `endpoint-discovery` | `http_records` | Extract API endpoints from source code |
| `injection-sinks` | `findings` | Find injection sinks and taint flows |
| `auth-bypass` | `findings` | Analyze authentication and authorization logic |
| `secret-detection` | `findings` | Find hardcoded secrets and credentials |
| `api-input-gen` | `http_records` | Generate API test inputs from source |
| `curl-command-gen` | `http_records` | Generate curl commands for testing |
| `interactive-scan` | `findings` | Interactive scanning with module awareness |
| `targeted-retest` | `findings` | Retest previously found issues |
| `attack-surface-mapper` | `http_records` | Map the complete attack surface |
| `nextjs-security-audit` | `findings` | Next.js-specific security review |
| `react-xss-audit` | `findings` | React XSS pattern analysis |
| `auth-session-review` | `findings` | Authentication and session management review |
| `cors-csrf-review` | `findings` | CORS and CSRF configuration review |
| `build-config-audit` | `findings` | Build and deployment config security |

```bash
# List all available templates
vigolium agent --list-templates

# List configured agent backends
vigolium agent --list-agents
```

### Output Schemas

Templates declare an output schema that controls how agent output is parsed and ingested.

**`findings` schema** — The agent outputs security findings:

```json
{
  "findings": [
    {
      "title": "SQL Injection in user lookup",
      "description": "User input is concatenated directly into SQL query",
      "severity": "high",
      "confidence": "firm",
      "file": "src/db/users.go",
      "line": 42,
      "snippet": "db.Query(\"SELECT * FROM users WHERE id=\" + userID)",
      "cwe": "CWE-89",
      "tags": ["sqli", "injection"]
    }
  ]
}
```

**`http_records` schema** — The agent outputs HTTP endpoints to test:

```json
{
  "http_records": [
    {
      "method": "POST",
      "url": "https://api.example.com/users",
      "headers": {"Content-Type": "application/json"},
      "body": "{\"username\": \"test\", \"email\": \"test@example.com\"}",
      "notes": "User creation endpoint"
    }
  ]
}
```

## Single-Shot Agent Analysis

Run the agent once with a specific template:

```bash
# Security code review
vigolium agent --prompt-template security-code-review --repo ./my-app

# Review specific files only
vigolium agent --prompt-template security-code-review --repo ./my-app \
  --files src/auth/login.go --files src/middleware/jwt.go

# Endpoint discovery
vigolium agent --prompt-template endpoint-discovery --repo ./my-app

# Use a specific agent backend
vigolium agent --prompt-template security-code-review --repo ./my-app --agent gemini

# Append extra context to the prompt
vigolium agent --prompt-template security-code-review --repo ./my-app \
  --append "Focus on the payment processing module"

# Dry run: see the rendered prompt without executing
vigolium agent --prompt-template security-code-review --repo ./my-app --dry-run

# Save raw agent output to file
vigolium agent --prompt-template security-code-review --repo ./my-app --output review.txt

# Custom timeout
vigolium agent --prompt-template security-code-review --repo ./my-app --agent-timeout 10m
```

### Inline Prompts

For ad-hoc analysis without a template:

```bash
# Inline prompt
vigolium agent query --prompt "Review this Go code for race conditions" --repo ./my-app

# Prompt from stdin
echo "Find all SQL queries that don't use parameterized statements" | \
  vigolium agent query --stdin --repo ./my-app
```

Inline prompts do not have an output schema, so results are not parsed or ingested into the database.

## Template Variables and Context Enrichment

Templates declare which variables they need. Variables are only populated if declared, preventing unnecessary database queries.

| Variable | Source | Description |
|----------|--------|-------------|
| `{{.SourceCode}}` | `--repo` / `--files` | Concatenated source files |
| `{{.Language}}` | Auto-detected | Programming language |
| `{{.Framework}}` | Manual | Framework name (if set) |
| `{{.FilePath}}` | `--files` | Last collected file path |
| `{{.RepoPath}}` | `--repo` | Repository root path |
| `{{.TargetURL}}` | `--target` / `-t` | Target URL |
| `{{.Hostname}}` | Derived from URL | Target hostname |
| `{{.PreviousFindings}}` | Database | JSON array of up to 50 findings (filtered by hostname) |
| `{{.DiscoveredEndpoints}}` | Database | JSON array of up to 100 HTTP records |
| `{{.ModuleList}}` | Module registry | JSON array of all active and passive scanner modules |
| `{{.ScanStats}}` | Database | JSON object of scan statistics |
| `{{.AvailableCommands}}` | Hardcoded | CLI reference for `scan-url` and `scan-request` |

## Custom Prompt Templates

Create custom templates as Markdown files with YAML frontmatter:

```markdown
---
id: my-custom-review
name: Custom Security Review
description: Focus on business logic flaws
output_schema: findings
variables:
  - SourceCode
  - Language
  - TargetURL
  - PreviousFindings
---

You are a security expert analyzing a {{.Language}} application.

## Source Code

{{.SourceCode}}

## Target

{{.TargetURL}}

## Previous Findings

{{.PreviousFindings}}

## Instructions

Analyze the source code for business logic vulnerabilities. Focus on:
1. Authorization bypass
2. Race conditions
3. IDOR vulnerabilities

Output your findings as JSON:
{
  "findings": [...]
}
```

Save to `~/.vigolium/prompts/my-custom-review.md`, then use:

```bash
vigolium agent --prompt-template my-custom-review --repo ./my-app
```

Or reference a file path directly:

```bash
vigolium agent --prompt-file ./my-template.md --repo ./my-app
```

## Combining Agent Findings with Dynamic Scanning

Agent findings are ingested into the database with a module ID of `agent-<template-id>` (e.g., `agent-security-code-review`). HTTP records generated by agents become scan targets.

```bash
# Step 1: Agent discovers endpoints
vigolium agent --prompt-template endpoint-discovery --repo ./my-app

# Step 2: Dynamic scan uses agent-discovered endpoints from DB
vigolium scan -t https://api.example.com --strategy lite
```


## Common Workflows

```bash
# Quick code review with Claude
vigolium agent --prompt-template security-code-review --repo ./my-app

# Discover endpoints then scan them
vigolium agent --prompt-template endpoint-discovery --repo ./my-app
vigolium scan -t https://api.example.com

# Focused review of auth code with Gemini
vigolium agent --prompt-template auth-bypass --repo ./my-app \
  --files src/auth/ --agent gemini

# Next.js-specific audit
vigolium agent --prompt-template nextjs-security-audit --repo ./my-nextjs-app

# Attack surface mapping
vigolium agent --prompt-template attack-surface-mapper --repo ./my-app

```
