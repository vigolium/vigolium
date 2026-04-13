# Agent Query Mode

Query mode is Vigolium's single-shot AI prompt execution mode. It sends a prompt template or inline prompt to an AI agent and returns structured output -- no network scanning, no multi-phase orchestration. One AI call, one response.

## What It Does

- Loads a prompt template, enriches it with source code and database context, and sends it to the configured AI agent
- The agent analyzes the provided context and returns structured JSON (findings or HTTP records)
- Results are parsed and saved to the Vigolium database
- No network scanning occurs -- query mode purely analyzes what you give it

Query mode is not an agentic scan. It does not discover targets, send attack traffic, or iterate. It is a code analysis tool that leverages AI to find vulnerabilities, extract endpoints, or answer security questions from source code.

## CLI Usage

### Template-Based Execution

Run a built-in or custom prompt template against source code:

```bash
# Security code review
vigolium agent query --prompt-template security-code-review --source ./src

# Endpoint discovery from a Django project
vigolium agent query --prompt-template endpoint-discovery --source ~/projects/django-app

# Review specific files only
vigolium agent query --prompt-template injection-sinks --source ./src --files db/query.go,api/handler.go
```

### Custom Prompt File

Use your own Markdown prompt file with YAML frontmatter:

```bash
vigolium agent query --prompt-file my-prompt.md --source ./src
```

### Freeform Questions

Ask a security question without a template:

```bash
vigolium agent query "What are common JWT vulnerabilities?"

# With source context
vigolium agent query "What authentication mechanisms does this app use?" --source ./src
```

### Stdin

Pipe a prompt from stdin:

```bash
echo "explain CSRF" | vigolium agent query --stdin
```

### Dry Run

Render the full prompt without sending it to the agent -- useful for debugging templates:

```bash
vigolium agent query --prompt-template endpoint-discovery --source ./src --dry-run
```

### List Templates and Agents

```bash
vigolium agent --list-templates
vigolium agent --list-agents
```

### More Examples

```bash
# Code review with additional focus instructions
vigolium agent query --prompt-template security-code-review --source ./src \
  --append "Pay special attention to deserialization and file upload handling"

# Save agent output to a file
vigolium agent query --prompt-template security-code-review --source ./src --output review-results.json

# Scope to a specific project
vigolium agent query --prompt-template security-code-review --source ./src --project my-api

# Chain with jq to extract high-severity findings
vigolium agent query --prompt-template security-code-review --source ./src --json \
  | jq '.[] | select(.severity == "high")'

# Detect hardcoded secrets in config files
vigolium agent query --prompt-template secret-detection --source ./src --files config/,deploy/
```

## Key Flags

| Flag | Description |
|------|-------------|
| `--prompt-template` | Template ID to use (e.g., `security-code-review`, `endpoint-discovery`) |
| `--prompt-file` | Path to a custom prompt Markdown file |
| `--source` | Path to source code directory |
| `--files` | Specific files to include, relative to `--source` (comma-separated) |
| `--agent` | Agent backend to use (overrides `agent.default_agent` from config) |
| `--append` | Extra text appended to the rendered prompt |
| `--output` | Write raw agent output to a file |
| `--dry-run` | Render the prompt without executing it |
| `--source-label` | Label for records ingested from agent output (e.g., `agent-review`) |

## API

```
POST /api/agent/run/query
```

```json
{
  "agent": "claude",
  "prompt_template": "security-code-review",
  "source": "/path/to/repo",
  "files": ["main.go", "handlers.go"],
  "append": "Focus on authentication logic",
  "stream": true
}
```

At least one of `prompt_template`, `prompt_file`, or `prompt` is required. When `stream` is `true`, the response uses Server-Sent Events for real-time output.

## Use Cases

- **Code review** -- run `security-code-review` before deployment to catch injection sinks, hardcoded secrets, and auth bypasses
- **Endpoint discovery** -- extract API routes from source code (Express, Spring, Django, etc.) and ingest them as HTTP records for subsequent scanning
- **Secret detection** -- scan config files, deploy scripts, and environment templates for hardcoded credentials
- **CI/CD integration** -- single AI call completes in seconds, making it suitable for pipeline gates
- **Triage questions** -- ask the agent about a specific vulnerability pattern or security concept

## Pros and Cons

| Pros | Cons |
|------|------|
| Fast -- single AI call, completes in seconds | No network scanning -- code analysis only |
| Low cost -- one prompt, one response | Requires source code access for most templates |
| Deterministic scope -- same template produces consistent coverage | Findings are unverified (no live confirmation) |
| Good for CI/CD -- predictable runtime, structured output | Limited to what the template asks for |
| Works without a running target | Cannot discover runtime-only vulnerabilities |
| Supports structured output schemas (findings, HTTP records) | Freeform questions return unstructured text |
