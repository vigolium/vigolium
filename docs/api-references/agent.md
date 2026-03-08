# Vigolium API Reference — Agent

## Overview

The agent API provides three run modes that mirror the `vigolium agent` CLI subcommands:

| Endpoint                         | CLI Equivalent              | Description                              |
|----------------------------------|-----------------------------|------------------------------------------|
| `POST /api/agent/run/query`      | `vigolium agent [query]`    | Single-shot prompt execution             |
| `POST /api/agent/run/autopilot`  | `vigolium agent autopilot`  | Autonomous AI-driven scanning session    |
| `POST /api/agent/run/pipeline`   | `vigolium agent pipeline`   | Multi-phase scanning pipeline            |

All three modes share a global concurrency lock — only one agent run can be active at a time. Attempting to start a second run returns `409 Conflict`.

---

## POST /api/agent/run/query — Single-Shot Agent Run

Starts an AI agent run with a prompt template, file, or inline prompt. Returns `202 Accepted` (async) or an SSE stream when `stream: true`.

**Request body:**

| Field              | Type     | Required | Description                                                    |
|--------------------|----------|----------|----------------------------------------------------------------|
| `agent`            | string   | No       | Agent backend name (e.g. `claude`, `opencode`, `gemini`)       |
| `prompt_template`  | string   | No*      | Name of a prompt template (from `~/.vigolium/prompts/`)        |
| `prompt_file`      | string   | No*      | Path to a prompt file on disk                                  |
| `prompt`           | string   | No*      | Inline prompt text                                             |
| `repo_path`        | string   | No       | Path to source code repository for context                     |
| `files`            | string[] | No       | Specific files to include as context                           |
| `append`           | string   | No       | Additional text appended to the prompt                         |
| `source`           | string   | No       | Source label for findings                                      |
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
    "repo_path": "/home/user/src/my-app"
  }' | jq .

# Run with an inline prompt
curl -s -X POST http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Analyze the authentication flow for vulnerabilities",
    "repo_path": "/home/user/src/my-app",
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

Launches an AI agent that autonomously discovers, scans, and triages vulnerabilities using vigolium CLI commands via a sandboxed terminal.

**Request body:**

| Field              | Type     | Required | Description                                                    |
|--------------------|----------|----------|----------------------------------------------------------------|
| `target`           | string   | **Yes**  | Target URL to scan                                             |
| `agent`            | string   | No       | Agent backend name (default from config)                       |
| `repo_path`        | string   | No       | Path to source code repository for context                     |
| `files`            | string[] | No       | Specific files to include as context                           |
| `focus`            | string   | No       | Focus area hint (e.g. `"API injection"`, `"auth bypass"`)      |
| `system_prompt`    | string   | No       | Custom system prompt file path (overrides default)             |
| `timeout`          | string   | No       | Go duration string (default `"30m"`)                           |
| `max_commands`     | int      | No       | Max CLI commands the agent can execute (default `100`)         |
| `dry_run`          | bool     | No       | Render the prompt without executing the agent                  |
| `stream`           | bool     | No       | If `true`, returns an SSE stream                               |
| `scan_uuid`        | string   | No       | Link results to a specific scan UUID                           |

```bash
# Basic autopilot scan
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "agent": "claude",
    "focus": "API injection"
  }' | jq .

# Autopilot with source code context and streaming
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "repo_path": "/home/user/src/my-app",
    "focus": "authentication bypass",
    "timeout": "45m",
    "max_commands": 50,
    "stream": true
  }'
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

## POST /api/agent/run/pipeline — Multi-Phase Scanning Pipeline

Runs the fixed multi-phase scanning pipeline with AI agent checkpoints. The pipeline phases are:

1. **Discover** — Content discovery and spidering (native, no AI)
2. **Plan** — AI agent analyzes discovery results, plans attack strategy
3. **Scan** — Dynamic assessment with agent-selected modules (native)
4. **Triage** — AI agent reviews findings, identifies false positives
5. **Rescan** — Targeted re-scanning based on triage recommendations
6. **Report** — Structured output from scan results

AI agents are only called at phases 2 (Plan) and 4 (Triage).

**Request body:**

| Field               | Type     | Required | Description                                                    |
|---------------------|----------|----------|----------------------------------------------------------------|
| `target`            | string   | **Yes**  | Target URL to scan                                             |
| `agent`             | string   | No       | Agent backend name (default from config)                       |
| `repo_path`         | string   | No       | Path to source code repository for context                     |
| `files`             | string[] | No       | Specific files to include as context                           |
| `focus`             | string   | No       | Focus area hint for the planning agent                         |
| `profile`           | string   | No       | Scanning profile name (e.g. `"light"`, `"thorough"`)           |
| `timeout`           | string   | No       | Go duration string (default `"1h"`)                            |
| `max_rescan_rounds` | int      | No       | Max triage→rescan iterations (default `2`)                     |
| `skip_phases`       | string[] | No       | Phases to skip (e.g. `["rescan"]`)                             |
| `start_from`        | string   | No       | Resume pipeline from a specific phase                          |
| `dry_run`           | bool     | No       | Render agent prompts without executing                         |
| `stream`            | bool     | No       | If `true`, returns an SSE stream with phase events             |
| `scan_uuid`         | string   | No       | Link results to a specific scan UUID                           |
| `project_uuid`      | string   | No       | Scope results to a project                                     |

```bash
# Basic pipeline scan
curl -s -X POST http://localhost:9002/api/agent/run/pipeline \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "agent": "claude"
  }' | jq .

# Pipeline with focus, profile, and streaming
curl -s -X POST http://localhost:9002/api/agent/run/pipeline \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "focus": "auth bypass",
    "profile": "thorough",
    "skip_phases": ["rescan"],
    "timeout": "2h",
    "stream": true
  }'

# Resume a pipeline from the triage phase
curl -s -X POST http://localhost:9002/api/agent/run/pipeline \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "start_from": "triage"
  }' | jq .
```

**Response (202):**

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "pipeline run started"
}
```

---

## SSE Streaming

All three run endpoints support `"stream": true`, which returns a `text/event-stream` (Server-Sent Events) response. Each event is a JSON object on a `data:` line.

**Event types:**

| Type    | Description                                                        | Modes              |
|---------|--------------------------------------------------------------------|---------------------|
| `chunk` | Incremental text output from the agent                             | All                 |
| `phase` | Pipeline phase transition (includes `phase` field)                 | Pipeline only       |
| `done`  | Final event with the complete result object                        | All                 |
| `error` | Agent run failed; includes `error` message                         | All                 |

**Example SSE stream (query/autopilot):**

```
data: {"type":"chunk","text":"Analyzing authentication flow..."}

data: {"type":"chunk","text":" found potential issue in session handling."}

data: {"type":"done","result":{"agent_name":"claude","findings":[...],"saved_count":3}}

```

**Example SSE stream (pipeline):**

```
data: {"type":"phase","phase":"discover"}

data: {"type":"chunk","text":"Running discovery..."}

data: {"type":"phase","phase":"plan"}

data: {"type":"chunk","text":"Analyzing endpoints for attack strategy..."}

data: {"type":"phase","phase":"scan"}

data: {"type":"phase","phase":"triage"}

data: {"type":"chunk","text":"Reviewing findings..."}

data: {"type":"done","pipeline_result":{"total_findings":5,"confirmed":3,"false_positives":2,"phases_run":["discover","plan","scan","triage"]}}

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
    "mode": "pipeline",
    "status": "running",
    "current_phase": "scan",
    "phases_run": ["discover", "plan"]
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
| `mode`             | string   | Run mode: `"query"`, `"autopilot"`, or `"pipeline"`        |
| `status`           | string   | `"running"`, `"completed"`, or `"failed"`                  |
| `agent_name`       | string   | Agent backend used                                         |
| `template_id`      | string   | Prompt template ID (query mode)                            |
| `finding_count`    | int      | Number of findings produced                                |
| `record_count`     | int      | Number of HTTP records produced (query/autopilot)          |
| `saved_count`      | int      | Number of records saved to DB (query/autopilot)            |
| `error`            | string   | Error message (failed runs only)                           |
| `completed_at`     | string   | ISO 8601 completion timestamp                              |
| `result`           | object   | Full agent result (query/autopilot, completed runs only)   |
| `current_phase`    | string   | Currently executing phase (pipeline, running only)         |
| `phases_run`       | string[] | Completed phases (pipeline only)                           |
| `pipeline_result`  | object   | Full pipeline result (pipeline, completed runs only)       |

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

**Pipeline completed run:**

```json
{
  "run_id": "agt-772a0622-g4bd-63f6-c938-668877662222",
  "mode": "pipeline",
  "status": "completed",
  "finding_count": 5,
  "completed_at": "2026-02-16T16:30:00Z",
  "phases_run": ["discover", "plan", "scan", "triage", "report"],
  "pipeline_result": {
    "plan": {
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
    "rescan_rounds": 0,
    "phases_run": ["discover", "plan", "scan", "triage", "report"],
    "duration": "45m12s"
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

## POST /api/agent/chat/completions — OpenAI-Compatible Chat Completions

Accepts an OpenAI-compatible Chat Completions request and returns an OpenAI-compatible response. This allows any OpenAI-compatible client or tool to use Vigolium agents by changing the base URL.

The `model` field maps to agent names in config. If `model` matches a configured agent name (e.g. `"claude"`, `"opencode"`, `"gemini"`), that agent is used. Unrecognized model names fall back to the default agent.

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

See [Agent Mode](../agent-mode.md) for full agent documentation.
