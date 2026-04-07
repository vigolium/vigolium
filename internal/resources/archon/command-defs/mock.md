---
description: Mock audit — vestigial command definition. Mock mode is handled entirely in Go code (autopilot_pipeline.go) and never launches a subprocess.
argument-hint: "None"
allowed-tools: Bash, Write
---

## Note

This file exists for reference only. When `--archon-mode mock` is used, the autopilot pipeline writes a sample `audit-state.json` directly in Go without launching any agent subprocess. This command definition is never executed.

## Sample `audit-state.json`

The mock mode initializes `archon/audit-state.json` with a single entry:

```json
{
  "audits": [
    {
      "audit_id": "<ISO timestamp>",
      "commit": "<HEAD SHA from: git rev-parse HEAD>",
      "branch": "<current branch>",
      "repository": "<org/repo from: git remote get-url origin 2>/dev/null | sed 's|.*://[^/]*/||;s|.*:||;s|\\.git$||' — fallback: basename $(pwd)>",
      "mode": "mock",
      "model": "none",
      "agent_sdk": "none",
      "started_at": "<ISO timestamp>",
      "completed_at": "<ISO timestamp>",
      "status": "complete",
      "phases": {
        "mock": {
          "status": "complete",
          "completed_at": "<ISO timestamp>",
          "summary": "Mock mode — sample output, no agent executed"
        }
      }
    }
  ]
}
```
