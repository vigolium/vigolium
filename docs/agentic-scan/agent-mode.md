# Agent Mode

Vigolium currently exposes seven commands under `vigolium agent`:

| Command | Use it for |
|---|---|
| `query` | One prompt or template against source code |
| `autopilot` | An autonomous operator that drives Vigolium and browser tools |
| `swarm` | A structured AI-planned native scan and triage pipeline |
| `audit` | A unified source audit using audit, piolium, or both |
| `triage` | AI verification of one stored finding |
| `olium` | Interactive or one-shot general-purpose agent access |
| `session` | Agent-run history and output inspection |

The parent command only lists templates and agents. Run work through a
subcommand.

## Choosing a Command

- Use `query` for bounded code review or extraction with structured output.
- Use `swarm` when you want AI planning around the deterministic native scan
  pipeline.
- Use `autopilot` when you want an autonomous operator to explore, scan,
  inspect evidence, and decide its next action.
- Use `audit` for source-only, multi-phase security review.
- Use `triage` to confirm or reject an existing finding.
- Use `olium` for ad-hoc interactive work that is not a scan workflow.

## Query

```bash
vigolium agent query \
  --prompt-template security-code-review \
  --source ./src

vigolium agent query -p "List every unauthenticated route" --source .
```

Useful flags include `--prompt-template`, `--prompt-file`, `-p/--prompt`,
`--stdin`, `--source`, `--files`, `--source-label`, `--output`, `--dry-run`,
and `--max-duration`.

Query is single-shot. It does not perform autonomous network scanning.

## Autopilot

```bash
vigolium agent autopilot \
  -t https://app.example.com \
  --source ./src \
  --intensity deep \
  --triage
```

Autopilot's operator uses Vigolium's CLI, HTTP, browser, and source tools until
it halts or reaches its wall-clock limit. The browser is available without a
`--browser` flag; put credentials and login intent in the prompt.

Important flags include:

- input: `[prompt]`, `--prompt`, `--input`, `--plan-file`, `--record-uuid`,
  `-t/--target`, `--burp-bridge-url`;
- context: `--source`, `--files`, `--knowledge-base`,
  `--knowledge-base-raw`, `--prior-context`, `--diff`, `--last-commits`;
- audit: `--audit`, `--piolium`;
- control: `--intensity`, `--max-duration`, `--dry-run`, `--resume`;
- debugging: `--session-dir`, `--transcript`, `--verbose`.

There is no public `--max-commands` or `--timeout` flag. Intensity selects the
internal turn budget; use `--max-duration` for the wall-clock cap.

Durable resume is available when `agent.olium.autopilot_mode` is `shadow` or
`enforced`:

```bash
vigolium agent autopilot --resume <agentic-scan-uuid>
```

`legacy` mode does not support durable resume. See [Autopilot](autopilot.md)
for scratchpad, candidate, checkpoint, and transcript behavior.

## Swarm

```bash
vigolium agent swarm \
  -t https://app.example.com \
  --source ./src \
  --discover \
  --triage
```

Swarm normalizes inputs, optionally analyzes source and authentication, plans
the scan, generates extensions when useful, runs native modules, and can
triage and rescan. Useful flags include `--input`, `--record-uuid`,
`--records-from`, `--all-records`, `--plan-file`, `--source`, `--code-audit`,
`--audit`, `--piolium`, `--discover`, `--triage`, `--max-iterations`,
`--max-duration`, `--only`, `--skip`, and `--start-from`.

Authentication can be supplied with `--auth-config`, repeatable `--cookie`,
repeatable `-H/--header`, or `--login-curl`. `--browser-auth` enables the
browser-driven authentication phase.

Swarm has no checkpoint `--resume` flag. `--start-from` starts a newly invoked
pipeline at a selected phase; it does not restore an old run.

## Plan Files

Autopilot and swarm accept `--plan-file <path>`. A plan file can contain prose
followed by one or more raw HTTP requests. Split request blocks with a line
containing only `---`, or use fenced `http`/`request` blocks.

```text
Focus on cross-account order access.

GET /order/details?orderId=0254809 HTTP/2
Host: shop.example.com
Cookie: session=...
```

Autopilot uses the first request as its live seed and treats the rest as
context. Swarm treats every request as a seed. `--plan-file` cannot be combined
with `--input` or a positional/`--prompt` prompt.

## Audit

```bash
# Automatic audit-driver selection
vigolium agent audit --source . --intensity balanced

# Force one driver or run both
vigolium agent audit --source . --driver audit --agent codex
vigolium agent audit --source . --driver piolium
vigolium agent audit --source . --driver both --intensity deep
```

There is one audit subcommand; piolium is selected with `--driver piolium`.
`--driver auto` falls back to piolium only when the resolved audit coding CLI
is unavailable during preflight. `--driver both` runs both sequentially.

Use `--mode`, `--modes`, or `--intensity`, and inspect the current mode graph
with `--list-modes`. The command also supports stateless HTML output,
`--output-dir`, raw-result retention, and explicit audit-agent/BYOK flags.

See [Vigolium Audit](vigolium-audit.md), [Piolium](piolium-audit.md), and
[Audit BYOK](audit-byok.md).

## Triage

```bash
vigolium agent triage 42
vigolium agent triage          # open the finding picker
vigolium agent triage 42 --dry-run
```

Triage may re-probe the target. A confirmed result sets the finding status to
`triaged`; a false positive is downgraded to informational while retaining the
original evidence and appended reasoning.

## Olium

```bash
vigolium agent olium
vigolium ol -p "list the routes in pkg/server"
echo "summarize this repository" | vigolium olium -p -
```

Passing `-p/--prompt` selects non-interactive one-shot mode. There is no
`--headless` flag. A positional prompt seeds the interactive TUI.

Provider overrides include `--provider`, `--model`, `--base-url`,
`--llm-api-key`, `--oauth-cred`, and `--oauth-token`. The shipped default is
`openai-compatible`; configure its endpoint and model under
`agent.olium.custom_provider`, or choose another provider explicitly.

## Sessions and Transcripts

```bash
vigolium agent session
vigolium agent session --mode autopilot --limit 20
vigolium agent session <uuid> --full
```

Session directories default to `~/.vigolium/agent-sessions/` and are
configurable with `agent.sessions_dir`.

Olium engine runs record Pi-compatible JSONL transcripts. Direct olium and
autopilot write `transcript.jsonl`; query and swarm write per-phase
`transcript-<template>.jsonl` files, adding numeric suffixes for concurrent
same-template calls. Autopilot additionally exposes `--session-dir` and
`--transcript` convenience flags.

## Cross-Cutting Behavior

- `--source` is the source-code flag; legacy `--repo` flags are gone.
- Provider configuration lives under `agent.olium`.
- Built-in prompt templates are embedded; custom templates live under
  `~/.vigolium/prompts/`.
- Skills are materialized under `~/.vigolium/skills/` and can also be loaded
  from `.agents/skills/` or `.claude/skills/`.
- `-j/--json` on agent commands emits one compact completion summary to stdout
  while live progress is sent to stderr.

## REST API

The server exposes these agent operations unless started with `--no-agent`:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/agent/run/query` | Run query |
| `POST` | `/api/agent/run/autopilot` | Run autopilot |
| `POST` | `/api/agent/run/swarm` | Run swarm |
| `POST` | `/api/agent/run/audit` | Run unified audit |
| `POST` | `/api/agent/scans/:uuid/cancel` | Cancel an agent run |
| `GET` | `/api/agent/status/list` | List run states |
| `GET` | `/api/agent/status/:id` | Get one run state |
| `GET` | `/api/agent/sessions` | List sessions |
| `GET` | `/api/agent/sessions/:id` | Get session details |
| `GET` | `/api/agent/sessions/:id/logs` | Read or stream logs |
| `GET` | `/api/agent/sessions/:id/artifacts` | List artifacts |
| `GET` | `/api/agent/sessions/:id/artifacts/*` | Read an artifact |

Run endpoints support asynchronous `202 Accepted` responses and streaming
where documented. Provider selection for server workloads comes from the
server's `agent.olium` configuration rather than per-request provider fields.
