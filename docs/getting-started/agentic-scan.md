# Agentic Scan

The **agentic scan** is Vigolium's AI-driven scanning mode. Where the
[native scan](native-scan.md) runs a deterministic, Go-based pipeline of
scanner modules, the agentic scan hands the wheel (or part of it) to an LLM
that reasons about the target, decides what to test, drives tools, and
reports findings as it confirms them.

This page is the quickest path from a fresh install to your first AI-driven
scan. For source-code review and whitebox audits, see
[Agentic Security Audit](agentic-security-audit.md).

## What you get

Two agentic-scan modes ship under `vigolium agent`:

| Mode | One-line | Best for |
|---|---|---|
| `autopilot` | Autonomous tool loop, optionally durable and resumable | Free-form pentest-style exploration |
| `swarm` | LLM plans → native scanner executes → optional triage | Structured, repeatable scans of a known target |

Both write findings to the same database used by the native scan, so the
usual `vigolium finding` / `/api/findings` surfaces work unchanged.

## Prerequisites

Agentic scans need exactly one configured LLM provider. The full provider
matrix and BYOK auth options live in
[Setting Up the Agent](setup-agent.md) — the short version:

```bash
# Cheapest path if you already have a ChatGPT Plus/Pro/Team sub.
codex login
vigolium config set agent.olium.provider openai-codex-oauth

# Sanity check — should print a model name.
vigolium ol -p 'what model are you running'
```

Anything that returns a model name from `vigolium ol -p` is wired correctly
— `autopilot` and `swarm` will reuse the same provider.

## 1. Autopilot — hand the agent a target

`autopilot` is the simplest agentic mode: an autonomous tool loop with shell,
file, HTTP, and browser access. It picks its own strategy and stops when it has
nothing productive left to do. With durable mode enabled it also maintains a
scratchpad and candidate ledger that can survive resume.

```bash
# Plain URL target.
vigolium agent autopilot -t https://example.com

# A specific request — paste a curl, raw HTTP, or Burp XML; auto-detected.
vigolium agent autopilot --input "curl -X POST -d 'q=test' https://example.com/api"

# Cap cost / time on CI-style runs.
vigolium agent autopilot -t https://example.com --intensity quick --max-duration 5m
```

The `--intensity` preset (`quick` / `balanced` / `deep`) tunes turn count,
duration limits, and how aggressively the agent explores.

## 2. Swarm — let the AI direct the native scanner

`swarm` keeps the AI in the planning seat and the native Go scanner in the
execution seat. The agent picks modules, optionally writes custom JS
extensions, the deterministic pipeline runs, and an optional triage pass
verifies findings.

```bash
# Targeted scan of a single request the LLM decides how to attack.
vigolium agent swarm -t https://example.com/api/users?id=1

# Full-scope scan — AI plans, native discovery + scanning execute.
vigolium agent swarm -t https://example.com --discover --triage
```

Useful flags:

- `--discover` — run native content discovery before scanning.
- `--triage` — AI reviews each finding to suppress false positives.
- `--vuln-type sqli` — focus on one bug class.
- `-m xss -m sqli` — restrict to specific scanner modules.

## 3. Add source code for a deeper read

If you have the codebase, point `--source` at it. Both modes pick up
filesystem read/write access and the agent can correlate code with traffic.

```bash
vigolium agent autopilot -t https://example.com --source ~/src/your-app
vigolium agent swarm -t https://example.com --source ~/src/your-app --code-audit --triage
```

Source code unlocks the dedicated audit pipeline — for the full whitebox
flow, see [Agentic Security Audit](agentic-security-audit.md).

## Choosing between autopilot and swarm

| You want... | Use |
|---|---|
| Creative, exploratory testing — let the agent improvise | `autopilot` |
| Structured, repeatable scans with optional verification | `swarm` |
| Source-aware code review alongside scanning | either, with `--source` |
| A single request hit hard from many angles | `swarm` with `--input` |
| Full-scope crawl + scan with AI planning | `swarm --discover --triage` |

## Where results go

Findings stream to the console and persist to the same SQLite database the
native scan uses:

```bash
vigolium finding                                # all findings
vigolium finding --agentic-scan <uuid>           # one agent run
vigolium agent session                           # past runs
```

Each run also writes a session directory under
`~/.vigolium/agent-sessions/<uuid>/` containing `runtime.log`, generated
extensions, and the raw agent output — handy when a scan looked off and you
want to read the agent's reasoning.

## REST API

If you'd rather drive scans from your own controller, the same modes are
exposed over HTTP:

```bash
vigolium server &

curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{"input": "https://example.com", "discover": true, "triage": true}'
```

Each call returns `202 Accepted` with an `agentic_scan_uuid`; poll
`/api/agent/status/:id` and pull session artifacts from
`/api/agent/sessions/:id/...` when it finishes.

## Next steps

- [Setting Up the Agent](setup-agent.md) — full provider matrix and BYOK.
- [Agentic Security Audit](agentic-security-audit.md) — whitebox source-code audits.
- [Autopilot](../agentic-scan/autopilot.md) — single-loop autonomous scan reference.
- [Swarm](../agentic-scan/swarm.md) — multi-phase AI-guided scan reference.
- [Agent Mode](../agentic-scan/agent-mode.md) — every `vigolium agent` subcommand at a glance.
