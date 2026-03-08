# Agent Mode Improvement Plan

## Current State

### `vigolium agent` (Single Run)
Takes a prompt template + optional source code repo, enriches it with context (previous findings, endpoints, module list, scan stats from the database), sends it to an AI backend (Claude/Gemini/custom CLI via pipe or ACP protocol), parses structured JSON output (findings or HTTP records), and ingests results into the database.

### `vigolium agent loop` (Removed)
Previously ran an analyze → scan → repeat cycle with hardcoded iteration logic.
Removed in favor of `vigolium agent autopilot` which gives the agent full
autonomy to run CLI commands via terminal and decide its own workflow.

**Key limitation of the old approach**: The agent relied on pre-defined prompt
templates and a fixed analyze→retest loop. The "intelligence" was entirely in
the prompt template — the loop engine itself was mechanical.

---

## Goal

An autonomous mode: give it a URL (or raw request) → it automatically decides what to do → scans → analyzes results → decides next steps → repeats until convergence.

---

## Options

### Option A: "Auto Mode" — Enhanced Loop with Decision Engine

Extend the existing loop engine with a **planning step**:
1. **Recon**: Run discovery/spidering automatically on the URL
2. **Plan**: Agent sees discovered endpoints + tech fingerprint → outputs a **scan plan** (which modules to run, which endpoints to focus on, parameter priorities)
3. **Execute**: Run the planned scans
4. **Analyze**: Agent reviews findings → decides: retest with different payloads? Explore adjacent endpoints? Escalate a finding?
5. **Repeat** until convergence

Builds on what exists — adds a "plan" output schema and a smarter loop controller.

**Pros**:
- Lowest implementation effort — builds directly on existing `loop.go` + prompt templates
- Predictable execution — the loop controller is still deterministic, agent only influences *what* to scan
- Easy to debug — each iteration has a clear plan→execute→review cycle you can log
- Works with any AI backend (pipe mode) — no tool-calling requirement
- Cost-efficient — fewer agent calls, each one is batched (plan N scans at once)

**Cons**:
- Agent can't react in real-time — it plans, waits for all scans to finish, then reviews. Can't pivot mid-execution
- Rigid phase boundaries — if a finding in scan 3 should change the plan for scan 4, too late
- Prompt bloat — as iterations grow, you're stuffing more and more context (previous findings, endpoints, plans) into the prompt
- Limited adaptability — the set of "actions" the agent can plan is whatever you hardcode in the output schema
- Template maintenance burden — you need carefully crafted templates for plan/review/retest phases

**Best use cases**:
- Scheduled/batch scanning where you want automated but auditable runs
- CI/CD integration — run on deploy, get a report, no human in the loop
- Teams that want guardrails — the agent suggests, the engine controls execution
- Budget-conscious — minimizes AI API calls

---

### Option B: "Autopilot Mode" — Agent as Orchestrator with Tool Use

Give the agent **tool-calling** capabilities (not just stdin→stdout):
- `scan_url(url, modules, options)` — run targeted scans
- `discover(url)` — run discovery phase
- `query_findings(filters)` — check what's been found
- `query_endpoints(filters)` — see discovered endpoints
- `ingest_request(method, url, headers, body)` — feed custom requests

The agent becomes a **ReAct-style loop**: think → call tool → observe result → think → call tool...

**Pros**:
- Most flexible — agent can dynamically adapt strategy based on each individual result
- Real-time pivoting — finds SQLi on `/api/users`? Immediately tests `/api/admin` with same technique
- Natural fit for Claude — tool use is a first-class capability, structured and reliable
- Composable — adding a new capability is just adding a new tool, no template rewrite
- Rich reasoning — agent explains *why* it's taking each action, full audit trail
- Can handle unexpected situations — weird responses, WAFs, auth flows, the agent reasons through them

**Cons**:
- Higher AI API cost — many back-and-forth tool calls per session (could be 20-50+ calls)
- Latency — each think→act cycle is a round-trip to the AI API
- Harder to predict execution time and cost — depends on what the agent decides to do
- Needs tool-calling support in backend — rules out simple pipe-mode agents
- Risk of loops/rabbit holes — agent might fixate on one endpoint or retry failing scans
- Harder to test deterministically — same input can produce different scan paths

**Best use cases**:
- Interactive/exploratory pentesting — "scan this app and find what you can"
- Complex apps with auth flows — agent can reason about login→session→authorized endpoints
- Bug bounty workflows — where creative, adaptive scanning matters
- Single-target deep dives — when thoroughness matters more than speed
- When source code is available — agent can correlate code patterns with runtime behavior

---

### Option C: "Full Auto" — Multi-Phase Pipeline with Agent Checkpoints

Fixed pipeline (discover → plan → scan → triage → retest → report) where the agent only intervenes at specific checkpoints to make decisions.

```
URL input
  → Phase 1: Fingerprint & discover (no agent needed, use existing deparos)
  → Phase 2: Agent plans attack strategy based on discovery results
  → Phase 3: Run scans (existing executor)
  → Phase 4: Agent triages findings, identifies false positives, suggests follow-ups
  → Phase 5: Targeted re-scanning based on agent recommendations
  → Converge & report
```

**Pros**:
- Most predictable and production-ready — fixed phases, clear SLAs on each
- Best performance — heavy lifting (discovery, scanning) runs natively without AI overhead
- Lowest total AI cost — agent only called 2-3 times per run (plan, triage, follow-up)
- Easiest to parallelize — scanning phase can fan out across modules/endpoints independently
- Robust error handling — each phase has well-defined inputs/outputs, failures are contained
- Easiest to explain to users/stakeholders — "it does discovery, then scanning, then AI triage"

**Cons**:
- Least adaptive — pipeline structure is rigid, can't skip phases or reorder dynamically
- Agent has limited context at each checkpoint — only sees what that phase provides
- Complex apps may need non-linear workflows — hard to express in a fixed pipeline
- More upfront design work — need to define phase boundaries, data flow between phases, checkpoint schemas
- Agent decisions at triage may come too late — if the scan missed something, you have to loop the whole pipeline

**Best use cases**:
- Enterprise/production scanning — predictable runtime, consistent output format
- Large-scale scanning (many targets) — pipeline parallelizes well across targets
- Compliance workflows — fixed phases map cleanly to audit requirements
- Teams that don't trust AI autonomy — agent advises, pipeline controls
- When you need SLAs — "scan completes in X minutes" is achievable with fixed phases

---

## Side-by-Side Summary

| | **A: Enhanced Loop** | **B: Tool Use** | **C: Pipeline** |
|---|---|---|---|
| Implementation effort | Low | Medium | Medium-High |
| AI API cost per scan | Low (3-5 calls) | High (20-50+ calls) | Lowest (2-3 calls) |
| Adaptability | Medium | High | Low |
| Predictability | Medium | Low | High |
| Debugging ease | Medium | Medium (good audit trail) | High |
| Backend requirements | Any | Tool-calling capable | Any |
| Best for | Batch/CI | Deep dives/exploration | Enterprise/scale |

---

## Recommended Approach

**Start with A, design toward B:**

1. **Ship Option A first** — add a `plan` output schema to the loop, let the agent choose modules/focus areas between iterations. Immediately useful.

2. **Build the tool interface for B** — define the tools (`scan_url`, `discover`, `query_findings`, etc.) as a clean internal API. This is useful regardless — it also improves A's plan execution.

3. **Wire up B as a separate mode** — `vigolium agent autopilot --target URL`. Uses the same tools but lets the agent call them directly. Power-user mode.

4. **Option C emerges naturally** — compose the tools from B into a fixed pipeline with agent checkpoints for managed/enterprise mode.
