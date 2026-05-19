---
description: Cross-agent reinvest mode. Re-verifies CRITICAL and HIGH findings from a prior audit using a DIFFERENT agent platform / model than the one that originally produced them, surfacing model-specific blind spots. Reads the existing archon/findings/ directory; does NOT re-run discovery, KB construction, probe, or chamber phases.
argument-hint: "Optional: comma-separated finding ID list to constrain the reinvest scope"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: reinvest
phases:
  - id: "1"
    title: Enumerate Findings
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: []
  - id: "2"
    title: Fan Out Wave-Verifier
    agent: cross-verifier
    requires_git: false
    parallel_with: []
    depends_on: ["1"]
  - id: "3"
    title: Consensus Summary
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: ["2"]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat archon/audit-context.md 2>/dev/null || echo "(none)"`
- Existing audit state: !`cat archon/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Existing findings: !`ls archon/findings/ 2>/dev/null | grep -E "^(C|H)[0-9]" | head -20 || echo "No CRIT/HIGH findings"`
- Prior reinvest waves: !`ls archon/findings/*/wave-*-verdict.md 2>/dev/null | wc -l | xargs -I{} echo "{} prior wave verdicts on disk"`

## Your Task

Re-verify the CRITICAL and HIGH findings in `archon/findings/` using a different agent platform than the one that produced them. The goal is to surface model-specific blind spots — Opus and Codex agree on most findings but diverge on a meaningful minority, and that disagreement is exactly what this mode exists to capture.

This mode does NOT run discovery, KB construction, static analysis, probe teams, or review chambers. It only spawns `archon:cross-verifier` per finding directory and surfaces the resulting consensus (or disagreement) in the final report.

### When to Use Reinvest

Run `/archon:reinvest` after a deep or balanced audit completes, then re-launch `archon-audit` from the SAME archon/ directory but with a different `--agent` flag than the original audit. Concrete flow:

```
# Original audit (produced archon/findings/ with C1, H1, H2, ...)
archon-audit run --mode deep --agent claude

# Cross-agent reinvest using Codex on top of those findings
archon-audit run --mode reinvest --agent codex
```

If `--agent` matches the agent_sdk recorded on `audits[-1]` of the prior run, this mode WILL still run, but the cross-agent value collapses to a same-agent retry. Use `AskUserQuestion` to confirm the user really wants that.

### Argument Handling

Parse `$ARGUMENTS`:

- **Comma-separated ID list (e.g., `C1,H1,H3`)**: reinvest only those findings.
- **Empty**: reinvest every CRITICAL and HIGH finding under `archon/findings/`. MEDIUM findings are intentionally excluded — they are too numerous and the per-finding cost of cross-verifier is too high to justify a mass second pass at MEDIUM.

### Pre-Flight Check

If `archon/findings/` does not exist or contains no `C*-*` / `H*-*` directories, exit with a message telling the user to run `/archon:deep` or `/archon:balanced` first.

If `archon/audit-state.json` does not exist, exit — this mode requires a prior audit to compute `parent_audit_id`.

Read `archon/audit-state.json`. The most recent audit's `agent_sdk` and `model` are the BASELINE this reinvest is comparing against. If the current `$AGENT_SDK` env var (set by the CLI) matches the baseline `agent_sdk`, prompt the user with `AskUserQuestion`:

> "The most recent audit ran on `<baseline-agent>` and you are reinvesting on the same platform. The cross-agent value of /archon:reinvest comes from swapping platforms (Claude ↔ Codex). What would you like to do?"
> Options:
>   - "Continue anyway (same-platform retry)"
>   - "Cancel — switch --agent to a different platform first"

Do not proceed past pre-flight without an explicit user choice.

### Wave Number Assignment

For each in-scope finding directory `archon/findings/<ID>-<slug>/`:

1. List existing `wave-*-verdict.md` files.
2. The next wave number is `max(existing) + 1`. If none exist, start at wave 2 (wave 1 implicitly being the original audit's independent-verifier / chamber verdict).

The wave number is per-finding, not global — different findings may carry different wave counts depending on how often each has been reinvested.

### Audit-State Append

Append a new entry to `audits[]` in `archon/audit-state.json` BEFORE dispatching wave-verifiers:

```json
{
  "audit_id": "<ISO timestamp>",
  "parent_audit_id": "<audits[-2].audit_id>",
  "mode": "reinvest",
  "model": "<current model>",
  "agent_sdk": "<current platform>",
  "wave_scope": ["C1", "H1", "H2"],
  "started_at": "<ISO timestamp>",
  "completed_at": null,
  "status": "in_progress"
}
```

This entry intentionally does not carry a `phases` map — reinvest is one-shot, not multi-phase.

## Reinvest Pipeline

### Step 1: Enumerate Findings

```bash
ls archon/findings/ | grep -E "^(C|H)[0-9]+-" | sort
```

If the user passed an explicit ID list, intersect it with the discovery result. Skip MEDIUM (`M*-*`) directories regardless.

### Step 2: Fan Out cross-verifier (batches of 3)

For each in-scope finding, spawn `archon:cross-verifier` with `run_in_background: true` in **batches of at most 3 background agents**. Each prompt contains:

- The finding directory path (`archon/findings/<ID>-<slug>/`)
- The wave number to assign (per-finding, computed in pre-flight)
- The current agent identity (model + sdk) — the verifier writes these into its output

Concrete prompt template:

> `archon:cross-verifier`
> "Cross-agent reinvest of `archon/findings/<ID>-<slug>/`. Assign wave number <N>. You are running under `<sdk>`/`<model>`. Read `report.md` and `evidence/`, restate the claim independently, trace from source, search for protections, attempt PoC reproduction if `poc.*` exists and is safely runnable, then read prior `wave-*-verdict.md` files (after forming your own view) and write `wave-<N>-verdict.md` with verdict CONFIRMED/DISPROVED/UNCERTAIN and explicit agreement/disagreement notes. Append `Wave-<N>-Verdict:` and `Wave-<N>-Agent:` lines to `draft.md` frontmatter. DO NOT modify report.md, poc.*, evidence/, or any other finding directory."

Wait for each batch to complete before launching the next.

### Step 3: Consensus Summary

After all wave-verifiers complete, walk every reinvested finding directory and compute the consensus across waves:

- **Stable CONFIRMED** — all waves agree CONFIRMED. The original verdict is corroborated.
- **Flipped to DISPROVED** — at least one wave returned DISPROVED. Surface this prominently — the original audit may have produced a false positive.
- **Mixed / UNCERTAIN** — waves disagree, or any wave returned UNCERTAIN. Needs human review.

Write the summary to `archon/reinvest-report.md`:

```markdown
# Cross-Agent Reinvest Report

**Reinvest audit_id:** <id>
**Parent audit:** <parent_audit_id> (<agent_sdk>/<model>)
**Reinvest agent:** <current sdk>/<current model>
**Findings reinvested:** <count> (C: <n>, H: <n>)

## Consensus

| ID | Slug | Original | Wave 2 | Wave 3 | … | Consensus |
|----|------|----------|--------|--------|---|-----------|

## Findings That Flipped

<for each DISPROVED wave verdict, a paragraph naming the decisive evidence the reinvest agent cited>

## Findings That Remain Uncertain

<list of findings where any wave returned UNCERTAIN, with a one-line summary of the ambiguity>
```

The original `archon/final-audit-report.md` is NOT modified by this mode. Reinvest produces its own delta report (`archon/reinvest-report.md`) so the original report remains the authoritative artefact for that audit's commit.

### Step 4: Stamp audit-state Complete

Update the reinvest entry in `audits[]`:

```json
{
  "completed_at": "<ISO timestamp>",
  "status": "complete",
  "consensus": {
    "stable_confirmed": <count>,
    "flipped_disproved": <count>,
    "uncertain": <count>
  }
}
```

## Lead Responsibilities

1. **Do not perform verification work yourself.** Your role is coordination only.
2. Burst cap: 3 concurrent wave-verifiers maximum.
3. If a cross-verifier fails, retry it ONCE for the failed finding only. If it fails again, record the failure in `reinvest-report.md` under a `## Failed Reinvests` section and move on.
4. The original `report.md`, `poc.*`, and `evidence/` are immutable in reinvest mode. If you observe a cross-verifier modifying them, treat that as an agent failure and surface it.
