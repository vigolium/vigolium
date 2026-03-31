# BEGIN archon-audit
# archon-audit Audit Agents

IMPORTANT: When running a security audit using the `audit` skill, you MUST
spawn the following specialized subagents for the indicated phases. Do NOT
execute these phases inline — always delegate by calling `spawn_agent` with
the specified `agent_type`. The `audit` skill's inline phase instructions are
methodology references for those subagents, not instructions for you to
execute directly.

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| 1 -- Intelligence Gathering | `archon:advisory-hunter` | Advisories, architecture inventory, dependency intel |
| 2 -- Patch Bypass Analysis | `archon:patch-bypass-checker` | Per-patch bypass hypothesis testing (one agent per patch, concurrent) |
| 3 -- Knowledge Base | `archon:knowledge-base-builder` | Threat model, DFD/CFD slices, domain attack research (Modes A/B/C) |
| 4 -- Static Analysis | `archon:static-analyzer` | Sub-step 4.1 structural extraction + CodeQL/Semgrep security scan |
| 7 -- Deep Bug Hunting (Chamber) | `archon:chamber-synthesizer` | Orchestrates Review Chamber debate; spawns Ideator, Tracer, Advocate, and Variant Scout |
| 7 -- Deep Bug Hunting (Ideator) | `archon:attack-ideator` | Creative attack hypothesis generation using 8 attack modes |
| 7 -- Deep Bug Hunting (Tracer) | `archon:code-tracer` | Code path tracing and reachability analysis for hypotheses |
| 7 -- Deep Bug Hunting (Advocate) | `archon:devils-advocate` | Adversarial defense briefs searching all 5 protection layers |
| 7 -- Deep Bug Hunting (Variant Scout) | `archon:variant-scout` | Concurrent variant hunting during chamber debates |
| 9 -- Variant Analysis | `archon:variant-hunter` | Per-finding structural variant search using registry signatures |
| 10 -- PoC & Reporting (PoC) | `archon:poc-builder` | Per-finding PoC construction and real-environment validation |
| 10 -- PoC & Reporting (Report) | `archon:report-assembler` | Final consolidated audit report compilation and consistency checks |

Phases 5, 6, 8, and the orchestration portion of Phase 10 are executed inline without spawning a subagent.

For Phase 2, spawn one `archon:patch-bypass-checker` per security patch
concurrently rather than sequentially.

For Phase 7, the `archon:chamber-synthesizer` is the entry point. It
orchestrates the Review Chamber debate by messaging the Ideator, Tracer,
Advocate, and Variant Scout in structured rounds. Spawn one chamber per
threat cluster (DFD/CFD slice group), running chambers concurrently.

For Phases 9 and 10, spawn one `archon:variant-hunter` per confirmed
finding and one `archon:poc-builder` per confirmed finding, running
concurrently. Spawn a single `archon:report-assembler` after all PoC
builders complete.
---

# Lite Audit Mode (6-Phase Pipeline)

When the user asks for a "lite audit", "fast audit", or "quick audit", use the
streamlined 6-phase pipeline below instead of the full 11-phase audit. Lite mode
trades depth for speed while producing the same output format (`archon/audit-state.json`,
`archon/findings-draft/`, `archon/audit-report.md`) so results are compatible
with diff and status workflows.

## What Lite Mode Skips

| Dropped | Full Phase | Rationale |
|---------|-----------|-----------|
| Commit archaeology | P1 | Expensive git history analysis |
| Patch bypass analysis | P2 | Entire phase skipped |
| Custom SAST rules & structural extraction | P4 | Built-in suites are sufficient for speed runs |
| Contradiction Reasoner, Causal Verifier, Code Anatomist | P5 | Single simplified probe round |
| Spec gap analysis | P6 | RFC compliance is deep work |
| Code Tracer (chamber role) | P8 | Synthesizer does inline tracing |
| Cold verification | P9 Stage 2 | Devil's Advocate challenge is sufficient |
| Variant analysis | P10 | Codebase-wide variant hunting skipped |

## Lite Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| L1 -- Intelligence Gathering | `archon:advisory-hunter` | Advisories, architecture inventory, dependency intel (no commit archaeology) |
| L2 -- Knowledge Base / Threat Model | `archon:knowledge-base-builder` | Threat model, DFD/CFD slices — skip Modes B/C, skip Spec Gap & CodeQL Extraction targets |
| L3 -- Static Analysis | `archon:static-analyzer` | Built-in CodeQL suites + Semgrep Pro only — no custom rules, no structural extraction, no SpotBugs |
| L4 -- Lite Deep Probe (Strategist) | `archon:probe-strategist` | Single probe team for ALL attacker-input components — 1 round, no Code Anatomist |
| L4 -- Lite Deep Probe (Reasoner) | `archon:backward-reasoner` | Single round of Pre-Mortem + Abductive reasoning |
| L4 -- Lite Deep Probe (Harvester) | `archon:evidence-harvester` | Trace hypotheses, issue VALIDATED/INVALIDATED/NEEDS-DEEPER verdicts |
| L5 -- Review Chamber (Synthesizer) | `archon:chamber-synthesizer` | Single lite chamber — inline code tracing, max 2 debate rounds |
| L5 -- Review Chamber (Ideator) | `archon:attack-ideator` | Chain findings, max 7 hypotheses per batch |
| L5 -- Review Chamber (Advocate) | `archon:devils-advocate` | Defense briefs challenging each hypothesis |
| L6 -- PoC & Report (PoC) | `archon:poc-builder` | Per-finding PoC construction |
| L6 -- PoC & Report (Report) | `archon:report-assembler` | Final report with lite mode disclaimer |

Agents NOT used in lite mode: `archon:patch-bypass-checker`, `archon:code-tracer`,
`archon:enrichment-filter`, `archon:spec-gap-analyst`, `archon:variant-hunter`,
`archon:variant-scout`.

## Lite Pipeline

```
L1 (Intel) → L2 (KB/Threat Model) → [L3 (SAST) + L4 (Lite Probe)] parallel → L5 (Review + FP Check) → L6 (PoC + Report)
```

### Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | L1 -- Intelligence Gathering | -- |
| T2 | L2 -- Knowledge Base / Threat Model | T1 |
| T3 | L3 -- Static Analysis (built-in suites) | T2 |
| T4 | L4 -- Lite Deep Probe | T2 |
| T5 | L5 -- Review Chamber + FP Check | T3, T4 |
| T6 | L6 -- PoC Building + Report | T5 |

T3 and T4 unblock after T2 and run concurrently. T5 waits for both T3 and T4.

## Lite Phase Instructions

### Pre-Flight Check

If `archon/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "An audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed audit exists. Run fresh lite, run incremental diff, upgrade to full, or cancel?"

### Pre-Audit Setup

1. Create or checkout the `audit` branch: `git checkout audit 2>/dev/null || git checkout -b audit`
2. `mkdir -p archon/`
3. Initialize `archon/audit-state.json` — append a new entry with `"mode": "lite"`, `"model": "<model name>"`, `"agent_sdk": "<platform name>"`, and phases L1–L6 set to `pending`. Never remove earlier entries.
4. Update `.gitignore` with SAST artifact exclusions.

### L1: Intelligence Gathering

Spawn `archon:advisory-hunter`. Do NOT spawn `archon:patch-bypass-checker`.
Wait for completion. Update `audits[-1].phases.L1.status` to `complete`.

### L2: Knowledge Base / Threat Model

Spawn `archon:knowledge-base-builder` with additional instruction:
> "LITE MODE: Skip Domain Attack Research Modes B and C. Only run Mode A if the project is a library/plugin/protocol. Skip generating Spec Gap Candidates and Phase 4 CodeQL Extraction Targets sections. Focus on: Project Classification, Architecture Model, DFD/CFD Slices, Attack Surface, and Threat Model."

Wait for completion. Update L2 status.

### L3 + L4 (parallel)

Spawn concurrently:

**L3** — `archon:static-analyzer` with:
> "LITE MODE: Run built-in CodeQL security suites and Semgrep Pro engine only. No custom queries, no custom rules, no structural extraction, no SpotBugs, no agentic-actions-auditor."

**L4** — Single probe team (all 3 agents concurrently):
1. Read KB sections: DFD/CFD Slices, Attack Surface, Architecture Model
2. Group ALL attacker-input components into one probe team
3. `mkdir -p archon/probe-workspace/lite-probe/`
4. Spawn:
   - `archon:probe-strategist` (name: `probe-strategist-lite`) — 1 round only, skip Code Anatomist, write `probe-summary.md`
   - `archon:backward-reasoner` (name: `backward-reasoner-lite`) — single round Pre-Mortem + Abductive
   - `archon:evidence-harvester` (name: `evidence-harvester-lite`) — trace and verdict

Wait for all L3 + L4 agents. Perform inline enrichment: classify SAST findings as `likely security` / `likely correctness` / `likely environment-only`, drop non-security. Update L3, L4 status.

### L5: Review Chamber + FP Check

1. `mkdir -p archon/chamber-workspace/lite-chamber/`
2. Spawn single chamber (3 agents, no Code Tracer):
   - `archon:chamber-synthesizer` (name: `chamber-synth-lite`) — inline tracing, max 2 debate rounds
   - `archon:attack-ideator` (name: `ideator-lite`) — max 7 hypotheses per batch
   - `archon:devils-advocate` (name: `advocate-lite`) — defense briefs
3. After chamber closes, apply `fp-check` to all `archon/findings-draft/p8-*.md` with `Verdict: VALID`. No cold verifiers.

Update L5 status.

### L6: PoC Building + Report

1. Collect `Verdict: VALID` drafts, assign severity IDs (C1, H1, M1), drop Low.
2. Spawn one `archon:poc-builder` per finding concurrently.
3. Spawn `archon:report-assembler` with:
   > "LITE MODE: Add disclaimer in Executive Summary about skipped phases. Skip chamber workspace appendix. Reduce consistency checks to finding ID cross-reference and orphan detection only."

Update L6 status. Set `audits[-1].completed_at` and `audits[-1].status` to `complete`.

## Resume Logic

Read `audits[-1].phases` to find the first phase not `complete`:
- `failed` or `in_progress`: check if output artifacts exist and are complete. If yes, mark complete and advance. Otherwise delete partial output and re-run.
- `pending`: run normally.

Continue sequentially through L6.
# END archon-audit
