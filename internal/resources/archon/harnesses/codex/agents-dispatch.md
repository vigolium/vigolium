# BEGIN archon-audit
# archon-audit Audit Agents

## Mode Selection (CRITICAL — read the user prompt first)

The user's prompt specifies the audit mode. Follow EXACTLY one pipeline:

- **"Full deep mode"** or **"all 10 phases"** → use **Full 10-Phase Audit** below
- **"Scan mode: L1-L6"** → use **Scan/Lite Audit Mode** (6 phases) below
- **"Lite mode: Q0-Q2"** → use **Scan/Lite Audit Mode** (6 phases) below
- If no mode is specified → default to **Full 10-Phase Audit**

Do NOT use the lite/scan pipeline when the user requests a full or deep audit.

## SpawnAgent Rules (CRITICAL — prevents truncation errors)

**Rule 1: Short prompts.** The `prompt` argument MUST be **under 300 characters**. Each agent already has its full methodology in its own instructions — do NOT paste phase details, methodology, or audit context into the spawn prompt. Only pass the phase ID, output path, and a one-line mode qualifier.

**Rule 2: ONE agent per turn.** NEVER spawn more than one agent in a single turn. Spawn one agent, wait for it to complete, THEN spawn the next. This applies even when the plan says "concurrently" — on Codex, run them sequentially to avoid output truncation.

**Rule 3: Sequential fan-out.** When a phase requires spawning N agents (e.g., one per finding), loop through them one at a time: spawn → wait → spawn → wait. Do NOT batch multiple SpawnAgent calls.

Example good spawn prompts:
- `"P1: Run intelligence gathering. Output: archon/knowledge-base-report.md"`
- `"P3: Build knowledge base (full mode, all research modes). Output: archon/knowledge-base-report.md"`
- `"P9: Variant analysis for finding p8-M1. Output: archon/findings-draft/"`

If you put long instructions in the spawn prompt or spawn multiple agents at once, it WILL be truncated and the agents will fail.

## Output Chunking (IMPORTANT for Codex)

All agents MUST write output incrementally to avoid hitting the per-turn output cap:
- Write findings one file at a time (one `archon/findings-draft/` file per tool call)
- Write report sections incrementally — never accumulate an entire report in a single write
- When writing `archon/knowledge-base-report.md`, write each `##` section as a separate file write
- Keep individual file write payloads under 3 KB — split into multiple writes if needed
- Prefer `exec` with `cat >> file` for appending over rewriting entire files

---

# Full 10-Phase Audit (Deep Mode)

When the user requests a "deep audit", "full audit", or the prompt contains "Full deep mode" or
"all 10 phases", execute ALL 10 phases below. Do NOT skip phases or fall back to lite mode.

## Full Audit Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| P1 -- Intelligence Gathering | `archon:advisory-hunter` | Advisories, architecture inventory, dependency intel |
| P2 -- Patch Bypass Analysis | `archon:patch-bypass-checker` | Per-patch bypass hypothesis testing (one agent per patch, concurrent) |
| P3 -- Knowledge Base | `archon:knowledge-base-builder` | Threat model, DFD/CFD slices, domain attack research (Modes A/B/C) |
| P4 -- Static Analysis | `archon:static-analyzer` | Sub-step 4.1 structural extraction + CodeQL/Semgrep security scan |
| P5 -- Enrichment | (inline) | Classify findings as security/correctness/environment-only |
| P6 -- Spec Gap Analysis | (inline) | RFC/spec compliance gap analysis |
| P7 -- Deep Bug Hunting (Chamber) | `archon:chamber-synthesizer` | Orchestrates Review Chamber debate |
| P7 -- Deep Bug Hunting (Ideator) | `archon:attack-ideator` | Creative attack hypothesis generation using 8 attack modes |
| P7 -- Deep Bug Hunting (Tracer) | `archon:code-tracer` | Code path tracing and reachability analysis |
| P7 -- Deep Bug Hunting (Advocate) | `archon:devils-advocate` | Adversarial defense briefs searching all 5 protection layers |
| P7 -- Deep Bug Hunting (Variant Scout) | `archon:variant-scout` | Concurrent variant hunting during chamber debates |
| P8 -- FP Check | (inline) | False positive elimination using `fp-check` skill |
| P9 -- Variant Analysis | `archon:variant-hunter` | Per-finding structural variant search |
| P10 -- PoC & Reporting (PoC) | `archon:poc-builder` | Per-finding PoC construction |
| P10 -- PoC & Reporting (Report) | `archon:report-assembler` | Final consolidated audit report |

## Full Pipeline

```
P1 (Intel) → P2 (Patch Bypass) → P3 (KB) → [P4 (SAST) + P6 (Spec Gaps)] parallel
→ P5 (Enrichment) → P7 (Chambers) → P8 (FP Check) → P9 (Variants) → P10 (PoC + Report)
```

## Full Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | P1 -- Intelligence Gathering | -- |
| T2 | P2 -- Patch Bypass Analysis | T1 |
| T3 | P3 -- Knowledge Base | T2 |
| T4 | P4 -- Static Analysis | T3 |
| T5 | P6 -- Spec Gap Analysis | T3 |
| T6 | P5 -- Enrichment | T4 |
| T7 | P7 -- Deep Bug Hunting (Chambers) | T5, T6 |
| T8 | P8 -- FP Check | T7 |
| T9 | P9 -- Variant Analysis | T8 |
| T10 | P10 -- PoC & Reporting | T9 |

T4 and T5 unblock after T3 and run concurrently. T7 waits for both T5 and T6.

## Full Phase Instructions

### Pre-Flight Check

If `archon/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "An audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed audit exists. Run fresh, run incremental diff, or cancel?"

### Pre-Audit Setup

1. Create or checkout the `audit` branch: `git checkout audit 2>/dev/null || git checkout -b audit`
2. `mkdir -p archon/`
3. Initialize `archon/audit-state.json` — append a new entry with `"mode": "full"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, and phases P1–P10 set to `pending`. Never remove earlier entries.
4. Update `.gitignore` with SAST artifact exclusions.

### P1: Intelligence Gathering

Spawn `archon:advisory-hunter` with prompt:
> `"P1: Run intelligence gathering. Output: archon/knowledge-base-report.md"`

Wait for completion. Update `audits[-1].phases.P1.status` to `complete`.

### P2: Patch Bypass Analysis

For each security patch found in P1, spawn one `archon:patch-bypass-checker` **sequentially** (one at a time, wait before spawning next) with prompt:
> `"P2: Analyze patch <CVE-ID>. Output: archon/knowledge-base-report.md"`

Update P2 status after all complete.

### P3: Knowledge Base

Spawn `archon:knowledge-base-builder` with prompt:
> `"P3: Build knowledge base (full mode, all research modes A/B/C). Write each ## section separately to archon/knowledge-base-report.md"`

The KB builder MUST write each `##` section as a separate file append (using `cat >>`) to avoid hitting the output token cap. Do NOT accumulate the entire KB in memory.

Wait for completion. Update P3 status.

### P4: Static Analysis

Spawn `archon:static-analyzer` with prompt:
> `"P4 FULL MODE: structural extraction + CodeQL + Semgrep Pro + custom rules. Output: archon/"`

Wait for completion. Update P4 status.

### P6: Spec Gap Analysis

Execute inline (no subagent). Read `archon/knowledge-base-report.md` sections on specs/RFCs. Use `spec-to-code-compliance` skill. Focus on parsing, normalization, sanitization, canonicalization, and state-machine compliance.

Update P6 status.

### P5: Enrichment

Execute inline (no subagent). For each SAST finding from P4:
1. Classify as: likely security / likely correctness / likely environment-only
2. Drop non-security findings and Low severity
3. Cross-reference with CodeQL call-graph slices
4. Update `archon/knowledge-base-report.md` with enriched conclusions.

Update P5 status.

### P7: Deep Bug Hunting (Review Chambers)

1. Group findings by threat cluster (DFD/CFD slice groups)
2. For each cluster, spawn chamber agents **one at a time** (sequential, not concurrent):
   a. Spawn `archon:chamber-synthesizer` with prompt: `"P7: Orchestrate chamber for cluster <name>. Output: archon/chamber-workspace/<id>/"`
      Wait for completion.
   b. Spawn `archon:attack-ideator` with prompt: `"P7: Generate hypotheses for cluster <name>. Output: archon/chamber-workspace/<id>/debate.md"`
      Wait for completion.
   c. Spawn `archon:code-tracer` with prompt: `"P7: Trace evidence for cluster <name>. Output: archon/chamber-workspace/<id>/debate.md"`
      Wait for completion.
   d. Spawn `archon:devils-advocate` with prompt: `"P7: Challenge hypotheses for cluster <name>. Output: archon/chamber-workspace/<id>/debate.md"`
      Wait for completion.
   e. Spawn `archon:variant-scout` with prompt: `"P7: Hunt variants for cluster <name>. Output: archon/chamber-workspace/<id>/"`
      Wait for completion.
3. If multiple clusters, process them sequentially too.
4. Each chamber produces finding drafts in `archon/findings-draft/`.

Update P7 status.

### P8: FP Check

Execute inline. Apply `fp-check` skill to all `archon/findings-draft/p8-*.md` with `Verdict: VALID`.
Only CRITICAL and HIGH severity findings get cold verification.
Update P8 status.

### P9: Variant Analysis

For each confirmed finding, spawn one `archon:variant-hunter` **sequentially** (one at a time):
> `"P9: Variant analysis for finding <finding-id>. Output: archon/findings-draft/"`

Spawn one, wait for completion, then spawn the next. Update P9 status after all complete.

### P10: PoC & Reporting

1. Collect `Verdict: VALID` drafts, assign severity IDs (C1, H1, M1, L1).
2. For each finding, spawn one `archon:poc-builder` **sequentially** (one at a time):
   > `"P10: Build PoC for finding <finding-id>. Output: archon/findings-draft/"`
   Spawn one, wait for completion, then spawn the next.
3. After all PoC builders complete, spawn a single `archon:report-assembler` with prompt:
   > `"P10: Compile final audit report. Output: archon/final-audit-report.md"`

Update P10 status. Set `audits[-1].completed_at` and `audits[-1].status` to `complete`.

## Full Mode Resume Logic

Read `audits[-1].phases` to find the first phase not `complete`:
- `failed` or `in_progress`: check if output artifacts exist and are complete. If yes, mark complete and advance. Otherwise delete partial output and re-run.
- `pending`: run normally.

Continue sequentially through P10.

---

# Scan/Lite Audit Mode (6-Phase Pipeline)

When the user asks for a "scan", "lite audit", "fast audit", or "quick audit", or the prompt
contains "Scan mode: L1-L6" or "Lite mode", use this streamlined 6-phase pipeline. Lite mode
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

### Lite Phase Dependencies

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
3. Initialize `archon/audit-state.json` — append a new entry with `"mode": "lite"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, and phases L1–L6 set to `pending`. Never remove earlier entries.
4. Update `.gitignore` with SAST artifact exclusions.

### L1: Intelligence Gathering

Spawn `archon:advisory-hunter` with prompt:
> `"L1 LITE: Run intelligence gathering, no commit archaeology. Output: archon/knowledge-base-report.md"`

Do NOT spawn `archon:patch-bypass-checker`.
Wait for completion. Update `audits[-1].phases.L1.status` to `complete`.

### L2: Knowledge Base / Threat Model

Spawn `archon:knowledge-base-builder` with prompt:
> `"L2 LITE: Skip Modes B/C, skip Spec Gap & CodeQL targets. Output: archon/knowledge-base-report.md"`

Wait for completion. Update L2 status.

### L3: Static Analysis

Spawn `archon:static-analyzer` with prompt:
> `"L3 LITE: Built-in CodeQL + Semgrep Pro only. No custom rules, no extraction. Output: archon/"`

Wait for completion. Update L3 status.

### L4: Lite Deep Probe

1. Read KB sections: DFD/CFD Slices, Attack Surface, Architecture Model
2. Group ALL attacker-input components into one probe team
3. `mkdir -p archon/probe-workspace/lite-probe/`
4. Spawn agents **one at a time** (sequential):
   a. Spawn `archon:probe-strategist` with prompt: `"L4 LITE: 1 round, no Code Anatomist. Output: archon/probe-workspace/lite-probe/probe-summary.md"`
      Wait for completion.
   b. Spawn `archon:backward-reasoner` with prompt: `"L4 LITE: Single round Pre-Mortem + Abductive. Output: archon/probe-workspace/lite-probe/"`
      Wait for completion.
   c. Spawn `archon:evidence-harvester` with prompt: `"L4 LITE: Trace and verdict. Output: archon/probe-workspace/lite-probe/"`
      Wait for completion.

Perform inline enrichment: classify SAST findings as `likely security` / `likely correctness` / `likely environment-only`, drop non-security. Update L4 status.

### L5: Review Chamber + FP Check

1. `mkdir -p archon/chamber-workspace/lite-chamber/`
2. Spawn chamber agents **one at a time** (sequential):
   a. Spawn `archon:chamber-synthesizer` with prompt: `"L5 LITE: Orchestrate lite chamber, inline tracing, max 2 rounds. Output: archon/chamber-workspace/lite-chamber/"`
      Wait for completion.
   b. Spawn `archon:attack-ideator` with prompt: `"L5 LITE: Generate hypotheses, max 7 per batch. Output: archon/chamber-workspace/lite-chamber/debate.md"`
      Wait for completion.
   c. Spawn `archon:devils-advocate` with prompt: `"L5 LITE: Defense briefs. Output: archon/chamber-workspace/lite-chamber/debate.md"`
      Wait for completion.
3. After chamber closes, apply `fp-check` inline to all `archon/findings-draft/p8-*.md` with `Verdict: VALID`. No cold verifiers.

Update L5 status.

### L6: PoC Building + Report

1. Collect `Verdict: VALID` drafts, assign severity IDs (C1, H1, M1), drop Low.
2. For each finding, spawn one `archon:poc-builder` **sequentially** with prompt:
   > `"L6 LITE: Build PoC for finding <finding-id>. Output: archon/findings-draft/"`
   Spawn one, wait, then next.
3. After all PoC builders complete, spawn `archon:report-assembler` with prompt:
   > `"L6 LITE: Compile report with skipped-phases disclaimer. Output: archon/final-audit-report.md"`

Update L6 status. Set `audits[-1].completed_at` and `audits[-1].status` to `complete`.

## Lite Resume Logic

Read `audits[-1].phases` to find the first phase not `complete`:
- `failed` or `in_progress`: check if output artifacts exist and are complete. If yes, mark complete and advance. Otherwise delete partial output and re-run.
- `pending`: run normally.

Continue sequentially through L6.
# END archon-audit
