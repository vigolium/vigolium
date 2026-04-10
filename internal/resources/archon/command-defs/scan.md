---
description: Run a 6-phase security audit (scan mode) on the current repository. Skips deep probe rounds, variant analysis, spec gap analysis, and cold verification to deliver results faster. Resumes from the last checkpoint if an audit is already in progress.
argument-hint: "Optional: target path/scope"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
---

## Context

- Current branch: !`git branch --show-current`
- Existing audit state: !`cat archon/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Security directory: !`ls archon/ 2>/dev/null || echo "No security directory"`

## Your Task

Run a **scan** security audit of the current repository. Target scope: $ARGUMENTS

This is a streamlined 6-phase pipeline that trades depth for speed. It produces the same output format as the full audit (`/archon:deep`) so findings are compatible with `/archon:diff` and `/archon:status`.

### What Scan Mode Skips

Compared to the full 11-phase audit:

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

### Pre-Flight Check

If `archon/audit-state.json` exists, use `AskUserQuestion` to gate the next action:

- **Incomplete phases**: ask "An audit is already in progress. What would you like to do?" with options:
  - "Resume from last checkpoint"
  - "Start fresh (clears existing state)"
  - "Cancel"

- **All phases complete**: ask "A completed audit exists for this repository. What would you like to do?" with options:
  - "Run a fresh scan audit (clears existing state)"
  - "Run an incremental diff audit (/archon:diff)"
  - "Upgrade to deep audit (/archon:deep)"
  - "Cancel"

If the user chooses **Resume**: find the first phase not marked `complete` in the state file and continue from there (see [Resume Logic](#resume-logic)).

If the user chooses **Start fresh**: delete `archon/audit-state.json` and proceed with Pre-Audit Setup.

Do not proceed past the pre-flight check without an explicit user choice.

### Pre-Audit Setup

1. Create or checkout the `audit` branch: `git checkout audit 2>/dev/null || git checkout -b audit`
2. Create output directory: `mkdir -p archon/`
3. Initialize `archon/audit-state.json` by appending a new entry (or creating the file):
   ```json
   {
     "audits": [
       {
         "audit_id": "<ISO timestamp>",
         "commit": "<HEAD SHA from: git rev-parse HEAD>",
         "branch": "<current branch>",
         "repository": "<org/repo from: git remote get-url origin 2>/dev/null | sed 's|.*://[^/]*/||;s|.*:||;s|\\.git$||' — fallback: basename $(pwd)>",
         "mode": "scan",
         "model": "<model name, e.g. opus-4.6, gpt-5.3-codex, sonnet-4.6>",
         "agent_sdk": "<platform name, e.g. claude-code, codex, bytesec, opencode, traecli>",
         "started_at": "<ISO timestamp>",
         "completed_at": null,
         "status": "in_progress",
         "phases": {
           "L1": {"status": "pending"},
           "L2": {"status": "pending"},
           "L3": {"status": "pending"},
           "L4": {"status": "pending"},
           "L5": {"status": "pending"},
           "L6": {"status": "pending"}
         }
       }
     ]
   }
   ```
   If the file already exists, read it and append a new entry to the `audits` array rather than replacing the file. Never remove earlier entries.
4. Update `.gitignore`: add the following entries if not already present:
   ```
   archon/codeql-artifacts/db/
   archon/codeql-artifacts/flow-paths-raw.sarif
   archon/codeql-artifacts/*.bqrs
   archon/codeql-queries/
   archon/semgrep-rules/
   archon/semgrep-res/
   archon/probe-workspace/
   ```

---

## Scan Pipeline

```
L1 (Intel) → L2 (KB/Threat Model) → [L3 (SAST) + L4 (Lite Probe)] parallel → L5 (Review + FP Check) → L6 (PoC + Report)
```

### Task List

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | L1 -- Intelligence Gathering | -- |
| T2 | L2 -- Knowledge Base / Threat Model | T1 |
| T3 | L3 -- Static Analysis (built-in suites) | T2 |
| T4 | L4 -- Lite Deep Probe | T2 |
| T5 | L5 -- Review Chamber + FP Check | T3, T4 |
| T6 | L6 -- PoC Building + Report | T5 |

T3 and T4 unblock after T2 and run in parallel. T5 waits for both T3 and T4.

---

## Phase Execution

You are the orchestrator. Dispatch agents, monitor completion, aggregate results. Do NOT perform audit work yourself.

### Phase L1: Intelligence Gathering (T1)

Spawn `archon:advisory-hunter` with `run_in_background: true`.

**Scope**: advisory-hunter only. Do NOT spawn `commit-archaeologist` or `patch-bypass-checker`.

Wait for completion. Read the KB section it produces.

Update `archon/audit-state.json`: set `L1` status to `complete` with timestamp. Mark T1 complete.

### Phase L2: Knowledge Base / Threat Model (T2)

Spawn `archon:knowledge-base-builder` (foreground) with the following additional instruction in the prompt:

> "SCAN MODE: Skip Domain Attack Research Modes B and C. Only run Mode A if the project is a library/plugin/protocol. Skip generating `## Spec Gap Candidates` and `## Phase 4 CodeQL Extraction Targets` sections. Focus on: Project Classification, Architecture Model, DFD/CFD Slices, Attack Surface, and Threat Model."

Wait for completion. Mark T2 complete.

### Phase L3 + L4: Static Analysis + Lite Probe (parallel)

In a **single message**, spawn both with `run_in_background: true`:

#### L3: Static Analysis (T3)

Spawn `archon:static-analyzer` with the following additional instruction in the prompt:

> "SCAN MODE: Run built-in CodeQL security suites and Semgrep Pro engine only. Do NOT generate custom CodeQL queries or custom Semgrep rules. Do NOT run structural extraction (entry-points.json, sinks.json, call-graph-slices.json). Do NOT run SpotBugs or agentic-actions-auditor. Output SARIF results and write the `## Static Analysis Summary` section to the KB."

#### L4: Lite Deep Probe (T4)

Deploy a **single probe team** covering all components with attacker-controlled input. Only 3 agents (not 6):

1. Read `archon/knowledge-base-report.md` sections `## DFD/CFD Slices`, `## Attack Surface`, `## Architecture Model`.
2. Identify all components handling attacker-controlled input. Group them ALL into a single probe team.
3. `mkdir -p archon/probe-workspace/lite-probe/`
4. Spawn 3 agents with `run_in_background: true` in the same message as L3:

> **Probe Strategist** (coordinator):
> `subagent_type: "archon:probe-strategist"`, `name: "probe-strategist-lite"`
> Prompt: "SCAN MODE — You are the Probe Strategist for ALL components: <component list>. KB path: archon/knowledge-base-report.md. Workspace: archon/probe-workspace/lite-probe/. Your team: backward-reasoner-lite, evidence-harvester-lite. LITE RULES: (1) Skip Code Anatomist — read source directly. (2) Run only 1 round: SendMessage backward-reasoner-lite for Round 1, then SendMessage evidence-harvester-lite with all hypotheses. (3) Skip Contradiction Reasoner, Causal Verifier, Cross-Pollination, and Bayesian decision loop. (4) Write probe-summary.md when done."

> **Backward Reasoner** (single round):
> `subagent_type: "archon:backward-reasoner"`, `name: "backward-reasoner-lite"`
> Prompt: "You are the Backward Reasoner (scan mode) for all components. Wait for the Probe Strategist (probe-strategist-lite) to message you. Apply Pre-Mortem and Abductive reasoning to generate hypotheses. Single round — be thorough but concise."

> **Evidence Harvester** (trace and verdict):
> `subagent_type: "archon:evidence-harvester"`, `name: "evidence-harvester-lite"`
> Prompt: "You are the Evidence Harvester (scan mode). Wait for the Probe Strategist (probe-strategist-lite) to message you with hypotheses. Trace each hypothesis and issue VALIDATED / INVALIDATED / NEEDS-DEEPER verdicts with Fragility Scores."

Wait for all L3 and L4 agents to complete.

**Post-L3 Enrichment (inline)**: After static analyzer completes, perform a quick inline enrichment pass — for each SAST finding, classify as `likely security` / `likely correctness` / `likely environment-only` based on trust boundary crossing and attacker-controlled input. Drop `likely correctness` and `likely environment-only` findings. This replaces the full Phase 7 enrichment-filter agent.

Mark T3, T4 complete.

### Phase L5: Review Chamber + FP Check (T5)

1. `mkdir -p archon/chamber-workspace/lite-chamber/`
2. Read probe results: `cat archon/probe-workspace/lite-probe/probe-summary.md`
3. Read enriched SAST findings from KB `## Static Analysis Summary`.
4. Read `archon/knowledge-base-report.md` threat model sections.

Spawn a **single chamber** with 3 agents (not 4 — drop Code Tracer, Synthesizer does inline tracing):

> **Chamber Synthesizer** (lead):
> `subagent_type: "archon:chamber-synthesizer"`, `name: "chamber-synth-lite"`
> Prompt: "SCAN MODE — You are the Synthesizer for a single lite Review Chamber. Threat cluster: ALL identified threats. NNN range: s5-001 to s5-049. State: archon/audit-state.json. Workspace: archon/chamber-workspace/lite-chamber/debate.md. Deep Probe pre-validated hypotheses: <list from probe-summary.md>. LITE RULES: (1) You perform code tracing yourself instead of delegating to a Code Tracer. (2) Max 2 debate rounds total (1 ideation+challenge round, 1 optional follow-up for ambiguous findings). (3) Your Ideator is ideator-lite, Advocate is advocate-lite. Use SendMessage to coordinate."

> **Attack Ideator**:
> `subagent_type: "archon:attack-ideator"`, `name: "ideator-lite"`
> Prompt: "You are the Attack Ideator (scan mode). Wait for the Synthesizer (chamber-synth-lite) to message you. Deep Probe results are pre-seeded in debate.md — do NOT regenerate. Focus on chaining findings and cross-mode combinations. Max 7 hypotheses per batch."

> **Devil's Advocate**:
> `subagent_type: "archon:devils-advocate"`, `name: "advocate-lite"`
> Prompt: "You are the Devil's Advocate (scan mode). Wait for the Synthesizer (chamber-synth-lite) to message you. Write defense briefs challenging each hypothesis."

Wait for the chamber to close.

**Inline FP Check (replaces Phase 9)**: Apply `fp-check` skill to every `*.md` file under `archon/findings-draft/` with `Verdict: VALID` (the chamber synthesizer writes drafts with a `p8-` prefix regardless of the NNN range it was given, so do not filter by prefix — iterate the whole directory). Write verdicts back into drafts. **No cold verifiers** — the Devil's Advocate challenge is sufficient for scan mode.

Mark T5 complete.

### Phase L6: PoC Building + Report (T6)

**Finding consolidation**: Run the consolidation helper — it reads every draft in `archon/findings-draft/`, keeps the `Verdict: VALID` drafts with `Severity-Original` in {CRITICAL, HIGH, MEDIUM}, assigns deterministic severity-prefixed IDs (`C1`, `H1`, `M1`, …), creates `archon/findings/<ID>-<slug>/evidence/`, copies `draft.md` and `debate.md` (resolved from the draft's `Debate:` field), and emits a manifest.

```bash
python3 ~/.config/archon-audit/skills/audit/scripts/consolidate_drafts.py archon
```

The script writes `archon/findings-draft/consolidation-manifest.json`. If it exits non-zero, STOP — report the failure to the user and do not proceed to PoC building or report assembly.

**PoC Building**: Read `archon/findings-draft/consolidation-manifest.json`. For each entry in its `findings` array, spawn `archon:poc-builder` with `run_in_background: true`, passing the entry's `draft_path` as the finding draft path and its `id` as the assigned ID.

Wait for all PoC builders.

**Report Assembly**: Spawn `archon:report-assembler` (foreground) with the following additional instruction:

> "SCAN MODE: This is a scan audit report. Add a note in the Executive Summary: 'This report was generated using scan audit mode. Phases skipped: commit archaeology, patch bypass analysis, spec gap analysis, variant analysis, and cold verification. For comprehensive coverage, run a full audit with /archon:deep.' Skip the chamber workspace appendix. Reduce consistency checks to: finding ID cross-reference and orphan detection only."

**Post-audit cleanup**: After report-assembler completes and reports consistency checks passed, delete intermediate working artifacts:
```bash
rm -rf archon/findings-draft/
rm -rf archon/probe-workspace/
rm -rf archon/chamber-workspace/
rm -rf archon/codeql-artifacts/
rm -rf archon/codeql-queries/
rm -rf archon/semgrep-rules/
rm -rf archon/semgrep-res/
```
Retained: `archon/audit-state.json`, `archon/knowledge-base-report.md`, `archon/findings/`, `archon/final-audit-report.md`. If consistency checks failed, skip cleanup and report the failures to the user first.

Mark T6 complete. Update `audits[-1].completed_at` and `audits[-1].status` to `complete`. Print post-audit summary.

---

## Resume Logic

Read `audits[-1].phases` from `archon/audit-state.json` to find phase statuses. Find the first phase with status `pending`, `in_progress`, or `failed`:

- `failed` or `in_progress`: check whether the expected KB sections or output artifacts exist and appear complete. If so, mark `complete` and advance. Otherwise delete the partial output and re-run.
- `pending`: run normally.

Continue sequentially through L6 using the phase execution above.

---

## Lead Responsibilities

1. **Do not perform audit work.** Your role is coordination only.
2. Monitor via task completions and incoming agent messages.
3. If an agent fails, check `archon/findings-draft/` for partial output. Spawn replacement with remaining work only.
4. For the chamber: if it fails, check `archon/chamber-workspace/lite-chamber/debate.md` for partial findings already written.
5. If the probe team fails, read its workspace for partial summaries and pass whatever results exist to L5.
