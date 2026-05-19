---
description: Run a 9-phase security audit (balanced mode) on the current repository. Skips commit archaeology, patch-bypass, the dedicated authorization phase, custom SAST/structural extraction, multi-round probing, and the deep chamber's inline cross-service taint reasoning + variant expansion to deliver results faster. Resumes from the last checkpoint if an audit is already in progress.
argument-hint: "Optional: target path/scope"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: balanced
phases:
  - id: "B1"
    title: Intelligence Pass
    agent: cve-scout
    requires_git: false
    parallel_with: []
    depends_on: []
  - id: "B2"
    title: Threat Model
    agent: threat-modeler
    requires_git: false
    parallel_with: []
    depends_on: ["B1"]
  - id: "B3"
    title: Code Scan
    agent: code-scanner
    requires_git: false
    parallel_with: ["B4"]
    depends_on: ["B2"]
  - id: "B4"
    title: Targeted Probe
    agent: probe-lead
    requires_git: false
    parallel_with: ["B3"]
    depends_on: ["B2"]
  - id: "B5"
    title: Review Panel
    agent: review-adjudicator
    requires_git: false
    parallel_with: []
    depends_on: ["B3", "B4"]
  - id: "B6"
    title: Intent Reconciliation
    agent: context-reviewer
    requires_git: false
    parallel_with: []
    depends_on: ["B5"]
  - id: "B7"
    title: PoC Authoring
    agent: poc-author
    requires_git: false
    parallel_with: []
    depends_on: ["B6"]
  - id: "B8"
    title: Finding Finalize
    agent: finding-writer
    requires_git: false
    parallel_with: []
    depends_on: ["B7"]
  - id: "B9"
    title: Report Compose
    agent: report-composer
    requires_git: false
    parallel_with: []
    depends_on: ["B8"]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat archon/audit-context.md 2>/dev/null || echo "(none)"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree (plain directory target)"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "No git branch (plain directory target)"`
- Existing audit state: !`cat archon/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Security directory: !`ls archon/ 2>/dev/null || echo "No security directory"`

## Your Task

Run a **balanced** security audit of the current repository. Target scope: $ARGUMENTS

This is a streamlined 9-phase pipeline that trades depth for speed. It produces the same output format as the full audit (`/archon:deep`) so findings are compatible with `/archon:diff` and `/archon:status`.

This mode supports auditing a plain source folder with no `.git` directory or local history.

### What Balanced Mode Skips

Compared to the full 12-phase deep audit (`/archon:deep`):

| Dropped | Deep phase | Rationale |
|---------|-----------|-----------|
| Commit archaeology | D2 | Expensive git-history analysis |
| Patch bypass analysis | D3 | Entire phase skipped |
| Custom SAST rules & structural extraction | D5 | Built-in suites are sufficient for speed runs |
| Cross-service edge enumeration (`cross-service-edges.json`) | D5 | Folded into deep's D5 structural pass, which balanced skips — balanced assumes single-service |
| Contradiction Reasoner + multi-round probe | D6 | Single simplified probe round |
| Dedicated Authorization Audit (authz-matrix) | D7 | Chamber Ideator covers authz inline |
| Code Tracer chamber role | D8 | Synthesizer does inline tracing |
| Inline cross-service taint reasoning | D8 | Deep folds this into the D8 chamber Ideator; balanced's lighter chamber skips it (no `cross-service-edges.json` is produced anyway) |
| Inline variant expansion | D8 | Deep folds same-pattern variant hunting into the D8 chamber Code Tracer; balanced has no Code Tracer, so it is skipped |

Cross-service taint and variant analysis are no longer standalone deep phases — deep folds them into its D5 structural pass and D8 Review Chamber. Balanced skips them because it skips structural extraction and runs a lighter chamber without a Code Tracer.

Balanced still runs an inline FP tail in its Review Chamber phase: fp-check, a CRITICAL-only cold-verify pass (matching deep), and the triage pass. It also runs the dedicated Intent Reconciliation phase (B6) so documented-intentional behavior is reconciled before any PoC effort.

### Pre-Flight Check

If `archon/audit-state.json` exists, use `AskUserQuestion` to gate the next action:

- **Incomplete phases**: ask "An audit is already in progress. What would you like to do?" with options:
  - "Resume from last checkpoint"
  - "Start fresh (clears existing state)"
  - "Cancel"

- **All phases complete**: ask "A completed audit exists for this repository. What would you like to do?" with options:
  - "Run a fresh balanced audit (clears existing state)"
  - "Run an incremental diff audit (/archon:diff)"
  - "Upgrade to deep audit (/archon:deep)"
  - "Cancel"

If the user chooses **Resume**: find the first phase not marked `complete` in the state file and continue from there (see [Resume Logic](#resume-logic)).

If the user chooses **Start fresh**: delete `archon/audit-state.json` and proceed with Pre-Audit Setup.

Do not proceed past the pre-flight check without an explicit user choice.

### Pre-Audit Setup

1. Detect whether Git history is available:
   ```bash
   if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
     export ARCHON_GIT_AVAILABLE=true
   else
     export ARCHON_GIT_AVAILABLE=false
   fi
   ```
2. **Do NOT switch branches.** Stay on the current branch for the entire audit. Do NOT run `git checkout`, `git switch`, `git branch`, `git commit`, `git add`, or `git push` against the target repo at any point. The audit writes all artifacts under `archon/` (untracked) — the user controls staging and commits. If `ARCHON_GIT_AVAILABLE=false`, continue auditing the directory in place; do NOT initialize a new repo just for the audit.
3. Create output directory: `mkdir -p archon/`
4. Initialize `archon/audit-state.json` by appending a new entry (or creating the file):
   ```json
   {
     "audits": [
       {
         "audit_id": "<ISO timestamp>",
         "commit": "<HEAD SHA from: git rev-parse HEAD, or null / \"nogit\" when Git is unavailable>",
         "branch": "<current branch, or \"nogit\">",
         "repository": "<value of $ARCHON_REPOSITORY env var, pre-computed by the CLI from git remote / package manifests / basename — substitute the literal string before writing>",
         "history_available": "<true if Git worktree detected, else false>",
         "mode": "balanced",
         "model": "<model name, e.g. opus-4.6, gpt-5.3-codex, sonnet-4.6>",
         "agent_sdk": "<platform name, e.g. claude-code, codex>",
         "started_at": "<ISO timestamp>",
         "completed_at": null,
         "status": "in_progress",
         "phases": {
           "B1": {"status": "pending"},
           "B2": {"status": "pending"},
           "B3": {"status": "pending"},
           "B4": {"status": "pending"},
           "B5": {"status": "pending"},
           "B6": {"status": "pending"},
           "B7": {"status": "pending"},
           "B8": {"status": "pending"},
           "B9": {"status": "pending"}
         }
       }
     ]
   }
   ```
   If the file already exists, read it and append a new entry to the `audits` array rather than replacing the file. Never remove earlier entries.
5. If `ARCHON_GIT_AVAILABLE=true`, update `.gitignore`: add the following entries if not already present:
   ```
   archon/codeql-artifacts/db/
   archon/codeql-artifacts/flow-paths-raw.sarif
   archon/codeql-artifacts/*.bqrs
   archon/codeql-queries/
   archon/semgrep-rules/
   archon/semgrep-res/
   archon/probe-workspace/
   ```
   If `ARCHON_GIT_AVAILABLE=false`, skip `.gitignore` edits.

---

## Balanced Pipeline

```
B1 (Intel) → B2 (Threat Model) → [B3 (Code Scan) + B4 (Targeted Probe)] parallel → B5 (Review + FP Check) → B6 (Intent Reconciliation) → B7 (PoC) → B8 (Finalize per-finding report.md) → B9 (Report Compose)
```

### Task List

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | B1 -- Intelligence Pass | -- |
| T2 | B2 -- Threat Model | T1 |
| T3 | B3 -- Code Scan (built-in suites) | T2 |
| T4 | B4 -- Targeted Probe | T2 |
| T5 | B5 -- Review Panel + FP Check | T3, T4 |
| T6 | B6 -- Intent Reconciliation | T5 |
| T7 | B7 -- PoC Authoring | T6 |
| T8 | B8 -- Finding Finalize (report.md per finding) | T7 |
| T9 | B9 -- Report Compose | T8 |

T3 and T4 unblock after T2 and run in parallel. T5 waits for both T3 and T4. T6 (Intent Reconciliation) runs after the Review Panel FP/triage tail and before any PoC effort. T8 is the mandatory gate before T9 — the final report assembler is NOT dispatched until every finding directory in BOTH `archon/findings/` and `archon/findings-theoretical/` has a non-empty `report.md`.

---

## Phase Execution

You are the orchestrator. Dispatch agents, monitor completion, aggregate results. Do NOT perform audit work yourself.

### Phase B1: Intelligence Pass (T1)

Spawn `archon:cve-scout` with `run_in_background: true`.

**Scope**: cve-scout only. Do NOT spawn `history-miner` or `patch-auditor`.

Wait for completion. Read the KB section it produces.

Update `archon/audit-state.json`: set `B1` status to `complete` with timestamp. Mark T1 complete.

### Phase B2: Threat Model (T2)

If `ARCHON_INFO_AVAILABLE=true` (or `archon/INFO.md` exists), the KB-builder treats that file as authoritative project context and skips its rediscovery work for project type, trust boundaries, auth primitives, known FP sources, out-of-scope paths, and spec commitments. Mention this in the prompt explicitly so the agent reads INFO.md first.

Spawn `archon:threat-modeler` (foreground) with the following additional instruction in the prompt:

> "BALANCED MODE: Skip Domain Attack Research Modes B and C. Only run Mode A if the project is a library/plugin/protocol. Skip generating `## Spec Gap Candidates` and `## Phase 4 CodeQL Extraction Targets` sections. Focus on: Project Classification, Architecture Model, DFD/CFD Slices, Attack Surface, and Threat Model. If `archon/INFO.md` exists, read it first and use it as authoritative for the sections it covers (per the agent's INFO.md handling rules)."

Wait for completion. Mark T2 complete.

### Phase B3 + B4: Code Scan + Targeted Probe (parallel)

In a **single message**, spawn both with `run_in_background: true`:

#### Phase B3: Code Scan (T3)

Spawn `archon:code-scanner` with the following additional instruction in the prompt:

> "BALANCED MODE: Run built-in CodeQL security suites and Semgrep Pro engine only. Do NOT generate custom CodeQL queries or custom Semgrep rules. Do NOT run structural extraction (entry-points.json, sinks.json, call-graph-slices.json). Do NOT enumerate cross-service edges (skip Sub-step 4.1b — no cross-service-edges.json; balanced assumes single-service). Do NOT run SpotBugs or agentic-actions-auditor. Output SARIF results and write the `## Static Analysis Summary` section to the KB."

#### Phase B4: Targeted Probe (T4)

Deploy a **single probe team** covering all components with attacker-controlled input. Only 3 agents (not 6):

1. Read `archon/attack-surface/knowledge-base-report.md` sections `## DFD/CFD Slices`, `## Attack Surface`, `## Architecture Model`.
2. Identify all components handling attacker-controlled input. Group them ALL into a single probe team.
3. `mkdir -p archon/probe-workspace/balanced-probe/`
4. Spawn 3 agents with `run_in_background: true` in the same message as Phase B3:

> **Probe Strategist** (coordinator):
> `subagent_type: "archon:probe-lead"`, `name: "probe-lead-balanced"`
> Prompt: "BALANCED MODE — You are the Probe Strategist for ALL components: <component list>. KB path: archon/attack-surface/knowledge-base-report.md. Workspace: archon/probe-workspace/balanced-probe/. Your team: goal-backtracer-balanced, evidence-collector-balanced. BALANCED RULES: (1) Skip the inline Code Anatomy write — reasoners read source directly. (2) Run only 1 round: SendMessage goal-backtracer-balanced for Round 1, then SendMessage evidence-collector-balanced with all hypotheses. (3) Skip Contradiction Reasoner, Cross-Pollination, and the Bayesian decision loop — the harvester covers causal challenge inline. (4) Write probe-summary.md when done."

> **Backward Reasoner** (single round):
> `subagent_type: "archon:goal-backtracer"`, `name: "goal-backtracer-balanced"`
> Prompt: "You are the Backward Reasoner (balanced mode) for all components. Wait for the Probe Strategist (probe-lead-balanced) to message you. Apply Pre-Mortem and Abductive reasoning to generate hypotheses. Single round — be thorough but concise."

> **Evidence Harvester** (trace and verdict):
> `subagent_type: "archon:evidence-collector"`, `name: "evidence-collector-balanced"`
> Prompt: "You are the Evidence Harvester (balanced mode). Wait for the Probe Strategist (probe-lead-balanced) to message you with hypotheses. Trace each hypothesis and issue VALIDATED / INVALIDATED / NEEDS-DEEPER verdicts with Fragility Scores."

Wait for all Phase B3 and Phase B4 agents to complete.

**Post-Phase-3 Enrichment (inline)**: After static analyzer completes, perform a quick inline enrichment pass — for each SAST finding, classify as `likely security` / `likely correctness` / `likely environment-only` based on trust boundary crossing and attacker-controlled input. Drop `likely correctness` and `likely environment-only` findings.

Mark T3, T4 complete.

### Phase B5: Review Panel + FP Check (T5)

1. `mkdir -p archon/chamber-workspace/balanced-chamber/`
2. Read probe results: `cat archon/probe-workspace/balanced-probe/probe-summary.md`
3. Read enriched SAST findings from KB `## Static Analysis Summary`.
4. Read `archon/attack-surface/knowledge-base-report.md` threat model sections.

Spawn a **single chamber** with 3 agents (not 4 — drop Code Tracer, Synthesizer does inline tracing):

> **Chamber Synthesizer** (lead):
> `subagent_type: "archon:review-adjudicator"`, `name: "chamber-synth-balanced"`
> Prompt: "BALANCED MODE — You are the Synthesizer for a single balanced Review Chamber. Threat cluster: ALL identified threats. NNN range: b5-001 to b5-049. State: archon/audit-state.json. Workspace: archon/chamber-workspace/balanced-chamber/debate.md. Deep Probe pre-validated hypotheses: <list from probe-summary.md>. BALANCED RULES: (1) You perform code tracing yourself instead of delegating to a Code Tracer. (2) Max 2 debate rounds total (1 ideation+challenge round, 1 optional follow-up for ambiguous findings). (3) Your Ideator is ideator-balanced, Advocate is advocate-balanced. Use SendMessage to coordinate."

> **Attack Ideator**:
> `subagent_type: "archon:attack-designer"`, `name: "ideator-balanced"`
> Prompt: "You are the Attack Ideator (balanced mode). Wait for the Synthesizer (chamber-synth-balanced) to message you. Deep Probe results are pre-seeded in debate.md — do NOT regenerate. Focus on chaining findings and cross-mode combinations. Max 7 hypotheses per batch."

> **Devil's Advocate**:
> `subagent_type: "archon:red-challenger"`, `name: "advocate-balanced"`
> Prompt: "You are the Devil's Advocate (balanced mode). Wait for the Synthesizer (chamber-synth-balanced) to message you. Write defense briefs challenging each hypothesis."

Wait for the chamber to close.

**Inline FP Check**: Apply `fp-check` skill to every `*.md` file under `archon/findings-draft/` with `Verdict: VALID` (the chamber synthesizer writes drafts with a `p10-` prefix regardless of the NNN range it was given, so do not filter by prefix — iterate the whole directory). Write verdicts back into drafts.

**Cold-verify (CRITICAL only)**: for each finding still `Verdict: VALID` after the FP check whose `Severity-Original` is `CRITICAL`, spawn `archon:independent-verifier` in **batches of at most 3 background agents**. The prompt contains ONLY the finding draft file path — no debate transcript, no context. **HIGH and MEDIUM findings skip the cold pass** — the Devil's Advocate challenge in the chamber is sufficient for them; the cold pass is reserved for CRITICAL claims where a false positive is most costly. Wait for each independent-verifier batch before launching the next one. Write verdicts back into drafts.

**Triage Pass (cheap-tier model)**: After FP check and the CRITICAL cold-verify pass, fan out `archon:finding-grader` over every `archon/findings-draft/*.md` file that is still `Verdict: VALID`. Use **batches of at most 3 background agents**. Each triager prompt contains ONLY the draft path. The triager writes `Triage-Priority` (P0/P1/P2/skip), `Triage-Exploitability`, `Triage-Impact`, and `Triage-Reasoning` back into the draft frontmatter; do not invoke it on drafts already carrying a `Triage-Priority` line.

The triager runs on a cheaper model than the chamber agents (Sonnet on Claude, defaults on others) — it does not re-read source code, it only classifies based on the draft. Skipping is reversible: drafts marked `skip` are routed to `archon/findings-theoretical/` (as full finding directories) during Phase B7 consolidation and still get a report. The remaining drafts are processed by Phase B7 PoC building in P0-first order.

Mark T5 complete.

### Phase B6: Intent Reconciliation (T6)

Runs after the B5 FP/triage tail (so every VALID draft already carries a `Triage-Priority`) and **before** any PoC effort. The goal: reconcile each surviving finding against what the project documents as intentional design, an exposed feature, or an explicitly in-scope risk — so engineering effort is not spent confirming behavior the maintainers already declared by-design, and so classes the project explicitly cares about are not deprioritized.

Spawn `archon:context-reviewer` (foreground) with the following prompt:

> "AUDIT CONTRACT (balanced B6). Target directory: <abs_target>. Findings drafts: archon/findings-draft/ (evaluate every `*.md` with `Verdict: VALID`). KB: archon/attack-surface/knowledge-base-report.md (read the `## Architecture Model`, `## Domain Attack Research`, `## Known False-Positive Sources` sections). Read `archon/INFO.md` `## Known False-Positive Sources` if present. For each VALID draft, do a bounded read of ONLY the `file:line` it cites, reconcile against documented intent, and write `Intent-Verdict` / `Intent-Source` / `Intent-Quote` into the draft frontmatter. For `intentional-design` or `documented-feature` whose decisive basis is `confidence: strong` (or operator INFO.md), reuse the triage skip channel: overwrite `Triage-Priority: skip` with a `Triage-Reasoning: context-reviewer: …` note. Do NOT touch `Verdict` or `Severity`. Write the corpus to archon/attack-surface/intent-corpus.json, per-finding verdicts to archon/attack-surface/intent-verdicts.json, and the human-readable report to archon/attack-surface/intent-reconciliation.md."

**Failure policy: skip-and-continue.** If the agent fails, errors out, or produces no corpus, log the failure and proceed to B7 without intent routing. The absence of `intent-corpus.json` must NOT suppress any finding — every VALID draft keeps the `Triage-Priority` the B5 triage pass assigned. Strongly-intentional drafts routed via `Triage-Priority: skip` are consolidated into `archon/findings-theoretical/` in Phase B7 (full report, kept out of the Summary table, reversible).

Mark T6 (phase `B6`) complete (or `failed` with `policy: skip-and-continue` recorded).

### Phase B7: PoC Authoring (T7)

**Finding consolidation**: Run the consolidation helper — it reads every draft in `archon/findings-draft/`, keeps the `Verdict: VALID` drafts with `Severity-Original` in {CRITICAL, HIGH, MEDIUM}, assigns deterministic severity-prefixed IDs (`C1`, `H1`, `M1`, …) from one global namespace, and materialises each as a directory (`evidence/`, `draft.md`, `debate.md`, variant `metadata.json`). Drafts the triager — or Phase B6 Intent Reconciliation — marked `Triage-Priority: skip` go to `archon/findings-theoretical/<ID>-<slug>/`; the rest go to `archon/findings/<ID>-<slug>/`.

```bash
python3 ~/.config/archon-audit/skills/audit/scripts/consolidate_drafts.py archon
```

The manifest at `archon/findings-draft/consolidation-manifest.json` has `findings` (actionable → poc-author), `theoretical` (triage-skipped / intent-skipped → reporter only), and `dropped`. Exit non-zero means nothing was promoted at all — STOP. Exit zero with an empty `findings` array but non-empty `theoretical` is normal: skip PoC building + partition and go straight to finalization over the theoretical bucket.

**PoC Building**: Read the manifest. For each entry in its `findings` array, spawn `archon:poc-author` with `run_in_background: true`, passing the entry's `draft_path` and `id`. poc-author writes `PoC-Status` back into the finding's `draft.md` and is explicitly NOT responsible for `report.md` — that is Phase B8.

Wait for all PoC builders. **Confirmed/theoretical partition**: then run

```bash
python3 ~/.config/archon-audit/skills/audit/scripts/partition_findings.py archon
```

which demotes any `archon/findings/<ID>-<slug>/` that did not reach `PoC-Status: executed` into `archon/findings-theoretical/` (IDs unchanged; idempotent). Mark T7 (phase `B7`) complete.

### Phase B8: Finding Finalize (T8)

After every poc-author completes, fan out one `archon:finding-writer` per finding to author `report.md` from cold context. This is the structural fix that prevents `report.md` from being starved by the heavy PoC workload.

1. Enumerate every finding directory across **both** buckets: `archon/findings/*/` AND `archon/findings-theoretical/*/` (`C*-*`, `H*-*`, `M*-*`).
2. For each directory, spawn `archon:finding-writer` with `run_in_background: true`. The prompt contains ONLY the finding directory path. Theoretical-bucket folders get the same nine-section report; their `Proof of concept & Evidence` section states the no-PoC reason.
3. Wait for all reporters.
4. **Phase gate (MANDATORY)**: enumerate `archon/findings/*/report.md` AND `archon/findings-theoretical/*/report.md`. For every finding directory in both buckets, assert `report.md` exists and is larger than 500 bytes. If any are missing or truncated, respawn `archon:finding-writer` ONCE for those folders. If any remain incomplete after the retry, STOP — report the list to the user and do NOT proceed to B9.

Mark T8 (phase `B8`) complete only when every finding directory in both buckets has a non-empty `report.md`.

### Phase B9: Report Compose (T9)

Spawn `archon:report-composer` (foreground) with the following additional instruction:

> "BALANCED MODE: This is a balanced audit report. Add a note in the Executive Summary: 'This report was generated using balanced audit mode. Skipped vs deep: commit archaeology, patch-bypass analysis, the dedicated authorization phase, custom SAST/structural extraction, multi-round deep probing, and the deep chamber''s inline cross-service taint reasoning + variant expansion (cold verification and intent reconciliation still run). For comprehensive coverage, run a full audit with /archon:deep.' Render confirmed findings (PoC executed) in the main report and put theoretical/unconfirmed ones in the dedicated Theoretical / Unconfirmed Findings section, kept out of the Summary-of-Findings table. Surface the Intent Reconciliation summary from archon/attack-surface/intent-reconciliation.md. Skip the chamber workspace appendix. Consistency checks MUST include: finding ID cross-reference (across both buckets), orphan detection, AND finding completeness (every `<ID>-<slug>/` in BOTH `archon/findings/` and `archon/findings-theoretical/` must contain `draft.md` and a non-empty `report.md`; a `poc.*` is required only in `archon/findings/`). Do NOT drop the finding-completeness check — Phase B8 has already guaranteed it, so any failure here is a real regression."

**File-state stamp (incremental basis)**: Before cleanup, stamp `archon/file-state.json` so the next audit can compute an incremental scope (changed/new/deleted files) against this run. This adds nothing to the user-facing report — it just persists per-file hashes and the audit IDs that touched each file.

```bash
python3 ~/.config/archon-audit/skills/audit/scripts/stamp_file_state.py --target . 2>&1
```

The script reads `archon/audit-state.json` to detect the current audit_id and phase set, walks the target tree (excluding `archon/`, `node_modules/`, `vendor/`, etc.), sha-256 hashes every text-readable source file under ~512 KB, and merges the result into `archon/file-state.json`. If it errors, log the failure but DO NOT fail the audit — the report is the deliverable.

**Post-audit cleanup**: After report-composer completes and reports consistency checks passed, delete intermediate working artifacts:
```bash
rm -rf archon/findings-draft/
rm -rf archon/probe-workspace/
rm -rf archon/chamber-workspace/
rm -rf archon/codeql-artifacts/
rm -rf archon/codeql-queries/
rm -rf archon/semgrep-rules/
rm -rf archon/semgrep-res/
```
Retained: `archon/audit-state.json`, `archon/file-state.json`, `archon/INFO.md` (if present), `archon/attack-surface/knowledge-base-report.md`, `archon/attack-surface/intent-corpus.json`, `archon/attack-surface/intent-reconciliation.md`, `archon/findings/`, `archon/findings-theoretical/` (if present), `archon/final-audit-report.md`. If consistency checks failed, skip cleanup and report the failures to the user first.

Mark T9 (phase `B9`) complete. Update `audits[-1].completed_at` and `audits[-1].status` to `complete`. Print post-audit summary.

---

## Resume Logic

Read `audits[-1].phases` from `archon/audit-state.json` to find phase statuses. Walk phases in order: B1, B2, B3, B4, B5, B6, B7, B8, B9. Find the first phase with status `pending`, `in_progress`, or `failed`:

- `failed` or `in_progress`: check whether the expected KB sections or output artifacts exist and appear complete. Artifact gates:
  - B6 complete if `archon/attack-surface/intent-corpus.json` exists (empty arrays acceptable) OR the phase was recorded `failed` under `policy: skip-and-continue`
  - B7 complete if every directory under `archon/findings/` has a PoC script AND the draft inside has a `PoC-Status` line written back
  - B7 complete if `archon/findings-draft/partition-manifest.json` exists (PoC + partition ran), or the consolidation manifest had an empty `findings` array (all theoretical)
  - B8 complete if every directory under `archon/findings/` AND `archon/findings-theoretical/` has a non-empty `report.md` (>500 bytes)
  - B9 complete if `archon/final-audit-report.md` exists and references the finding IDs currently in `archon/findings/` and `archon/findings-theoretical/`

  If so, mark `complete` and advance. Otherwise delete the partial output and re-run.
- `pending`: run normally.

Continue sequentially through B9 using the phase execution above.

---

## Lead Responsibilities

1. **Do not perform audit work.** Your role is coordination only.
2. Monitor via task completions and incoming agent messages.
3. If an agent fails, check `archon/findings-draft/` for partial output. Spawn replacement with remaining work only.
4. For the chamber: if it fails, check `archon/chamber-workspace/balanced-chamber/debate.md` for partial findings already written.
5. If the probe team fails, read its workspace for partial summaries and pass whatever results exist to B5.
6. If Intent Reconciliation (B6) fails, proceed to B7 without intent routing — it is best-effort and never blocks the pipeline.
