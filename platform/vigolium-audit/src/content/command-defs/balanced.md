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
    completion:
      repair_attempts: 1
      artifacts:
        - kind: file
          path: attack-surface/knowledge-base-report.md
          min_bytes: 80
          contains: ["## Advisory Intelligence"]
  - id: "B2"
    title: Threat Model
    agent: threat-modeler
    requires_git: false
    parallel_with: []
    depends_on: ["B1"]
    completion:
      repair_attempts: 1
      artifacts:
        - kind: file
          path: attack-surface/knowledge-base-report.md
          min_bytes: 160
          contains: ["## Architecture Model", "## Attack Surface"]
        - kind: file
          path: attack-surface/unauthenticated-surface.md
          min_bytes: 40
          contains: ["# Unauthenticated Attack Surface"]
  - id: "B3"
    title: Code Scan
    agent: code-scanner
    requires_git: false
    parallel_with: ["B4"]
    depends_on: ["B2"]
    completion:
      repair_attempts: 1
      artifacts:
        - kind: file
          path: attack-surface/knowledge-base-report.md
          min_bytes: 200
          contains: ["## Static Analysis Summary"]
  - id: "B4"
    title: Targeted Probe
    agent: probe-lead
    requires_git: false
    parallel_with: ["B3"]
    depends_on: ["B2"]
    completion:
      repair_attempts: 1
      artifacts:
        - kind: file
          path: probe-workspace/balanced-probe/probe-summary.md
          min_bytes: 40
  - id: "B5"
    title: Review Panel
    agent: review-adjudicator
    requires_git: false
    parallel_with: []
    depends_on: ["B3", "B4"]
    completion:
      repair_attempts: 1
      artifacts:
        - kind: file
          path: chamber-workspace/balanced-chamber/debate.md
          min_bytes: 40
        - kind: glob
          pattern: findings-draft/*.md
          min_matches: 0
          each_min_bytes: 1
          select_contains: ["Verdict: VALID"]
          each_contains: ["Triage-Priority:"]
  - id: "B6"
    title: Intent Reconciliation
    agent: context-reviewer
    requires_git: false
    parallel_with: []
    depends_on: ["B5"]
    completion:
      enforcement: advisory
      repair_attempts: 0
      artifacts:
        - kind: file
          path: attack-surface/intent-corpus.json
          min_bytes: 2
          json: true
        - kind: file
          path: attack-surface/intent-reconciliation.md
          min_bytes: 40
  - id: "B7"
    title: PoC Authoring
    agent: poc-author
    requires_git: false
    parallel_with: []
    depends_on: ["B6"]
    completion:
      repair_attempts: 1
      artifacts:
        - kind: file
          path: findings-draft/consolidation-manifest.json
          min_bytes: 20
          json: true
  - id: "B8"
    title: Finding Finalize
    agent: finding-writer
    requires_git: false
    parallel_with: []
    depends_on: ["B7"]
    completion:
      repair_attempts: 1
      artifacts:
        - kind: finding_reports
          roots: [findings, findings-theoretical]
          filename: report.md
          min_bytes: 501
          allow_empty: true
          manifest_path: findings-draft/consolidation-manifest.json
          manifest_lists: [findings, theoretical]
  - id: "B9"
    title: Report Compose
    agent: report-composer
    requires_git: false
    parallel_with: []
    depends_on: ["B8"]
    completion:
      repair_attempts: 1
      artifacts:
        - kind: file
          path: final-audit-report.md
          min_bytes: 200
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat vigolium-results/audit-context.md 2>/dev/null || echo "(none)"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree (plain directory target)"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "No git branch (plain directory target)"`
- Existing audit state: !`cat vigolium-results/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Security directory: !`ls vigolium-results/ 2>/dev/null || echo "No security directory"`

## Your Task

Run a **balanced** security audit of the current repository. Target scope: $ARGUMENTS

This is a streamlined 9-phase pipeline that trades depth for speed. It produces the same output format as the full audit (`/vigolium-audit:deep`) so findings are compatible with `/vigolium-audit:diff` and `/vigolium-audit:status`.

This mode supports auditing a plain source folder with no `.git` directory or local history.

### What Balanced Mode Skips

Compared to the full 12-phase deep audit (`/vigolium-audit:deep`):

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

If `vigolium-results/audit-context.md` contains `## Engine-Owned Audit State`, the CLI has already selected the current run. Do not ask a resume/fresh question and do not create, delete, or edit `audit-state.json`; proceed from the first non-complete phase shown there.

Only in a native interactive session without that directive, apply the legacy choice below.

If `vigolium-results/audit-state.json` exists, use `AskUserQuestion` to gate the next action:

- **Incomplete phases**: ask "An audit is already in progress. What would you like to do?" with options:
  - "Resume from last checkpoint"
  - "Start fresh (append a new run)"
  - "Cancel"

- **All phases complete**: ask "A completed audit exists for this repository. What would you like to do?" with options:
  - "Run a fresh balanced audit (append a new run)"
  - "Run an incremental diff audit (/vigolium-audit:diff)"
  - "Upgrade to deep audit (/vigolium-audit:deep)"
  - "Cancel"

If the user chooses **Resume**: find the first phase not marked `complete` in the state file and continue from there (see [Resume Logic](#resume-logic)).

If the user chooses **Start fresh**: preserve prior entries, append a new audit entry, and proceed with Pre-Audit Setup.

Do not proceed past the pre-flight check without an explicit user choice.

### Pre-Audit Setup

1. Detect whether Git history is available:
   ```bash
   if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
     export VIGOLIUM_AUDIT_GIT_AVAILABLE=true
   else
     export VIGOLIUM_AUDIT_GIT_AVAILABLE=false
   fi
   ```
2. **Do NOT switch branches.** Stay on the current branch for the entire audit. Do NOT run `git checkout`, `git switch`, `git branch`, `git commit`, `git add`, or `git push` against the target repo at any point. The audit writes all artifacts under `vigolium-results/` (untracked) — the user controls staging and commits. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, continue auditing the directory in place; do NOT initialize a new repo just for the audit.
3. Create output directory: `mkdir -p vigolium-results/`
4. If the audit context does **not** declare engine-owned state, initialize `vigolium-results/audit-state.json` by appending a new entry (or creating the file):
   ```json
   {
     "audits": [
       {
         "audit_id": "<ISO timestamp>",
         "commit": "<HEAD SHA from: git rev-parse HEAD, or null / \"nogit\" when Git is unavailable>",
         "branch": "<current branch, or \"nogit\">",
         "repository": "<value of $VIGOLIUM_AUDIT_REPOSITORY env var, pre-computed by the CLI from git remote / package manifests / basename — substitute the literal string before writing>",
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
5. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, update `.gitignore`: add the following entries if not already present:
   ```
   vigolium-results/codeql-artifacts/db/
   vigolium-results/codeql-artifacts/flow-paths-raw.sarif
   vigolium-results/codeql-artifacts/*.bqrs
   vigolium-results/codeql-queries/
   vigolium-results/semgrep-rules/
   vigolium-results/semgrep-res/
   vigolium-results/probe-workspace/
   ```
   If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, skip `.gitignore` edits.

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

T3 and T4 unblock after T2 and run in parallel. T5 waits for both T3 and T4. T6 (Intent Reconciliation) runs after the Review Panel FP/triage tail and before any PoC effort. T8 is the mandatory gate before T9 — the final report assembler is NOT dispatched until every finding directory in BOTH `vigolium-results/findings/` and `vigolium-results/findings-theoretical/` has a non-empty `report.md`.

---

## Phase Execution

You are the orchestrator. Dispatch agents, monitor completion, aggregate results. Do NOT perform audit work yourself.

### Phase B1: Intelligence Pass (T1)

Spawn `vigolium-audit:cve-scout` with `run_in_background: true`.

**Scope**: cve-scout only. Do NOT spawn `history-miner` or `patch-auditor`.

Wait for completion. Read the KB section it produces.

After the B1 artifact is sufficient, mark the in-session task T1 complete. When state is engine-owned, do not edit `audit-state.json`.

### Phase B2: Threat Model (T2)

If `VIGOLIUM_AUDIT_INFO_AVAILABLE=true` (or `vigolium-results/INFO.md` exists), the KB-builder treats that file as authoritative project context and skips its rediscovery work for project type, trust boundaries, auth primitives, known FP sources, out-of-scope paths, and spec commitments. Mention this in the prompt explicitly so the agent reads INFO.md first.

Spawn `vigolium-audit:threat-modeler` (foreground) with the following additional instruction in the prompt:

> "BALANCED MODE: Skip Domain Attack Research Modes B and C. Only run Mode A if the project is a library/plugin/protocol. Skip generating `## Spec Gap Candidates` and `## Phase 4 CodeQL Extraction Targets` sections. Focus on: Project Classification, Architecture Model, DFD/CFD Slices, Attack Surface, and Threat Model. Still run Step 6 — write `vigolium-results/attack-surface/unauthenticated-surface.md` (balanced has no access-auditor phase, so this is the final unauthenticated-surface artifact). If `vigolium-results/INFO.md` exists, read it first and use it as authoritative for the sections it covers (per the agent's INFO.md handling rules)."

Wait for completion. Mark T2 complete.

### Phase B3 + B4: Code Scan + Targeted Probe (parallel)

In a **single message**, spawn both with `run_in_background: true`:

#### Phase B3: Code Scan (T3)

Spawn `vigolium-audit:code-scanner` with the following additional instruction in the prompt:

> "BALANCED MODE: Run built-in CodeQL security suites and Semgrep Pro engine only. Do NOT generate custom CodeQL queries or custom Semgrep rules. Do NOT run structural extraction (entry-points.json, sinks.json, call-graph-slices.json). Do NOT enumerate cross-service edges (skip Sub-step 4.1b — no cross-service-edges.json; balanced assumes single-service). Do NOT run SpotBugs or agentic-actions-auditor. Output SARIF results and write the `## Static Analysis Summary` section to the KB."

#### Phase B4: Targeted Probe (T4)

Deploy a **single probe team** covering all components with attacker-controlled input. Only 3 agents (not 6):

1. Read `vigolium-results/attack-surface/knowledge-base-report.md` sections `## DFD/CFD Slices`, `## Attack Surface`, `## Architecture Model`.
2. Identify all components handling attacker-controlled input. Group them ALL into a single probe team.
3. `mkdir -p vigolium-results/probe-workspace/balanced-probe/`
4. Spawn 3 agents with `run_in_background: true` in the same message as Phase B3:

> **Probe Strategist** (coordinator):
> `subagent_type: "vigolium-audit:probe-lead"`, `name: "probe-lead-balanced"`
> Prompt: "BALANCED MODE — You are the Probe Strategist for ALL components: <component list>. KB path: vigolium-results/attack-surface/knowledge-base-report.md. Workspace: vigolium-results/probe-workspace/balanced-probe/. Your team: goal-backtracer-balanced, evidence-collector-balanced. BALANCED RULES: (1) Skip the inline Code Anatomy write — reasoners read source directly. (2) Run only 1 round: SendMessage goal-backtracer-balanced for Round 1, then SendMessage evidence-collector-balanced with all hypotheses. (3) Skip Contradiction Reasoner, Cross-Pollination, and the Bayesian decision loop — the harvester covers causal challenge inline. (4) Write probe-summary.md when done."

> **Backward Reasoner** (single round):
> `subagent_type: "vigolium-audit:goal-backtracer"`, `name: "goal-backtracer-balanced"`
> Prompt: "You are the Backward Reasoner (balanced mode) for all components. Wait for the Probe Strategist (probe-lead-balanced) to message you. Apply Pre-Mortem and Abductive reasoning to generate hypotheses. Single round — be thorough but concise."

> **Evidence Harvester** (trace and verdict):
> `subagent_type: "vigolium-audit:evidence-collector"`, `name: "evidence-collector-balanced"`
> Prompt: "You are the Evidence Harvester (balanced mode). Wait for the Probe Strategist (probe-lead-balanced) to message you with hypotheses. Trace each hypothesis and issue VALIDATED / INVALIDATED / NEEDS-DEEPER verdicts with Fragility Scores."

Wait for all Phase B3 and Phase B4 agents to complete.

**Post-Phase-3 Enrichment (inline)**: After static analyzer completes, perform a quick inline enrichment pass — for each SAST finding, classify as `likely security` / `likely correctness` / `likely environment-only` based on trust boundary crossing and attacker-controlled input. Drop `likely correctness` and `likely environment-only` findings.

Mark T3, T4 complete.

### Phase B5: Review Panel + FP Check (T5)

1. `mkdir -p vigolium-results/chamber-workspace/balanced-chamber/`
2. Read probe results: `cat vigolium-results/probe-workspace/balanced-probe/probe-summary.md`
3. Read enriched SAST findings from KB `## Static Analysis Summary`.
4. Read `vigolium-results/attack-surface/knowledge-base-report.md` threat model sections.

Spawn a **single chamber** with 3 agents (not 4 — drop Code Tracer, Synthesizer does inline tracing):

> **Chamber Synthesizer** (lead):
> `subagent_type: "vigolium-audit:review-adjudicator"`, `name: "chamber-synth-balanced"`
> Prompt: "BALANCED MODE — You are the Synthesizer for a single balanced Review Chamber. Threat cluster: ALL identified threats. NNN range: b5-001 to b5-049. State: vigolium-results/audit-state.json. Workspace: vigolium-results/chamber-workspace/balanced-chamber/debate.md. Deep Probe pre-validated hypotheses: <list from probe-summary.md>. BALANCED RULES: (1) You perform code tracing yourself instead of delegating to a Code Tracer. (2) Max 2 debate rounds total (1 ideation+challenge round, 1 optional follow-up for ambiguous findings). (3) Your Ideator is ideator-balanced, Advocate is advocate-balanced. Use SendMessage to coordinate."

> **Attack Ideator**:
> `subagent_type: "vigolium-audit:attack-designer"`, `name: "ideator-balanced"`
> Prompt: "You are the Attack Ideator (balanced mode). Wait for the Synthesizer (chamber-synth-balanced) to message you. Deep Probe results are pre-seeded in debate.md — do NOT regenerate. Focus on chaining findings and cross-mode combinations. Max 7 hypotheses per batch."

> **Devil's Advocate**:
> `subagent_type: "vigolium-audit:red-challenger"`, `name: "advocate-balanced"`
> Prompt: "You are the Devil's Advocate (balanced mode). Wait for the Synthesizer (chamber-synth-balanced) to message you. Write defense briefs challenging each hypothesis."

Wait for the chamber to close.

**Inline FP Check**: Apply `fp-check` skill to every `*.md` file under `vigolium-results/findings-draft/` with `Verdict: VALID` (the chamber synthesizer writes drafts with a `p10-` prefix regardless of the NNN range it was given, so do not filter by prefix — iterate the whole directory). Write verdicts back into drafts.

**Cold-verify (CRITICAL only)**: for each finding still `Verdict: VALID` after the FP check whose `Severity-Original` is `CRITICAL`, spawn `vigolium-audit:independent-verifier` in **batches of at most 3 background agents**. The prompt contains ONLY the finding draft file path — no debate transcript, no context. **HIGH and MEDIUM findings skip the cold pass** — the Devil's Advocate challenge in the chamber is sufficient for them; the cold pass is reserved for CRITICAL claims where a false positive is most costly. Wait for each independent-verifier batch before launching the next one. Write verdicts back into drafts.

**Triage Pass (cheap-tier model)**: After FP check and the CRITICAL cold-verify pass, fan out `vigolium-audit:finding-grader` over every `vigolium-results/findings-draft/*.md` file that is still `Verdict: VALID`. Use **batches of at most 3 background agents**. Each triager prompt contains ONLY the draft path. The triager writes `Triage-Priority` (P0/P1/P2/skip), `Triage-Exploitability`, `Triage-Impact`, and `Triage-Reasoning` back into the draft frontmatter; do not invoke it on drafts already carrying a `Triage-Priority` line.

The triager runs on a cheaper model than the chamber agents (Sonnet on Claude, defaults on others) — it does not re-read source code, it only classifies based on the draft. Skipping is reversible: drafts marked `skip` are routed to `vigolium-results/findings-theoretical/` (as full finding directories) during Phase B7 consolidation and still get a report. The remaining drafts are processed by Phase B7 PoC building in P0-first order.

Mark T5 complete.

### Phase B6: Intent Reconciliation (T6)

Runs after the B5 FP/triage tail (so every VALID draft already carries a `Triage-Priority`) and **before** any PoC effort. The goal: reconcile each surviving finding against what the project documents as intentional design, an exposed feature, or an explicitly in-scope risk — so engineering effort is not spent confirming behavior the maintainers already declared by-design, and so classes the project explicitly cares about are not deprioritized.

Spawn `vigolium-audit:context-reviewer` (foreground) with the following prompt:

> "AUDIT CONTRACT (balanced B6). Target directory: <abs_target>. Findings drafts: vigolium-results/findings-draft/ (evaluate every `*.md` with `Verdict: VALID`). KB: vigolium-results/attack-surface/knowledge-base-report.md (read the `## Architecture Model`, `## Domain Attack Research`, `## Known False-Positive Sources` sections). Read `vigolium-results/INFO.md` `## Known False-Positive Sources` if present. For each VALID draft, do a bounded read of ONLY the `file:line` it cites, reconcile against documented intent, and write `Intent-Verdict` / `Intent-Source` / `Intent-Quote` into the draft frontmatter. For `intentional-design` or `documented-feature` whose decisive basis is `confidence: strong` (or operator INFO.md), reuse the triage skip channel: overwrite `Triage-Priority: skip` with a `Triage-Reasoning: context-reviewer: …` note. Do NOT touch `Verdict` or `Severity`. Write the corpus to vigolium-results/attack-surface/intent-corpus.json, per-finding verdicts to vigolium-results/attack-surface/intent-verdicts.json, and the human-readable report to vigolium-results/attack-surface/intent-reconciliation.md."

**Failure policy: skip-and-continue.** If the agent fails, errors out, or produces no corpus, log the failure and proceed to B7 without intent routing. The absence of `intent-corpus.json` must NOT suppress any finding — every VALID draft keeps the `Triage-Priority` the B5 triage pass assigned. Strongly-intentional drafts routed via `Triage-Priority: skip` are consolidated into `vigolium-results/findings-theoretical/` in Phase B7 (full report, kept out of the Summary table, reversible).

Mark T6 (phase `B6`) complete (or `failed` with `policy: skip-and-continue` recorded).

### Phase B7: PoC Authoring (T7)

**Finding consolidation**: Run the consolidation helper — it reads every draft in `vigolium-results/findings-draft/`, keeps the `Verdict: VALID` drafts with `Severity-Original` in {CRITICAL, HIGH, MEDIUM}, assigns deterministic severity-prefixed IDs (`C1`, `H1`, `M1`, …) from one global namespace, and materialises each as a directory (`evidence/`, `draft.md`, `debate.md`, variant `metadata.json`). Drafts the triager — or Phase B6 Intent Reconciliation — marked `Triage-Priority: skip` go to `vigolium-results/findings-theoretical/<ID>-<slug>/`; the rest go to `vigolium-results/findings/<ID>-<slug>/`.

```bash
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/consolidate_drafts.py vigolium-results
```

The manifest at `vigolium-results/findings-draft/consolidation-manifest.json` has `findings` (actionable → poc-author), `theoretical` (triage-skipped / intent-skipped → reporter only), and `dropped`. Exit 1 with empty `findings` and `theoretical` arrays is a clean no-findings result: skip PoC/partition/finding-writer work and continue to B9 so the report records zero findings. Other helper errors are fatal. An empty `findings` array with non-empty `theoretical` is also normal: skip PoC building + partition and finalize the theoretical bucket.

**PoC Building**: Read the manifest. For each entry in its `findings` array, spawn `vigolium-audit:poc-author` with `run_in_background: true`, passing the entry's `draft_path` and `id`. poc-author writes `PoC-Status` back into the finding's `draft.md` and is explicitly NOT responsible for `report.md` — that is Phase B8.

Wait for all PoC builders. **Confirmed/theoretical partition**: then run

```bash
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/partition_findings.py vigolium-results
```

which demotes any `vigolium-results/findings/<ID>-<slug>/` that did not reach `PoC-Status: executed` into `vigolium-results/findings-theoretical/` (IDs unchanged; idempotent). Mark T7 (phase `B7`) complete.

### Phase B8: Finding Finalize (T8)

After every poc-author completes, fan out one `vigolium-audit:finding-writer` per finding to author `report.md` from cold context. This is the structural fix that prevents `report.md` from being starved by the heavy PoC workload.

1. Enumerate every finding directory across **both** buckets: `vigolium-results/findings/*/` AND `vigolium-results/findings-theoretical/*/` (`C*-*`, `H*-*`, `M*-*`).
2. For each directory, spawn `vigolium-audit:finding-writer` with `run_in_background: true`. The prompt contains ONLY the finding directory path. Theoretical-bucket folders get the same nine-section report; their `Proof of concept & Evidence` section states the no-PoC reason.
3. Wait for all reporters.
4. **Phase gate (MANDATORY)**: enumerate `vigolium-results/findings/*/report.md` AND `vigolium-results/findings-theoretical/*/report.md`. For every finding directory in both buckets, assert `report.md` exists and is larger than 500 bytes. If any are missing or truncated, respawn `vigolium-audit:finding-writer` ONCE for those folders. If any remain incomplete after the retry, STOP — report the list to the user and do NOT proceed to B9.

Mark T8 (phase `B8`) complete only when every finding directory in both buckets has a non-empty `report.md`.

### Phase B9: Report Compose (T9)

Spawn `vigolium-audit:report-composer` (foreground) with the following additional instruction:

> "BALANCED MODE: This is a balanced audit report. Add a note in the Executive Summary: 'This report was generated using balanced audit mode. Skipped vs deep: commit archaeology, patch-bypass analysis, the dedicated authorization phase, custom SAST/structural extraction, multi-round deep probing, and the deep chamber''s inline cross-service taint reasoning + variant expansion (cold verification and intent reconciliation still run). For comprehensive coverage, run a full audit with /vigolium-audit:deep.' Render confirmed findings (PoC executed) in the main report and put theoretical/unconfirmed ones in the dedicated Theoretical / Unconfirmed Findings section, kept out of the Summary-of-Findings table. Surface the Intent Reconciliation summary from vigolium-results/attack-surface/intent-reconciliation.md. Skip the chamber workspace appendix. Consistency checks MUST include: finding ID cross-reference (across both buckets), orphan detection, AND finding completeness (every `<ID>-<slug>/` in BOTH `vigolium-results/findings/` and `vigolium-results/findings-theoretical/` must contain `draft.md` and a non-empty `report.md`; a `poc.*` is required only in `vigolium-results/findings/`). Do NOT drop the finding-completeness check — Phase B8 has already guaranteed it, so any failure here is a real regression."

**File-state stamp (incremental basis)**: Before cleanup, stamp `vigolium-results/file-state.json` so the next audit can compute an incremental scope (changed/new/deleted files) against this run. This adds nothing to the user-facing report — it just persists per-file hashes and the audit IDs that touched each file.

```bash
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/stamp_file_state.py --target . 2>&1
```

The script reads `vigolium-results/audit-state.json` to detect the current audit_id and phase set, walks the target tree (excluding `vigolium-results/`, `node_modules/`, `vendor/`, etc.), sha-256 hashes every text-readable source file under ~512 KB, and merges the result into `vigolium-results/file-state.json`. If it errors, log the failure but DO NOT fail the audit — the report is the deliverable.

**Retention handoff**: Do not delete findings drafts, probe/chamber workspaces, or scanner artifacts inside the agent run; they are inputs to engine completion gates and resume recovery. The trusted CLI applies the requested retention/strip policy only after artifact validation. If report consistency checks fail, report them and leave all evidence intact.

Mark the in-session task T9 complete and print the post-audit summary. The engine validates artifacts and finalizes audit state when it owns the record.

---

## Resume Logic

Read `audits[-1].phases` from `vigolium-results/audit-state.json` to find phase statuses. Walk phases in order: B1, B2, B3, B4, B5, B6, B7, B8, B9. Find the first phase with status `pending`, `in_progress`, or `failed`:

- `failed` or `in_progress`: check whether the expected KB sections or output artifacts exist and appear complete. Artifact gates:
  - B6 complete if `vigolium-results/attack-surface/intent-corpus.json` exists (empty arrays acceptable) OR the phase was recorded `failed` under `policy: skip-and-continue`
  - B7 complete if every directory under `vigolium-results/findings/` has a PoC script AND the draft inside has a `PoC-Status` line written back
  - B7 complete if `vigolium-results/findings-draft/partition-manifest.json` exists (PoC + partition ran), or the consolidation manifest had an empty `findings` array (all theoretical)
  - B8 complete if every directory under `vigolium-results/findings/` AND `vigolium-results/findings-theoretical/` has a non-empty `report.md` (>500 bytes)
  - B9 complete if `vigolium-results/final-audit-report.md` exists and references the finding IDs currently in `vigolium-results/findings/` and `vigolium-results/findings-theoretical/`

  If so, mark `complete` and advance. Otherwise delete the partial output and re-run.
- `pending`: run normally.

Continue sequentially through B9 using the phase execution above.

---

## Lead Responsibilities

1. **Do not perform audit work.** Your role is coordination only.
2. Monitor via task completions and incoming agent messages.
3. If an agent fails, check `vigolium-results/findings-draft/` for partial output. Spawn replacement with remaining work only.
4. For the chamber: if it fails, check `vigolium-results/chamber-workspace/balanced-chamber/debate.md` for partial findings already written.
5. If the probe team fails, read its workspace for partial summaries and pass whatever results exist to B5.
6. If Intent Reconciliation (B6) fails, proceed to B7 without intent routing — it is best-effort and never blocks the pipeline.
