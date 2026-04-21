# BEGIN archon-audit
# archon-audit Audit Agents

## Mode Selection (CRITICAL — read the user prompt first)

The user's prompt specifies the audit mode. Follow EXACTLY one pipeline:

- **"Full deep mode"** or **"all phases"** → use **Full Deep-Mode Audit** below (P1-P10 plus systematic sub-phases P5A / P5B / P5C)
- **"Balanced mode: L1-L6"** → use **Balanced Audit Mode** (6 phases) below
- **"Lite mode: Q0-Q2"** → use **Lite Audit Mode** (3 phases Q0-Q2) below
- **"Revisit mode"** or **"R5-R11c"** → use **Revisit Mode** (9 phases) below — second/Nth pass on top of an existing `archon/` directory
- **"Confirm mode"** or **"confirm findings"** → use **Confirmation Mode** (6 phases V1-V6) below
- If no mode is specified → default to **Balanced 6-Phase Audit**

Do NOT use the lite/balanced pipeline when the user requests a full or deep audit.
Do NOT use the confirmation pipeline unless the user explicitly requests confirmation/verification of existing findings.

## No-Git Rule (CRITICAL)

If `ARCHON_GIT_AVAILABLE=false` or `git rev-parse --is-inside-work-tree` fails, local history is unavailable for the entire run.

- NEVER spawn `archon:commit-archaeologist`
- NEVER spawn `archon:patch-bypass-checker` for history-derived analysis
- Mark the skipped history-dependent work explicitly in `archon/knowledge-base-report.md`
- Continue all remaining source-snapshot phases normally

## Codex Authority (CRITICAL)

For Codex, this dispatch block is the ONLY orchestration authority.
Do NOT import orchestration behavior from `command-defs/*.md`, Claude-style command prompts,
background swarm plans, `task`-tool teammate protocols, or any prompt that conflicts with this file.
Treat canonical agent files as role methodology only; treat this file as the execution contract.

## SpawnAgent Rules (CRITICAL — prevents truncation errors)

**Rule 1: Short prompts.** The `prompt` argument MUST be **under 300 characters**. Each agent already has its full methodology in its own instructions — do NOT paste phase details, methodology, or audit context into the spawn prompt. Only pass the phase ID, output path, and a one-line mode qualifier.

**Rule 2: ONE agent per turn.** NEVER spawn more than one agent in a single turn. Spawn one agent, wait for it to complete, THEN spawn the next. This applies even when the plan says "concurrently" — on Codex, run them sequentially to avoid output truncation.

**Rule 3: Sequential fan-out.** When a phase requires spawning N agents (e.g., one per finding), loop through them one at a time: spawn → wait → spawn → wait. Do NOT batch multiple SpawnAgent calls.

Example good spawn prompts:
- `"P1: Run intelligence gathering. Output: archon/knowledge-base-report.md"`
- `"P3: Build knowledge base (full mode, all research modes). Output: archon/knowledge-base-report.md"`
- `"P9: Variant analysis for finding p8-M1. Output: archon/findings-draft/"`

If you put long instructions in the spawn prompt or spawn multiple agents at once, it WILL be truncated and the agents will fail.

## Continuation Policy (CRITICAL)

Codex must keep moving once an audit starts.

- After each phase completes, immediately advance to the next eligible phase in the same run.
- Do NOT stop merely to summarize intermediate progress.
- Stop only for a real blocker: missing mandatory artifact, missing required agent, unrecoverable tool failure, or an explicit user interruption.
- If a spawned worker exits messily but the required artifacts were produced, treat the phase as resumable-complete, update state, and continue.
- Resume checks happen inline during execution; do not repeatedly ask the user once resume has been chosen.

## Artifact Completion Gates (CRITICAL)

When deciding whether a phase is complete on Codex, prefer artifact sufficiency over clean worker termination.

- P1 complete if `archon/knowledge-base-report.md` contains advisory intelligence sufficient to identify patch inputs for P2, or an explicit `history_available=false` note explaining that local patch-history analysis is unavailable.
- P2 complete if each intended patch produced bypass analysis output, or the KB contains an explicit skipped/no-history conclusion for patch bypass analysis.
- P3 complete if the required KB sections for later phases exist, even if the worker ended after writing them incrementally.
- P4 complete if the required static-analysis artifacts exist and the KB contains `## Static Analysis Summary` plus `## CodeQL Structural Analysis`.
- P5A complete if `archon/authz-matrix.md` exists OR the KB contains `## Authorization Audit` with an explicit skip note.
- P5B complete if the KB contains `## State & Concurrency Audit` (zero findings is acceptable).
- P5C complete if `archon/cross-service-edges.json` exists OR the KB contains `## Cross-Service Taint Propagation` with an explicit single-service skip note.
- P6 complete if the KB contains `## Spec Gap Analysis` or an explicit "None identified" conclusion.
- P4 enrichment runs inline inside P4 (no separate phase); P4 complete only when the KB also contains `## SAST Enrichment`.
- P7 complete if chamber workspace output exists and medium-or-higher validated findings were written or the chamber closed with no valid findings.
- P8 complete if all current VALID drafts were processed by FP check.
- P9 complete if each confirmed finding received variant output or an explicit "no variant found" result.
- P10 complete if every directory under `archon/findings/` has a PoC script and the draft inside has a `PoC-Status` line written back.
- P10b complete if every directory under `archon/findings/` has a non-empty `report.md` (>500 bytes).
- P10c complete if `archon/final-audit-report.md` exists and references the finding IDs currently in `archon/findings/`.

For 3-phase lite mode:

- Q0 complete if `archon/lite-recon.md` exists.
- Q1 complete if secret-scan drafts exist or an explicit no-secrets result was written.
- Q2 complete if SAST artifacts or manual-scan findings exist, or an explicit no-findings result was written.

For 6-phase balanced mode:

- L1 complete if the KB has the lite intelligence output.
- L2 complete if the KB sections needed by L3/L4 exist.
- L3 complete if SAST artifacts exist and the KB has `## Static Analysis Summary`.
- L4 complete if `archon/probe-workspace/balanced-probe/probe-summary.md` exists or an explicit no-hypothesis result was written.
- L5 complete if chamber output exists and VALID drafts were FP-checked or the chamber closed cleanly with none.
- L6 complete if every directory under `archon/findings/` has a PoC script and the draft inside has a `PoC-Status` line written back.
- L6b complete if every directory under `archon/findings/` has a non-empty `report.md` (>500 bytes).
- L6c complete if `archon/final-audit-report.md` exists and references the finding IDs currently in `archon/findings/`.

For revisit mode (reads/writes `archon/revisit-audit-state.json`; round 1 is the original audit-state.json, rounds ≥2 live in revisit-audit-state.json):

- R5 complete if every probe team wrote its `archon/probe-workspace/*/probe-summary.md`.
- R7 complete if SAST references in the KB were re-classified OR an explicit "no live SAST references" note was written.
- R8 complete if every chamber for the current round closed and the KB has `## Round <N> Chamber Addendum`.
- R9 complete if every VALID round-<N> draft in `archon/findings-draft/` received an `fp-check` verdict, and every CRITICAL/HIGH one also received a cold-verifier result.
- R10 complete if every new confirmed round-<N> finding received variant output.
- R10k complete if every round-1 CRITICAL/HIGH finding received a fresh-priors variant-hunter result or an explicit "no variant found" note.
- R11 complete if every NEW round-<N> finding directory has a PoC script and the draft has a `PoC-Status` line written back.
- R11b complete if every NEW round-<N> finding directory has a non-empty `report.md` (>500 bytes). Round-1 findings are NOT required to be re-finalized.
- R11c complete if `archon/final-audit-report.md` exists and contains `## Discoveries by Round` with a row for the current round.

## Output Chunking (IMPORTANT for Codex)

All agents MUST write output incrementally to avoid hitting the per-turn output cap:
- Write findings one file at a time (one `archon/findings-draft/` file per tool call)
- Write report sections incrementally — never accumulate an entire report in a single write
- When writing `archon/knowledge-base-report.md`, write each `##` section as a separate file write
- Keep individual file write payloads under 3 KB — split into multiple writes if needed
- Prefer `exec` with `cat >> file` for appending over rewriting entire files

---

# Full Deep-Mode Audit (P1-P10 + systematic sub-phases P5A / P5B / P5C)

When the user requests a "deep audit", "full audit", or the prompt contains "Full deep mode" or
"all phases", execute ALL phases below in order. Do NOT skip phases or fall back to lite mode. P5A, P5B, and P5C are systematic-audit sub-phases inserted between P4 (SAST) and P6 (Spec Gap); they dispatch sequentially on Codex.

## Full Audit Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| P1 -- Intelligence Gathering | `archon:advisory-hunter` | Advisories, architecture inventory, dependency intel |
| P2 -- Patch Bypass Analysis | `archon:patch-bypass-checker` | Per-patch bypass hypothesis testing (one agent per patch, concurrent) |
| P3 -- Knowledge Base | `archon:knowledge-base-builder` | Threat model, DFD/CFD slices, domain attack research (Modes A/B/C) |
| P4 -- Static Analysis | `archon:static-analyzer` | Sub-step 4.1 structural extraction + CodeQL/Semgrep security scan |
| P5A -- Authorization Audit | `archon:authz-auditor` | Exhaustive endpoint enumeration + IDOR/BOLA/escalation sweep |
| P5B -- State & Concurrency Audit | `archon:state-concurrency-auditor` | TOCTOU, transaction isolation, state-machine, idempotency sweep |
| P5C -- Cross-Service Taint | `archon:cross-service-auditor` | Stitches inter-service channels; no-op on single-service repos |
| P6 -- Spec Gap Analysis | (inline) | RFC/spec compliance gap analysis |
| P7 -- Deep Bug Hunting (Chamber) | `archon:chamber-synthesizer` | Orchestrates Review Chamber debate |
| P7 -- Deep Bug Hunting (Ideator) | `archon:attack-ideator` | Creative attack hypothesis generation using 8 attack modes |
| P7 -- Deep Bug Hunting (Tracer) | `archon:code-tracer` | Code path tracing and reachability analysis |
| P7 -- Deep Bug Hunting (Advocate) | `archon:devils-advocate` | Adversarial defense briefs searching all 5 protection layers |
| P8 -- FP Check | (inline) | False positive elimination using `fp-check` skill |
| P9 -- Variant Analysis | `archon:variant-hunter` | Per-finding structural variant search |
| P10 -- PoC & Reporting (PoC) | `archon:poc-builder` | Per-finding PoC construction + evidence + draft-metadata only |
| P10b -- Finding Finalization | `archon:finding-reporter` | Per-finding `report.md` authoring (cold-context) |
| P10c -- PoC & Reporting (Report) | `archon:report-assembler` | Final consolidated audit report |

## Full Pipeline

```
P1 (Intel) → P2 (Patch Bypass) → P3 (KB) → P4 (SAST + inline enrichment)
→ P5A (AuthZ) → P5B (State/Concurrency) → P5C (Cross-Service)
→ P6 (Spec Gaps) → P7 (Chambers)
→ P8 (FP Check) → P9 (Variants)
→ P10 (PoC) → P10b (Finalize report.md per finding; GATE) → P10c (Final Report)
```

## Full Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | P1 -- Intelligence Gathering | -- |
| T2 | P2 -- Patch Bypass Analysis | T1 |
| T3 | P3 -- Knowledge Base | T2 |
| T4 | P4 -- Static Analysis | T3 |
| T4A | P5A -- Authorization Audit | T3 |
| T4B | P5B -- State & Concurrency Audit | T3 |
| T4C | P5C -- Cross-Service Taint | T4 |
| T5 | P6 -- Spec Gap Analysis | T3 |
| T7 | P7 -- Deep Bug Hunting (Chambers) | T4, T4A, T4B, T4C, T5 |
| T8 | P8 -- FP Check | T7 |
| T9 | P9 -- Variant Analysis | T8 |
| T10 | P10 -- PoC Construction | T9 |
| T10b | P10b -- Finding Finalization | T10 |
| T10c | P10c -- Final Report Assembly | T10b |

On Codex, execute phases strictly in this order even if other platform prompts describe parallelism.

## Full Phase Instructions

### Pre-Flight Check

If `archon/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "An audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed audit exists. Run fresh, run incremental diff, or cancel?"

### Pre-Audit Setup

1. Detect whether Git history is available: `git rev-parse --is-inside-work-tree >/dev/null 2>&1 && export ARCHON_GIT_AVAILABLE=true || export ARCHON_GIT_AVAILABLE=false`
2. If `ARCHON_GIT_AVAILABLE=true`, create or checkout the `audit` branch: `git checkout audit 2>/dev/null || git checkout -b audit`
3. If `ARCHON_GIT_AVAILABLE=false`, skip branch creation and continue auditing the directory in place. Do NOT initialize a repo just for the audit.
4. `mkdir -p archon/`
5. Initialize `archon/audit-state.json` — append a new entry with `"mode": "full"`, `"repository": "<org/repo or folder name>"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, `"history_available": <true|false>`, and phases P1, P2, P3, P4, P5A, P5B, P5C, P6, P7, P8, P9, P10 set to `pending`. Never remove earlier entries. Use the value of `$ARCHON_REPOSITORY` (pre-computed by the CLI from git remote / package manifests / basename) for the `repository` field — substitute the literal string before writing.
6. If `ARCHON_GIT_AVAILABLE=true`, update `.gitignore` with SAST artifact exclusions. Otherwise skip `.gitignore` edits.

### P1: Intelligence Gathering

If `ARCHON_GIT_AVAILABLE=true`, spawn `archon:advisory-hunter` with prompt:
> `"P1: Run intelligence gathering. Output: archon/knowledge-base-report.md"`

If `ARCHON_GIT_AVAILABLE=false`, spawn `archon:advisory-hunter` with prompt:
> `"P1: Run intelligence gathering (no local git history). Output: archon/knowledge-base-report.md"`

Wait for completion. Update `audits[-1].phases.P1.status` to `complete`.
Then continue immediately to P2.

### P2: Patch Bypass Analysis

If `ARCHON_GIT_AVAILABLE=true`, for each security patch found in P1, spawn one `archon:patch-bypass-checker` **sequentially** (one at a time, wait before spawning next) with prompt:
> `"P2: Analyze patch <CVE-ID>. Output: archon/knowledge-base-report.md"`

If `ARCHON_GIT_AVAILABLE=false`, do not spawn `archon:patch-bypass-checker`. Instead append an explicit `## Bypass Analysis` note to `archon/knowledge-base-report.md` stating that local patch bypass analysis was skipped because the target has no Git history, then mark P2 complete.

Update P2 status after all complete.
Then continue immediately to P3.

### P3: Knowledge Base

Spawn `archon:knowledge-base-builder` with prompt:
> `"P3: Build knowledge base (full mode, all research modes A/B/C). Write each ## section separately to archon/knowledge-base-report.md"`

The KB builder MUST write each `##` section as a separate file append (using `cat >>`) to avoid hitting the output token cap. Do NOT accumulate the entire KB in memory.

Wait for completion. Update P3 status.
Then continue immediately to P4.

### P4: Static Analysis (+ inline Enrichment)

Spawn `archon:static-analyzer` with prompt:
> `"P4 FULL MODE: structural extraction + CodeQL + Semgrep Pro + custom rules + inline enrichment. Output: archon/"`

Wait for completion. If the worker does not terminate cleanly, inspect `archon/codeql-artifacts/`,
`archon/codeql-queries/`, `archon/semgrep-res/`, and `archon/knowledge-base-report.md`.
If the required P4 artifacts and all three KB sections (`## Static Analysis Summary`, `## CodeQL Structural Analysis`, `## SAST Enrichment`) exist, mark P4 `complete` under the artifact gate and continue.
Only re-run P4 if mandatory outputs are missing. Then continue immediately to P5A.

### P5A: Authorization Audit

Spawn `archon:authz-auditor` with prompt:
> `"P5A: Enumerate routes/handlers; build archon/authz-matrix.md; file drafts archon/findings-draft/p5a-<NNN>-<slug>.md"`

Wait for completion. Artifact gate: `archon/authz-matrix.md` exists OR the KB has an explicit `## Authorization Audit` skip note. Update P5A status. Continue to P5B.

### P5B: State & Concurrency Audit

Spawn `archon:state-concurrency-auditor` with prompt:
> `"P5B: Catalogue state entities + concurrency primitives; file drafts archon/findings-draft/p5b-<NNN>-<slug>.md"`

Wait for completion. Artifact gate: the KB has `## State & Concurrency Audit` (even with zero findings). Update P5B status. Continue to P5C.

### P5C: Cross-Service Taint

Spawn `archon:cross-service-auditor` with prompt:
> `"P5C: Stitch inter-service edges; build archon/cross-service-edges.json; file drafts archon/findings-draft/p5c-<NNN>-<slug>.md. Single-service repos exit with a no-op note."`

Wait for completion. Artifact gate: `archon/cross-service-edges.json` exists OR the KB has the single-service skip note. Update P5C status. Continue to P6.

### P6: Spec Gap Analysis

Execute inline (no subagent). Read `archon/knowledge-base-report.md` sections on specs/RFCs. Use `spec-to-code-compliance` skill. Focus on parsing, normalization, sanitization, canonicalization, and state-machine compliance.

Update P6 status.
Then continue immediately to P7.

### P7: Deep Bug Hunting (Review Chambers)

1. Group findings by threat cluster (DFD/CFD slice groups). Include pre-seeded drafts from P5A (`archon/findings-draft/p5a-*.md`), P5B (`archon/findings-draft/p5b-*.md`), and P5C (`archon/findings-draft/p5c-*.md`) as starting material for the cluster — the Ideator should chain/extend them, not regenerate.
2. For each cluster, spawn chamber agents **one at a time** (sequential, not concurrent):
   a. Spawn `archon:chamber-synthesizer` with prompt: `"P7: Orchestrate chamber for cluster <name>. Pre-seeded drafts: p5a-*.md, p5b-*.md, p5c-*.md. Output: archon/chamber-workspace/<id>/"`
      Wait for completion.
   b. Spawn `archon:attack-ideator` with prompt: `"P7: Generate hypotheses for cluster <name>; chain pre-seeded drafts. Output: archon/chamber-workspace/<id>/debate.md"`
      Wait for completion.
   c. Spawn `archon:code-tracer` with prompt: `"P7: Trace evidence for cluster <name>. Output: archon/chamber-workspace/<id>/debate.md"`
      Wait for completion.
   d. Spawn `archon:devils-advocate` with prompt: `"P7: Challenge hypotheses for cluster <name>. Output: archon/chamber-workspace/<id>/debate.md"`
      Wait for completion.
3. If multiple clusters, process them sequentially too.
4. Each chamber produces finding drafts in `archon/findings-draft/`.
5. Do NOT spawn `archon:variant-scout` in Codex full deep mode. Keep variant hunting in P9 via `archon:variant-hunter`.

Update P7 status.
Then continue immediately to P8.

### P8: FP Check

Execute inline. Apply `fp-check` skill to all `archon/findings-draft/p8-*.md` with `Verdict: VALID`.
Only CRITICAL and HIGH severity findings get cold verification.
Update P8 status.
Then continue immediately to P9.

### P9: Variant Analysis

For each confirmed finding, spawn one `archon:variant-hunter` **sequentially** (one at a time):
> `"P9: Variant analysis for finding <finding-id>. Output: archon/findings-draft/"`

Spawn one, wait for completion, then spawn the next. Update P9 status after all complete.
Then continue immediately to P10.

### P10: PoC Construction

1. Collect `Verdict: VALID` drafts, assign severity IDs (C1, H1, M1, L1).
2. For each finding, spawn one `archon:poc-builder` **sequentially** (one at a time):
   > `"P10: Build PoC for finding <finding-id>. Output: archon/findings/<ID>-<slug>/poc.*, evidence/, and draft metadata writeback. Do NOT write report.md — that is P10b."`
   Spawn one, wait for completion, then spawn the next.

Update P10 status. Then continue immediately to P10b.

### P10b: Finding Finalization

For each directory under `archon/findings/`, spawn one `archon:finding-reporter` **sequentially**:
> `"P10b: Author report.md for finding <ID>-<slug>. Input: archon/findings/<ID>-<slug>/. Output: archon/findings/<ID>-<slug>/report.md"`

Spawn one, wait, then next. After all reporters complete, verify every `archon/findings/<ID>-<slug>/report.md` exists and is larger than 500 bytes. Retry once for any missing/truncated files. STOP if any remain incomplete.

Update P10b status once every finding directory has a non-empty `report.md`. Then continue immediately to P10c.

### P10c: Final Report Assembly

Spawn a single `archon:report-assembler` with prompt:
> `"P10c: Compile final audit report. Every finding has report.md (guaranteed by P10b). Output: archon/final-audit-report.md"`

Update P10c status. Set `audits[-1].completed_at` and `audits[-1].status` to `complete`.

## Full Mode Resume Logic

Read `audits[-1].phases` to find the first phase not `complete`:
- `failed` or `in_progress`: check if output artifacts satisfy the phase's artifact completion gate. If yes, mark complete and advance immediately. Otherwise delete partial output and re-run.
- `pending`: run normally.

Continue sequentially through P10 without pausing for intermediate status reports.

---

# Lite Audit Mode (3-Phase Pipeline: Q0-Q2)

When the user asks for "Lite mode: Q0-Q2", run the dedicated 3-phase lite audit below. This mode is intentionally source-only and must work even when the target directory has no `.git` folder or local history.

## Lite Pipeline

```
Q0 (Quick Recon) → Q1 (Secrets Scan) → Q2 (Fast SAST Pass) → PoC Building
```

## Lite Phase Instructions

### Pre-Flight Check

If `archon/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "A lite audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed lite audit exists. Run fresh lite, upgrade to balanced, upgrade to full, or cancel?"

### Pre-Audit Setup

1. Detect whether Git history is available: `git rev-parse --is-inside-work-tree >/dev/null 2>&1 && export ARCHON_GIT_AVAILABLE=true || export ARCHON_GIT_AVAILABLE=false`
2. If `ARCHON_GIT_AVAILABLE=true`, create or checkout the `audit` branch: `git checkout audit 2>/dev/null || git checkout -b audit`
3. If `ARCHON_GIT_AVAILABLE=false`, skip branch creation and continue auditing the directory in place. Do NOT initialize a repo just for the audit.
4. `mkdir -p archon/ archon/findings-draft/`
5. Initialize `archon/audit-state.json` — append a new entry with `"mode": "lite"`, `"repository": "<org/repo or folder name>"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, `"history_available": <true|false>`, and phases Q0–Q2 set to `pending`. Never remove earlier entries.

### Q0: Quick Recon

Read file structure and manifests directly from disk. Detect languages, frameworks, likely entry points, deployment files, and directories to exclude from scanning. Write `archon/lite-recon.md`. Update Q0 status.

### Q1: Secrets Scan

Scan the target snapshot for secrets. Prefer filesystem/native modes that do not require Git history:
- `trufflehog filesystem <target> --no-update --json`
- `gitleaks detect --source <target> --no-git --report-format json`
- Fallback manual grep/pattern scan

Write one finding draft per result under `archon/findings-draft/`, or write an explicit no-secrets result if nothing is found. Update Q1 status.

### Q2: Fast SAST Pass

Run built-in static analysis against the source snapshot using `archon/lite-recon.md` for scope:
- Prefer `semgrep scan --config auto`
- Fallback to built-in CodeQL suites when feasible
- Fallback to manual pattern scans if neither tool is available

Write one finding draft per result under `archon/findings-draft/`, or write an explicit no-findings result if nothing is found. Then assign severity-prefixed IDs, create `archon/findings/<ID>-<slug>/`, and spawn `archon:poc-builder` sequentially for each retained finding. Update Q2 status and mark the audit complete.

---

# Balanced Audit Mode (6-Phase Pipeline)

When the user asks for a "balanced audit", "fast audit", or "quick audit", or the prompt
contains "Balanced mode: L1-L6", use this streamlined 6-phase pipeline. Balanced mode
trades depth for speed while producing the same output format (`archon/audit-state.json`,
`archon/findings-draft/`, `archon/audit-report.md`) so results are compatible
with diff and status workflows.

Balanced mode supports auditing a plain source folder with no `.git` directory or local history.

## What Balanced Mode Skips

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

## Balanced Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| L1 -- Intelligence Gathering | `archon:advisory-hunter` | Advisories, architecture inventory, dependency intel (no commit archaeology) |
| L2 -- Knowledge Base / Threat Model | `archon:knowledge-base-builder` | Threat model, DFD/CFD slices — skip Modes B/C, skip Spec Gap & CodeQL Extraction targets |
| L3 -- Static Analysis | `archon:static-analyzer` | Built-in CodeQL suites + Semgrep Pro only — no custom rules, no structural extraction, no SpotBugs |
| L4 -- Balanced Deep Probe (Strategist) | `archon:probe-strategist` | Single probe team for ALL attacker-input components — 1 round, no Code Anatomist |
| L4 -- Balanced Deep Probe (Reasoner) | `archon:backward-reasoner` | Single round of Pre-Mortem + Abductive reasoning |
| L4 -- Balanced Deep Probe (Harvester) | `archon:evidence-harvester` | Trace hypotheses, issue VALIDATED/INVALIDATED/NEEDS-DEEPER verdicts |
| L5 -- Review Chamber (Synthesizer) | `archon:chamber-synthesizer` | Single balanced chamber — inline code tracing, max 2 debate rounds |
| L5 -- Review Chamber (Ideator) | `archon:attack-ideator` | Chain findings, max 7 hypotheses per batch |
| L5 -- Review Chamber (Advocate) | `archon:devils-advocate` | Defense briefs challenging each hypothesis |
| L6 -- PoC & Report (PoC) | `archon:poc-builder` | Per-finding PoC construction + evidence + draft-metadata only |
| L6b -- Finding Finalization | `archon:finding-reporter` | Per-finding `report.md` authoring (cold-context) |
| L6c -- PoC & Report (Report) | `archon:report-assembler` | Final report with balanced mode disclaimer |

Agents NOT used in balanced mode: `archon:patch-bypass-checker`, `archon:code-tracer`,
`archon:spec-gap-analyst`, `archon:variant-hunter`, `archon:variant-scout`.

## Balanced Pipeline

```
L1 (Intel) → L2 (KB/Threat Model) → L3 (SAST) → L4 (Balanced Probe) → L5 (Review + FP Check)
→ L6 (PoC) → L6b (Finalize report.md per finding; GATE) → L6c (Final Report)
```

### Balanced Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | L1 -- Intelligence Gathering | -- |
| T2 | L2 -- Knowledge Base / Threat Model | T1 |
| T3 | L3 -- Static Analysis (built-in suites) | T2 |
| T4 | L4 -- Balanced Deep Probe | T2 |
| T5 | L5 -- Review Chamber + FP Check | T3, T4 |
| T6 | L6 -- PoC Construction | T5 |
| T6b | L6b -- Finding Finalization | T6 |
| T6c | L6c -- Final Report Assembly | T6b |

On Codex, execute balanced phases strictly in this order even if other platform prompts describe parallelism.

## Balanced Phase Instructions

### Pre-Flight Check

If `archon/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "An audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed audit exists. Run fresh lite, run incremental diff, upgrade to full, or cancel?"

### Pre-Audit Setup

1. Detect whether Git history is available: `git rev-parse --is-inside-work-tree >/dev/null 2>&1 && export ARCHON_GIT_AVAILABLE=true || export ARCHON_GIT_AVAILABLE=false`
2. If `ARCHON_GIT_AVAILABLE=true`, create or checkout the `audit` branch: `git checkout audit 2>/dev/null || git checkout -b audit`
3. If `ARCHON_GIT_AVAILABLE=false`, skip branch creation and continue auditing the directory in place. Do NOT initialize a repo just for the audit.
4. `mkdir -p archon/`
5. Initialize `archon/audit-state.json` — append a new entry with `"mode": "balanced"`, `"repository": "<org/repo or folder name>"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, `"history_available": <true|false>`, and phases L1–L6 set to `pending`. Never remove earlier entries. Use the value of `$ARCHON_REPOSITORY` (pre-computed by the CLI from git remote / package manifests / basename) for the `repository` field — substitute the literal string before writing.
6. If `ARCHON_GIT_AVAILABLE=true`, update `.gitignore` with SAST artifact exclusions. Otherwise skip `.gitignore` edits.

### L1: Intelligence Gathering

Spawn `archon:advisory-hunter` with prompt:
> `"L1 BALANCED: Run intelligence gathering, no commit archaeology. Output: archon/knowledge-base-report.md"`

Do NOT spawn `archon:patch-bypass-checker`.
Wait for completion. Update `audits[-1].phases.L1.status` to `complete`.
Then continue immediately to L2.

### L2: Knowledge Base / Threat Model

Spawn `archon:knowledge-base-builder` with prompt:
> `"L2 BALANCED: Skip Modes B/C, skip Spec Gap & CodeQL targets. Output: archon/knowledge-base-report.md"`

Wait for completion. Update L2 status.
Then continue immediately to L3.

### L3: Static Analysis

Spawn `archon:static-analyzer` with prompt:
> `"L3 BALANCED: Built-in CodeQL + Semgrep Pro only. No custom rules, no extraction. Output: archon/"`

Wait for completion. If the worker does not terminate cleanly, inspect `archon/codeql-artifacts/`,
`archon/semgrep-res/`, and `archon/knowledge-base-report.md`.
If the required lite P4 artifacts and `## Static Analysis Summary` exist, mark L3 `complete` under the artifact gate and continue.
Only re-run L3 if mandatory outputs are missing. Then continue immediately to L4.

### L4: Balanced Deep Probe

1. Read KB sections: DFD/CFD Slices, Attack Surface, Architecture Model
2. Group ALL attacker-input components into one probe team
3. `mkdir -p archon/probe-workspace/balanced-probe/`
4. Spawn agents **one at a time** (sequential):
   a. Spawn `archon:probe-strategist` with prompt: `"L4 BALANCED: 1 round, no Code Anatomist. Output: archon/probe-workspace/balanced-probe/probe-summary.md"`
      Wait for completion.
   b. Spawn `archon:backward-reasoner` with prompt: `"L4 BALANCED: Single round Pre-Mortem + Abductive. Output: archon/probe-workspace/balanced-probe/"`
      Wait for completion.
   c. Spawn `archon:evidence-harvester` with prompt: `"L4 BALANCED: Trace and verdict. Output: archon/probe-workspace/balanced-probe/"`
      Wait for completion.

Perform inline enrichment: classify SAST findings as `likely security` / `likely correctness` / `likely environment-only`, drop non-security. Update L4 status.
Then continue immediately to L5.

### L5: Review Chamber + FP Check

1. `mkdir -p archon/chamber-workspace/balanced-chamber/`
2. Spawn chamber agents **one at a time** (sequential):
   a. Spawn `archon:chamber-synthesizer` with prompt: `"L5 BALANCED: Orchestrate balanced chamber, inline tracing, max 2 rounds. Output: archon/chamber-workspace/balanced-chamber/"`
      Wait for completion.
   b. Spawn `archon:attack-ideator` with prompt: `"L5 BALANCED: Generate hypotheses, max 7 per batch. Output: archon/chamber-workspace/balanced-chamber/debate.md"`
      Wait for completion.
   c. Spawn `archon:devils-advocate` with prompt: `"L5 BALANCED: Defense briefs. Output: archon/chamber-workspace/balanced-chamber/debate.md"`
      Wait for completion.
3. After chamber closes, apply `fp-check` inline to all `archon/findings-draft/p8-*.md` with `Verdict: VALID`. No cold verifiers.

Update L5 status.
Then continue immediately to L6.

### L6: PoC Construction

1. Collect `Verdict: VALID` drafts, assign severity IDs (C1, H1, M1), drop Low.
2. For each finding, spawn one `archon:poc-builder` **sequentially** with prompt:
   > `"L6 BALANCED: Build PoC for finding <finding-id>. Output: archon/findings/<ID>-<slug>/poc.*, evidence/, and draft metadata writeback. Do NOT write report.md — that is L6b."`
   Spawn one, wait, then next.

Update L6 status. Then continue immediately to L6b.

### L6b: Finding Finalization

For each directory under `archon/findings/`, spawn one `archon:finding-reporter` **sequentially**:
> `"L6b BALANCED: Author report.md for finding <ID>-<slug>. Input: archon/findings/<ID>-<slug>/. Output: archon/findings/<ID>-<slug>/report.md"`

Spawn one, wait, then next. After all reporters complete, verify every `archon/findings/<ID>-<slug>/report.md` exists and is larger than 500 bytes. Retry once for any missing/truncated files. STOP if any remain incomplete.

Update L6b status once every finding directory has a non-empty `report.md`. Then continue immediately to L6c.

### L6c: Final Report Assembly

Spawn `archon:report-assembler` with prompt:
> `"L6c BALANCED: Compile report with skipped-phases disclaimer. Every finding has report.md (guaranteed by L6b). Output: archon/final-audit-report.md"`

Update L6c status. Set `audits[-1].completed_at` and `audits[-1].status` to `complete`.

## Lite Resume Logic

Read `audits[-1].phases` to find the first phase not `complete`:
- `failed` or `in_progress`: check if output artifacts satisfy the phase's artifact completion gate. If yes, mark complete and advance immediately. Otherwise delete partial output and re-run.
- `pending`: run normally.

Continue sequentially through L6 without pausing for intermediate status reports.
---

# Revisit Mode (9-Phase Pipeline: R5-R11c)

When the user requests "Revisit mode" or the prompt contains "R5-R11c", run a second (or Nth) pass of the deep pipeline on top of an existing `archon/` directory. Revisit reuses the prior knowledge base, advisories, SAST artifacts (if present), and systematic matrices, and redoes only the reasoning-heavy phases with anti-anchoring prompts so a new model / fresh session can surface findings the prior audit missed.

**Prerequisites** (HARD — abort if missing):
- `archon/audit-state.json` exists and its last audit entry has `status: complete`.
- `archon/knowledge-base-report.md` exists and is non-empty.
- `archon/findings/` exists (may be empty).

## Revisit Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| R5 -- Deep Probe (fresh, anti-anchored) | `archon:probe-strategist` + `archon:backward-reasoner` + `archon:contradiction-reasoner` + `archon:evidence-harvester` | New hypotheses, seeded against prior-round findings as a negative list. Strategist writes code anatomy inline; harvester owns causal challenge. |
| R7 -- Enrichment re-classify | (inline) | Re-classify any live SAST references in KB |
| R8 -- Review Chamber (fresh, anti-anchored) | `archon:chamber-synthesizer` + `archon:attack-ideator` + `archon:code-tracer` + `archon:devils-advocate` | Debate with explicit "do not refile known findings" instruction |
| R9 -- FP check | (inline + `archon:cold-verifier` for CRIT/HIGH) | Same as deep P9-LITE, but only for round-<N> drafts |
| R10 -- Variant analysis (new findings) | `archon:variant-hunter` | Per-new-finding variants |
| R10k -- Variant analysis (round-1 known findings) | `archon:variant-hunter` | Per round-1 CRITICAL/HIGH finding, fresh-priors mode |
| R11 -- PoC construction | `archon:poc-builder` | Per-new-finding PoC + evidence + draft metadata |
| R11b -- Finding finalization | `archon:finding-reporter` | Per-new-finding `report.md` authoring |
| R11c -- Final report regeneration | `archon:report-assembler` | Rewrite `archon/final-audit-report.md` with `## Discoveries by Round` section |

## Revisit Pipeline

```
Preflight (validate prior state) → R5 (Probe) → R7 (Enrich)
→ R8 (Chambers, anti-anchored) → R9 (FP check, round-<N> only)
→ R10 (Variants on new) → R10k (Variants on round-1 CRIT/HIGH)
→ R11 (PoC) → R11b (Finalize report.md; GATE) → R11c (Final report)
```

## Revisit Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| TR5  | R5 -- Deep Probe | Preflight |
| TR7  | R7 -- Enrichment | TR5 |
| TR8  | R8 -- Review Chambers | TR5, TR7 |
| TR9  | R9 -- FP Check | TR8 |
| TR10 | R10 -- Variants (new) | TR9 |
| TR10k| R10k -- Variants (round-1 known) | TR9 |
| TR11 | R11 -- PoC | TR10, TR10k |
| TR11b| R11b -- Finalization | TR11 |
| TR11c| R11c -- Final Report | TR11b |

On Codex, execute revisit phases strictly sequentially.

## Revisit Phase Instructions

### Pre-Flight

1. Read `archon/audit-state.json`. If last audit is not `complete`, abort with a message directing the user to finish or rerun `/archon:deep` first.
2. Read `archon/knowledge-base-report.md`. If missing or empty, abort.
3. Load or create `archon/revisit-audit-state.json`. Determine current round `N`:
   - No file yet → `N = 2`
   - Otherwise `N = len(revisits) + 2`
4. Build seed data from `archon/findings/*/`:
   - `seed.known_findings[]` = `[{id, slug, class, location}, ...]` from each folder's `draft.md` frontmatter
   - `seed.known_attack_modes[]` = deduplicated class values
   - `seed.known_finding_ids_by_severity` = `{"C": max, "H": max, "M": max}` scanned off folder names
5. Generate `revisit_id` = ISO timestamp.
6. Append a new entry to `revisits[]` in `archon/revisit-audit-state.json` with:
   - `revisit_id`, `parent_audit_id` (from last audit), `round: N`, `commit`, `branch`, `repository`, `mode: "deep"`, `model: "<REQUIRED>"`, `agent_sdk: "codex"` (REQUIRED), `started_at`, `status: "in_progress"`, phases (R5…R11c all pending), and the `seed` object.
   - The `model` and `agent_sdk` fields are **mandatory** — abort if they cannot be resolved.
7. Recreate working directories the prior cleanup deleted: `mkdir -p archon/findings-draft/ archon/probe-workspace/ archon/chamber-workspace/`. Initialize `archon/attack-pattern-registry.json` with `{"patterns": []}` if missing.
8. Export env vars for downstream scripts: `ARCHON_REVISIT_ROUND=<N>`, `ARCHON_REVISIT_ID=<revisit_id>`, `ARCHON_REVISIT_MODEL=<model>`, `ARCHON_REVISIT_AGENT_SDK=codex`.

### Anti-Anchoring Block (inject into EVERY reasoning-phase agent prompt below)

Every spawned agent in R5, R8, and R10k must receive this block (kept short to stay under codex's 300-char spawn-prompt cap — serialize as ONE compact line):

> `"REVISIT R<N>: (1) treat KB as facts, not complete threat picture (2) do NOT refile: <top-10 known findings as id+class+location pairs> (3) round-1 exhausted: <known_attack_modes csv> — expand into adjacent modes"`

For the full rationale, the agent should read `archon/revisit-audit-state.json` `revisits[-1].seed` directly.

### R5: Deep Probe

Form probe teams identically to deep-mode P5 (read KB, group by attacker-input components). For each team, spawn agents sequentially (one at a time):

1. `archon:probe-strategist` with the anti-anchoring block + workspace path (writes attack-surface-map.md AND code-anatomy.md inline)
2. `archon:backward-reasoner` with the anti-anchoring block
3. `archon:contradiction-reasoner` with the anti-anchoring block
4. `archon:evidence-harvester` with the anti-anchoring block (also owns causal challenge — no separate verifier)

Mark R5 complete when all teams' `probe-summary.md` files exist.

### R7: Enrichment Re-classify

Inline — walk any SAST references still in the KB and re-classify using the same rules as Phase 4's `## SAST Enrichment` pass (security / correctness / environment-only, CodeQL reachability cross-reference). If no live SAST references remain, append a one-line note to the KB: `Round <N> R7: no live SAST references to re-classify.` Mark R7 complete.

### R8: Review Chambers

Form threat clusters identically to deep-mode P7 (from KB DFD/CFD slices). For each cluster, spawn chamber agents **sequentially** with the anti-anchoring block in each prompt:

1. `archon:chamber-synthesizer` with cluster name + workspace `archon/chamber-workspace/r<N>-<cluster>/`
2. `archon:attack-ideator` with cluster name + negative-list reminder
3. `archon:code-tracer` with cluster name
4. `archon:devils-advocate` with cluster name

Append `## Round <N> Chamber Addendum` to the KB with: chambers spawned, new hypotheses, new attack patterns. Mark R8 complete.

### R9: FP Check

Apply `fp-check` skill inline to each round-<N> draft in `archon/findings-draft/` with `Verdict: VALID`. For CRITICAL and HIGH, spawn `archon:cold-verifier` **sequentially** with the anti-anchoring block. Mark R9 complete.

### R10: Variants on New Findings

For each confirmed Medium-or-higher round-<N> finding draft, spawn one `archon:variant-hunter` sequentially. Mark R10 complete.

### R10k: Variants on Round-1 Known Findings

For each entry in `seed.known_findings` with severity CRITICAL or HIGH (skip MEDIUM), spawn one `archon:variant-hunter` sequentially with prompt:
> `"R10k R<N>: variant hunt on known finding <id>-<slug> (<class>, <location>). Fresh priors. Do NOT refile original. Output: archon/findings-draft/p10k-<NNN>-<slug>.md with Origin-Finding: <id>-<slug>."`

Mark R10k complete.

### R11: PoC Construction

Run the consolidator in continuation mode so new IDs skip the round-1 range:
```bash
ARCHON_REVISIT_ROUND=<N> ARCHON_REVISIT_ID=<id> ARCHON_REVISIT_MODEL=<model> ARCHON_REVISIT_AGENT_SDK=codex \
  python3 ~/.config/archon-audit/skills/audit/scripts/consolidate_drafts.py archon --continue-ids
```

If non-zero exit, abort. For each entry in the emitted manifest, spawn one `archon:poc-builder` sequentially. poc-builder does NOT write `report.md` (that is R11b). Capture the new finding IDs into `revisits[-1].new_finding_ids[]`. Mark R11 complete.

### R11b: Finding Finalization

For each NEW round-<N> finding directory (`metadata.json` has `round == N`), spawn one `archon:finding-reporter` sequentially. Do NOT re-finalize round-1 findings. After all reporters, verify every NEW finding has a non-empty `report.md` (>500 bytes). Retry once for missing; abort if still incomplete. Mark R11b complete.

### R11c: Final Report Regeneration

Spawn `archon:report-assembler` with the instruction to:
> `"R11c R<N>: regenerate archon/final-audit-report.md with a ## Discoveries by Round section. Read both audit-state.json (round 1) and revisit-audit-state.json (rounds 2+). Mark round-<N> findings as [NEW IN ROUND <N>] in the detail section. Consistency checks MUST include finding completeness."`

After the assembler finishes, run post-audit cleanup:
```bash
rm -rf archon/findings-draft/ archon/probe-workspace/ archon/chamber-workspace/ archon/adversarial-reviews/
rm -f  archon/attack-pattern-registry.json
```

Mark R11c complete. Set `revisits[-1].status = "complete"` and `revisits[-1].completed_at = now`.

## Revisit Resume Logic

Read `revisits[-1].phases`. Walk in order: R5, R7, R8, R9, R10, R10k, R11, R11b, R11c. First phase not `complete`: if its artifact gate is satisfied, mark `complete` and advance; otherwise run.

---

# Confirmation Mode (6-Phase Pipeline: V1-V6)

When the user's prompt contains "Confirm mode", "confirm findings", or "verify findings",
use this pipeline. It reads existing findings from `archon/findings/`, boots the target
application, executes PoC scripts, and falls back to generated test cases.

**Prerequisites**: `archon/findings/` must contain finding directories with `report.md`.
`archon/audit-state.json` is optional supplemental metadata only.

## Confirmation Agents

| Phase | Agent | Role |
|-------|-------|------|
| V2 -- Environment Discovery | `archon:env-detective` | Scan repo for Dockerfile, docker-compose, Makefile, test frameworks |
| V3 -- Environment Provisioning | `archon:env-provisioner` | Start the app, run healthchecks, output connection details |
| V4 -- PoC Execution | `archon:poc-executor` | Run existing PoC scripts against live environment |
| V5 -- Test Fallback | `archon:test-mapper` | Generate and run reproducer tests for unconfirmed findings |
| V6 -- Report | `archon:confirm-reporter` | Compile confirmation report with per-finding verdicts |

## Confirmation Execution Plan

### Pre-Flight

1. Verify `archon/findings/` has at least one `report.md`. Abort if not.
2. If `archon/audit-state.json` exists, use it only as optional metadata and update its `confirmation` object when present.
3. `mkdir -p archon/confirm-workspace/`
4. **Workspace lock**: if `archon/confirm-workspace/.lock` exists, read its `pid` — if alive, abort; if stale, remove. Then write a new lock with the current PID and a fresh session UUID.
5. **Generate session UUID**: `ARCHON_SESSION_UUID=$(uuidgen 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())')`. Export it. Every spawned agent prompt MUST include the session UUID. Every container/process MUST be stamped with `archon.session=<UUID>` so cleanup is label-based, not stored-cmd-based.
6. **Trap cleanup**: install a shell trap on EXIT/INT/TERM that removes containers labelled with this session, kills any PID in `archon/confirm-workspace/app.pid`, and removes the lock — so Ctrl-C never leaks resources.
7. Check if user prompt includes a target URL. If yes, set `REMOTE_TARGET` and skip V2/V3.

### V1: Findings Inventory (inline — no agent needed)

Scan `archon/findings/*/report.md`. `report.md` is the source of truth for confirmation.
For each finding, record: ID, slug, severity, vulnerability class, title, PoC script path (if exists), `Protocol` field (default: http), `Auth-Required` field (default: no), and `exploitability_class` (network-exploitable | local-exploitable | non-exploitable — derived from vuln_class + Protocol). Write inventory to `archon/confirm-workspace/findings-inventory.json`. Sort by severity (CRITICAL first).

**Class routing** (applies to V4 and V5):
- `non-exploitable` findings: write `Confirm-Status: analytical-only` directly in `report.md` and skip both V4 and V5.
- `local-exploitable` findings: skip V4, send to V5 with mode `local`.
- `network-exploitable` findings: V4 → V5 fallback as today.

### V2: Environment Discovery (skip if REMOTE_TARGET)

Spawn `archon:env-detective` with prompt:
> `"V2 session=$ARCHON_SESSION_UUID: Discover startup + test infra. Output: archon/confirm-workspace/env-strategies.json + archon/confirm-workspace/auth-spec.json (if auth scaffolding present)"`

Wait for completion.

### V3: Environment Provisioning (skip if REMOTE_TARGET)

Spawn `archon:env-provisioner` with prompt:
> `"V3 session=$ARCHON_SESSION_UUID: Start app, label all containers archon.session=$ARCHON_SESSION_UUID, honour IMAGE_PULL_TIMEOUT/SERVICE_BOOT_TIMEOUT/HEALTHCHECK_TIMEOUT, allocate port with fallback range, seed identities from auth-spec.json, snapshot DB unless SKIP_ISOLATION=1. Output: archon/confirm-workspace/env-connection.json"`

Wait for completion. If `status: failed`, skip V4 and run V5 for ALL network-exploitable findings.

### V4: PoC Execution

**Reachability gate**: before any per-finding spawn, hit `base_url` once (`curl -sf -o /dev/null --max-time 5 "$base_url"`). If unreachable, mark every queued finding `Confirm-Status: blocked` with reason `app-unreachable-at-V4-start` and skip directly to V5.

For each `network-exploitable` finding with a PoC script, spawn `archon:poc-executor` **sequentially** (codex constraint — no concurrent fan-out):
> `"V4 session=$ARCHON_SESSION_UUID: Execute PoC for <ID>-<slug>. Per-variant timeout 30s (max 2 variants). Connection: archon/confirm-workspace/env-connection.json. Parse structured PoC output (final JSON line {status,evidence,notes}). On failed→fp-check the draft."`

Spawn one, wait, then next. Collect verdicts by re-reading each finding's `report.md` `Confirm-*` fields.

### V5: Test-Based Fallback (skip if REMOTE_TARGET)

For each unconfirmed/blocked/no-poc/local-exploitable finding, spawn `archon:test-mapper` **sequentially**:
> `"V5 session=$ARCHON_SESSION_UUID: Generate reproducer test for <ID>-<slug>. Strategies: archon/confirm-workspace/env-strategies.json. Connection (auth identities): archon/confirm-workspace/env-connection.json. Mode: <full|fallback|local>. Per-test timeout 60s."`

Spawn one, wait, then next.

### V6: Confirmation Report

Spawn `archon:confirm-reporter` with prompt:
> `"V6 session=$ARCHON_SESSION_UUID: Compile confirmation report grouped by exploitability_class. Dedupe by ID (priority: confirmed-live > confirmed-test > ...). Audit state optional — if present, append to confirmation_history[] (do NOT overwrite). Output: archon/confirmation-report.md"`

### Cleanup

The trap installed at Pre-Flight handles cleanup automatically (containers by session label, app.pid kill, lock removal). After V6, additionally:
- Update `audits[-1].confirmation.status` to `complete` if `audit-state.json` exists.
- The reporter has already appended a new entry to `audits[-1].confirmation_history[]`.

# END archon-audit
