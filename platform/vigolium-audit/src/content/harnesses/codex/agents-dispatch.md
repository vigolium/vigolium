# BEGIN vigolium-audit
# vigolium-audit Audit Agents

## Mode Selection (CRITICAL — read the user prompt first)

The user's prompt specifies the audit mode. Follow EXACTLY one pipeline:

- **"Full deep mode"** or **"all phases"** → use **Full Deep-Mode Audit** below (P1-P12 plus systematic sub-phases P6 / P7 and P10a Intent Reconciliation; cross-service taint and per-finding variant analysis are folded into P4 + the chamber, not standalone phases)
- **"Balanced mode: B1-B9"** → use **Balanced Audit Mode** (9 phases) below
- **"Lite mode: L1-L3"** → use **Lite Audit Mode** (3 phases L1-L3) below
- **"Revisit mode"** or **"1-9"** → use **Revisit Mode** (9 phases) below — second/Nth pass on top of an existing `vigolium-results/` directory
- **"Confirm mode"** or **"confirm findings"** → use **Confirmation Mode** (6 phases V1-V6) below
- If no mode is specified → default to **Balanced 9-Phase Audit**

Do NOT use the lite/balanced pipeline when the user requests a full or deep audit.
Do NOT use the confirmation pipeline unless the user explicitly requests confirmation/verification of existing findings.

## No-Git Rule (CRITICAL)

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false` or `git rev-parse --is-inside-work-tree` fails, local history is unavailable for the entire run.

- NEVER spawn `vigolium-audit:history-miner`
- NEVER spawn `vigolium-audit:patch-auditor` for history-derived analysis
- Mark the skipped history-dependent work explicitly in `vigolium-results/attack-surface/knowledge-base-report.md`
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
- `"P1: Run intelligence gathering. Output: vigolium-results/attack-surface/knowledge-base-report.md"`
- `"P3: Build knowledge base (full mode, all research modes). Output: vigolium-results/attack-surface/knowledge-base-report.md"`
- `"P6: Enumerate routes/handlers; build vigolium-results/attack-surface/authz-matrix.md"`

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

- P1 complete if `vigolium-results/attack-surface/knowledge-base-report.md` contains advisory intelligence sufficient to identify patch inputs for P2, or an explicit `history_available=false` note explaining that local patch-history analysis is unavailable.
- P2 complete if each intended patch produced bypass analysis output, or the KB contains an explicit skipped/no-history conclusion for patch bypass analysis.
- P3 complete if the required KB sections for later phases exist, even if the worker ended after writing them incrementally.
- P4 complete if the required static-analysis artifacts exist and the KB contains `## Static Analysis Summary` plus `## CodeQL Structural Analysis`; AND, when `## Architecture Model` marks `Multi-service: true`, `vigolium-results/attack-surface/cross-service-edges.json` exists (single-service projects need no such artifact — cross-service edge enumeration is folded into P4).
- P6 complete if `vigolium-results/attack-surface/authz-matrix.md` exists OR the KB contains `## Authorization Audit` with an explicit skip note.
- P7 complete if the KB contains `## State & Concurrency Audit` (zero findings is acceptable).
- P8 (cross-service taint) is **folded away** — there is no standalone P8. Edge enumeration is gated into P4 (see P4 gate above, multi-service only); cross-service taint reasoning happens inside the P7 chamber Ideator. Do not dispatch `vigolium-audit:taint-tracer`.
- P9 complete if the KB contains `## Spec Gap Analysis` or an explicit "None identified" conclusion.
- P4 enrichment runs inline inside P4 (no separate phase); P4 complete only when the KB also contains `## SAST Enrichment`.
- P7 complete if chamber workspace output exists and medium-or-higher validated findings were written or the chamber closed with no valid findings.
- P10 complete if all current VALID drafts were processed by FP check.
- P10a complete if `vigolium-results/attack-surface/intent-corpus.json` exists (empty arrays acceptable) OR P10a was recorded skipped under skip-and-continue (Intent Reconciliation is best-effort and never blocks).
- P11 (variant analysis) is **folded away** — there is no standalone P11. Per-finding variant expansion runs inside the P7 chamber Code Tracer (same-pattern search on every VALID finding, filed in the `p10-` namespace with `Origin-Finding:`/`Origin-Pattern:`). Do not dispatch `vigolium-audit:variant-scanner` in full deep mode (it remains a `revisit`-mode agent).
- P12 complete if every directory under `vigolium-results/findings/` has a PoC script and the draft inside has a `PoC-Status` line written back.
- P10b complete if every directory under `vigolium-results/findings/` has a non-empty `report.md` (>500 bytes).
- P10c complete if `vigolium-results/final-audit-report.md` exists and references the finding IDs currently in `vigolium-results/findings/`.

For 3-phase lite mode:

- L1 complete if `vigolium-results/attack-surface/lite-recon.md` exists.
- L2 complete if secret-scan drafts exist or an explicit no-secrets result was written.
- L3 complete if SAST artifacts or manual-scan findings exist, or an explicit no-findings result was written.

For 9-phase balanced mode:

- B1 complete if the KB has the lite intelligence output.
- B2 complete if the KB sections needed by B3/B4 exist.
- B3 complete if SAST artifacts exist and the KB has `## Static Analysis Summary`.
- B4 complete if `vigolium-results/probe-workspace/balanced-probe/probe-summary.md` exists or an explicit no-hypothesis result was written.
- B5 complete if chamber output exists and VALID drafts were FP-checked or the chamber closed cleanly with none.
- B6 complete if `vigolium-results/attack-surface/intent-corpus.json` exists (empty arrays acceptable) OR B6 was recorded skipped under skip-and-continue (Intent Reconciliation is best-effort and never blocks).
- B7 complete if every directory under `vigolium-results/findings/` has a PoC script and the draft inside has a `PoC-Status` line written back.
- B8 complete if every directory under `vigolium-results/findings/` has a non-empty `report.md` (>500 bytes).
- B9 complete if `vigolium-results/final-audit-report.md` exists and references the finding IDs currently in `vigolium-results/findings/`.

For revisit mode (reads/writes `vigolium-results/revisit-audit-state.json`; round 1 is the original audit-state.json, rounds ≥2 live in revisit-audit-state.json):

- 1 complete if every probe team wrote its `vigolium-results/probe-workspace/*/probe-summary.md`.
- 2 complete if SAST references in the KB were re-classified OR an explicit "no live SAST references" note was written.
- 3 complete if every chamber for the current round closed and the KB has `## Round <N> Chamber Addendum`.
- 4 complete if every VALID round-<N> draft in `vigolium-results/findings-draft/` received an `fp-check` verdict, and every CRITICAL/HIGH one also received a independent-verifier result.
- 5 complete if every new confirmed round-<N> finding received variant output.
- 6 complete if every round-1 CRITICAL/HIGH finding received a fresh-priors variant-scanner result or an explicit "no variant found" note.
- 7 complete if every NEW round-<N> finding directory has a PoC script and the draft has a `PoC-Status` line written back.
- 8 complete if every NEW round-<N> finding directory has a non-empty `report.md` (>500 bytes). Round-1 findings are NOT required to be re-finalized.
- 9 complete if `vigolium-results/final-audit-report.md` exists and contains `## Discoveries by Round` with a row for the current round.

## Output Chunking (IMPORTANT for Codex)

All agents MUST write output incrementally to avoid hitting the per-turn output cap:
- Write findings one file at a time (one `vigolium-results/findings-draft/` file per tool call)
- Write report sections incrementally — never accumulate an entire report in a single write
- When writing `vigolium-results/attack-surface/knowledge-base-report.md`, write each `##` section as a separate file write
- Keep individual file write payloads under 3 KB — split into multiple writes if needed
- Prefer `exec` with `cat >> file` for appending over rewriting entire files

---

# Full Deep-Mode Audit (P1-P12 + systematic sub-phases P6 / P7 + P10a Intent Reconciliation)

When the user requests a "deep audit", "full audit", or the prompt contains "Full deep mode" or
"all phases", execute ALL phases below in order. Do NOT skip phases or fall back to lite mode. P6 and P7 are systematic-audit sub-phases inserted between P4 (SAST) and P9 (Spec Gap); they dispatch sequentially on Codex. Cross-service taint and per-finding variant analysis are NOT standalone phases — cross-service edge enumeration is folded into P4 (multi-service only), cross-service taint reasoning into the P7 chamber Ideator, and variant expansion into the P7 chamber Code Tracer.

## Full Audit Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| P1 -- Intelligence Gathering | `vigolium-audit:cve-scout` | Advisories, architecture inventory, dependency intel |
| P2 -- Patch Bypass Analysis | `vigolium-audit:patch-auditor` | Per-patch bypass hypothesis testing (one agent per patch, concurrent) |
| P3 -- Knowledge Base | `vigolium-audit:threat-modeler` | Threat model, DFD/CFD slices, domain attack research (Modes A/B/C) |
| P4 -- Static Analysis | `vigolium-audit:code-scanner` | Sub-step 4.1 structural extraction + CodeQL/Semgrep security scan |
| P6 -- Authorization Audit | `vigolium-audit:access-auditor` | Exhaustive endpoint enumeration + IDOR/BOLA/escalation review |
| P7 -- State & Concurrency Audit | `vigolium-audit:concurrency-auditor` | TOCTOU, transaction isolation, state-machine, idempotency review |
| P9 -- Spec Gap Analysis | (inline) | RFC/spec compliance gap analysis |
| P7 -- Deep Bug Hunting (Chamber) | `vigolium-audit:review-adjudicator` | Orchestrates Review Chamber debate |
| P7 -- Deep Bug Hunting (Ideator) | `vigolium-audit:attack-designer` | Creative attack hypothesis generation using 8 attack modes |
| P7 -- Deep Bug Hunting (Tracer) | `vigolium-audit:flow-tracer` | Code path tracing and reachability analysis |
| P7 -- Deep Bug Hunting (Advocate) | `vigolium-audit:red-challenger` | Adversarial defense briefs searching all 5 protection layers |
| P10 -- FP Check | (inline) | False positive elimination using `fp-check` skill |
| P10a -- Intent Reconciliation | `vigolium-audit:context-reviewer` | Reconcile VALID drafts vs documented intent; reuse `Triage-Priority: skip` for strongly-intentional findings; skip-and-continue |
| P12 -- PoC & Reporting (PoC) | `vigolium-audit:poc-author` | Per-finding PoC construction + evidence + draft-metadata only |
| P10b -- Finding Finalization | `vigolium-audit:finding-writer` | Per-finding `report.md` authoring (cold-context) |
| P10c -- PoC & Reporting (Report) | `vigolium-audit:report-composer` | Final consolidated audit report |

## Full Pipeline

```
P1 (Intel) → P2 (Patch Bypass) → P3 (KB) → P4 (SAST + inline enrichment + multi-service edge enum)
→ P6 (AuthZ) → P7 (State/Concurrency)
→ P9 (Spec Gaps) → P7 (Chambers: + inline cross-service taint + inline variant expansion)
→ P10 (FP Check) → P10a (Intent Reconciliation)
→ P12 (PoC) → P10b (Finalize report.md per finding; GATE) → P10c (Final Report)
```

## Full Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | P1 -- Intelligence Gathering | -- |
| T2 | P2 -- Patch Bypass Analysis | T1 |
| T3 | P3 -- Knowledge Base | T2 |
| T4 | P4 -- Static Analysis | T3 |
| T4A | P6 -- Authorization Audit | T3 |
| T4B | P7 -- State & Concurrency Audit | T3 |
| T5 | P9 -- Spec Gap Analysis | T3 |
| T7 | P7 -- Deep Bug Hunting (Chambers; + inline cross-service taint + inline variant expansion) | T4, T4A, T4B, T5 |
| T10 | P10 -- FP Check | T7 |
| T10a | P10a -- Intent Reconciliation | T10 |
| T12 | P12 -- PoC Construction | T10a |
| T10b | P10b -- Finding Finalization | T12 |
| T10c | P10c -- Final Report Assembly | T10b |

On Codex, execute phases strictly in this order even if other platform prompts describe parallelism.

## Full Phase Instructions

### Pre-Flight Check

If `vigolium-results/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "An audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed audit exists. Run fresh, run incremental diff, or cancel?"

### Pre-Audit Setup

1. Detect whether Git history is available: `git rev-parse --is-inside-work-tree >/dev/null 2>&1 && export VIGOLIUM_AUDIT_GIT_AVAILABLE=true || export VIGOLIUM_AUDIT_GIT_AVAILABLE=false`
2. **Do NOT switch branches.** Stay on the current branch. Do NOT run `git checkout`, `git switch`, `git branch`, `git commit`, `git add`, or `git push` against the target repo at any point. The audit writes everything under `vigolium-results/` (untracked) — the user controls staging and commits.
3. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, continue auditing the directory in place. Do NOT initialize a repo just for the audit.
4. `mkdir -p vigolium-results/`
5. Initialize `vigolium-results/audit-state.json` — append a new entry with `"mode": "full"`, `"repository": "<org/repo or folder name>"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, `"history_available": <true|false>`, and phases P1, P2, P3, P4, P6, P7, P9, P7, P10, P10a, P12 set to `pending`. Never remove earlier entries. Use the value of `$VIGOLIUM_AUDIT_REPOSITORY` (pre-computed by the CLI from git remote / package manifests / basename) for the `repository` field — substitute the literal string before writing.
6. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, update `.gitignore` with SAST artifact exclusions. Otherwise skip `.gitignore` edits.

### P1: Intelligence Gathering

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, spawn `vigolium-audit:cve-scout` with prompt:
> `"P1: Run intelligence gathering. Output: vigolium-results/attack-surface/knowledge-base-report.md"`

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, spawn `vigolium-audit:cve-scout` with prompt:
> `"P1: Run intelligence gathering (no local git history). Output: vigolium-results/attack-surface/knowledge-base-report.md"`

Wait for completion. Update `audits[-1].phases.P1.status` to `complete`.
Then continue immediately to P2.

### P2: Patch Bypass Analysis

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, for each security patch found in P1, spawn one `vigolium-audit:patch-auditor` **sequentially** (one at a time, wait before spawning next) with prompt:
> `"P2: Analyze patch <CVE-ID>. Output: vigolium-results/attack-surface/knowledge-base-report.md"`

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, do not spawn `vigolium-audit:patch-auditor`. Instead append an explicit `## Bypass Analysis` note to `vigolium-results/attack-surface/knowledge-base-report.md` stating that local patch bypass analysis was skipped because the target has no Git history, then mark P2 complete.

Update P2 status after all complete.
Then continue immediately to P3.

### P3: Knowledge Base

Spawn `vigolium-audit:threat-modeler` with prompt:
> `"P3: Build knowledge base (full mode, all research modes A/B/C). Write each ## section separately to vigolium-results/attack-surface/knowledge-base-report.md"`

The KB builder MUST write each `##` section as a separate file append (using `cat >>`) to avoid hitting the output token cap. Do NOT accumulate the entire KB in memory.

Wait for completion. Update P3 status.
Then continue immediately to P4.

### P4: Static Analysis (+ inline Enrichment)

Spawn `vigolium-audit:code-scanner` with prompt:
> `"P4 FULL MODE: structural extraction + CodeQL + Semgrep Pro + custom rules + inline enrichment + cross-service edge enum if Multi-service. Output: vigolium-results/"`

If the KB `## Architecture Model` marks `Multi-service: true`, code-scanner also enumerates inter-service channels and writes `vigolium-results/attack-surface/cross-service-edges.json` + `.md` (Sub-step 4.1b). Single-service projects skip that — it is a legitimate no-op. No `vigolium-audit:taint-tracer` is spawned.

Wait for completion. If the worker does not terminate cleanly, inspect `vigolium-results/codeql-artifacts/`,
`vigolium-results/codeql-queries/`, `vigolium-results/semgrep-res/`, and `vigolium-results/attack-surface/knowledge-base-report.md`.
If the required P4 artifacts and all three KB sections (`## Static Analysis Summary`, `## CodeQL Structural Analysis`, `## SAST Enrichment`) exist (plus `cross-service-edges.json` when multi-service), mark P4 `complete` under the artifact gate and continue.
Only re-run P4 if mandatory outputs are missing. Then continue immediately to P6.

### P6: Authorization Audit

Spawn `vigolium-audit:access-auditor` with prompt:
> `"P6: Enumerate routes/handlers; build vigolium-results/attack-surface/authz-matrix.md; file drafts vigolium-results/findings-draft/p6-<NNN>-<slug>.md"`

Wait for completion. Artifact gate: `vigolium-results/attack-surface/authz-matrix.md` exists OR the KB has an explicit `## Authorization Audit` skip note. Update P6 status. Continue to P7.

### P7: State & Concurrency Audit

Spawn `vigolium-audit:concurrency-auditor` with prompt:
> `"P7: Catalogue state entities + concurrency primitives; file drafts vigolium-results/findings-draft/p7-<NNN>-<slug>.md"`

Wait for completion. Artifact gate: the KB has `## State & Concurrency Audit` (even with zero findings). Update P7 status. Continue to P8.

### P8: Cross-Service Taint — FOLDED (no dispatch)

There is no standalone P8. Cross-service edge *enumeration* is folded into P4 (`code-scanner` writes `cross-service-edges.json` only when `Multi-service: true`); cross-service taint *reasoning* is folded into the P7 chamber Ideator (which reads `cross-service-edges.json` and adds boundary-sanitization / transitive-trust / write-driven-injection / queue-source-auth / cross-service-SSRF / event-replay / internal-exposed hypotheses). Do NOT spawn `vigolium-audit:taint-tracer`. Skip directly from P7 (State & Concurrency) to P9.

### P9: Spec Gap Analysis

Execute inline (no subagent). Read `vigolium-results/attack-surface/knowledge-base-report.md` sections on specs/RFCs. Use `spec-to-code-compliance` skill. Focus on parsing, normalization, sanitization, canonicalization, and state-machine compliance.

Update P9 status.
Then continue immediately to P7.

### P7: Deep Bug Hunting (Review Chambers)

1. Group findings by threat cluster (DFD/CFD slice groups). Include pre-seeded drafts from P6 (`vigolium-results/findings-draft/p6-*.md`) and P7 (`vigolium-results/findings-draft/p7-*.md`) as starting material — the Ideator chains/extends them, not regenerate. If `vigolium-results/attack-surface/cross-service-edges.json` exists (multi-service), also hand the Ideator the edges for the cluster.
2. For each cluster, spawn chamber agents **one at a time** (sequential, not concurrent):
   a. Spawn `vigolium-audit:review-adjudicator` with prompt: `"P7: Orchestrate chamber for cluster <name>. Pre-seed p6-*/p7-* + cross-service-edges.json edges. Output: vigolium-results/chamber-workspace/<id>/"`
      Wait for completion.
   b. Spawn `vigolium-audit:attack-designer` with prompt: `"P7: Hypotheses for cluster <name>; chain pre-seeded drafts; add cross-service taint hypotheses for supplied edges. Output: vigolium-results/chamber-workspace/<id>/debate.md"`
      Wait for completion.
   c. Spawn `vigolium-audit:flow-tracer` with prompt: `"P7: Trace evidence for cluster <name>; on every VALID finding run an inline same-pattern variant search, file variants p10-<NNN> with Origin-Finding/Origin-Pattern. Output: vigolium-results/chamber-workspace/<id>/debate.md"`
      Wait for completion.
   d. Spawn `vigolium-audit:red-challenger` with prompt: `"P7: Challenge hypotheses for cluster <name>. Output: vigolium-results/chamber-workspace/<id>/debate.md"`
      Wait for completion.
3. If multiple clusters, process them sequentially too.
4. Each chamber produces finding drafts in `vigolium-results/findings-draft/` (including inline cross-service and variant drafts in the `p10-` namespace).
5. Do NOT spawn `vigolium-audit:variant-spotter` or `vigolium-audit:variant-scanner` in Codex full deep mode — variant expansion is inline in the `vigolium-audit:flow-tracer` Code Tracer step (5c). Do NOT spawn `vigolium-audit:taint-tracer` — cross-service taint is inline in the `vigolium-audit:attack-designer` Ideator step (5b).

Update P7 status.
Then continue immediately to P10.

### P10: FP Check

Execute inline. Apply `fp-check` skill to all `vigolium-results/findings-draft/p10-*.md` with `Verdict: VALID`.
Only CRITICAL and HIGH severity findings get cold verification.
Update P10 status.
Then continue immediately to P10a.

### P10a: Intent Reconciliation

Runs after the P10 FP/triage tail and **before** PoC. Spawn one `vigolium-audit:context-reviewer` with prompt:
> `"P10a AUDIT CONTRACT: reconcile VALID drafts in vigolium-results/findings-draft/ vs documented intent. Reuse Triage-Priority: skip for strong intentional/feature. Output: vigolium-results/attack-surface/intent-corpus.json + intent-verdicts.json + intent-reconciliation.md"`

Wait for completion. **Skip-and-continue**: if it fails or writes no corpus, log it and continue to P12 — the absence of `intent-corpus.json` must NOT suppress any finding (every VALID draft keeps its P10 triage priority). Artifact gate: `vigolium-results/attack-surface/intent-corpus.json` exists OR P10a recorded skipped. Update P10a status.
Then continue immediately to P12.

### P11: Variant Analysis — FOLDED (no dispatch)

There is no standalone P11. Per-finding variant expansion ran inline in the P7 chamber Code Tracer (step 5c): on every VALID finding the `vigolium-audit:flow-tracer` did a same-pattern search and filed Medium+ variants in the `p10-` namespace with `Origin-Finding:`/`Origin-Pattern:` frontmatter, so they already passed through P10 FP/triage and P10a intent reconciliation. Do NOT spawn `vigolium-audit:variant-scanner` here (it remains a `revisit`-mode agent). Proceed directly from P10a to P12.

### P12: PoC Construction

1. Collect `Verdict: VALID` drafts, assign severity IDs (C1, H1, M1, 1).
2. For each finding, spawn one `vigolium-audit:poc-author` **sequentially** (one at a time):
   > `"P12: Build PoC for finding <finding-id>. Output: vigolium-results/findings/<ID>-<slug>/poc.*, evidence/, and draft metadata writeback. Do NOT write report.md — that is P10b."`
   Spawn one, wait for completion, then spawn the next.

Update P12 status. Then continue immediately to P10b.

### P10b: Finding Finalization

For each directory under `vigolium-results/findings/`, spawn one `vigolium-audit:finding-writer` **sequentially**:
> `"P10b: Author report.md for finding <ID>-<slug>. Input: vigolium-results/findings/<ID>-<slug>/. Output: vigolium-results/findings/<ID>-<slug>/report.md"`

Spawn one, wait, then next. After all reporters complete, verify every `vigolium-results/findings/<ID>-<slug>/report.md` exists and is larger than 500 bytes. Retry once for any missing/truncated files. STOP if any remain incomplete.

Update P10b status once every finding directory has a non-empty `report.md`. Then continue immediately to P10c.

### P10c: Final Report Assembly

Spawn a single `vigolium-audit:report-composer` with prompt:
> `"P10c: Compile final audit report. Every finding has report.md (guaranteed by P10b). Output: vigolium-results/final-audit-report.md"`

Update P10c status. Set `audits[-1].completed_at` and `audits[-1].status` to `complete`.

## Full Mode Resume Logic

Read `audits[-1].phases` to find the first phase not `complete`:
- `failed` or `in_progress`: check if output artifacts satisfy the phase's artifact completion gate. If yes, mark complete and advance immediately. Otherwise delete partial output and re-run.
- `pending`: run normally.

Continue sequentially through P12 without pausing for intermediate status reports.

---

# Lite Audit Mode (3-Phase Pipeline: L1-L3)

When the user asks for "Lite mode: L1-L3", run the dedicated 3-phase lite audit below. This mode is intentionally source-only and must work even when the target directory has no `.git` folder or local history.

## Lite Pipeline

```
L1 (Quick Recon) → L2 (Secrets Scan) → L3 (Fast SAST Pass) → PoC Building
```

## Lite Phase Instructions

### Pre-Flight Check

If `vigolium-results/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "A lite audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed lite audit exists. Run fresh lite, upgrade to balanced, upgrade to full, or cancel?"

### Pre-Audit Setup

1. Detect whether Git history is available: `git rev-parse --is-inside-work-tree >/dev/null 2>&1 && export VIGOLIUM_AUDIT_GIT_AVAILABLE=true || export VIGOLIUM_AUDIT_GIT_AVAILABLE=false`
2. **Do NOT switch branches.** Stay on the current branch. Do NOT run `git checkout`, `git switch`, `git branch`, `git commit`, `git add`, or `git push` against the target repo at any point. The audit writes everything under `vigolium-results/` (untracked) — the user controls staging and commits.
3. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, continue auditing the directory in place. Do NOT initialize a repo just for the audit.
4. `mkdir -p vigolium-results/ vigolium-results/findings-draft/`
5. Initialize `vigolium-results/audit-state.json` — append a new entry with `"mode": "lite"`, `"repository": "<org/repo or folder name>"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, `"history_available": <true|false>`, and phases L1–L3 set to `pending`. Never remove earlier entries.

### L1: Quick Recon

Read file structure and manifests directly from disk. Detect languages, frameworks, likely entry points, deployment files, and directories to exclude from scanning. Write `vigolium-results/attack-surface/lite-recon.md`. Update L1 status.

### L2: Secrets Scan

Scan the target snapshot for secrets. Prefer filesystem/native modes that do not require Git history:
- `trufflehog filesystem <target> --no-update --json`
- `gitleaks detect --source <target> --no-git --report-format json`
- Fallback manual grep/pattern scan

Write one finding draft per result under `vigolium-results/findings-draft/`, or write an explicit no-secrets result if nothing is found. Update L2 status.

### L3: Fast SAST Pass

Run built-in static analysis against the source snapshot using `vigolium-results/attack-surface/lite-recon.md` for scope:
- Prefer `semgrep scan --config auto`
- Fallback to built-in CodeQL suites when feasible
- Fallback to manual pattern scans if neither tool is available

Write one finding draft per result under `vigolium-results/findings-draft/`, or write an explicit no-findings result if nothing is found. Then assign severity-prefixed IDs, create `vigolium-results/findings/<ID>-<slug>/`, and spawn `vigolium-audit:poc-author` sequentially for each retained finding. Update L3 status and mark the audit complete.

---

# Balanced Audit Mode (9-Phase Pipeline)

When the user asks for a "balanced audit", "fast audit", or "quick audit", or the prompt
contains "Balanced mode: B1-B9", use this streamlined 9-phase pipeline. Balanced mode
trades depth for speed while producing the same output format (`vigolium-results/audit-state.json`,
`vigolium-results/findings-draft/`, `vigolium-results/audit-report.md`) so results are compatible
with diff and status workflows.

Balanced mode supports auditing a plain source folder with no `.git` directory or local history.

## What Balanced Mode Skips

| Dropped | Full Phase | Rationale |
|---------|-----------|-----------|
| Commit archaeology | P1 | Expensive git history analysis |
| Patch bypass analysis | P2 | Entire phase skipped |
| Custom SAST rules & structural extraction | P4 | Built-in suites are sufficient for speed runs |
| Contradiction Reasoner, Causal Verifier, Code Anatomist | P5 | Single simplified probe round |
| Spec gap analysis | P9 | RFC compliance is deep work |
| Code Tracer (chamber role) | P10 | Synthesizer does inline tracing |
| Cold verification (CRITICAL cold-verify) | chamber FP tail | Devil's Advocate challenge is sufficient |
| Inline cross-service taint reasoning | folded into deep P4 + chamber | Balanced skips structural extraction, so no `cross-service-edges.json`; lighter chamber does not reason cross-service taint |
| Inline variant expansion | folded into deep chamber Code Tracer | Balanced has no Code Tracer, so the same-pattern variant search is skipped |

## Balanced Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| B1 -- Intelligence Gathering | `vigolium-audit:cve-scout` | Advisories, architecture inventory, dependency intel (no commit archaeology) |
| B2 -- Knowledge Base / Threat Model | `vigolium-audit:threat-modeler` | Threat model, DFD/CFD slices — skip Modes B/C, skip Spec Gap & CodeQL Extraction targets |
| B3 -- Static Analysis | `vigolium-audit:code-scanner` | Built-in CodeQL suites + Semgrep Pro only — no custom rules, no structural extraction, no SpotBugs |
| B4 -- Balanced Deep Probe (Strategist) | `vigolium-audit:probe-lead` | Single probe team for ALL attacker-input components — 1 round, no Code Anatomist |
| B4 -- Balanced Deep Probe (Reasoner) | `vigolium-audit:goal-backtracer` | Single round of Pre-Mortem + Abductive reasoning |
| B4 -- Balanced Deep Probe (Harvester) | `vigolium-audit:evidence-collector` | Trace hypotheses, issue VALIDATED/INVALIDATED/NEEDS-DEEPER verdicts |
| B5 -- Review Chamber (Synthesizer) | `vigolium-audit:review-adjudicator` | Single balanced chamber — inline code tracing, max 2 debate rounds |
| B5 -- Review Chamber (Ideator) | `vigolium-audit:attack-designer` | Chain findings, max 7 hypotheses per batch |
| B5 -- Review Chamber (Advocate) | `vigolium-audit:red-challenger` | Defense briefs challenging each hypothesis |
| B6 -- Intent Reconciliation | `vigolium-audit:context-reviewer` | Reconcile VALID drafts vs documented intent; reuse `Triage-Priority: skip` for strongly-intentional findings; skip-and-continue |
| B7 -- PoC & Report (PoC) | `vigolium-audit:poc-author` | Per-finding PoC construction + evidence + draft-metadata only |
| B8 -- Finding Finalization | `vigolium-audit:finding-writer` | Per-finding `report.md` authoring (cold-context) |
| B9 -- PoC & Report (Report) | `vigolium-audit:report-composer` | Final report with balanced mode disclaimer |

Agents NOT used in balanced mode: `vigolium-audit:patch-auditor`, `vigolium-audit:flow-tracer`,
`vigolium-audit:spec-auditor`, `vigolium-audit:variant-scanner`, `vigolium-audit:variant-spotter`.

## Balanced Pipeline

```
B1 (Intel) → B2 (Threat Model) → B3 (Code Scan) → B4 (Targeted Probe) → B5 (Review + FP Check)
→ B6 (Intent Reconciliation) → B7 (PoC) → B8 (Finalize report.md per finding; GATE) → B9 (Report Compose)
```

### Balanced Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | B1 -- Intelligence Gathering | -- |
| T2 | B2 -- Knowledge Base / Threat Model | T1 |
| T3 | B3 -- Static Analysis (built-in suites) | T2 |
| T4 | B4 -- Balanced Deep Probe | T2 |
| T5 | B5 -- Review Chamber + FP Check | T3, T4 |
| T6 | B6 -- Intent Reconciliation | T5 |
| T7 | B7 -- PoC Construction | T6 |
| T8 | B8 -- Finding Finalization | T7 |
| T9 | B9 -- Final Report Assembly | T8 |

On Codex, execute balanced phases strictly in this order even if other platform prompts describe parallelism.

## Balanced Phase Instructions

### Pre-Flight Check

If `vigolium-results/audit-state.json` exists, ask the user before proceeding:

- **Incomplete phases**: "An audit is already in progress. Resume, start fresh, or cancel?"
- **All phases complete**: "A completed audit exists. Run fresh lite, run incremental diff, upgrade to full, or cancel?"

### Pre-Audit Setup

1. Detect whether Git history is available: `git rev-parse --is-inside-work-tree >/dev/null 2>&1 && export VIGOLIUM_AUDIT_GIT_AVAILABLE=true || export VIGOLIUM_AUDIT_GIT_AVAILABLE=false`
2. **Do NOT switch branches.** Stay on the current branch. Do NOT run `git checkout`, `git switch`, `git branch`, `git commit`, `git add`, or `git push` against the target repo at any point. The audit writes everything under `vigolium-results/` (untracked) — the user controls staging and commits.
3. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, continue auditing the directory in place. Do NOT initialize a repo just for the audit.
4. `mkdir -p vigolium-results/`
5. Initialize `vigolium-results/audit-state.json` — append a new entry with `"mode": "balanced"`, `"repository": "<org/repo or folder name>"`, `"model": "<model name>"`, `"agent_sdk": "codex"`, `"history_available": <true|false>`, and phases B1–B9 set to `pending`. Never remove earlier entries. Use the value of `$VIGOLIUM_AUDIT_REPOSITORY` (pre-computed by the CLI from git remote / package manifests / basename) for the `repository` field — substitute the literal string before writing.
6. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, update `.gitignore` with SAST artifact exclusions. Otherwise skip `.gitignore` edits.

### B1: Intelligence Gathering

Spawn `vigolium-audit:cve-scout` with prompt:
> `"B1 BALANCED: Run intelligence gathering, no commit archaeology. Output: vigolium-results/attack-surface/knowledge-base-report.md"`

Do NOT spawn `vigolium-audit:patch-auditor`.
Wait for completion. Update `audits[-1].phases.B1.status` to `complete`.
Then continue immediately to B2.

### B2: Knowledge Base / Threat Model

Spawn `vigolium-audit:threat-modeler` with prompt:
> `"B2 BALANCED: Skip Modes B/C, skip Spec Gap & CodeQL targets. Output: vigolium-results/attack-surface/knowledge-base-report.md"`

Wait for completion. Update B2 status.
Then continue immediately to B3.

### B3: Static Analysis

Spawn `vigolium-audit:code-scanner` with prompt:
> `"B3 BALANCED: Built-in CodeQL + Semgrep Pro only. No custom rules, no extraction. Output: vigolium-results/"`

Wait for completion. If the worker does not terminate cleanly, inspect `vigolium-results/codeql-artifacts/`,
`vigolium-results/semgrep-res/`, and `vigolium-results/attack-surface/knowledge-base-report.md`.
If the required lite P4 artifacts and `## Static Analysis Summary` exist, mark B3 `complete` under the artifact gate and continue.
Only re-run B3 if mandatory outputs are missing. Then continue immediately to B4.

### B4: Balanced Deep Probe

1. Read KB sections: DFD/CFD Slices, Attack Surface, Architecture Model
2. Group ALL attacker-input components into one probe team
3. `mkdir -p vigolium-results/probe-workspace/balanced-probe/`
4. Spawn agents **one at a time** (sequential):
   a. Spawn `vigolium-audit:probe-lead` with prompt: `"B4 BALANCED: 1 round, no Code Anatomist. Output: vigolium-results/probe-workspace/balanced-probe/probe-summary.md"`
      Wait for completion.
   b. Spawn `vigolium-audit:goal-backtracer` with prompt: `"B4 BALANCED: Single round Pre-Mortem + Abductive. Output: vigolium-results/probe-workspace/balanced-probe/"`
      Wait for completion.
   c. Spawn `vigolium-audit:evidence-collector` with prompt: `"B4 BALANCED: Trace and verdict. Output: vigolium-results/probe-workspace/balanced-probe/"`
      Wait for completion.

Perform inline enrichment: classify SAST findings as `likely security` / `likely correctness` / `likely environment-only`, drop non-security. Update B4 status.
Then continue immediately to B5.

### B5: Review Chamber + FP Check

1. `mkdir -p vigolium-results/chamber-workspace/balanced-chamber/`
2. Spawn chamber agents **one at a time** (sequential):
   a. Spawn `vigolium-audit:review-adjudicator` with prompt: `"B5 BALANCED: Orchestrate balanced chamber, inline tracing, max 2 rounds. Output: vigolium-results/chamber-workspace/balanced-chamber/"`
      Wait for completion.
   b. Spawn `vigolium-audit:attack-designer` with prompt: `"B5 BALANCED: Generate hypotheses, max 7 per batch. Output: vigolium-results/chamber-workspace/balanced-chamber/debate.md"`
      Wait for completion.
   c. Spawn `vigolium-audit:red-challenger` with prompt: `"B5 BALANCED: Defense briefs. Output: vigolium-results/chamber-workspace/balanced-chamber/debate.md"`
      Wait for completion.
3. After chamber closes, apply `fp-check` inline to all `vigolium-results/findings-draft/p10-*.md` with `Verdict: VALID`. No cold verifiers.

Update B5 status.
Then continue immediately to B6.

### B6: Intent Reconciliation

Runs after the B5 FP/triage tail and **before** any PoC effort. Spawn one `vigolium-audit:context-reviewer` with prompt:
> `"B6 AUDIT CONTRACT: reconcile VALID drafts in vigolium-results/findings-draft/ vs documented intent. Reuse Triage-Priority: skip for strong intentional/feature. Output: vigolium-results/attack-surface/intent-corpus.json + intent-verdicts.json + intent-reconciliation.md"`

Wait for completion. **Skip-and-continue**: if it fails or writes no corpus, log it and continue to B7 — the absence of `intent-corpus.json` must NOT suppress any finding (every VALID draft keeps its B5 triage priority). Artifact gate: `vigolium-results/attack-surface/intent-corpus.json` exists OR B6 recorded skipped.

Update B6 status. Then continue immediately to B7.

### B7: PoC Construction

1. Collect `Verdict: VALID` drafts, assign severity IDs (C1, H1, M1), drop Low.
2. For each finding, spawn one `vigolium-audit:poc-author` **sequentially** with prompt:
   > `"B7 BALANCED: Build PoC for finding <finding-id>. Output: vigolium-results/findings/<ID>-<slug>/poc.*, evidence/, and draft metadata writeback. Do NOT write report.md — that is B8."`
   Spawn one, wait, then next.

Update B7 status. Then continue immediately to B8.

### B8: Finding Finalization

For each directory under `vigolium-results/findings/`, spawn one `vigolium-audit:finding-writer` **sequentially**:
> `"B8 BALANCED: Author report.md for finding <ID>-<slug>. Input: vigolium-results/findings/<ID>-<slug>/. Output: vigolium-results/findings/<ID>-<slug>/report.md"`

Spawn one, wait, then next. After all reporters complete, verify every `vigolium-results/findings/<ID>-<slug>/report.md` exists and is larger than 500 bytes. Retry once for any missing/truncated files. STOP if any remain incomplete.

Update B8 status once every finding directory has a non-empty `report.md`. Then continue immediately to B9.

### B9: Final Report Assembly

Spawn `vigolium-audit:report-composer` with prompt:
> `"B9 BALANCED: Compile report with skipped-phases disclaimer. Surface vigolium-results/attack-surface/intent-reconciliation.md. Every finding has report.md (guaranteed by B8). Output: vigolium-results/final-audit-report.md"`

Update B9 status. Set `audits[-1].completed_at` and `audits[-1].status` to `complete`.

## Lite Resume Logic

Read `audits[-1].phases` to find the first phase not `complete`:
- `failed` or `in_progress`: check if output artifacts satisfy the phase's artifact completion gate. If yes, mark complete and advance immediately. Otherwise delete partial output and re-run.
- `pending`: run normally.

Continue sequentially through 6 without pausing for intermediate status reports.
---

# Revisit Mode (9-Phase Pipeline: 1-9)

When the user requests "Revisit mode" or the prompt contains "1-9", run a second (or Nth) pass of the deep pipeline on top of an existing `vigolium-results/` directory. Revisit reuses the prior knowledge base, advisories, SAST artifacts (if present), and systematic matrices, and redoes only the reasoning-heavy phases with anti-anchoring prompts so a new model / fresh session can surface findings the prior audit missed.

**Prerequisites** (HARD — abort if missing):
- `vigolium-results/audit-state.json` exists and its last audit entry has `status: complete`.
- `vigolium-results/attack-surface/knowledge-base-report.md` exists and is non-empty.
- `vigolium-results/findings/` exists (may be empty).

## Revisit Agent Dispatch

| Phase | agent_type | Responsibility |
|-------|-----------|----------------|
| 1 -- Deep Probe (fresh, anti-anchored) | `vigolium-audit:probe-lead` + `vigolium-audit:goal-backtracer` + `vigolium-audit:assumption-breaker` + `vigolium-audit:evidence-collector` | New hypotheses, seeded against prior-round findings as a negative list. Strategist writes code anatomy inline; harvester owns causal challenge. |
| 2 -- Enrichment re-classify | (inline) | Re-classify any live SAST references in KB |
| 3 -- Review Chamber (fresh, anti-anchored) | `vigolium-audit:review-adjudicator` + `vigolium-audit:attack-designer` + `vigolium-audit:flow-tracer` + `vigolium-audit:red-challenger` | Debate with explicit "do not refile known findings" instruction |
| 4 -- FP check | (inline + `vigolium-audit:independent-verifier` for CRIT/HIGH) | Same as deep P11-LITE, but only for round-<N> drafts |
| 5 -- Variant analysis (new findings) | `vigolium-audit:variant-scanner` | Per-new-finding variants |
| 6 -- Variant analysis (round-1 known findings) | `vigolium-audit:variant-scanner` | Per round-1 CRITICAL/HIGH finding, fresh-priors mode |
| 7 -- PoC construction | `vigolium-audit:poc-author` | Per-new-finding PoC + evidence + draft metadata |
| 8 -- Finding finalization | `vigolium-audit:finding-writer` | Per-new-finding `report.md` authoring |
| 9 -- Final report regeneration | `vigolium-audit:report-composer` | Rewrite `vigolium-results/final-audit-report.md` with `## Discoveries by Round` section |

## Revisit Pipeline

```
Preflight (validate prior state) → 1 (Probe) → 2 (Enrich)
→ 3 (Chambers, anti-anchored) → 4 (FP check, round-<N> only)
→ 5 (Variants on new) → 6 (Variants on round-1 CRIT/HIGH)
→ 7 (PoC) → 8 (Finalize report.md; GATE) → 9 (Final report)
```

## Revisit Phase Dependencies

| Task | Phase | Depends on |
|------|-------|-----------|
| TR5  | 1 -- Deep Probe | Preflight |
| TR7  | 2 -- Enrichment | TR5 |
| TR8  | 3 -- Review Chambers | TR5, TR7 |
| TR9  | 4 -- FP Check | TR8 |
| TR10 | 5 -- Variants (new) | TR9 |
| TR10k| 6 -- Variants (round-1 known) | TR9 |
| TR11 | 7 -- PoC | TR10, TR10k |
| TR11b| 8 -- Finalization | TR11 |
| TR11c| 9 -- Final Report | TR11b |

On Codex, execute revisit phases strictly sequentially.

## Revisit Phase Instructions

### Pre-Flight

1. Read `vigolium-results/audit-state.json`. If last audit is not `complete`, abort with a message directing the user to finish or rerun `/vigolium-audit:deep` first.
2. Read `vigolium-results/attack-surface/knowledge-base-report.md`. If missing or empty, abort.
3. Load or create `vigolium-results/revisit-audit-state.json`. Determine current round `N`:
   - No file yet → `N = 2`
   - Otherwise `N = len(revisits) + 2`
4. Build seed data from `vigolium-results/findings/*/`:
   - `seed.known_findings[]` = `[{id, slug, class, location}, ...]` from each folder's `draft.md` frontmatter
   - `seed.known_attack_modes[]` = deduplicated class values
   - `seed.known_finding_ids_by_severity` = `{"C": max, "H": max, "M": max}` scanned off folder names
5. Generate `revisit_id` = ISO timestamp.
6. Append a new entry to `revisits[]` in `vigolium-results/revisit-audit-state.json` with:
   - `revisit_id`, `parent_audit_id` (from last audit), `round: N`, `commit`, `branch`, `repository`, `mode: "deep"`, `model: "<REQUIRED>"`, `agent_sdk: "codex"` (REQUIRED), `started_at`, `status: "in_progress"`, phases (1…9 all pending), and the `seed` object.
   - The `model` and `agent_sdk` fields are **mandatory** — abort if they cannot be resolved.
7. Recreate working directories the prior cleanup deleted: `mkdir -p vigolium-results/findings-draft/ vigolium-results/probe-workspace/ vigolium-results/chamber-workspace/`. Initialize `vigolium-results/attack-pattern-registry.json` with `{"patterns": []}` if missing.
8. Export env vars for downstream scripts: `VIGOLIUM_AUDIT_REVISIT_ROUND=<N>`, `VIGOLIUM_AUDIT_REVISIT_ID=<revisit_id>`, `VIGOLIUM_AUDIT_REVISIT_MODEL=<model>`, `VIGOLIUM_AUDIT_REVISIT_AGENT_SDK=codex`.

### Anti-Anchoring Block (inject into EVERY reasoning-phase agent prompt below)

Every spawned agent in 1, 3, and 6 must receive this block (kept short to stay under codex's 300-char spawn-prompt cap — serialize as ONE compact line):

> `"REVISIT R<N>: (1) treat KB as facts, not complete threat picture (2) do NOT refile: <top-10 known findings as id+class+location pairs> (3) round-1 exhausted: <known_attack_modes csv> — expand into adjacent modes"`

For the full rationale, the agent should read `vigolium-results/revisit-audit-state.json` `revisits[-1].seed` directly.

### 1: Deep Probe

Form probe teams identically to deep-mode P5 (read KB, group by attacker-input components). For each team, spawn agents sequentially (one at a time):

1. `vigolium-audit:probe-lead` with the anti-anchoring block + workspace path (writes attack-surface-map.md AND code-anatomy.md inline)
2. `vigolium-audit:goal-backtracer` with the anti-anchoring block
3. `vigolium-audit:assumption-breaker` with the anti-anchoring block
4. `vigolium-audit:evidence-collector` with the anti-anchoring block (also owns causal challenge — no separate verifier)

Mark 1 complete when all teams' `probe-summary.md` files exist.

### 2: Enrichment Re-classify

Inline — walk any SAST references still in the KB and re-classify using the same rules as Phase 4's `## SAST Enrichment` pass (security / correctness / environment-only, CodeQL reachability cross-reference). If no live SAST references remain, append a one-line note to the KB: `Round <N> 2: no live SAST references to re-classify.` Mark 2 complete.

### 3: Review Chambers

Form threat clusters identically to deep-mode P7 (from KB DFD/CFD slices). For each cluster, spawn chamber agents **sequentially** with the anti-anchoring block in each prompt:

1. `vigolium-audit:review-adjudicator` with cluster name + workspace `vigolium-results/chamber-workspace/r<N>-<cluster>/`
2. `vigolium-audit:attack-designer` with cluster name + negative-list reminder
3. `vigolium-audit:flow-tracer` with cluster name
4. `vigolium-audit:red-challenger` with cluster name

Append `## Round <N> Chamber Addendum` to the KB with: chambers spawned, new hypotheses, new attack patterns. Mark 3 complete.

### 4: FP Check

Apply `fp-check` skill inline to each round-<N> draft in `vigolium-results/findings-draft/` with `Verdict: VALID`. For CRITICAL and HIGH, spawn `vigolium-audit:independent-verifier` **sequentially** with the anti-anchoring block. Mark 4 complete.

### 5: Variants on New Findings

For each confirmed Medium-or-higher round-<N> finding draft, spawn one `vigolium-audit:variant-scanner` sequentially. Mark 5 complete.

### 6: Variants on Round-1 Known Findings

For each entry in `seed.known_findings` with severity CRITICAL or HIGH (skip MEDIUM), spawn one `vigolium-audit:variant-scanner` sequentially with prompt:
> `"6 R<N>: variant hunt on known finding <id>-<slug> (<class>, <location>). Fresh priors. Do NOT refile original. Output: vigolium-results/findings-draft/p10k-<NNN>-<slug>.md with Origin-Finding: <id>-<slug>."`

Mark 6 complete.

### 7: PoC Construction

Run the consolidator in continuation mode so new IDs skip the round-1 range:
```bash
VIGOLIUM_AUDIT_REVISIT_ROUND=<N> VIGOLIUM_AUDIT_REVISIT_ID=<id> VIGOLIUM_AUDIT_REVISIT_MODEL=<model> VIGOLIUM_AUDIT_REVISIT_AGENT_SDK=codex \
  python3 ~/.config/vigolium-audit/skills/audit/scripts/consolidate_drafts.py vigolium-results --continue-ids
```

If non-zero exit, abort. For each entry in the emitted manifest, spawn one `vigolium-audit:poc-author` sequentially. poc-author does NOT write `report.md` (that is 8). Capture the new finding IDs into `revisits[-1].new_finding_ids[]`. Mark 7 complete.

### 8: Finding Finalization

For each NEW round-<N> finding directory (`metadata.json` has `round == N`), spawn one `vigolium-audit:finding-writer` sequentially. Do NOT re-finalize round-1 findings. After all reporters, verify every NEW finding has a non-empty `report.md` (>500 bytes). Retry once for missing; abort if still incomplete. Mark 8 complete.

### 9: Final Report Regeneration

Spawn `vigolium-audit:report-composer` with the instruction to:
> `"9 R<N>: regenerate vigolium-results/final-audit-report.md with a ## Discoveries by Round section. Read both audit-state.json (round 1) and revisit-audit-state.json (rounds 2+). Mark round-<N> findings as [NEW IN ROUND <N>] in the detail section. Consistency checks MUST include finding completeness."`

After the assembler finishes, run post-audit cleanup:
```bash
rm -rf vigolium-results/findings-draft/ vigolium-results/probe-workspace/ vigolium-results/chamber-workspace/ vigolium-results/adversarial-reviews/
rm -f  vigolium-results/attack-pattern-registry.json
```

Mark 9 complete. Set `revisits[-1].status = "complete"` and `revisits[-1].completed_at = now`.

## Revisit Resume Logic

Read `revisits[-1].phases`. Walk in order: 1, 2, 3, 4, 5, 6, 7, 8, 9. First phase not `complete`: if its artifact gate is satisfied, mark `complete` and advance; otherwise run.

---

# Confirmation Mode (6-Phase Pipeline: V1-V6)

When the user's prompt contains "Confirm mode", "confirm findings", or "verify findings",
use this pipeline. It reads existing findings from `vigolium-results/findings/`, boots the target
application, executes PoC scripts, and falls back to generated test cases.

**Prerequisites**: `vigolium-results/findings/` must contain finding directories with `report.md`.
`vigolium-results/audit-state.json` is optional supplemental metadata only.

## Confirmation Agents

| Phase | Agent | Role |
|-------|-------|------|
| V2 -- Environment Discovery | `vigolium-audit:env-profiler` | Scan repo for Dockerfile, docker-compose, Makefile, test frameworks |
| V3 -- Environment Provisioning | `vigolium-audit:env-builder` | Start the app, run healthchecks, output connection details |
| V4 -- PoC Execution | `vigolium-audit:poc-runner` | Run existing PoC scripts against live environment |
| V5 -- Test Fallback | `vigolium-audit:test-locator` | Generate and run reproducer tests for not-reproduced / blocked / no-poc findings |
| V6 -- Report | `vigolium-audit:confirm-writer` | Compile confirmation report with per-finding verdicts |

## Confirmation Execution Plan

### Pre-Flight

1. Verify `vigolium-results/findings/` has at least one `report.md`. Abort if not.
2. If `vigolium-results/audit-state.json` exists, use it only as optional metadata and update its `confirmation` object when present.
3. `mkdir -p vigolium-results/confirm-workspace/`
4. **Workspace lock**: if `vigolium-results/confirm-workspace/.lock` exists, read its `pid` — if alive, abort; if stale, remove. Then write a new lock with the current PID and a fresh session UUID.
5. **Generate session UUID**: `VIGOLIUM_AUDIT_SESSION_UUID=$(uuidgen 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())')`. Export it. Every spawned agent prompt MUST include the session UUID. Every container/process MUST be stamped with `vigolium-audit.session=<UUID>` so cleanup is label-based, not stored-cmd-based.
6. **Trap cleanup**: install a shell trap on EXIT/INT/TERM that removes containers labelled with this session, kills any PID in `vigolium-results/confirm-workspace/app.pid`, and removes the lock — so Ctrl-C never leaks resources.
7. Check if user prompt includes a target URL. If yes, set `REMOTE_TARGET` and skip V2/V3.

### V1: Findings Inventory (inline — no agent needed)

Scan `vigolium-results/findings/*/report.md`. `report.md` is the source of truth for confirmation.
For each finding, record: ID, slug, severity, vulnerability class, title, PoC script path (if exists), `Protocol` field (default: http), `Auth-Required` field (default: no), and `exploitability_class` (network-exploitable | local-exploitable | non-exploitable — derived from vuln_class + Protocol). Write inventory to `vigolium-results/confirm-workspace/findings-inventory.json`. Sort by severity (CRITICAL first).

**Class routing** (applies to V4 and V5):
- `non-exploitable` findings: write `Confirm-Status: analytical` directly in `report.md` and skip both V4 and V5.
- `local-exploitable` findings: skip V4, send to V5 with mode `local`.
- `network-exploitable` findings: V4 → V5 fallback as today.

### V2: Environment Discovery (skip if REMOTE_TARGET)

Spawn `vigolium-audit:env-profiler` with prompt:
> `"V2 session=$VIGOLIUM_AUDIT_SESSION_UUID: Discover startup + test infra. Output: vigolium-results/confirm-workspace/env-strategies.json + vigolium-results/confirm-workspace/auth-spec.json (if auth scaffolding present)"`

Wait for completion.

### V3: Environment Provisioning (skip if REMOTE_TARGET)

Spawn `vigolium-audit:env-builder` with prompt:
> `"V3 session=$VIGOLIUM_AUDIT_SESSION_UUID: Start app, label all containers vigolium-audit.session=$VIGOLIUM_AUDIT_SESSION_UUID, honour IMAGE_PULL_TIMEOUT/SERVICE_BOOT_TIMEOUT/HEALTHCHECK_TIMEOUT, allocate port with fallback range, seed identities from auth-spec.json, snapshot DB unless SKIP_ISOLATION=1. Output: vigolium-results/confirm-workspace/env-connection.json"`

Wait for completion. If `status: failed`, skip V4 and run V5 for ALL network-exploitable findings.

### V4: PoC Execution

**Reachability gate**: before any per-finding spawn, hit `base_url` once (`curl -sf -o /dev/null --max-time 5 "$base_url"`). If unreachable, mark every queued finding `Confirm-Status: blocked` with reason `app-unreachable-at-V4-start` and skip directly to V5.

For each `network-exploitable` finding with a PoC script, spawn `vigolium-audit:poc-runner` **sequentially** (codex constraint — no concurrent fan-out):
> `"V4 session=$VIGOLIUM_AUDIT_SESSION_UUID: Execute PoC for <ID>-<slug>. Per-variant timeout 30s (max 2 variants). Connection: vigolium-results/confirm-workspace/env-connection.json. Parse structured PoC output (final JSON line {status,evidence,notes}). On not-reproduced→fp-check the draft."`

Spawn one, wait, then next. Collect verdicts by re-reading each finding's `report.md` `Confirm-*` fields.

### V5: Test-Based Fallback (skip if REMOTE_TARGET)

For each not-reproduced/flaky/blocked/no-poc/local-exploitable finding, spawn `vigolium-audit:test-locator` **sequentially**:
> `"V5 session=$VIGOLIUM_AUDIT_SESSION_UUID: Generate reproducer test for <ID>-<slug>. Strategies: vigolium-results/confirm-workspace/env-strategies.json. Connection (auth identities): vigolium-results/confirm-workspace/env-connection.json. Mode: <full|fallback|local>. Per-test timeout 60s."`

Spawn one, wait, then next.

### V6: Confirmation Report

Spawn `vigolium-audit:confirm-writer` with prompt:
> `"V6 session=$VIGOLIUM_AUDIT_SESSION_UUID: Compile confirmation report grouped by exploitability_class. Stage findings into report-ready/{live-verified,test-verified,analytical,false-positive} and needs-review/{not-reproduced,flaky,blocked,no-poc,errored}. Dedupe by ID (priority: live-verified > test-verified > false-positive > analytical > not-reproduced > flaky > blocked > no-poc > errored). Audit state optional — if present, append to confirmation_history[] (do NOT overwrite). Output: vigolium-results/confirmation-report.md"`

### Cleanup

The trap installed at Pre-Flight handles cleanup automatically (containers by session label, app.pid kill, lock removal). After V6, additionally:
- Update `audits[-1].confirmation.status` to `complete` if `audit-state.json` exists.
- The reporter has already appended a new entry to `audits[-1].confirmation_history[]`.

# END vigolium-audit
