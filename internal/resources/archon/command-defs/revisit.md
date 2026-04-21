---
description: Run a second (or Nth) pass of security audit on top of an existing archon/ directory, reusing the knowledge base and matrices from the prior audit but redoing the reasoning-heavy phases (Deep Probe, Review Chambers, variant analysis, PoC + report) with anti-anchoring prompts so a new model, new session, or new priors can surface findings the prior audit missed. State is tracked in archon/revisit-audit-state.json; round-1 artifacts are preserved.
argument-hint: "Optional: target path/scope"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
---

## Context

- Prior audit state: !`cat archon/audit-state.json 2>/dev/null | head -80 || echo "No prior audit found"`
- Prior revisits: !`cat archon/revisit-audit-state.json 2>/dev/null | head -80 || echo "No prior revisit found"`
- Knowledge base: !`test -f archon/knowledge-base-report.md && echo "present ($(wc -c < archon/knowledge-base-report.md) bytes)" || echo "MISSING — /archon:revisit requires a prior audit's KB"`
- Findings directory: !`ls archon/findings/ 2>/dev/null | head -40 || echo "No findings directory"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree"`
- Current HEAD: !`git rev-parse HEAD 2>/dev/null || echo "nogit"`

## Your Task

Run a **revisit audit** — a second (or Nth) pass of the full deep pipeline on top of an existing `archon/` directory. The purpose is to surface findings that the prior audit missed, by applying fresh reasoning (new model, fresh session, or different priors) to the *same commit* without redoing the expensive deterministic phases.

Target scope: $ARGUMENTS

**What revisit is NOT:**
- NOT `/archon:diff` — that re-audits *code changes since the last audit*. Revisit re-audits the *same code* with a fresh attempt.
- NOT `/archon:deep` or `/archon:balanced` — those start from zero. Revisit explicitly reuses the prior KB, advisories, static-analysis, and systematic matrices.
- NOT `/archon:confirm` — that verifies existing findings work. Revisit hunts for new findings.

### Preflight (HARD REQUIREMENTS)

1. `archon/audit-state.json` must exist and the most recent audit entry must have `status: "complete"`. If missing or incomplete, STOP and direct the user to `/archon:deep` first.
2. `archon/knowledge-base-report.md` must exist and be non-empty. If missing, STOP — revisit cannot run without a KB.
3. `archon/findings/` must exist (can be empty — revisit is still useful on a clean bill of health in case the prior audit missed everything, but flag a warning if empty).

If `archon/revisit-audit-state.json` already exists, use `AskUserQuestion`:

- **Incomplete revisit in progress**: "A revisit audit is already in progress. Resume, start a new round (append), or cancel?"
  - Options: "Resume last revisit" | "Start a new round (round N+1)" | "Cancel"
- **All revisits complete**: "The last revisit is complete. Start a new round (round N+1) or cancel?"
  - Options: "Start a new round (round N+1)" | "Cancel"

Do not proceed past preflight without an explicit user choice.

### Setup

1. Read `audits[-1]` from `archon/audit-state.json` — capture `audit_id`, `commit`, `mode` (expected: `deep`; warn if prior was `balanced`/`lite` but proceed).
2. Determine round number:
   - If no `revisit-audit-state.json` yet → round = 2 (round 1 = the original audit).
   - Otherwise round = `len(revisits) + 2` (the existing revisits array length plus 2, because round 1 lives in audit-state.json not revisit-audit-state.json).
3. Generate `revisit_id` = current ISO timestamp.
4. Build `seed.known_findings[]` by reading every `archon/findings/*/draft.md` (or `report.md` as fallback):
   - Extract: `id` (from folder prefix), `slug` (from folder), `class` (from the draft's `Class:` field or `## Details` summary), `location` (from the draft's `Location:` field or `## Root Cause` file:line).
   - This list is the **negative list** — Ideators and variant-hunters will be told NOT to refile any of these.
5. Build `seed.known_attack_modes[]` as the deduplicated list of `class` values from step 4 (normalized: lowercase, hyphenated).
6. Build `seed.known_finding_ids_by_severity` = `{"C": [existing max C id], "H": [...], "M": [...]}`. This seeds the consolidation helper so new findings don't collide with round-1 IDs.
7. Write the initial `archon/revisit-audit-state.json` entry (append to `revisits[]` array, or create file with new array):

   ```json
   {
     "revisits": [
       {
         "revisit_id": "<ISO timestamp>",
         "parent_audit_id": "<audits[-1].audit_id>",
         "round": <N>,
         "commit": "<HEAD SHA or 'nogit'>",
         "branch": "<branch or 'nogit'>",
         "repository": "<value of $ARCHON_REPOSITORY>",
         "history_available": <true|false>,
         "mode": "deep",
         "model": "<REQUIRED — substitute actual model name, e.g. opus-4.7, gpt-5.4-codex>",
         "agent_sdk": "<REQUIRED — substitute actual platform, e.g. claude-code, codex, bytesec>",
         "started_at": "<ISO timestamp>",
         "completed_at": null,
         "status": "in_progress",
         "phases": {
           "R5":   {"status": "pending"},
           "R7":   {"status": "pending"},
           "R8":   {"status": "pending"},
           "R9":   {"status": "pending"},
           "R10":  {"status": "pending"},
           "R10k": {"status": "pending"},
           "R11":  {"status": "pending"},
           "R11b": {"status": "pending"},
           "R11c": {"status": "pending"}
         },
         "seed": {
           "kb_path": "archon/knowledge-base-report.md",
           "known_findings": [ {"id": "C1", "slug": "...", "class": "...", "location": "..."} ],
           "known_attack_modes": ["sqli", "idor", "..."],
           "known_finding_ids_by_severity": {"C": <max>, "H": <max>, "M": <max>}
         },
         "new_finding_ids": []
       }
     ]
   }
   ```

   `model` and `agent_sdk` are **mandatory** — refuse to proceed if either cannot be resolved. These fields are the whole analytical payoff of revisit mode (attributing which model/session found which finding across rounds).

8. Recreate working directories that the prior audit's cleanup deleted:
   ```bash
   mkdir -p archon/findings-draft/ archon/probe-workspace/ archon/chamber-workspace/
   ```
   If `archon/attack-pattern-registry.json` is missing, initialize with `{"patterns": []}`.

9. Export `ARCHON_REVISIT_ROUND=<N>` and `ARCHON_REVISIT_ID=<revisit_id>` for downstream scripts.

### Anti-anchoring Prompt (SHARED — paste into every agent prompt below)

Inject the following block into the prompt of every agent spawned in R5 (probe-strategist, reasoners, evidence-harvester), R8 (chamber-synthesizer, attack-ideator, code-tracer, devils-advocate), and R10k (variant-hunter on known findings):

> **REVISIT MODE — ROUND <N>. READ CAREFULLY.**
>
> 1. The prior round(s) may have missed major findings. Treat `archon/knowledge-base-report.md` as *facts about the system*, NOT as *the complete threat picture*. Do not defer to prior conclusions.
>
> 2. **Negative list — do NOT refile any of these findings** (they were already confirmed in round 1):
>    ```
>    <inline the seed.known_findings list here: id, slug, class, location, one line each>
>    ```
>    If your hypothesis overlaps in class AND location with a known finding, drop it. Overlap in class only, different location, is OK and encouraged (new instance of a known bug class).
>
> 3. Round-1 used these attack modes: `<seed.known_attack_modes>`. Expand into *adjacent* modes it did not exhaust: for example, if round-1 focused on authz, push harder on state/concurrency, parser confusion, supply-chain, race conditions, cryptographic misuse, serialization, or business-logic chains. A good revisit finding is one the round-1 agent could plausibly have reached but chose not to, OR one that requires a reasoning path round-1 did not take.
>
> 4. Output drafts go to `archon/findings-draft/` with the Phase-8 `p8-` prefix as usual; the consolidation step at the end will assign IDs that continue from round-1's highest.

### Phase Pipeline

```
(Preflight reads prior state)
→ R5 (Deep Probe, fresh teams with anti-anchoring)
→ R7 (Enrichment re-classify)
→ R8 (Review Chambers with anti-anchoring + negative list)
→ R9 (P9-LITE FP check on new drafts)
→ R10 (Variant analysis on new findings)
→ R10k (Variant analysis on ROUND-1 CRITICAL/HIGH findings with fresh priors)
→ R11 (PoC construction on new findings + new variants)
→ R11b (Finding finalization — report.md per new finding)
→ R11c (Final report regeneration with round provenance)
```

**Skipped** (reused from round 1): P1 advisories, P2 patch bypass, P3 KB, P4 SAST, P5A/5B/5C systematic matrices, P6 spec gaps. These do not change when the code doesn't change, so re-running is pure waste.

### R5 — Deep Probe (fresh teams, anti-anchored)

Spawn deep probe teams exactly as `/archon:deep` Phase 5 does, but inject the anti-anchoring block into every probe-strategist, reasoner, and evidence-harvester prompt. The strategist writes code anatomy inline during its setup (no separate Code Anatomist agent).

Component grouping: read `archon/knowledge-base-report.md` sections `## DFD/CFD Slices`, `## Attack Surface`, `## Architecture Model` (same as deep.md). Form teams identically to round-1.

Teams write to `archon/probe-workspace/<component>/probe-summary.md`. Update `R5` status to `complete` when all teams close.

### R7 — Enrichment

Re-classify any SAST findings still referenced in the KB that may benefit from a second look (same classification rules as the Phase 4 `## SAST Enrichment` pass in deep mode: security / correctness / environment-only, with CodeQL reachability cross-reference). This is optional-value — if the KB has no live SAST references, mark R7 complete with an "inline skip — no live SAST references" note. Do not re-run SAST itself (decision: SAST is skipped on revisit).

### R8 — Review Chambers (fresh, anti-anchored)

Spawn Review Chambers exactly as `/archon:deep` Phase 8 does, with the anti-anchoring block injected into **every** chamber-synthesizer, attack-ideator, code-tracer, and devils-advocate prompt. Chamber workspace: `archon/chamber-workspace/r<round>-<cluster>/`. Drafts go to `archon/findings-draft/p8-<NNN>-<slug>.md` as usual.

The chamber synthesizer's prompt MUST additionally include the negative-list instruction verbatim and the known_attack_modes list.

When all chambers close, write `## Round <N> Chamber Addendum` to `archon/knowledge-base-report.md` summarizing: chambers spawned, new hypotheses generated, new attack patterns added. Do NOT overwrite round-1's `## Phase 8 Addendum`.

Mark R8 complete.

### R9 — FP Check

Apply the `fp-check` skill to all `archon/findings-draft/p8-*.md` drafts with `Verdict: VALID` that are NEW in this round (i.e., not present in `archon/findings/` already). Write verdicts back into drafts.

For CRITICAL and HIGH drafts still VALID after Stage 1, spawn `archon:cold-verifier` with `run_in_background: true` as in deep mode. Inject the anti-anchoring block.

Wait for all cold verifiers. Mark R9 complete.

### R10 — Variant Analysis (on new round-<N> findings)

For each confirmed Medium+ finding NEW in this round, spawn `archon:variant-hunter` with `run_in_background: true` (standard deep-mode protocol).

Mark R10 complete when all finish.

### R10k — Variant Analysis on ROUND-1 findings with fresh priors

This is the phase that earns its keep on its own. For each finding in `seed.known_findings` with severity CRITICAL or HIGH, spawn `archon:variant-hunter` with `run_in_background: true` and this prompt:

> "REVISIT ROUND <N> — STRUCTURAL VARIANT SEARCH ON KNOWN FINDING.
>
> This finding was confirmed in round 1: `<id>-<slug>`, class `<class>`, location `<location>`. Round-1's variant-hunter already ran on it once. Your job: find variants that round-1 missed — same bug class, different location — by applying your fresh priors.
>
> Do NOT refile the original finding. Do NOT refile any variants round-1 already produced (check `archon/findings/*/metadata.json` for `origin_finding_id == <id>`).
>
> Output drafts to `archon/findings-draft/p10k-<NNN>-<slug>.md` with `Origin-Finding: <id>-<slug>` set in the frontmatter. The consolidation step at the end will promote them as variants of the round-1 parent."

For MEDIUM round-1 findings, skip R10k (matches round-1's Phase 9 Stage-2 CRIT+HIGH gate — the cost/value tradeoff is worse for Medium).

Mark R10k complete when all finish.

### R11 — PoC Construction (new findings only)

Run the consolidation helper with **ID continuation mode** so new findings get IDs that do not collide with round-1:

```bash
ARCHON_REVISIT_ROUND=<N> python3 ~/.config/archon-audit/skills/audit/scripts/consolidate_drafts.py archon --continue-ids
```

The script reads existing `archon/findings/*/` to determine the max existing ID per severity and continues numbering from there. It also writes `metadata.json` on every newly-created finding directory with:

```json
{
  "round": <N>,
  "revisit_id": "<revisit_id>",
  "model": "<from revisit-audit-state.json>",
  "agent_sdk": "<from revisit-audit-state.json>",
  "is_variant": <true|false>,
  "origin_finding_id": "<only for variants>"
}
```

If the script exits non-zero, STOP. Do not proceed to R11b or R11c.

Read `archon/findings-draft/consolidation-manifest.json`. For each entry in its `findings` array, spawn `archon:poc-builder` with `run_in_background: true`, passing the entry's `draft_path` and `id`. poc-builder is NOT responsible for `report.md` (same as deep mode — that is R11b).

Capture each new finding's ID in `audits[-1].new_finding_ids[]` of `revisit-audit-state.json`.

Wait for all PoC builders. Mark R11 complete.

### R11b — Finding Finalization

For each NEW finding directory (i.e., those whose `metadata.json` has `round == <N>`), spawn `archon:finding-reporter` with `run_in_background: true`. Do NOT re-run finding-reporter on round-1 findings — their `report.md` already exists and is authoritative.

Wait for all reporters. **Phase gate**: verify every NEW finding's `report.md` exists and is larger than 500 bytes. Retry once for missing/truncated. STOP if any remain incomplete.

Mark R11b complete.

### R11c — Final Report Regeneration

Spawn `archon:report-assembler` (foreground) with this additional instruction:

> "REVISIT MODE — ROUND <N>. This is a revisit-audit regeneration. Read `archon/revisit-audit-state.json` alongside `archon/audit-state.json` to build a **Discoveries by Round** section at the top of `archon/final-audit-report.md`, formatted as:
>
> ```markdown
> ## Discoveries by Round
>
> | Round | Model / SDK | Started | Findings added | Finding IDs |
> |-------|-------------|---------|----------------|-------------|
> | 1 | <audit.model>/<audit.agent_sdk> | <audit.started_at> | <N> | C1, C2, H1, ... |
> | 2 | <revisit.model>/<revisit.agent_sdk> | <revisit.started_at> | <M> | C3, H3, ... |
> ```
>
> For each finding, read its `metadata.json` (if present — round-1 findings have no metadata.json, treat as round 1). Group the Technical Findings Detail section with round-2+ findings first (marked `[NEW IN ROUND N]`), then round-1 findings. Consistency checks MUST include finding completeness — every finding must have `draft.md` and non-empty `report.md`."

When the assembler finishes, mark R11c complete and set `revisits[-1].status = "complete"` + `revisits[-1].completed_at = now`.

### Post-audit Cleanup

Delete the round-<N> working artifacts (same policy as round-1):

```bash
rm -rf archon/findings-draft/
rm -rf archon/probe-workspace/
rm -rf archon/chamber-workspace/
rm -rf archon/adversarial-reviews/
rm -f  archon/attack-pattern-registry.json
```

Retained: `archon/audit-state.json`, `archon/revisit-audit-state.json`, `archon/knowledge-base-report.md`, `archon/findings/` (now merged across rounds), `archon/final-audit-report.md`, `archon/authz-matrix.md`, `archon/cross-service-edges.{json,md}`.

### Resume Logic

Read `revisits[-1].phases` from `archon/revisit-audit-state.json`. Walk in order: R5, R7, R8, R9, R10, R10k, R11, R11b, R11c. Find the first phase not `complete`. Artifact gates:

- R5 complete if `archon/probe-workspace/*/probe-summary.md` exists for each team.
- R8 complete if all chambers closed and KB has `## Round <N> Chamber Addendum`.
- R9 complete if every VALID round-<N> draft has an `fp-check` verdict written back.
- R10 complete if every new confirmed finding received variant output.
- R10k complete if every seed.known_findings[CRIT|HIGH] received variant output or an explicit "no variant found" result.
- R11 complete if every new finding directory has `poc.*` and the draft has `PoC-Status`.
- R11b complete if every new finding directory has `report.md` >500 bytes.
- R11c complete if `archon/final-audit-report.md` exists AND has the `## Discoveries by Round` section AND references the current round's new_finding_ids.

If a phase is `failed` or `in_progress` and its artifact gate is satisfied, mark `complete` and advance. Otherwise delete partial output and re-run that phase.

### Lead Responsibilities

1. You are the orchestrator. Do NOT perform audit work yourself.
2. Always inject the anti-anchoring block into every reasoning-phase agent prompt — this is the core value proposition of revisit mode.
3. Never mutate round-1's findings (the directories under `archon/findings/<ID>-<slug>/`) — round-2 adds new directories, it does not edit old ones. The only exception is `final-audit-report.md`, which is a regenerated summary.
4. The `round` counter is authoritative — preserve it in every finding's `metadata.json` so future Nth revisits can attribute discoveries correctly.
