---
description: Run a second (or Nth) pass of security audit on top of an existing vigolium-results/ directory, reusing the knowledge base and matrices from the prior audit but redoing the reasoning-heavy phases (Deep Probe, Review Chambers, variant analysis, PoC + report) with anti-anchoring prompts so a new model, new session, or new priors can surface findings the prior audit missed. State is tracked in vigolium-results/revisit-audit-state.json; round-1 artifacts are preserved.
argument-hint: "Optional: target path/scope"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: revisit
phases:
  - id: "0"
    title: Intent Cartography
    agent: intent-mapper
    requires_git: false
    parallel_with: []
    depends_on: []
  - id: "1"
    title: Deep Probe (fresh teams, anti-anchored)
    agent: probe-lead
    requires_git: false
    parallel_with: []
    depends_on: ["0"]
  - id: "2"
    title: Enrichment Re-classify
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: ["1"]
  - id: "3"
    title: Review Chambers (fresh, anti-anchored)
    agent: review-adjudicator
    requires_git: false
    parallel_with: []
    depends_on: ["2"]
  - id: "4"
    title: FP Check
    agent: independent-verifier
    requires_git: false
    parallel_with: []
    depends_on: ["3"]
  - id: "5"
    title: Variant Analysis (new round findings)
    agent: variant-scanner
    requires_git: false
    parallel_with: []
    depends_on: ["4"]
  - id: "6"
    title: Variant Analysis on Round-1 CRIT/HIGH
    agent: variant-scanner
    requires_git: false
    parallel_with: []
    depends_on: ["5"]
  - id: "7"
    title: PoC Construction (new findings only)
    agent: poc-author
    requires_git: false
    parallel_with: []
    depends_on: ["6"]
  - id: "8"
    title: Finding Finalization
    agent: finding-writer
    requires_git: false
    parallel_with: []
    depends_on: ["7"]
  - id: "9"
    title: Final Report Regeneration
    agent: report-composer
    requires_git: false
    parallel_with: []
    depends_on: ["8"]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat vigolium-results/audit-context.md 2>/dev/null || echo "(none)"`
- Prior audit state: !`cat vigolium-results/audit-state.json 2>/dev/null | head -80 || echo "No prior audit found"`
- Prior revisits: !`cat vigolium-results/revisit-audit-state.json 2>/dev/null | head -80 || echo "No prior revisit found"`
- Knowledge base: !`test -f vigolium-results/attack-surface/knowledge-base-report.md && echo "present ($(wc -c < vigolium-results/attack-surface/knowledge-base-report.md) bytes)" || echo "MISSING — /vigolium-audit:revisit requires a prior audit's KB"`
- Findings directory: !`ls vigolium-results/findings/ 2>/dev/null | head -40 || echo "No findings directory"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree"`
- Current HEAD: !`git rev-parse HEAD 2>/dev/null || echo "nogit"`

## Your Task

Run a **revisit audit** — a second (or Nth) pass of the full deep pipeline on top of an existing `vigolium-results/` directory. The purpose is to surface findings that the prior audit missed, by applying fresh reasoning (new model, fresh session, or different priors) to the *same commit* without redoing the expensive deterministic phases.

Target scope: $ARGUMENTS

**What revisit is NOT:**
- NOT `/vigolium-audit:diff` — that re-audits *code changes since the last audit*. Revisit re-audits the *same code* with a fresh attempt.
- NOT `/vigolium-audit:deep` or `/vigolium-audit:balanced` — those start from zero. Revisit explicitly reuses the prior KB, advisories, static-analysis, and systematic matrices.
- NOT `/vigolium-audit:confirm` — that verifies existing findings work. Revisit hunts for new findings.

### Preflight (HARD REQUIREMENTS)

1. `vigolium-results/audit-state.json` must exist and the most recent audit entry must have `status: "complete"`. If missing or incomplete, STOP and direct the user to `/vigolium-audit:deep` first.
2. `vigolium-results/attack-surface/knowledge-base-report.md` must exist and be non-empty. If missing, STOP — revisit cannot run without a KB.
3. `vigolium-results/findings/` must exist (can be empty — revisit is still useful on a clean bill of health in case the prior audit missed everything, but flag a warning if empty).

Resolve `vigolium-results/revisit-audit-state.json` deterministically — **never prompt the user**. This mode exists to add a fresh anti-anchored round on top of whatever exists; the orchestrator wants progress, not confirmation.

- **File absent** → start round 2 (fresh).
- **Last entry `status: "in_progress"`** → resume that revisit in place (continue from the first non-`complete` phase per the [Resume Logic](#resume-logic) section). Do not start a new round on top of an unfinished one.
- **Last entry `status: "complete"`** (or `failed`/`aborted`) → start a new round, `round = len(revisits) + 2` (the existing array length plus 2, since round 1 lives in `audit-state.json`).

Do NOT ask the user to choose between resume / fresh / cancel — pick the option above and proceed.

### Setup

1. Read `audits[-1]` from `vigolium-results/audit-state.json` — capture `audit_id`, `commit`, `mode` (expected: `deep`; warn if prior was `balanced`/`lite` but proceed).
2. Determine round number:
   - If no `revisit-audit-state.json` yet → round = 2 (round 1 = the original audit).
   - Otherwise round = `len(revisits) + 2` (the existing revisits array length plus 2, because round 1 lives in audit-state.json not revisit-audit-state.json).
3. Generate `revisit_id` = current ISO timestamp.
4. Build `seed.known_findings[]` by reading every `vigolium-results/findings/*/draft.md` AND `vigolium-results/findings-theoretical/*/draft.md` (or that finding's `report.md` as fallback) — both buckets are part of the negative list:
   - Extract: `id` (from folder prefix), `slug` (from folder), `class` (from the draft's `Class:` field, else the report's `## Severity, Confidence, Vulnerability Type` section), `location` (from the draft's `Location:` field, else the report's `## Affected Component` / first source link in `## Source to Sink Flow`).
   - This list is the **negative list** — Ideators and variant-hunters will be told NOT to refile any of these.
5. Build `seed.known_attack_modes[]` as the deduplicated list of `class` values from step 4 (normalized: lowercase, hyphenated).
6. Build `seed.known_finding_ids_by_severity` = `{"C": [existing max C id], "H": [...], "M": [...]}`. This seeds the consolidation helper so new findings don't collide with round-1 IDs.
7. Write the initial `vigolium-results/revisit-audit-state.json` entry (append to `revisits[]` array, or create file with new array):

   ```json
   {
     "revisits": [
       {
         "revisit_id": "<ISO timestamp>",
         "parent_audit_id": "<audits[-1].audit_id>",
         "round": <N>,
         "commit": "<HEAD SHA or 'nogit'>",
         "branch": "<branch or 'nogit'>",
         "repository": "<value of $VIGOLIUM_AUDIT_REPOSITORY>",
         "history_available": <true|false>,
         "mode": "deep",
         "model": "<REQUIRED — substitute actual model name, e.g. opus-4.7, gpt-5.4-codex>",
         "agent_sdk": "<REQUIRED — substitute actual platform, e.g. claude-code, codex>",
         "started_at": "<ISO timestamp>",
         "completed_at": null,
         "status": "in_progress",
         "phases": {
           "0":   {"status": "pending"},
           "1":   {"status": "pending"},
           "2":   {"status": "pending"},
           "3":   {"status": "pending"},
           "4":   {"status": "pending"},
           "5":  {"status": "pending"},
           "6": {"status": "pending"},
           "7":  {"status": "pending"},
           "8": {"status": "pending"},
           "9": {"status": "pending"}
         },
         "seed": {
           "kb_path": "vigolium-results/attack-surface/knowledge-base-report.md",
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
   mkdir -p vigolium-results/findings-draft/ vigolium-results/probe-workspace/ vigolium-results/chamber-workspace/
   ```
   If `vigolium-results/attack-pattern-registry.json` is missing, initialize with `{"patterns": []}`.

9. Export `VIGOLIUM_AUDIT_REVISIT_ROUND=<N>` and `VIGOLIUM_AUDIT_REVISIT_ID=<revisit_id>` for downstream scripts.

### Anti-anchoring Prompt (SHARED — paste into every agent prompt below)

Inject the following block into the prompt of every agent spawned in Phase 1 (probe-lead, reasoners, evidence-collector), Phase 3 (review-adjudicator, attack-designer, flow-tracer, red-challenger), and Phase 6 (variant-scanner on known findings):

> **REVISIT MODE — ROUND <N>. READ CAREFULLY.**
>
> 1. The prior round(s) may have missed major findings. Treat `vigolium-results/attack-surface/knowledge-base-report.md` as *facts about the system*, NOT as *the complete threat picture*. Do not defer to prior conclusions.
>
> 2. **Negative list — do NOT refile any of these findings** (they were already confirmed in round 1):
>    ```
>    <inline the seed.known_findings list here: id, slug, class, location, one line each>
>    ```
>    If your hypothesis overlaps in class AND location with a known finding, drop it. Overlap in class only, different location, is OK and encouraged (new instance of a known bug class).
>
> 3. Round-1 used these attack modes: `<seed.known_attack_modes>`. Expand into *adjacent* modes it did not exhaust: for example, if round-1 focused on authz, push harder on state/concurrency, parser confusion, supply-chain, race conditions, cryptographic misuse, serialization, or business-logic chains. A good revisit finding is one the round-1 agent could plausibly have reached but chose not to, OR one that requires a reasoning path round-1 did not take.
>
> 4. Output drafts go to `vigolium-results/findings-draft/` with the Phase-10 `p10-` prefix as usual; the consolidation step at the end will assign IDs that continue from round-1's highest.
>
> 5. **Intent corpus** (priority signal, not a gate). `vigolium-results/attack-surface/intent-corpus.json` (built by Phase 0) lists behaviors the project documents as intentional (`intentional_behaviors[]`) and vuln classes it explicitly considers in scope (`acknowledged_risks[]`). Consume this as a **soft prioritization hint** only:
>    - Devils-advocate / independent-verifier may cite an `intentional_behaviors[]` entry as a defense argument, but the chamber synthesizer still issues the verdict — do not auto-drop a hypothesis because a weak-confidence doc match exists.
>    - Probe-strategist / attack-designer may push harder on classes listed in `acknowledged_risks[]` (the project explicitly cares about these), but do NOT skip classes that are absent from the list.
>    - If `intent-corpus.json` is missing or empty (Phase 0 failed or repo has no security docs), proceed without it — there is no fallback corpus.

### Phase Pipeline

```
(Preflight reads prior state)
→ 0 (Intent Cartography — repo-local doc scan, output to attack-surface/intent-corpus.json)
→ 1 (Deep Probe, fresh teams with anti-anchoring)
→ 2 (Enrichment re-classify)
→ 3 (Review Chambers with anti-anchoring + negative list + intent corpus)
→ 4 (P13-LITE FP check on new drafts)
→ 5 (Variant analysis on new findings)
→ 6 (Variant analysis on ROUND-1 CRITICAL/HIGH findings with fresh priors)
→ 7 (PoC construction on new findings + new variants)
→ 8 (Finding finalization — report.md per new finding)
→ 9 (Final report regeneration with round provenance)
```

**Skipped** (reused from round 1): P1 advisories, P2 patch bypass, P3 KB, P4 SAST, P6/7/8 systematic matrices, P9 spec gaps. These do not change when the code doesn't change, so re-running is pure waste.

### Phase 0 — Intent Cartography

Spawn `vigolium-audit:intent-mapper` (foreground):

> Prompt: "Scan the target repository for documented security intent. Target directory: <abs_target>. Output corpus to vigolium-results/attack-surface/intent-corpus.json. No findings inventory is provided — produce the corpus only (no cross-check pass). Revisit round: <N>."

The corpus is reused across rounds: Phase 0 unconditionally regenerates `vigolium-results/attack-surface/intent-corpus.json` (overwriting any prior copy) so the latest docs are reflected. Even when round-1 already produced a corpus, the docs may have changed between rounds and the cheapest correct option is to rebuild.

**Failure policy: skip-and-continue.** If the agent fails or writes an empty corpus, log the failure and proceed to Phase 1 without intent context. Phases 1, 3, and 4 must tolerate the absence of `intent-corpus.json` — the anti-anchoring block's bullet 5 already states this explicitly.

Mark `0` complete when the corpus file exists (empty corpus is still a valid completion).

### Phase 1 — Deep Probe (fresh teams, anti-anchored)

Spawn deep probe teams exactly as `/vigolium-audit:deep` Phase D6 does, but inject the anti-anchoring block into every probe-lead, reasoner, and evidence-collector prompt. The strategist writes code anatomy inline during its setup (no separate Code Anatomist agent).

Component grouping: read `vigolium-results/attack-surface/knowledge-base-report.md` sections `## DFD/CFD Slices`, `## Attack Surface`, `## Architecture Model` (same as deep.md). Form teams identically to round-1.

Teams write to `vigolium-results/probe-workspace/<component>/probe-summary.md`. Update `1` status to `complete` when all teams close.

### Phase 2 — Enrichment

Re-classify any SAST findings still referenced in the KB that may benefit from a second look (same classification rules as the Phase D5 `## SAST Enrichment` pass in deep mode: security / correctness / environment-only, with CodeQL reachability cross-reference). This is optional-value — if the KB has no live SAST references, mark 2 complete with an "inline skip — no live SAST references" note. Do not re-run SAST itself (decision: SAST is skipped on revisit).

### Phase 3 — Review Chambers (fresh, anti-anchored)

Spawn Review Chambers exactly as `/vigolium-audit:deep` Phase D8 does, with the anti-anchoring block injected into **every** review-adjudicator, attack-designer, flow-tracer, and red-challenger prompt. Chamber workspace: `vigolium-results/chamber-workspace/r<round>-<cluster>/`. Drafts go to `vigolium-results/findings-draft/p10-<NNN>-<slug>.md` as usual.

The chamber synthesizer's prompt MUST additionally include the negative-list instruction verbatim and the known_attack_modes list.

When all chambers close, write `## Round <N> Chamber Addendum` to `vigolium-results/attack-surface/knowledge-base-report.md` summarizing: chambers spawned, new hypotheses generated, new attack patterns added. Do NOT overwrite round-1's `## Phase 10 Addendum`.

Mark 3 complete.

### Phase 4 — FP Check

Apply the `fp-check` skill to all `vigolium-results/findings-draft/p10-*.md` drafts with `Verdict: VALID` that are NEW in this round (i.e., not present in `vigolium-results/findings/` already). Write verdicts back into drafts.

For CRITICAL and HIGH drafts still VALID after Stage 1, spawn `vigolium-audit:independent-verifier` with `run_in_background: true` as in deep mode. Inject the anti-anchoring block.

Wait for all cold verifiers. Mark 4 complete.

### Phase 5 — Variant Analysis (on new round-<N> findings)

For each confirmed Medium+ finding NEW in this round, spawn `vigolium-audit:variant-scanner` with `run_in_background: true` (standard deep-mode protocol).

Mark 5 complete when all finish.

### Phase 6 — Variant Analysis on ROUND-1 findings with fresh priors

This is the phase that earns its keep on its own. For each finding in `seed.known_findings` with severity CRITICAL or HIGH, spawn `vigolium-audit:variant-scanner` with `run_in_background: true` and this prompt:

> "REVISIT ROUND <N> — STRUCTURAL VARIANT SEARCH ON KNOWN FINDING.
>
> This finding was confirmed in round 1: `<id>-<slug>`, class `<class>`, location `<location>`. Round-1's variant-scanner already ran on it once. Your job: find variants that round-1 missed — same bug class, different location — by applying your fresh priors.
>
> Do NOT refile the original finding. Do NOT refile any variants round-1 already produced (check `vigolium-results/findings/*/metadata.json` for `origin_finding_id == <id>`).
>
> Output drafts to `vigolium-results/findings-draft/p10k-<NNN>-<slug>.md` with `Origin-Finding: <id>-<slug>` set in the frontmatter. The consolidation step at the end will promote them as variants of the round-1 parent."

For MEDIUM round-1 findings, skip Phase 6 (matches round-1's deep-mode Phase D8 Stage-2 CRIT+HIGH gate — the cost/value tradeoff is worse for Medium).

Mark 6 complete when all finish.

### Phase 7 — PoC Construction (new findings only)

Run the consolidation helper with **ID continuation mode** so new findings get IDs that do not collide with round-1:

```bash
VIGOLIUM_AUDIT_REVISIT_ROUND=<N> python3 ~/.config/vigolium-audit/skills/audit/scripts/consolidate_drafts.py vigolium-results --continue-ids
```

The script reads existing IDs from **both** `vigolium-results/findings/*/` and `vigolium-results/findings-theoretical/*/` to determine the max existing ID per severity and continues numbering from there (one global namespace, no cross-bucket collisions). New triage-skipped drafts go straight to `vigolium-results/findings-theoretical/`; the rest to `vigolium-results/findings/`. It also writes `metadata.json` on every newly-created finding directory with:

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

If the script exits non-zero (nothing promoted at all), STOP. Do not proceed to 8 or 9. An empty `findings` array with a non-empty `theoretical` array is normal (all new drafts triage-skipped) — skip PoC + partition and go straight to finalization over the new theoretical dirs.

Read `vigolium-results/findings-draft/consolidation-manifest.json`. For each entry in its `findings` array, spawn `vigolium-audit:poc-author` with `run_in_background: true`, passing the entry's `draft_path` and `id`. poc-author writes `PoC-Status` back into the finding's `draft.md` and is NOT responsible for `report.md` (same as deep mode — that is 8).

Capture each new finding's ID in `audits[-1].new_finding_ids[]` of `revisit-audit-state.json`.

Wait for all PoC builders. **Confirmed/theoretical partition**: run `python3 ~/.config/vigolium-audit/skills/audit/scripts/partition_findings.py vigolium-results`. It demotes any `vigolium-results/findings/<ID>-<slug>/` lacking `PoC-Status: executed` into `vigolium-results/findings-theoretical/`. In practice this only touches the current round's new findings — round-1 confirmed findings already carry `PoC-Status: executed`, and round-1 theoretical findings are already in the theoretical bucket. Mark 7 complete.

### Phase 8 — Finding Finalization

For each NEW finding directory whose `metadata.json` has `round == <N>` — searching **both** `vigolium-results/findings/*/` and `vigolium-results/findings-theoretical/*/` — spawn `vigolium-audit:finding-writer` with `run_in_background: true`. Do NOT re-run finding-writer on round-1 findings — their `report.md` already exists and is authoritative.

Wait for all reporters. **Phase gate**: verify every NEW finding's `report.md` (in either bucket) exists and is larger than 500 bytes. Retry once for missing/truncated. STOP if any remain incomplete.

Mark 8 complete.

### Phase 9 — Final Report Regeneration

Spawn `vigolium-audit:report-composer` (foreground) with this additional instruction:

> "REVISIT MODE — ROUND <N>. This is a revisit-audit regeneration. Read `vigolium-results/revisit-audit-state.json` alongside `vigolium-results/audit-state.json` to build a **Discoveries by Round** section at the top of `vigolium-results/final-audit-report.md`, formatted as:
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
> For each finding, read its `metadata.json` (if present — round-1 findings have no metadata.json, treat as round 1). Scan BOTH `vigolium-results/findings/` (confirmed) and `vigolium-results/findings-theoretical/` (theoretical/unconfirmed). Put confirmed findings in Technical Findings Detail (round-2+ first, marked `[NEW IN ROUND N]`, then round-1) and theoretical findings in the dedicated Theoretical / Unconfirmed Findings section, kept out of the Summary-of-Findings table. Consistency checks MUST include finding completeness — every finding in both buckets must have `draft.md` and a non-empty `report.md` (a `poc.*` is required only in `vigolium-results/findings/`)."

When the assembler finishes, mark 9 complete and set `revisits[-1].status = "complete"` + `revisits[-1].completed_at = now`.

### Post-audit Cleanup

Delete the round-<N> working artifacts (same policy as round-1):

```bash
rm -rf vigolium-results/findings-draft/
rm -rf vigolium-results/probe-workspace/
rm -rf vigolium-results/chamber-workspace/
rm -rf vigolium-results/adversarial-reviews/
rm -f  vigolium-results/attack-pattern-registry.json
```

Retained: `vigolium-results/audit-state.json`, `vigolium-results/revisit-audit-state.json`, `vigolium-results/attack-surface/knowledge-base-report.md`, `vigolium-results/attack-surface/intent-corpus.json`, `vigolium-results/findings/` (confirmed, merged across rounds), `vigolium-results/findings-theoretical/` (theoretical/unconfirmed, merged across rounds), `vigolium-results/final-audit-report.md`, `vigolium-results/attack-surface/authz-matrix.md`, `vigolium-results/attack-surface/cross-service-edges.{json,md}`.

### Resume Logic

Read `revisits[-1].phases` from `vigolium-results/revisit-audit-state.json`. Walk in order: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9. Find the first phase not `complete`. Artifact gates:

- 0 complete if `vigolium-results/attack-surface/intent-corpus.json` exists (empty arrays acceptable). Resume re-runs Phase 0 unconditionally if `failed` — the agent is cheap.
- 1 complete if `vigolium-results/probe-workspace/*/probe-summary.md` exists for each team.
- 3 complete if all chambers closed and KB has `## Round <N> Chamber Addendum`.
- 4 complete if every VALID round-<N> draft has an `fp-check` verdict written back.
- 5 complete if every new confirmed finding received variant output.
- 6 complete if every seed.known_findings[CRIT|HIGH] received variant output or an explicit "no variant found" result.
- 7 complete if every new finding directory has `poc.*` and the draft has `PoC-Status`.
- 7 complete if `vigolium-results/findings-draft/partition-manifest.json` exists (PoC + partition ran) or the consolidation manifest had an empty `findings` array (all new drafts theoretical).
- 8 complete if every new finding directory (round == N) in both `vigolium-results/findings/` and `vigolium-results/findings-theoretical/` has `report.md` >500 bytes.
- 9 complete if `vigolium-results/final-audit-report.md` exists AND has the `## Discoveries by Round` section AND references the current round's new_finding_ids.

If a phase is `failed` or `in_progress` and its artifact gate is satisfied, mark `complete` and advance. Otherwise delete partial output and re-run that phase.

### Lead Responsibilities

1. You are the orchestrator. Do NOT perform audit work yourself.
2. Always inject the anti-anchoring block into every reasoning-phase agent prompt — this is the core value proposition of revisit mode.
3. Never mutate round-1's findings (the directories under `vigolium-results/findings/<ID>-<slug>/` and `vigolium-results/findings-theoretical/<ID>-<slug>/`) — a revisit round adds new directories and the partition step only moves the *current round's* new findings between buckets; it does not edit prior-round ones. The only exception is `final-audit-report.md`, which is a regenerated summary.
4. The `round` counter is authoritative — preserve it in every finding's `metadata.json` so future Nth revisits can attribute discoveries correctly.
