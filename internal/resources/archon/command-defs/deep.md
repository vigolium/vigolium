---
description: Run a full 11-phase security audit (plus 3 systematic sub-phases 5A/5B/5C) on the current repository. Resumes from the last checkpoint if an audit is already in progress. Runs a single phase if a phase number (1-11, 5A, 5B, or 5C) is given as argument.
argument-hint: "Optional: target path/scope, or phase number (1-11 / 5A / 5B / 5C)"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
---

## Context

- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree (plain directory target)"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "No git branch (plain directory target)"`
- Existing audit state: !`cat archon/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Security directory: !`ls archon/ 2>/dev/null || echo "No security directory"`

## Your Task

Run a full security audit of the current repository. Target scope: $ARGUMENTS

This mode can run against a plain source folder with no `.git` directory. When Git history is unavailable, degrade gracefully: skip commit archaeology and any patch-bypass work that depends on local patch history, record the degraded mode in `archon/audit-state.json`, and continue with the remaining phases.

### No-Git Rule

If `ARCHON_GIT_AVAILABLE=false` or `git rev-parse --is-inside-work-tree` fails, treat commit history as unavailable for the entire run.

- NEVER spawn `archon:commit-archaeologist`
- NEVER spawn `archon:patch-bypass-checker` for history-derived patches
- Record the skip explicitly in `archon/knowledge-base-report.md`
- Continue with KB, SAST, probe, chamber, PoC, and reporting phases against the source snapshot

### Argument Handling

Parse `$ARGUMENTS` first:

- **Single phase identifier (1-11, or 5A / 5B / 5C)**: skip pre-flight and mode selection; jump directly to [Single Phase Execution](#single-phase-execution).
- **Path or scope (or empty)**: continue with pre-flight below.

### Pre-Flight Check

If `archon/audit-state.json` exists, use `AskUserQuestion` to gate the next action:

- **Incomplete phases**: ask "An audit is already in progress. What would you like to do?" with options:
  - "Resume from last checkpoint"
  - "Start fresh (clears existing state)"
  - "Cancel"

- **All phases complete**: ask "A completed audit exists for this repository. What would you like to do?" with options:
  - "Run a full fresh audit (clears existing state)"
  - "Run an incremental diff audit (/archon:diff)"
  - "Run a scan audit (/archon:scan)"
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
2. If `ARCHON_GIT_AVAILABLE=true`, create or checkout the `audit` branch:
   ```bash
   git checkout audit 2>/dev/null || git checkout -b audit
   ```
   If `ARCHON_GIT_AVAILABLE=false`, skip branch creation and continue auditing the directory in place. Do NOT initialize a new repo just for the audit.
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
         "mode": "deep",
         "model": "<model name, e.g. opus-4.6, gpt-5.3-codex, sonnet-4.6>",
         "agent_sdk": "<platform name, e.g. claude-code, codex, bytesec, opencode, traecli>",
         "started_at": "<ISO timestamp>",
         "completed_at": null,
         "status": "in_progress",
         "phases": {
           "1": {"status": "pending"},
           "2": {"status": "pending"},
           "3": {"status": "pending"},
           "4": {"status": "pending"},
           "5": {"status": "pending"},
           "5A": {"status": "pending"},
           "5B": {"status": "pending"},
           "5C": {"status": "pending"},
           "6": {"status": "pending"},
           "7": {"status": "pending"},
           "8": {"status": "pending"},
           "9": {"status": "pending"},
           "10": {"status": "pending"},
           "11": {"status": "pending"}
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

### Mode Selection

After pre-flight setup, assess whether to use **Swarm Mode** (default) or **Solo Mode** (fallback).

Run: `find ${ARGUMENTS:-.} -type f | wc -l`

- **Swarm Mode** (default): target resolves to more than ~20 files, OR no specific narrow path is provided, OR the full repository is being audited.
- **Solo Mode** (fallback): `$ARGUMENTS` targets a single file, OR the resolved file count is 20 or fewer.

---

## Swarm Mode (Default)

You are the swarm orchestrator. Dispatch domain-specialist agents directly — no teammate layer. Your role is coordination only: create tasks, spawn agents, monitor completion, aggregate results.

### Lead Setup

1. Create directories: `mkdir -p archon/ archon/findings-draft/ archon/probe-workspace/`
2. Initialize `archon/audit-state.json` with all 11 phases (plus sub-phases 5A, 5B, 5C) set to `pending`.
3. Create the full task list using `TaskCreate` so dependencies are tracked automatically.

### Task List

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | Phase 1 -- Intelligence Gathering | -- |
| T2 | Phase 2 -- Patch Bypass Analysis | T1 |
| T3 | Phase 3 -- Knowledge Base | T2 |
| T4 | Phase 4 -- Static Analysis | T3 |
| T5 | Phase 5 -- Deep Probe | T3 |
| T5A | Phase 5A -- Authorization Audit | T3 |
| T5B | Phase 5B -- State & Concurrency Audit | T3 |
| T5C | Phase 5C -- Cross-Service Taint Propagation | T4, T5 |
| T6 | Phase 6 -- Spec Gap Analysis | T3 |
| T7 | Phase 7 -- Enrichment | T4 |
| T8 | Phase 8 -- Review Chamber Deep Bug Hunting | T5, T5A, T5B, T5C, T6, T7 |
| T9 | Phase 9 -- P9-LITE FP Elimination | T8 |
| T10 | Phase 10 -- Variant Analysis | T9 |
| T11 | Phase 11 -- Exploitation and Final Reporting | T10 |

T4, T5, T5A, T5B, and T6 all unblock after T3 and run in parallel. T5C waits for both T4 and T5. T8 waits for T5, T5A, T5B, T5C, T6, and T7.

### Swarm Orchestration Protocol

Execute the following steps sequentially. You are the coordinator — do NOT perform audit work.

**Step 1-2: Intelligence (T1, T2)**

If `ARCHON_GIT_AVAILABLE=true`, in a **single message**, spawn both Phase 1 agents with `run_in_background: true`:
- `archon:advisory-hunter`
- `archon:commit-archaeologist`

If `ARCHON_GIT_AVAILABLE=false`, spawn only:
- `archon:advisory-hunter`

Wait for the spawned Phase 1 agents to complete.

**Process advisory-hunter output**: read its KB section, extract patch list (commits with known CVE/GHSA) when present.
If `ARCHON_GIT_AVAILABLE=true`, also process `commit-archaeologist` output from `archon/commit-recon-report.md`:
- HIGH-risk commits from Categories 1, 2, 3 → feed to `patch-bypass-checker` as `type: undisclosed-fix`
- Dedup: skip any SHA already present in advisory-hunter's patch list

If `ARCHON_GIT_AVAILABLE=true`, for each patch (from advisory-hunter) AND each HIGH-risk undisclosed commit (from commit-archaeologist), spawn `archon:patch-bypass-checker` with `run_in_background: true`.

If `ARCHON_GIT_AVAILABLE=false`, do **not** spawn `commit-archaeologist` or `patch-bypass-checker`. Instead write an explicit Phase 2 note into `archon/knowledge-base-report.md` such as:
```markdown
## Bypass Analysis

Skipped local patch bypass analysis because this target has no Git history (`history_available=false`). Advisory hunting, KB construction, SAST, probe, chambers, and reporting continued against the source snapshot.
```

Wait for all patch agents. Merge bypass analysis files:
```bash
# Merge per-patch bypass files into KB
mkdir -p archon/bypass-analysis/
echo "## Bypass Analysis" > /tmp/bypass-merged.md
for f in archon/bypass-analysis/*.md; do
  [ -f "$f" ] && cat "$f" >> /tmp/bypass-merged.md && echo "" >> /tmp/bypass-merged.md
done
# Append to KB if bypass files exist
if [ -s /tmp/bypass-merged.md ]; then
  cat /tmp/bypass-merged.md >> archon/knowledge-base-report.md
fi
```
Mark T1, T2 complete.

**Step 3: Knowledge Base (T3)**

Spawn `archon:knowledge-base-builder` (foreground). Mark T3 complete.

**Step 4-5-6: Static Analysis + Deep Probe + Systematic Audits (5A/5B) + Spec Gap — all parallel**

In a **single message**, spawn ALL of the following:
- `archon:static-analyzer` with `run_in_background: true` (T4)
- `archon:authz-auditor` with `run_in_background: true` (T5A)
- `archon:state-concurrency-auditor` with `run_in_background: true` (T5B)
- `archon:spec-gap-analyst` with `run_in_background: true` (T6)
- Deep Probe teams (T5) — see below

**Systematic audits (T5A, T5B):** each is a single-agent phase that complements Deep Probe. Prompts:

> `archon:authz-auditor` — "Phase 5A: enumerate every route/handler/consumer, build `archon/authz-matrix.md`, file drafts `archon/findings-draft/p5a-<NNN>-<slug>.md`. KB: archon/knowledge-base-report.md. Coordinate with Phase 5 — check archon/probe-workspace/*/probe-summary.md before filing to avoid duplicate drafts."

> `archon:state-concurrency-auditor` — "Phase 5B: catalogue state-holding entities and concurrency primitives, file drafts `archon/findings-draft/p5b-<NNN>-<slug>.md`. KB: archon/knowledge-base-report.md. Coordinate with Phase 5 — check archon/probe-workspace/*/probe-summary.md before filing."

**Deep Probe Dispatch (T5):**

1. Read `archon/knowledge-base-report.md` sections `## DFD/CFD Slices`, `## Attack Surface`, `## Architecture Model`.
2. Identify **ALL** components that handle attacker-controlled input.
3. Group into probe teams:
   - **Large components** (5+ functions handling attacker input): dedicated probe team
   - **Small components** (< 5 functions): group 2-4 related small components into one shared probe team
4. `mkdir -p archon/probe-workspace/`
5. For each probe team (NN = 01, 02, 03, ...), spawn **6 agents** with `run_in_background: true` **in the same single message as T4 and T6**:

> **Probe Strategist** (coordinator — orchestrates all other agents via SendMessage):
> `subagent_type: "archon:probe-strategist"`, `name: "probe-strategist-<NN>"`
> Prompt: "You are the Probe Strategist for: <component(s) list>. KB path: archon/knowledge-base-report.md. Workspace: archon/probe-workspace/<component>/. Your team: code-anatomist-<NN>, backward-reasoner-<NN>, contradiction-reasoner-<NN>, causal-verifier-<NN>, evidence-harvester-<NN>. Step 1: Read KB, build attack surface map and Layer Trust Chain. Step 2: SendMessage to code-anatomist-<NN> to produce Code Anatomy. Step 3: SendMessage backward-reasoner-<NN> and contradiction-reasoner-<NN> in parallel (Round 1+2). Step 4: Cross-pollinate findings. Step 5: SendMessage causal-verifier-<NN> with validated findings + seeds (Round 3). Step 6: SendMessage evidence-harvester-<NN> with all hypotheses. Step 7: Bayesian/Socratic decision loop. Step 8: Write probe-summary.md and message orchestrator."

> **Code Anatomist** (Haiku — reads source code, produces structured anatomy):
> `subagent_type: "archon:code-anatomist"`, `name: "code-anatomist-<NN>"`
> Prompt: "You are the Code Anatomist for: <component(s) list>. Wait for the Probe Strategist (probe-strategist-<NN>) to message you with source file paths and output path. Produce the Code Anatomy document."

> **Backward Reasoner** (Pre-Mortem + Abductive reasoning):
> `subagent_type: "archon:backward-reasoner"`, `name: "backward-reasoner-<NN>"`
> Prompt: "You are the Backward Reasoner for: <component(s) list>. Wait for the Probe Strategist (probe-strategist-<NN>) to message you with the Code Anatomy path, attack surface map, and output path. Apply Pre-Mortem and Abductive reasoning to generate hypotheses."

> **Contradiction Reasoner** (TRIZ + Game Theory reasoning):
> `subagent_type: "archon:contradiction-reasoner"`, `name: "contradiction-reasoner-<NN>"`
> Prompt: "You are the Contradiction Reasoner for: <component(s) list>. Wait for the Probe Strategist (probe-strategist-<NN>) to message you with the Code Anatomy path, attack surface map, and output path. Apply TRIZ and Game Theory reasoning to generate hypotheses."

> **Causal Verifier** (Pearl's causal reasoning — runs after Round 1+2):
> `subagent_type: "archon:causal-verifier"`, `name: "causal-verifier-<NN>"`
> Prompt: "You are the Causal Verifier for: <component(s) list>. Wait for the Probe Strategist (probe-strategist-<NN>) to message you with validated Round 1+2 findings, cross-model seeds, and output path. Apply causal reasoning to find dormant and confounded protections."

> **Evidence Harvester** (code tracer with fragility scoring):
> `subagent_type: "archon:evidence-harvester"`, `name: "evidence-harvester-<NN>"`
> Prompt: "You are the Evidence Harvester for: <component(s) list>. Wait for the Probe Strategist (probe-strategist-<NN>) to message you with hypotheses files and output path. Trace each hypothesis and issue verdicts with Fragility Scores for INVALIDATED findings."

**Step 7: Enrichment (T7)**

Wait for T4 (static analyzer). Spawn `archon:enrichment-filter` (foreground). Mark T7 complete.
Wait for T6 (spec gap) if not done. Mark T6 complete.
Wait for T5A (authz audit) and T5B (state/concurrency audit); mark each complete as it finishes. These run in background and typically complete alongside T4/T5 — do not block chamber dispatch on them beyond this point.

**Step 7B: Cross-Service Taint Propagation (T5C)**

Wait for both T4 (static analyzer) and T5 (all probe teams complete) before dispatching. Mark T5 complete once all probe teams close.

Spawn `archon:cross-service-auditor` (foreground). Prompt:

> "Phase 5C: read KB sections `## Architecture Model`, `## DFD/CFD Slices`; read `archon/probe-workspace/*/probe-summary.md`; read `archon/codeql-artifacts/entry-points.json`, `sinks.json`, `call-graph-slices.json`; read `archon/authz-matrix.md` if present. Build `archon/cross-service-edges.json` + `archon/cross-service-edges.md`. File cross-service drafts `archon/findings-draft/p5c-<NNN>-<slug>.md`. If single-service topology, exit cleanly with the no-op note."

Mark T5C complete.

**Step 8: Review Chambers (T8) — enhanced with Deep Probe + Systematic Audit results**

Before dispatching: all of T5, T5A, T5B, T5C, T6, T7 must be `complete`. Read every draft in `archon/findings-draft/` (p5a-*, p5b-*, p5c-* in addition to Deep Probe workspace). Chamber Synthesizers pre-seed these systematic drafts alongside Deep Probe hypotheses so Ideators do not regenerate them.

1. Initialize: `mkdir -p archon/chamber-workspace/` and create `archon/attack-pattern-registry.json` with `{"patterns": []}`
2. **Read probe results**: `cat archon/probe-workspace/*/probe-summary.md` to collect all validated hypotheses across all probe teams. Group by threat cluster affinity.
3. Read `archon/knowledge-base-report.md`. Form threat clusters from `## High-Risk DFD Slices` and `## High-Risk CFD Slices` — group by shared trust boundary or component affinity.
4. Assign NNN ranges: Chamber 1 = p8-001 to p8-019, Chamber 2 = p8-020 to p8-039, etc.
5. For each cluster (up to 3 concurrent), spawn a 4-agent chamber team:

For each chamber, spawn 4 agents with `run_in_background: true`:

> **Chamber Synthesizer** (lead of each chamber):
> `subagent_type: "archon:chamber-synthesizer"`, `name: "chamber-synth-<NN>"`
> Prompt: "You are the Synthesizer for Review Chamber <chamber-id>. Threat cluster: <description>. DFD slices: <list>. NNN range: p8-<start> to p8-<end>. Methodology: `~/.config/archon-audit/skills/audit/SKILL.md` Phase 8. State: `archon/audit-state.json`. Create debate.md at `archon/chamber-workspace/<chamber-id>/debate.md` and orchestrate the debate. Pre-seeded drafts relevant to this cluster (DO NOT regenerate): Deep Probe hypotheses from `archon/probe-workspace/*/probe-summary.md`, Phase 5A authz drafts `archon/findings-draft/p5a-*.md`, Phase 5B state/concurrency drafts `archon/findings-draft/p5b-*.md`, Phase 5C cross-service drafts `archon/findings-draft/p5c-*.md` — include each with title, class, evidence file:line, severity estimate. Instruct the Ideator to chain / extend these rather than regenerating them. Your Ideator is `ideator-<NN>`, Tracer is `tracer-<NN>`, Advocate is `advocate-<NN>`. Use SendMessage to coordinate turns."

> **Attack Ideator**:
> `subagent_type: "archon:attack-ideator"`, `name: "ideator-<NN>"`
> Prompt: "You are the Attack Ideator for Review Chamber <chamber-id>. Wait for the Synthesizer (`chamber-synth-<NN>`) to message you. Pre-seeded drafts (Deep Probe + Phase 5A authz + Phase 5B state/concurrency + Phase 5C cross-service) are already in the debate.md — do NOT regenerate those hypotheses. Focus your creative modes on: (a) chaining pre-seeded findings with each other and across classes, (b) cross-mode combinations the systematic audits did not attempt, (c) attack classes that require lateral thinking rather than systematic enumeration (supply chain, creative business-logic combinations, auth+state chained escalations). Then generate hypotheses and write to debate.md."

> **Code Tracer**:
> `subagent_type: "archon:code-tracer"`, `name: "tracer-<NN>"`
> Prompt: "You are the Code Tracer for Review Chamber <chamber-id>. Wait for the Synthesizer (`chamber-synth-<NN>`) to message you. For hypotheses that have Deep Probe pre-traced evidence (noted in debate.md), extend and verify that evidence rather than re-tracing from scratch. Then trace hypotheses and write evidence to debate.md."

> **Devil's Advocate**:
> `subagent_type: "archon:devils-advocate"`, `name: "advocate-<NN>"`
> Prompt: "You are the Devil's Advocate for Review Chamber <chamber-id>. Wait for the Synthesizer (`chamber-synth-<NN>`) to message you. Then write defense briefs to debate.md."

Optionally spawn `archon:variant-scout` for clusters with 3+ DFD slices.

6. **Monitor chambers**: read `archon/attack-pattern-registry.json` periodically. When a chamber closes, it messages you.
7. Wait for ALL chambers to close.
8. Write `## Phase 8 Addendum` to `archon/knowledge-base-report.md` (read all p8-*.md files for newly discovered attack surfaces).
9. Mark T8 complete.

**Step 9: P9-LITE FP Elimination (T9)**

Stage 1 (inline): apply `fp-check` skill to all `archon/findings-draft/p8-*.md` files with `Verdict: VALID`. Write verdicts back into drafts. Prioritize findings with `Pre-FP-Flag` annotations.

Stage 2 (CRITICAL/HIGH only): for each CRITICAL or HIGH finding still `VALID` after Stage 1, spawn `archon:cold-verifier` with `run_in_background: true`. The prompt contains ONLY the finding draft file path — no debate transcript, no context. **Medium findings skip Stage 2** (already challenged by Devil's Advocate in chambers).

Wait for all cold verifiers. Mark T9 complete.

**Step 10: Variant Analysis (T10)**

For each confirmed Medium+ finding: spawn `archon:variant-hunter` with `run_in_background: true`. Each agent receives: finding path, NNN range, KB path, and `archon/attack-pattern-registry.json` as primary input.

Wait for all variant hunters. Delete CodeQL database: `rm -rf archon/codeql-artifacts/db/`. Mark T10 complete.

**Step 11: Exploitation and Final Reporting (T11)**

**Finding consolidation**: Run the consolidation helper — it reads every draft in `archon/findings-draft/`, keeps the `Verdict: VALID` drafts with `Severity-Original` in {CRITICAL, HIGH, MEDIUM}, assigns deterministic severity-prefixed IDs (`C1`, `H1`, `M1`, …), creates `archon/findings/<ID>-<slug>/evidence/`, copies `draft.md`, `adversarial-review.md` (from `archon/adversarial-reviews/<slug>-review.md` if present), `debate.md` (from the draft's `Debate:` field if the file exists), and writes `metadata.json` for Phase 10 variant drafts with the parent ID resolved from `Origin-Finding`.

```bash
python3 ~/.config/archon-audit/skills/audit/scripts/consolidate_drafts.py archon
```

The script writes `archon/findings-draft/consolidation-manifest.json` and also prints the manifest to stdout. If it exits non-zero, STOP — report the failure to the user and do not proceed to PoC building or report assembly.

Read `archon/findings-draft/consolidation-manifest.json`. For each entry in its `findings` array, spawn `archon:poc-builder` with `run_in_background: true`. Each poc-builder receives the entry's `draft_path` as the finding draft path and its `id` as the assigned ID.

Wait for all PoC builders. Spawn `archon:report-assembler` (foreground) to produce `archon/final-audit-report.md`.

**No-git disclaimer (CRITICAL)**: Before spawning the report assembler, check `audits[-1].history_available` in `archon/audit-state.json`. If it is `false`, append the following instruction to the assembler's prompt:

> "history_available is false: add an Executive Summary note explaining that commit archaeology (Phase 1), local patch-bypass analysis (Phase 2), and git-derived advisory enrichment (Phase 1 advisory-hunter Source 1 + Section 5 patch-commit discovery) were skipped because the target has no Git history. Recommend re-running on a git checkout for full coverage. Also surface any `Coverage gaps recorded` from advisory-hunter's Historical coverage metadata."

**Post-audit cleanup**: After report-assembler completes and reports consistency checks passed, delete intermediate working artifacts:
```bash
rm -rf archon/findings-draft/
rm -rf archon/adversarial-reviews/
rm -rf archon/probe-workspace/
rm -rf archon/chamber-workspace/
rm -rf archon/codeql-artifacts/
rm -rf archon/codeql-queries/
rm -rf archon/semgrep-rules/
rm -rf archon/semgrep-res/
rm -f archon/attack-pattern-registry.json
```
Retained: `archon/audit-state.json`, `archon/knowledge-base-report.md`, `archon/findings/`, `archon/final-audit-report.md`. If consistency checks failed, skip cleanup and report the failures to the user first.

Mark T11 complete. Update `audits[-1].completed_at` and `audits[-1].status` to `complete`. Print post-audit summary.

### Lead Responsibilities

1. **Do not perform audit work.** Your role is coordination only.
2. Monitor via task completions and incoming agent messages.
3. If an agent fails, check `archon/findings-draft/` for partial output. Spawn replacement with remaining work only.
4. For chamber failures: only the failed chamber needs respawning. Other chambers' findings are on disk.
5. If a probe team fails, read its workspace for partial summaries and pass whatever results exist to Phase 8 chambers.

---

## Solo Mode (Fallback)

Use when the target scope is a single file or fewer than ~20 files. Execute all 11 phases sequentially. Update `archon/audit-state.json` after each phase completes (status: `complete` with timestamp) or fails (status: `failed` with error).

Phases 1-4 **must** use the `Agent` tool with the registered `subagent_type` below. Provide phase context in the `prompt` field: target scope, state file path, and prior phase outputs.

| Phase | `subagent_type` |
|-------|-----------------|
| 1 -- Intelligence Gathering | Always `archon:advisory-hunter`. Add `archon:commit-archaeologist` only when `ARCHON_GIT_AVAILABLE=true`. |
| 2 -- Patch Bypass Analysis | `archon:patch-bypass-checker` when Git history or patch metadata exists; otherwise mark the phase skipped in the KB and continue. |
| 3 -- Knowledge Base | `archon:knowledge-base-builder` |
| 4 -- Static Analysis | `archon:static-analyzer` |

Phase 5 (Deep Probe): Single probe team (1 Strategist + 1 Generator + 1 Harvester) covering all components with attacker-controlled input. Strategist name: `probe-strategist-01`, Generator: `hyp-generator-01`, Harvester: `evidence-harvester-01`.

Phase 5A (Authorization Audit): single `archon:authz-auditor` invocation.
Phase 5B (State & Concurrency Audit): single `archon:state-concurrency-auditor` invocation.
Phase 5C (Cross-Service Taint): single `archon:cross-service-auditor` invocation, dispatched only after Phase 4 AND Phase 5 complete. Exits cleanly on single-service repos.

Phase 6: `archon:spec-gap-analyst`. Phase 7: `archon:enrichment-filter`.

Phase 8 (Review Chamber): In solo mode, spawn a single chamber with all 4 roles (Synthesizer, Ideator, Tracer, Advocate). Use the same chamber protocol as Swarm Mode but with one chamber covering all DFD slices. NNN range: p8-001 to p8-049. Include all Deep Probe validated hypotheses AND all Phase 5A/5B/5C drafts (`archon/findings-draft/p5a-*.md`, `p5b-*.md`, `p5c-*.md`) as pre-seeded drafts in the Ideator prompt — instruct the Ideator to chain and extend them rather than regenerating.

Phase 9 (P9-LITE): Stage 1 inline (fp-check). Stage 2: spawn cold verifier per CRITICAL/HIGH finding only.

Phase 10: spawn one `archon:variant-hunter` per confirmed finding with `run_in_background: true`.

Phase 11: run the consolidation helper (`python3 ~/.config/archon-audit/skills/audit/scripts/consolidate_drafts.py archon`) to create finding directories, copy drafts, adversarial reviews, debate transcripts, and variant metadata. If the script exits non-zero, stop and report the failure. Otherwise read `archon/findings-draft/consolidation-manifest.json` and for each entry in its `findings` array spawn one `archon:poc-builder` with `run_in_background: true` (passing the entry's `draft_path` and `id`). Then `archon:report-assembler` (foreground). When `audits[-1].history_available` is `false`, append the no-git disclaimer instruction to the assembler prompt (same wording as Swarm Step 11). After report assembly, run post-audit cleanup (same as Swarm Mode).

**Parallelism in solo mode**:
- After Phase 3: spawn Phase 4 (`archon:static-analyzer`), Phase 5 (probe team), Phase 5A (`archon:authz-auditor`), Phase 5B (`archon:state-concurrency-auditor`), and Phase 6 (`archon:spec-gap-analyst`) in a single message with `run_in_background: true`.
- Phase 5C (`archon:cross-service-auditor`): dispatch AFTER both Phase 4 and Phase 5 complete. Runs foreground.
- Phase 2: one `archon:patch-bypass-checker` per patch with `run_in_background: true` only when `ARCHON_GIT_AVAILABLE=true`.
- Phase 9 Stage 2: one cold verifier per CRITICAL/HIGH finding with `run_in_background: true`.
- Phase 10: one `archon:variant-hunter` per finding with `run_in_background: true`.
- Phase 11: one `archon:poc-builder` per finding with `run_in_background: true`.

**Phase sequence**:
```
P1 -> P2 (per-patch parallel) -> P3 -> [P4 + P5 + P5A + P5B + P6] (parallel) -> P5C (after P4 + P5) -> P7 (after P4) -> P8 (after P5, P5A, P5B, P5C, P6, P7) -> P9-LITE -> P10 (per-finding parallel) -> P11 (per-finding parallel + report)
```

After Phase 11, set `audits[-1].completed_at` to current timestamp and `audits[-1].status` to `complete`.

---

## Single Phase Execution

When `$ARGUMENTS` is a phase identifier (1-11, or 5A / 5B / 5C):

1. If no `archon/audit-state.json` exists, create one with all phases `pending` and run setup first.
2. Verify prerequisites — check that all required earlier phases are `complete` in the state file:
   - Phase 2 requires Phase 1 / Phase 3 requires 1-2 / Phase 4 requires 3 / Phase 5 requires 3
   - Phase 5A requires 3 / Phase 5B requires 3 / Phase 5C requires 4 and 5
   - Phase 6 requires 3 / Phase 7 requires 4 / Phase 8 requires 5, 5A, 5B, 5C, 6, 7 / Phase 9 requires 8
   - Phase 10 requires 9 / Phase 11 requires 10
   - If prerequisites are incomplete, ask the user whether to run all missing prerequisites first or cancel.
3. Set the phase status to `in_progress` with a start timestamp.
4. Execute only that phase per the phase map below.
5. On success: set status to `complete` with end timestamp. On failure: set `failed` with error.

| Phase | Name | Agent / Execution |
|-------|------|-------------------|
| 1 | Intelligence Gathering | Always `archon:advisory-hunter`; add `archon:commit-archaeologist` only when `ARCHON_GIT_AVAILABLE=true` |
| 2 | Patch Bypass Analysis | `archon:patch-bypass-checker` (one per patch, `run_in_background: true`) only when local patch history exists; otherwise record a skipped/no-history result and continue |
| 3 | Knowledge Base | `archon:knowledge-base-builder` |
| 4 | Static Analysis | `archon:static-analyzer` |
| 5 | Deep Probe | Probe teams: `archon:probe-strategist` + `archon:hypothesis-generator` + `archon:evidence-harvester` (one team per component group) |
| 5A | Authorization Audit | `archon:authz-auditor` (single agent) |
| 5B | State & Concurrency Audit | `archon:state-concurrency-auditor` (single agent) |
| 5C | Cross-Service Taint Propagation | `archon:cross-service-auditor` (single agent; exits cleanly on single-service repos) |
| 6 | Spec Gap Analysis | `archon:spec-gap-analyst` |
| 7 | Enrichment | `archon:enrichment-filter` |
| 8 | Review Chamber | Single chamber: `archon:chamber-synthesizer` + `archon:attack-ideator` + `archon:code-tracer` + `archon:devils-advocate` |
| 9 | P9-LITE FP Elimination | Stage 1 inline (fp-check). Stage 2: cold verifier per CRITICAL/HIGH |
| 10 | Variant Analysis | `archon:variant-hunter` (one per finding, `run_in_background: true`) |
| 11 | Exploitation and Reporting | `archon:poc-builder` per finding + `archon:report-assembler` |

---

## Resume Logic

Read `audits[-1].phases` from `archon/audit-state.json` to find phase statuses. Walk phases in dependency order: 1, 2, 3, [4, 5, 5A, 5B, 6] (parallel), 5C (after 4+5), 7 (after 4), 8 (after 5/5A/5B/5C/6/7), 9, 10, 11. Find the earliest-ordered phase with status `pending`, `in_progress`, or `failed`:

- `failed` or `in_progress`: check whether the expected KB sections or output artifacts exist and appear complete. Artifact gates for the new phases:
  - 5A complete if `archon/authz-matrix.md` exists OR the KB has `## Authorization Audit` with an explicit skip note
  - 5B complete if the KB has `## State & Concurrency Audit` with draft count (zero findings is acceptable)
  - 5C complete if `archon/cross-service-edges.json` exists OR the KB has `## Cross-Service Taint Propagation` with an explicit single-service skip note
  
  If so, mark `complete` and advance. Otherwise delete the partial output and re-run.
- `pending`: run normally.

Continue through Phase 11 using the phase map above.
