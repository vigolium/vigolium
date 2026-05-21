---
description: Run a full 12-phase security audit on the current repository. Resumes from the last checkpoint if an audit is already in progress. Runs a single phase if a phase id is given as argument.
argument-hint: "Optional: target path/scope, or phase number"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: deep
phases:
  - id: "D1"
    title: Intelligence Pass (CVE)
    agent: cve-scout
    requires_git: false
    parallel_with: ["D2"]
    depends_on: []
  - id: "D2"
    title: Intelligence Pass (History)
    agent: history-miner
    requires_git: true
    parallel_with: ["D1"]
    depends_on: []
  - id: "D3"
    title: Patch Audit
    agent: patch-auditor
    requires_git: true
    parallel_with: []
    depends_on: ["D1", "D2"]
  - id: "D4"
    title: Threat Model
    agent: threat-modeler
    requires_git: false
    parallel_with: []
    depends_on: ["D3"]
  - id: "D5"
    title: Code Scan
    agent: code-scanner
    requires_git: false
    parallel_with: []
    depends_on: ["D4"]
  - id: "D6"
    title: Deep Probe
    agent: probe-lead
    requires_git: false
    parallel_with: []
    depends_on: ["D4"]
  - id: "D7"
    title: Access Audit
    agent: access-auditor
    requires_git: false
    parallel_with: []
    depends_on: ["D4"]
  - id: "D8"
    title: Review Panel
    agent: review-adjudicator
    requires_git: false
    parallel_with: []
    depends_on: ["D5", "D6", "D7"]
  - id: "D9"
    title: Intent Reconciliation
    agent: context-reviewer
    requires_git: false
    parallel_with: []
    depends_on: ["D8"]
  - id: "D10"
    title: PoC Authoring
    agent: poc-author
    requires_git: false
    parallel_with: []
    depends_on: ["D9"]
  - id: "D11"
    title: Finding Finalize
    agent: finding-writer
    requires_git: false
    parallel_with: []
    depends_on: ["D10"]
  - id: "D12"
    title: Report Compose
    agent: report-composer
    requires_git: false
    parallel_with: []
    depends_on: ["D11"]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat vigolium-results/audit-context.md 2>/dev/null || echo "(none)"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree (plain directory target)"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "No git branch (plain directory target)"`
- Existing audit state: !`cat vigolium-results/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Security directory: !`ls vigolium-results/ 2>/dev/null || echo "No security directory"`

## Your Task

Run a full security audit of the current repository. Target scope: $ARGUMENTS

This mode can run against a plain source folder with no `.git` directory. When Git history is unavailable, degrade gracefully: skip commit archaeology and any patch-bypass work that depends on local patch history, record the degraded mode in `vigolium-results/audit-state.json`, and continue with the remaining phases.

Cross-service taint propagation and per-finding variant analysis are **not** separate phases. Cross-service edge enumeration is folded into Phase D5 (code-scanner, gated on a multi-service project), cross-service taint reasoning is folded into the Phase D8 Review Chamber Ideator, and variant expansion is folded into the Phase D8 Review Chamber Code Tracer. There is no `taint-tracer`, `variant-scanner`, or `variant-spotter` spawn in deep mode.

### No-Git Rule

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false` or `git rev-parse --is-inside-work-tree` fails, treat commit history as unavailable for the entire run.

- NEVER spawn `vigolium-audit:history-miner`
- NEVER spawn `vigolium-audit:patch-auditor` for history-derived patches
- Record the skip explicitly in `vigolium-results/attack-surface/knowledge-base-report.md`
- Continue with KB, SAST, probe, chamber, PoC, and reporting phases against the source snapshot

### Argument Handling

Parse `$ARGUMENTS` first:

- **Single phase identifier**: skip pre-flight and mode selection; jump directly to [Single Phase Execution](#single-phase-execution).
- **Path or scope (or empty)**: continue with pre-flight below.

### Pre-Flight Check

If `vigolium-results/audit-state.json` exists, use `AskUserQuestion` to gate the next action:

- **Incomplete phases**: ask "An audit is already in progress. What would you like to do?" with options:
  - "Resume from last checkpoint"
  - "Start fresh (clears existing state)"
  - "Cancel"

- **All phases complete**: ask "A completed audit exists for this repository. What would you like to do?" with options:
  - "Run a full fresh audit (clears existing state)"
  - "Run an incremental diff audit (/vigolium-audit:diff)"
  - "Run a balanced audit (/vigolium-audit:balanced)"
  - "Cancel"

If the user chooses **Resume**: find the first phase not marked `complete` in the state file and continue from there (see [Resume Logic](#resume-logic)).

If the user chooses **Start fresh**: delete `vigolium-results/audit-state.json` and proceed with Pre-Audit Setup.

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
4. Initialize `vigolium-results/audit-state.json` by appending a new entry (or creating the file):
   ```json
   {
     "audits": [
       {
         "audit_id": "<ISO timestamp>",
         "commit": "<HEAD SHA from: git rev-parse HEAD, or null / \"nogit\" when Git is unavailable>",
         "branch": "<current branch, or \"nogit\">",
         "repository": "<value of $VIGOLIUM_AUDIT_REPOSITORY env var, pre-computed by the CLI from git remote / package manifests / basename — substitute the literal string before writing>",
         "history_available": "<true if Git worktree detected, else false>",
         "mode": "deep",
         "model": "<model name, e.g. opus-4.6, gpt-5.3-codex, sonnet-4.6>",
         "agent_sdk": "<platform name, e.g. claude-code, codex>",
         "started_at": "<ISO timestamp>",
         "completed_at": null,
         "status": "in_progress",
         "phases": {
           "D1": {"status": "pending"},
           "D2": {"status": "pending"},
           "D3": {"status": "pending"},
           "D4": {"status": "pending"},
           "D5": {"status": "pending"},
           "D6": {"status": "pending"},
           "D7": {"status": "pending"},
           "D8": {"status": "pending"},
           "D9": {"status": "pending"},
           "D10": {"status": "pending"},
           "D11": {"status": "pending"},
           "D12": {"status": "pending"}
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

### Mode Selection

After pre-flight setup, assess whether to use **Swarm Mode** (default) or **Solo Mode** (fallback).

Run: `find ${ARGUMENTS:-.} -type f | wc -l`

- **Swarm Mode** (default): target resolves to more than ~20 files, OR no specific narrow path is provided, OR the full repository is being audited.
- **Solo Mode** (fallback): `$ARGUMENTS` targets a single file, OR the resolved file count is 20 or fewer.

---

## Swarm Mode (Default)

You are the swarm orchestrator. Dispatch domain-specialist agents directly — no teammate layer. Your role is coordination only: create tasks, spawn agents, monitor completion, aggregate results.

### Lead Setup

1. Create directories: `mkdir -p vigolium-results/ vigolium-results/findings-draft/ vigolium-results/probe-workspace/`
2. Initialize `vigolium-results/audit-state.json` with all 12 phases set to `pending`.
3. Create the full task list using `TaskCreate` so dependencies are tracked automatically.

### Swarm Burst Cap

To avoid quota spikes, keep a hard cap of **3 concurrent background agents** at all times.

- If a phase wants more than 3 agents, split it into batches or staged rounds.
- Do not launch the next batch until the current batch has finished and its outputs are usable.
- Treat the orchestrator as coordination-only; the cap applies to spawned audit agents.

### Task List

| Task | Phase | Depends on |
|------|-------|-----------|
| T1 | Phase D1/D2 -- Intelligence Pass | -- |
| T2 | Phase D3 -- Patch Audit | T1 |
| T3 | Phase D4 -- Threat Model | T2 |
| T4 | Phase D5 -- Code Scan (+ cross-service edge enumeration when multi-service) | T3 |
| T5 | Phase D6 -- Deep Probe | T3 |
| T6 | Phase D7 -- Access Audit | T3 |
| T7 | Phase D8 -- Review Panel + FP Elimination (inline taint reasoning + variant expansion) | T4, T5, T6 |
| T8 | Phase D9 -- Intent Reconciliation | T7 |
| T9 | Phase D10 -- PoC Authoring | T8 |
| T10 | Phase D11 -- Finding Finalize (report.md per finding) | T9 |
| T11 | Phase D12 -- Report Compose | T10 |

T4, T5, and T6 all unblock after T3, but for burst control execute them in waves:
`T4` first, then `T6`, then `T5`. T7 waits for T4, T5, and T6. FP elimination
(fp-check + CRITICAL-only cold-verify + triage pass) runs inline as the tail of
T7 — there is no separate FP phase. Cross-service taint reasoning and per-finding
variant expansion also run inline inside T7 (chamber Ideator + Code Tracer) — there
is no separate taint or variant task. T8 (Intent Reconciliation) runs after the T7
FP/triage tail and before any PoC effort. Enrichment runs inline inside Phase D5
(code-scanner), so there is no separate enrichment task. T10 ("Finding Finalize")
is the mandatory gate before T11 — the final report assembler is NOT dispatched
until every `vigolium-results/findings/<ID>-<slug>/` has a non-empty `report.md`.

### Swarm Orchestration Protocol

Execute the following steps sequentially. You are the coordinator — do NOT perform audit work.

**Step 1: Intelligence (T1, T2)**

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, in a **single message**, spawn both Phase D1/D2 agents with `run_in_background: true`:
- `vigolium-audit:cve-scout`
- `vigolium-audit:history-miner`

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, spawn only:
- `vigolium-audit:cve-scout`

Wait for the spawned Phase D1/D2 agents to complete.

**Process cve-scout output**: read its KB section, extract patch list (commits with known CVE/GHSA) when present.
If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, also process `history-miner` output from `vigolium-results/attack-surface/commit-recon-report.md`:
- HIGH-risk commits from Categories 1, 2, 3 → feed to `patch-auditor` as `type: undisclosed-fix`
- Dedup: skip any SHA already present in cve-scout's patch list

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`, for each patch (from cve-scout) AND each HIGH-risk
undisclosed commit (from history-miner), spawn `vigolium-audit:patch-auditor` in
**batches of at most 3 background agents**. Wait for the current batch to finish before
launching the next batch.

If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, do **not** spawn `history-miner` or `patch-auditor`. Instead write an explicit Phase D3 note into `vigolium-results/attack-surface/knowledge-base-report.md` such as:
```markdown
## Bypass Analysis

Skipped local patch bypass analysis because this target has no Git history (`history_available=false`). Advisory hunting, KB construction, SAST, probe, chambers, and reporting continued against the source snapshot.
```

Wait for all patch agents. Merge bypass analysis files:
```bash
# Merge per-patch bypass files into KB
mkdir -p vigolium-results/bypass-analysis/
echo "## Bypass Analysis" > /tmp/bypass-merged.md
for f in vigolium-results/bypass-analysis/*.md; do
  [ -f "$f" ] && cat "$f" >> /tmp/bypass-merged.md && echo "" >> /tmp/bypass-merged.md
done
# Append to KB if bypass files exist
if [ -s /tmp/bypass-merged.md ]; then
  cat /tmp/bypass-merged.md >> vigolium-results/attack-surface/knowledge-base-report.md
fi
```
Mark T1, T2 complete.

**Step 2: Knowledge Base (T3)**

If `VIGOLIUM_AUDIT_INFO_AVAILABLE=true` (or `vigolium-results/INFO.md` exists in the target repo), the KB-builder treats that file as authoritative project context and skips its rediscovery work for project type, trust boundaries, auth primitives, known FP sources, out-of-scope paths, and spec commitments. Mention this explicitly in the prompt so the agent reads `vigolium-results/INFO.md` before any discovery.

Spawn `vigolium-audit:threat-modeler` (foreground) with the following addition to the prompt:

> "If `vigolium-results/INFO.md` exists, read it first and use it as authoritative for the sections it covers (per the agent's INFO.md handling rules). Run domain attack research, threat modeling, and Phase D5 extraction targets as normal. In `## Architecture Model`, emit an explicit `Multi-service: true|false` line — `true` only when more than one independently deployable service/process is present (multiple distinct Dockerfiles / compose service definitions / `services/*` / `apps/*` / `cmd/*` entry points, or in-repo internal HTTP/gRPC/queue peers). This marker gates Phase D5 cross-service edge enumeration and the Phase D8 chamber's cross-service taint reasoning."

Mark T3 complete.

**Step 3: Burst-capped execution waves (max 3 background agents)**

Run the post-KB phases in these waves instead of one large fan-out:

1. **Wave A** — in a single message, spawn (2 agents, within the cap):
   - `vigolium-audit:code-scanner` with `run_in_background: true` (T4)
   - `vigolium-audit:access-auditor` with `run_in_background: true` (T6)
   Wait for both.
2. **Wave B** — Deep Probe teams (T5), one team at a time, using staged rounds that never exceed 3 active agents. See below.

**Static analysis + cross-service edge enumeration (T4):** Phase D5 code-scanner runs SAST, structural extraction, and inline enrichment. Prompt addition:

> `vigolium-audit:code-scanner` — "Phase D5. Run SAST + structural extraction + inline `## SAST Enrichment`. Read `## Architecture Model` in `vigolium-results/attack-surface/knowledge-base-report.md`: if it marks `Multi-service: true`, also enumerate inter-service channels (HTTP/gRPC/queue/shared-DB-write/file/IPC edges) and write `vigolium-results/attack-surface/cross-service-edges.json` + `vigolium-results/attack-surface/cross-service-edges.md` (services, edges with producer/consumer file:line + channel + boundary-sanitization observation, coverage gaps). If `Multi-service: false`, skip edge enumeration entirely and do NOT create those files — single-service is a legitimate no-op."

**Systematic audit (T6):** a single-agent phase that complements Deep Probe. Prompt:

> `vigolium-audit:access-auditor` — "Phase D7: enumerate every route/handler/consumer, build `vigolium-results/attack-surface/authz-matrix.md`, file drafts `vigolium-results/findings-draft/p6-<NNN>-<slug>.md`. KB: vigolium-results/attack-surface/knowledge-base-report.md. Coordinate with Phase D6 — check vigolium-results/probe-workspace/*/probe-summary.md before filing to avoid duplicate drafts."

**Deep Probe Dispatch (T5):**

1. Read `vigolium-results/attack-surface/knowledge-base-report.md` sections `## DFD/CFD Slices`, `## Attack Surface`, `## Architecture Model`.
2. Identify **ALL** components that handle attacker-controlled input.
3. Group into probe teams:
   - **Large components** (5+ functions handling attacker input): dedicated probe team
   - **Small components** (< 5 functions): group 2-4 related small components into one shared probe team
4. `mkdir -p vigolium-results/probe-workspace/`
5. For each probe team (NN = 01, 02, 03, ...), process the team **one at a time** with these staged rounds:

   **Round C1 -- Strategist setup (attack surface + code anatomy inline)**
   - Spawn `vigolium-audit:probe-lead` with `run_in_background: true`
   - The strategist maps attack surface AND authors the Code Anatomy inline (no separate code-anatomist agent)
   - Wait until the strategist has written `attack-surface-map.md` and `code-anatomy.md` and is ready to fan out

   **Round C2 -- Dual reasoning**
   - Keep the strategist active
   - Spawn `vigolium-audit:goal-backtracer` and `vigolium-audit:assumption-breaker` with `run_in_background: true`
   - This is the heaviest probe burst and it is capped at 3 active agents total: strategist + 2 reasoners
   - Wait for both reasoners to finish

   **Round C3 -- Evidence harvest (includes causal challenge)**
   - Keep the strategist active
   - Spawn `vigolium-audit:evidence-collector` with `run_in_background: true`
   - The harvester traces every hypothesis AND applies Pearl-style intervention / counterfactual / confounder tests before declaring any INVALIDATED verdict — it may flip verdicts or emit `Causal-Followup: PH-<NN>` hypotheses (this absorbs the former causal-verifier round)
   - Wait for it to finish, then wait for the strategist to write `probe-summary.md` and close the team

   Use these prompts for the staged team:

   - `vigolium-audit:probe-lead` / `probe-lead-<NN>`:
     "You are the Probe Strategist for: <component(s) list>. KB path: vigolium-results/attack-surface/knowledge-base-report.md. Workspace: vigolium-results/probe-workspace/<component>/. Your team: goal-backtracer-<NN>, assumption-breaker-<NN>, evidence-collector-<NN>. Write attack-surface-map.md AND author code-anatomy.md inline (no separate anatomist). Two rounds: backward+contradiction, then evidence harvest (harvester owns causal challenge). Never have more than two helper agents alive at once. Write probe-summary.md and message orchestrator when done."
   - `vigolium-audit:goal-backtracer` / `goal-backtracer-<NN>`:
     "You are the Backward Reasoner for: <component(s) list>. Wait for the Probe Strategist (probe-lead-<NN>) to message you with the Code Anatomy path, attack surface map, and output path. Apply Pre-Mortem and Abductive reasoning to generate hypotheses."
   - `vigolium-audit:assumption-breaker` / `assumption-breaker-<NN>`:
     "You are the Contradiction Reasoner for: <component(s) list>. Wait for the Probe Strategist (probe-lead-<NN>) to message you with the Code Anatomy path, attack surface map, and output path. Apply TRIZ and Game Theory reasoning to generate hypotheses."
   - `vigolium-audit:evidence-collector` / `evidence-collector-<NN>`:
     "You are the Evidence Harvester for: <component(s) list>. Wait for the Probe Strategist (probe-lead-<NN>) to message you with hypotheses files and output path. Trace each hypothesis; before declaring INVALIDATED apply intervention/counterfactual/confounder tests on the apparent blocking protection and emit Causal-Followup hypotheses when the tests reveal a gap. Issue verdicts with Fragility Scores for INVALIDATED findings."

**Step 4: Review Chambers + FP Elimination + Inline Taint & Variant (T7)**

Before dispatching: all of T4, T5, T6 must be `complete`. Phase D5 must also have written its inline `## SAST Enrichment` section (the former enrichment-filter output) and, when the project is multi-service, `vigolium-results/attack-surface/cross-service-edges.json`. Read every draft in `vigolium-results/findings-draft/` (p6-* from Phase D7 in addition to Deep Probe workspace). Chamber Synthesizers pre-seed these systematic drafts alongside Deep Probe hypotheses so Ideators do not regenerate them.

1. Initialize: `mkdir -p vigolium-results/chamber-workspace/` and create `vigolium-results/attack-pattern-registry.json` with `{"patterns": []}`
2. **Read probe results**: `cat vigolium-results/probe-workspace/*/probe-summary.md` to collect all validated hypotheses across all probe teams. Group by threat cluster affinity.
3. Read `vigolium-results/attack-surface/knowledge-base-report.md`. Form threat clusters from `## High-Risk DFD Slices` and `## High-Risk CFD Slices` — group by shared trust boundary or component affinity. If `vigolium-results/attack-surface/cross-service-edges.json` exists, treat each inter-service edge as an additional cross-service threat cluster.
4. Assign NNN ranges: Chamber 1 = p10-001 to p10-019, Chamber 2 = p10-020 to p10-039, etc.
5. For each cluster, process **one chamber at a time** and never exceed 3 active agents.

For each chamber:

> **Chamber Synthesizer** (lead of each chamber):
> `subagent_type: "vigolium-audit:review-adjudicator"`, `name: "chamber-synth-<NN>"`
> Prompt: "You are the Synthesizer for Review Chamber <chamber-id>. Threat cluster: <description>. DFD slices: <list>. NNN range: p10-<start> to p10-<end>. Methodology: `~/.config/vigolium-audit/skills/audit/SKILL.md` Phase 10. State: `vigolium-results/audit-state.json`. Create debate.md at `vigolium-results/chamber-workspace/<chamber-id>/debate.md` and orchestrate the debate. Pre-seeded drafts relevant to this cluster (DO NOT regenerate): Deep Probe hypotheses from `vigolium-results/probe-workspace/*/probe-summary.md`, Phase D7 authz drafts `vigolium-results/findings-draft/p6-*.md` — include each with title, class, evidence file:line, severity estimate. If `vigolium-results/attack-surface/cross-service-edges.json` exists, also hand the Ideator the edges for this cluster. Instruct the Ideator to chain / extend these rather than regenerating them, and to add cross-service taint hypotheses for the supplied edges. Instruct the Code Tracer to run a same-pattern variant search on every VALID finding. Your Ideator is `ideator-<NN>`, Tracer is `tracer-<NN>`, Advocate is `advocate-<NN>`. Use SendMessage to coordinate turns."

> **Attack Ideator**:
> `subagent_type: "vigolium-audit:attack-designer"`, `name: "ideator-<NN>"`
> Prompt: "You are the Attack Ideator for Review Chamber <chamber-id>. Wait for the Synthesizer (`chamber-synth-<NN>`) to message you. Pre-seeded drafts (Deep Probe + Phase D7 authz) are already in the debate.md — do NOT regenerate those hypotheses. Focus your creative modes on: (a) chaining pre-seeded findings with each other and across classes, (b) cross-mode combinations the systematic audits did not attempt, (c) attack classes that require lateral thinking rather than systematic enumeration (supply chain, creative business-logic combinations, auth+state chained escalations, state/concurrency and spec-compliance gaps no longer covered by a dedicated phase), and (d) **cross-service taint** when the Synthesizer supplied `cross-service-edges.json` edges: for each edge, reason about boundary-sanitization gaps, transitive-trust / false-trust markers, write-driven injection through shared storage, queue-message deserialization without source authentication, cross-service SSRF via URL propagation, event replay across the boundary, and internal-only endpoints reachable externally. Then generate hypotheses and write to debate.md."

> **Code Tracer**:
> `subagent_type: "vigolium-audit:flow-tracer"`, `name: "tracer-<NN>"`
> Prompt: "You are the Code Tracer for Review Chamber <chamber-id>. Wait for the Synthesizer (`chamber-synth-<NN>`) to message you. For hypotheses that have Deep Probe pre-traced evidence (noted in debate.md), extend and verify that evidence rather than re-tracing from scratch. For cross-service hypotheses, trace producer→channel→consumer using the supplied `cross-service-edges.json` and confirm whether either end re-validates. **Inline variant expansion**: for every hypothesis you confirm VALID, run a same-pattern search across the codebase — registry `detection_signature` (from `vigolium-results/attack-pattern-registry.json`), structural/AST and grep search for the same source→sink shape in sibling components, alternate transports, and background consumers. File each confirmed Medium+ variant as its own draft in this chamber's NNN namespace (`vigolium-results/findings-draft/p10-<NNN>-<slug>.md`) with `Origin-Finding:` and `Origin-Pattern:` set in frontmatter, and append the variant to the matching `vigolium-results/attack-pattern-registry.json` pattern's `confirmed_instances`. Then write evidence to debate.md."

> **Devil's Advocate**:
> `subagent_type: "vigolium-audit:red-challenger"`, `name: "advocate-<NN>"`
> Prompt: "You are the Devil's Advocate for Review Chamber <chamber-id>. Wait for the Synthesizer (`chamber-synth-<NN>`) to message you. Then write defense briefs to debate.md."

Run the chamber in staged rounds:
- Round 1: spawn `chamber-synth-<NN>` and `ideator-<NN>` with `run_in_background: true`; wait for ideation to finish
- Round 2: keep `chamber-synth-<NN>` active and spawn `tracer-<NN>` with `run_in_background: true`; wait for tracing + inline variant search to finish
- Round 3: keep `chamber-synth-<NN>` active and spawn `advocate-<NN>` with `run_in_background: true`; wait for challenge to finish
- Optional follow-up: if the synthesizer requests another tracer or advocate pass, run that helper in a new single-helper round

Do **not** run multiple chambers concurrently in burst-capped deep mode. Variant
expansion is inline — the Code Tracer runs a same-pattern search on every VALID
finding (see Tracer prompt); there is no separate variant phase and no
`vigolium-audit:variant-spotter` / `vigolium-audit:variant-scanner` spawn in deep mode.
Cross-service taint reasoning is likewise inline (Ideator + Tracer over
`cross-service-edges.json`); there is no `vigolium-audit:taint-tracer` spawn.

6. **Monitor chambers**: read `vigolium-results/attack-pattern-registry.json` periodically. When a chamber closes, it messages you.
7. Wait for ALL chambers to close.
8. Write `## Phase 10 Addendum` to `vigolium-results/attack-surface/knowledge-base-report.md` (read all p10-*.md files for newly discovered attack surfaces). The literal section name `## Phase 10 Addendum` is a stable KB identifier downstream consumers key on — keep the name regardless of this phase's D-number.
9. **Inline FP Elimination** (the tail of Phase D8):

   **Stage 1 (fp-check):** apply the `fp-check` skill to all `vigolium-results/findings-draft/p10-*.md` files with `Verdict: VALID` (including the inline cross-service and variant drafts the chamber filed in the p10-* namespace). Write verdicts back into drafts. Prioritize findings with `Pre-FP-Flag` annotations.

   **Stage 2 (cold-verify, CRITICAL only):** for each **CRITICAL** finding still `VALID` after Stage 1, spawn `vigolium-audit:independent-verifier` in **batches of at most 3 background agents**. The prompt contains ONLY the finding draft file path — no debate transcript, no context. **HIGH and MEDIUM findings skip Stage 2** — the Devil's Advocate challenge in the chamber is sufficient for them; the cold pass is reserved for CRITICAL claims where a false positive is most costly. Wait for each independent-verifier batch before launching the next one.

   **Stage 3 (Triage Pass, cheap-tier model):** for every `vigolium-results/findings-draft/*.md` still `Verdict: VALID` after Stages 1 and 2 — including HIGH/MEDIUM findings the independent-verifier did not touch — spawn `vigolium-audit:finding-grader` in **batches of at most 3 background agents**. Each triager prompt contains ONLY the draft path. The triager runs on a cheaper model (Sonnet on Claude, defaults on others), reads only the draft (and optionally the sibling `adversarial-review.md` plus `vigolium-results/INFO.md` Known FP Sources), and writes `Triage-Priority` (P0/P1/P2/skip), `Triage-Exploitability`, `Triage-Impact`, and `Triage-Reasoning` back into the draft frontmatter. Do NOT invoke the triager on drafts already carrying a `Triage-Priority` line. Drafts marked `skip` are routed to `vigolium-results/findings-theoretical/` (as full finding directories) during Phase D10 consolidation; the remaining drafts feed Phase D10 PoC building in P0-first order. Wait for the triage batches to complete.
10. Mark T7 complete (chambers + inline taint + inline variant + inline FP elimination all done).

**Step 5: Intent Reconciliation (T8)**

Runs after the T7 FP/triage tail (so every VALID draft carries a `Triage-Priority`) and **before** PoC construction. The goal: reconcile each surviving finding against what the project documents as intentional design, an exposed feature, or an explicitly in-scope risk — so PoC effort is not spent on behavior the maintainers already declared by-design, and classes the project explicitly cares about are not deprioritized.

Spawn `vigolium-audit:context-reviewer` (foreground) with the following prompt:

> "AUDIT CONTRACT (deep D9). Target directory: <abs_target>. Findings drafts: vigolium-results/findings-draft/ (evaluate every `*.md` with `Verdict: VALID`). KB: vigolium-results/attack-surface/knowledge-base-report.md (read the `## Architecture Model`, `## Domain Attack Research`, `## Known False-Positive Sources` sections). Read `vigolium-results/INFO.md` `## Known False-Positive Sources` if present. For each VALID draft, do a bounded read of ONLY the `file:line` it cites, reconcile against documented intent, and write `Intent-Verdict` / `Intent-Source` / `Intent-Quote` into the draft frontmatter. For `intentional-design` or `documented-feature` whose decisive basis is `confidence: strong` (or operator INFO.md), reuse the triage skip channel: overwrite `Triage-Priority: skip` with a `Triage-Reasoning: context-reviewer: …` note. Do NOT touch `Verdict` or `Severity`. Write the corpus to vigolium-results/attack-surface/intent-corpus.json, per-finding verdicts to vigolium-results/attack-surface/intent-verdicts.json, and the human-readable report to vigolium-results/attack-surface/intent-reconciliation.md."

**Failure policy: skip-and-continue.** If the agent fails, errors out, or produces no corpus, log the failure and proceed to Step 6 without intent routing. The absence of `intent-corpus.json` must NOT suppress any finding — every VALID draft keeps the `Triage-Priority` the Step 4 triage pass assigned. Strongly-intentional drafts routed via `Triage-Priority: skip` are consolidated into `vigolium-results/findings-theoretical/` in Phase D10 (full report, kept out of the Summary table, reversible).

Mark T8 (phase `D9`) complete (or `failed` with `policy: skip-and-continue` recorded).

**Step 6: PoC Construction (T9)**

**Finding consolidation**: Run the consolidation helper — it reads every draft in `vigolium-results/findings-draft/`, keeps the `Verdict: VALID` drafts with `Severity-Original` in {CRITICAL, HIGH, MEDIUM}, assigns deterministic severity-prefixed IDs (`C1`, `H1`, `M1`, …) from one global namespace, and materialises each as a directory (`evidence/`, `draft.md`, `adversarial-review.md`, `debate.md`, `metadata.json` for variants). Drafts the triager — or Phase D9 Intent Reconciliation — marked `Triage-Priority: skip` go straight to `vigolium-results/findings-theoretical/<ID>-<slug>/`; all others go to `vigolium-results/findings/<ID>-<slug>/`.

```bash
python3 ~/.config/vigolium-audit/skills/audit/scripts/consolidate_drafts.py vigolium-results
```

The script writes `vigolium-results/findings-draft/consolidation-manifest.json` (and prints it) with three arrays: `findings` (actionable → poc-author), `theoretical` (triage-skipped / intent-skipped → reporter only, no PoC), and `dropped`. Exit non-zero means **nothing** was promoted (no actionable AND no theoretical) — STOP and report. Exit zero with an empty `findings` array but a non-empty `theoretical` array is normal (everything was triage-skipped): skip PoC building and partition, and proceed straight to finalization over the theoretical bucket.

Read the manifest. For each entry in its `findings` array, spawn `vigolium-audit:poc-author` in **batches of at most 3 background agents**. Each poc-author receives the entry's `draft_path` and its `id`, and writes `PoC-Status` back into the finding's `draft.md`.

Wait for each PoC-builder batch before launching the next one.

**Confirmed/theoretical partition**: after every poc-author completes, run the routing helper. It demotes any `vigolium-results/findings/<ID>-<slug>/` whose `draft.md` did not reach `PoC-Status: executed` into `vigolium-results/findings-theoretical/` (IDs unchanged), so `vigolium-results/findings/` ends up holding only confirmed, PoC-executed findings:

```bash
python3 ~/.config/vigolium-audit/skills/audit/scripts/partition_findings.py vigolium-results
```

It is idempotent and a no-op when there were no PoC builds. Mark T9 complete. poc-author is explicitly NOT responsible for writing `report.md` — that is Phase D11 below.

**Step 7: Finding Finalization (T10)**

After every poc-author completes, fan out `vigolium-audit:finding-writer` in **batches of at most 3 background agents** to author `report.md` from cold context. This is the structural fix that prevents `report.md` from being starved by heavyweight PoC work.

1. Enumerate every finding directory across **both** buckets: `vigolium-results/findings/*/` AND `vigolium-results/findings-theoretical/*/` (`C*-*`, `H*-*`, `M*-*`).
2. For each directory, spawn `vigolium-audit:finding-writer` with `run_in_background: true` in capped batches of 3. The prompt contains ONLY the finding directory path — no chamber context, no KB. Finding Reporter reads draft / debate / adversarial-review / poc / evidence from the folder and writes the nine-section `report.md` in place. Theoretical-bucket folders get the same report (the `Proof of concept & Evidence` section states the no-PoC reason).
3. Wait for each reporter batch before launching the next one.
4. **Phase gate (MANDATORY)**: enumerate `vigolium-results/findings/*/report.md` AND `vigolium-results/findings-theoretical/*/report.md`. For every finding directory in both buckets, assert `report.md` exists and is larger than 500 bytes. If any are missing or truncated:
   - Respawn `vigolium-audit:finding-writer` ONCE for the missing/truncated folders.
   - If any are still missing after the retry, STOP. Report the list of incomplete findings to the user and do NOT proceed to Step 8. The audit is not complete without report.md.

Mark T10 complete only when every finding directory in both buckets has a non-empty `report.md`.

**Step 8: Final Report Assembly (T11)**

Spawn `vigolium-audit:report-composer` (foreground) to produce `vigolium-results/final-audit-report.md`. By Phase D11's gate, every per-finding `report.md` (in both `vigolium-results/findings/` and `vigolium-results/findings-theoretical/`) is guaranteed to exist, so the assembler inlines each finding's sections. Confirmed findings populate the main report; theoretical findings go in the dedicated Theoretical / Unconfirmed Findings section and are kept out of the Summary-of-Findings table. Surface the Intent Reconciliation summary from `vigolium-results/attack-surface/intent-reconciliation.md` (if present).

**No-git disclaimer (CRITICAL)**: Before spawning the report assembler, check `audits[-1].history_available` in `vigolium-results/audit-state.json`. If it is `false`, append the following instruction to the assembler's prompt:

> "history_available is false: add an Executive Summary note explaining that commit archaeology (Phase D1/D2), local patch-bypass analysis (Phase D3), and git-derived advisory enrichment (Phase D1/D2 cve-scout Source 1 + Section 5 patch-commit discovery) were skipped because the target has no Git history. Recommend re-running on a git checkout for full coverage. Also surface any `Coverage gaps recorded` from cve-scout's Historical coverage metadata."

**File-state stamp (incremental basis)**: Before cleanup, stamp `vigolium-results/file-state.json` so the next audit can compute an incremental scope (changed/new/deleted files) against this run. This adds nothing to the user-facing report — it just persists per-file hashes and the audit IDs that touched each file.

```bash
python3 ~/.config/vigolium-audit/skills/audit/scripts/stamp_file_state.py --target . 2>&1
```

The script reads `vigolium-results/audit-state.json` to detect the current audit_id and phase set, walks the target tree (excluding `vigolium-results/`, `node_modules/`, `vendor/`, etc.), sha-256 hashes every text-readable source file under ~512 KB, and merges the result into `vigolium-results/file-state.json`. If it errors, log the failure but DO NOT fail the audit — the report is the deliverable.

**Post-audit cleanup**: After report-composer completes and reports consistency checks passed, delete intermediate working artifacts:
```bash
rm -rf vigolium-results/findings-draft/
rm -rf vigolium-results/adversarial-reviews/
rm -rf vigolium-results/probe-workspace/
rm -rf vigolium-results/chamber-workspace/
rm -rf vigolium-results/codeql-artifacts/
rm -rf vigolium-results/codeql-queries/
rm -rf vigolium-results/semgrep-rules/
rm -rf vigolium-results/semgrep-res/
rm -f vigolium-results/attack-pattern-registry.json
```
Retained: `vigolium-results/audit-state.json`, `vigolium-results/file-state.json`, `vigolium-results/INFO.md` (if present), `vigolium-results/attack-surface/knowledge-base-report.md`, `vigolium-results/attack-surface/cross-service-edges.{json,md}` (if multi-service), `vigolium-results/attack-surface/intent-corpus.json`, `vigolium-results/attack-surface/intent-reconciliation.md`, `vigolium-results/findings/`, `vigolium-results/findings-theoretical/` (if present), `vigolium-results/final-audit-report.md`. If consistency checks failed, skip cleanup and report the failures to the user first.

Mark T11 complete (`audits[-1].phases["D12"].status = "complete"`). Update `audits[-1].completed_at` and `audits[-1].status` to `complete`. Print post-audit summary.

### Lead Responsibilities

1. **Do not perform audit work.** Your role is coordination only.
2. Monitor via task completions and incoming agent messages.
3. If an agent fails, check `vigolium-results/findings-draft/` for partial output. Spawn replacement with remaining work only.
4. For chamber failures: only the failed chamber needs respawning. Other chambers' findings are on disk.
5. If a probe team fails, read its workspace for partial summaries and pass whatever results exist to Phase D8 chambers.
6. If Intent Reconciliation (Phase D9) fails, proceed to Step 6 without intent routing — it is best-effort and never blocks the pipeline.

---

## Solo Mode (Fallback)

Use when the target scope is a single file or fewer than ~20 files. Execute all 12 phases sequentially. Even in solo mode, never exceed **3 simultaneous background agents**. Update `vigolium-results/audit-state.json` after each phase completes (status: `complete` with timestamp) or fails (status: `failed` with error).

Phases D1-D5 **must** use the `Agent` tool with the registered `subagent_type` below. Provide phase context in the `prompt` field: target scope, state file path, and prior phase outputs.

| Phase | `subagent_type` |
|-------|-----------------|
| 1 -- Intelligence Gathering | Always `vigolium-audit:cve-scout`. Add `vigolium-audit:history-miner` only when `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`. |
| 2 -- Patch Bypass Analysis | `vigolium-audit:patch-auditor` when Git history or patch metadata exists; otherwise mark the phase skipped in the KB and continue. |
| 3 -- Knowledge Base | `vigolium-audit:threat-modeler` (must emit `Multi-service: true|false` in `## Architecture Model`) |
| 4 -- Static Analysis | `vigolium-audit:code-scanner` (also enumerates `cross-service-edges.json` when `Multi-service: true`) |

Phase D6 (Deep Probe): Single probe team covering all components with attacker-controlled input. Run it in staged rounds so the team stays within the burst cap: `probe-lead-01` (writes attack surface map + code anatomy inline), then `goal-backtracer-01` + `assumption-breaker-01`, then `evidence-collector-01` (which also owns causal challenge).

Phase D7 (Authorization Audit): single `vigolium-audit:access-auditor` invocation.

Enrichment is handled inline by `vigolium-audit:code-scanner` in Phase D5 — no separate phase. Cross-service edge enumeration is also inline in Phase D5 (only when `Multi-service: true`). Cross-service taint reasoning and per-finding variant expansion are handled inline by the Phase D8 chamber (Ideator + Code Tracer) — no separate taint or variant phase. State/concurrency and spec-compliance no longer have dedicated phases; the Review Chamber Ideator covers those classes per its prompt.

Phase D8 (Review Chamber + Inline Taint/Variant + FP Elimination): In solo mode, spawn a single chamber, but run it in staged rounds so the chamber never exceeds 2 live helper roles at once. Use the same chamber protocol as Swarm Mode but with one chamber covering all DFD slices (and, when present, all `cross-service-edges.json` edges). NNN range: p10-001 to p10-049. Include all Deep Probe validated hypotheses AND all Phase D7 drafts (`vigolium-results/findings-draft/p6-*.md`) as pre-seeded drafts in the Ideator prompt — instruct the Ideator to chain and extend them rather than regenerating, to add cross-service taint hypotheses for any supplied edges, and instruct the Code Tracer to run an inline same-pattern variant search on every VALID finding (filing variant drafts in the p10-* namespace with `Origin-Finding:`/`Origin-Pattern:` frontmatter). After the chamber closes, run the inline FP elimination tail (Stage 1 fp-check; Stage 2 cold-verify CRITICAL only, batched ≤3; Stage 3 triage pass, batched ≤3) exactly as in Swarm Step 4, then mark phase `D8` complete.

Phase D9 (Intent Reconciliation): single `vigolium-audit:context-reviewer` invocation (foreground), AUDIT CONTRACT, dispatched after Phase D8's FP/triage tail. Reconciles every VALID draft against documented intent; reuses the `Triage-Priority: skip` channel for strongly-intentional findings. Skip-and-continue — never blocks the pipeline. Mark phase `D9` complete (or `failed` with `policy: skip-and-continue`).

Phase D10 (PoC Construction): run the consolidation helper (`python3 ~/.config/vigolium-audit/skills/audit/scripts/consolidate_drafts.py vigolium-results`) — it materialises finding directories, routing triage-skipped / intent-skipped ones to `vigolium-results/findings-theoretical/` and the rest to `vigolium-results/findings/`. If it exits non-zero (nothing promoted at all), stop and report. Otherwise read `vigolium-results/findings-draft/consolidation-manifest.json` and for each entry in its `findings` array spawn `vigolium-audit:poc-author` in batches of at most 3 with `run_in_background: true` (passing the entry's `draft_path` and `id`). Wait for each batch, then run `python3 ~/.config/vigolium-audit/skills/audit/scripts/partition_findings.py vigolium-results` to demote any non-`executed` finding into `vigolium-results/findings-theoretical/`. Mark phase `D10` complete.

Phase D11 (Finding Finalization): for each directory under **both** `vigolium-results/findings/` and `vigolium-results/findings-theoretical/`, spawn `vigolium-audit:finding-writer` in batches of at most 3 with `run_in_background: true`. Prompt contains ONLY the finding directory path. Wait for each batch. Enumerate `vigolium-results/findings/*/report.md` AND `vigolium-results/findings-theoretical/*/report.md` and verify each exists and is larger than 500 bytes — retry once for missing/truncated folders, then STOP if any remain incomplete. Mark phase `D11` complete only when every finding directory in both buckets has a non-empty `report.md`.

Phase D12 (Final Report): spawn `vigolium-audit:report-composer` (foreground). When `audits[-1].history_available` is `false`, append the no-git disclaimer instruction to the assembler prompt (same wording as Swarm Step 8). After report assembly, run post-audit cleanup (same as Swarm Mode). Mark phase `D12` complete.

**Burst-capped scheduling in solo mode**:
- After Phase D4: run Phase D5 (`vigolium-audit:code-scanner`) and Phase D7 (`vigolium-audit:access-auditor`) together as a 2-agent batch.
- Then run Phase D6 (single probe team).
- Phase D3: `vigolium-audit:patch-auditor` per patch in batches of at most 3 only when `VIGOLIUM_AUDIT_GIT_AVAILABLE=true`.
- Phase D8 inline FP Stage 2: cold verifiers (CRITICAL only) in batches of at most 3.
- Phase D9: single `vigolium-audit:context-reviewer` (foreground); skip-and-continue.
- Phase D10: PoC builders in batches of at most 3.
- Phase D11: finding reporters in batches of at most 3.

**Phase sequence**:
```
D1/D2 -> D3 (per-patch batched, max 3) -> D4 -> [D5 (incl. inline enrichment + multi-service edge enumeration) + D7] -> D6 -> D8 (staged single chamber + inline cross-service taint + inline variant search + inline FP: fp-check, CRITICAL-only cold-verify, triage) -> D9 (Intent Reconciliation; skip-and-continue) -> D10 (consolidate -> PoC batched, max 3 -> partition confirmed/theoretical) -> D11 (Finalize batched over BOTH findings/ + findings-theoretical/, max 3; GATE: every report.md present in both) -> D12 (Final report assembly)
```

After Phase D12, set `audits[-1].completed_at` to current timestamp and `audits[-1].status` to `complete`.

---

## Single Phase Execution

When `$ARGUMENTS` is a phase identifier (one of: D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11, D12):

1. If no `vigolium-results/audit-state.json` exists, create one with all phases `pending` and run setup first.
2. Verify prerequisites — check that all required earlier phases are `complete` in the state file:
   - Phase D3 requires D1/D2 / Phase D4 requires D3 / Phase D5 requires D4 / Phase D6 requires D4
   - Phase D7 requires D4 / Phase D8 requires D5, D6, D7 (Phase D5 enrichment + multi-service edge enumeration run inline)
   - Phase D9 requires D8 / Phase D10 requires D9 / Phase D11 requires D10 / Phase D12 requires D11
   - If prerequisites are incomplete, ask the user whether to run all missing prerequisites first or cancel.
3. Set the phase status to `in_progress` with a start timestamp.
4. Execute only that phase per the phase map below.
5. On success: set status to `complete` with end timestamp. On failure: set `failed` with error.

| Phase | Name | Agent / Execution |
|-------|------|-------------------|
| D1/D2 | Intelligence Pass | Always `vigolium-audit:cve-scout`; add `vigolium-audit:history-miner` only when `VIGOLIUM_AUDIT_GIT_AVAILABLE=true` |
| D3 | Patch Audit | `vigolium-audit:patch-auditor` (batched up to 3 at a time with `run_in_background: true`) only when local patch history exists; otherwise record a skipped/no-history result and continue |
| D4 | Threat Model | `vigolium-audit:threat-modeler` — must emit `Multi-service: true|false` in `## Architecture Model` |
| D5 | Code Scan (+ inline enrichment + multi-service edge enumeration) | `vigolium-audit:code-scanner` — runs SAST, classifies candidates for security relevance in the same pass, and writes `cross-service-edges.json` when the project is multi-service |
| D6 | Deep Probe | Probe teams processed in staged rounds: `vigolium-audit:probe-lead` + `vigolium-audit:goal-backtracer` + `vigolium-audit:assumption-breaker`, then `vigolium-audit:evidence-collector` (one team per component group; strategist authors Code Anatomy inline, harvester owns causal challenge) |
| D7 | Access Audit | `vigolium-audit:access-auditor` (single agent) |
| D8 | Review Panel + Inline Taint/Variant + FP Elimination | Chamber staged rounds: `vigolium-audit:review-adjudicator` + `vigolium-audit:attack-designer` (Ideator also reasons cross-service taint over `cross-service-edges.json`), then `vigolium-audit:flow-tracer` (Code Tracer also runs the inline same-pattern variant search), then `vigolium-audit:red-challenger`; then inline FP tail — Stage 1 fp-check, Stage 2 `vigolium-audit:independent-verifier` CRITICAL only (batched ≤3), Stage 3 `vigolium-audit:finding-grader` (batched ≤3) |
| D9 | Intent Reconciliation | `vigolium-audit:context-reviewer` (single agent, AUDIT CONTRACT; reconciles VALID drafts against documented intent, reuses `Triage-Priority: skip`; skip-and-continue) |
| D10 | PoC Authoring | consolidate (routes triage-skip / intent-skip → `findings-theoretical/`) → `vigolium-audit:poc-author` per finding (batched ≤3) → `partition_findings.py` (demote non-`executed` → `findings-theoretical/`) |
| D11 | Finding Finalize | `vigolium-audit:finding-writer` per finding over BOTH `vigolium-results/findings/` and `vigolium-results/findings-theoretical/` (batched ≤3) — authors nine-section `report.md`; gate: every finding in both buckets has non-empty `report.md` |
| D12 | Report Compose | `vigolium-audit:report-composer` — produces `vigolium-results/final-audit-report.md` |

---

## Resume Logic

Read `audits[-1].phases` from `vigolium-results/audit-state.json` to find phase statuses. Walk phases in **burst-capped execution order** — this is the schedule order, not the id order, so phase `D7` is visited before `D6` (the authz audit shares Wave A with the code scan, while Deep Probe gets its own wave). Ids are contiguous `D1`–`D12`; the historical cross-service taint and variant-search phases were removed and their work folded into `D5` (edge enumeration when multi-service) and `D8` (chamber Ideator taint reasoning + Code Tracer variant expansion):

```
D1/D2 → D3 → D4 → [D5 + D7]  → D6  → D8 → D9 → D10 → D11 → D12
linear chain        Wave A       Wave B   (D9 = Intent
                    (2 agents,   (Deep      Reconciliation,
                     parallel)    Probe)    skip-and-continue,
                                            foreground)
```

`[D5 + D7]` is one wave: the code scan (plus multi-service edge enumeration) and the access audit run together (2 agents, within the cap). Deep Probe (`D6`) runs in its own wave afterward because a single probe team already uses the full 3-agent burst. On resume, re-doing the light Wave A phases before re-entering the heavy Deep Probe is intentional.

Find the earliest-ordered phase (per the schedule above: `D1, D2, D3, D4, D5, D7, D6, D8, D9, D10, D11, D12`) with status `pending`, `in_progress`, or `failed`:

- `failed` or `in_progress`: check whether the expected KB sections or output artifacts exist and appear complete. Artifact gates:
  - D5 complete if the KB has `## Static Analysis Summary`, `## CodeQL Structural Analysis`, and `## SAST Enrichment`; AND, when the KB `## Architecture Model` marks `Multi-service: true`, `vigolium-results/attack-surface/cross-service-edges.json` exists (single-service projects require no such artifact)
  - D7 complete if `vigolium-results/attack-surface/authz-matrix.md` exists OR the KB has `## Authorization Audit` with an explicit skip note
  - D8 complete if the KB has a `## Phase 10 Addendum` section AND every `Verdict: VALID` draft under `vigolium-results/findings-draft/` carries a `Triage-Priority` line (the inline taint, variant, and FP tail ran)
  - D9 complete if `vigolium-results/attack-surface/intent-corpus.json` exists (empty arrays acceptable) OR the phase was recorded `failed` under `policy: skip-and-continue` (Intent Reconciliation is best-effort and never blocks)
  - D10 complete if `vigolium-results/findings-draft/partition-manifest.json` exists (PoC + partition ran) — or the consolidation manifest had an empty `findings` array (all theoretical, nothing to PoC)
  - D11 complete if every directory under `vigolium-results/findings/` AND `vigolium-results/findings-theoretical/` has a non-empty `report.md` (>500 bytes)
  - D12 complete if `vigolium-results/final-audit-report.md` exists and references at least the finding IDs currently in `vigolium-results/findings/` and `vigolium-results/findings-theoretical/`

  If so, mark `complete` and advance. Otherwise delete the partial output and re-run.
- `pending`: run normally.

Continue through Phase D12 using the phase map above.
