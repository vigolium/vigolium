# Vigolium-Audit Phase Reference

This document describes the implemented `vigolium-audit run --mode <mode>` commands,
what each phase does, and the main files each phase writes. All output paths
are relative to the target repository directory.

The package name is Vigolium-Audit. When invoked interactively (`vigolium-audit run -i`),
phases surface as Claude Code slash commands in the form `/vigolium-audit:<mode>` and
sub-agents in the form `vigolium-audit:<agent>`.

The canonical phase graph for each mode lives in
[`src/content/command-defs/<mode>.md`](../src/content/command-defs/) — the
engine has no hardcoded phase ids and reads them from YAML frontmatter at run
time.

## Common outputs

Most audit modes write these shared artifacts:

| Path | Purpose |
| --- | --- |
| `vigolium-results/audit-state.json` | Resumable run state, phase status, retry metadata, repository identity, model + agent SDK, and completion status. |
| `vigolium-results/file-state.json` | Per-source-file scan record (SHA-256, last audits, last phases). Backs `/vigolium-audit:diff`. |
| `vigolium-results/attack-surface/` | Durable audit context: recon, KB, SAST summaries, probe summaries, authz/concurrency/spec audits, cross-service edges. |
| `vigolium-results/attack-surface/knowledge-base-report.md` | Central KB document. Many phases append in-place sections rather than creating new files. |
| `vigolium-results/findings-draft/` | Candidate findings before promotion into final finding directories. |
| `vigolium-results/findings/<ID>-<slug>/` | Finalized findings with `draft.md`, `poc.*`, `evidence/`, `report.md`. |
| `vigolium-results/final-audit-report.md` | Consolidated final audit report (balanced, deep, revisit, merge). |
| `vigolium-results/confirm-workspace/` | Confirmation inputs, live-run results, cleanup state. |

See [output-structure.md](output-structure.md) for the full directory layout
and per-file descriptions.

## Modes without audit phases

| Mode | Usage | What it does | Outputs |
| --- | --- | --- | --- |
| `status` | `vigolium-audit run --mode status` | Prints current audit progress for the target directory. Read-only. | Displays `vigolium-results/audit-state.json` metadata, phase status, finding counts, and disk usage. |

## `vigolium-audit run --mode lite`

Usage: `vigolium-audit run --mode lite [--target <path>]`

Phase count: 3 (`L1`-`L3`)

Lite is a super-quick surface scan answering one question: "what would blow
up if this shipped right now?" It supports plain source folders with no `.git`
directory. L2 and L3 declare `parallel_with` against each other; the v1
engine still walks them sequentially but the dependency graph permits future
parallelization.

PoC building and severity-prefixed promotion happen inside the inline command
body during/after L3 — they're not separate orchestrator phases. Output paths
match the deeper modes so lite findings work with `/vigolium-audit:diff` and the merge
mode.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `L1` | Recon Pass | (inline) | Detects languages, frameworks, manifests, likely entry points, deployment model, git state, and scan exclusions. | `vigolium-results/attack-surface/lite-recon.md` |
| `L2` | Secrets Scan | (inline) | Hardcoded keys, tokens, passwords, credentials via trufflehog/gitleaks (filesystem mode) or pattern fallback. Runs parallel-eligible with L3. | `vigolium-results/findings-draft/l2-<NNN>-<slug>.md` |
| `L3` | Fast Code Scan | (inline) | Single high-signal pass scoped by L1 (prefer `semgrep scan --config auto`, fall back to CodeQL or manual patterns). Promotes survivors to severity-prefixed `findings/<C\|H\|M><N>-<slug>/` and dispatches `poc-author` per finding. Runs parallel-eligible with L2. | `vigolium-results/findings-draft/l3-<NNN>-<slug>.md`; `vigolium-results/findings-draft/consolidation-manifest.json`; `vigolium-results/findings/<id>-<slug>/draft.md`; `vigolium-results/findings/<id>-<slug>/poc.<ext>` (or `poc.theoretical.md`); `vigolium-results/findings/<id>-<slug>/evidence/` |

## `vigolium-audit run --mode balanced`

Usage: `vigolium-audit run --mode balanced [--target <path>]`

Phase count: 9 (`B1`-`B9`)

Balanced trades depth for speed while keeping the core false-positive
elimination loop. It produces the same output format as `deep` so findings
are compatible with `diff` and `status`. Phases B3 and B4 declare
`parallel_with` against each other.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `B1` | Intelligence Pass | `cve-scout` | Published advisory hunt + dependency intelligence. | `## Advisory Intelligence` section appended to `vigolium-results/attack-surface/knowledge-base-report.md` |
| `B2` | Threat Model | `threat-modeler` | Project type, trust boundaries, DFD/CFD slices, attack surface, threat model, coverage gaps, known false-positive sources. | `vigolium-results/attack-surface/knowledge-base-report.md` (creates the file with all phase-B2 sections) |
| `B3` | Code Scan | `code-scanner` | Built-in CodeQL suites + Semgrep Pro with inline SAST enrichment. Skips custom queries and structural extraction (deep-only). Parallel-eligible with `B4`. | `vigolium-results/codeql-artifacts/`; `vigolium-results/findings-draft/p4-<NNN>-<slug>.md` |
| `B4` | Targeted Probe | `probe-lead` | 3-agent single-round probe (Strategist, Backward Reasoner, Evidence Harvester). Parallel-eligible with `B3`. | `vigolium-results/probe-workspace/<component>/`; `vigolium-results/findings-draft/p8-<NNN>-<slug>.md` |
| `B5` | Review Panel + FP Check | `review-adjudicator` | 3-agent chamber (Synthesizer, Attack Ideator, Devil's Advocate), max 2 debate rounds. Promotes valid drafts into severity-prefixed `findings/<id>-<slug>/`. | `vigolium-results/chamber-workspace/balanced-chamber/debate.md`; `vigolium-results/findings-draft/p10-<NNN>-<slug>.md`; `vigolium-results/findings/<id>-<slug>/draft.md` |
| `B6` | Intent Reconciliation | `context-reviewer` | Reconciles every VALID draft against documented intent (SECURITY.md/README/docs/ADRs/inline pragmas + KB Architecture Model + each finding's cited code). Soft-routes strongly-documented-intentional findings to the theoretical bucket via `Triage-Priority: skip`. Skip-and-continue. | `vigolium-results/attack-surface/intent-corpus.json`; `vigolium-results/attack-surface/intent-verdicts.json`; `vigolium-results/attack-surface/intent-reconciliation.md`; `Intent-Verdict` annotations on drafts |
| `B7` | PoC Authoring | `poc-author` | Builds executable PoC + evidence per promoted finding; drops Low severity. | `vigolium-results/findings/<id>-<slug>/poc.<ext>` (or `poc.theoretical.md`); `vigolium-results/findings/<id>-<slug>/evidence/` |
| `B8` | Finding Finalize | `finding-writer` | Authors `report.md` per finding from cold context. Mandatory non-empty gate before phase B9. | `vigolium-results/findings/<id>-<slug>/report.md` |
| `B9` | Report Compose | `report-composer` | Compiles consolidated report with the balanced-audit disclaimer. | `vigolium-results/final-audit-report.md` |

## `vigolium-audit run --mode deep`

Usage: `vigolium-audit run --mode deep [--target <path>]`

Phase count: 12 (`D1`-`D12`)

Deep is the full pipeline. The Intelligence Pass splits into parallel-eligible
halves (`D1` CVE/advisory + `D2` commit archaeology); the remaining ids are
contiguous `D1`–`D12`. State/concurrency and spec-compliance no longer have
dedicated phases — that work is folded into the `D8` Review Panel. The former
standalone Cross-Service Taint and Variant Search phases were also folded: cross-service
edge enumeration is now part of `D5` (multi-service projects only), and both
cross-service taint reasoning and per-finding variant expansion run inside the `D8`
Review Chamber (Ideator + Code Tracer). FP elimination runs as the inline tail of
`D8`; `D9` Intent Reconciliation runs between the Review Panel and PoC Authoring.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `D1` | Intelligence Pass (CVE) | `cve-scout` | Public advisory + dependency intelligence. Parallel-eligible with `D2`. | `## Advisory Intelligence` section in `vigolium-results/attack-surface/knowledge-base-report.md` |
| `D2` | Intelligence Pass (History) | `history-miner` | Security-relevant git history: high-risk patches, sneaky reverts, half-fixed advisories. Skips when `requires_git: true` is unmet. Parallel-eligible with `D1`. | `vigolium-results/attack-surface/commit-recon-report.md`; `## Commit Archaeology` section in KB |
| `D3` | Patch Audit | `patch-auditor` | Per-advisory bypass review fan-out. Skips without git history. | `vigolium-results/bypass-analysis/<advisory-id>-bypass.md`; `## Bypass Analysis` section in KB |
| `D4` | Threat Model | `threat-modeler` | Architecture model (incl. the `Multi-service: true|false` marker), trust boundaries, DFD/CFD slices, attack surface, domain attack research, spec gap candidates, known FP sources. | `vigolium-results/attack-surface/knowledge-base-report.md` |
| `D5` | Code Scan | `code-scanner` | CodeQL build + custom queries + Semgrep Pro + structural extraction + inline SAST enrichment. When `Multi-service: true`, also enumerates the inter-service edge graph (folded former Cross-Service Taint Step 1–2). | `vigolium-results/codeql-artifacts/db/`, `entry-points.json`, `sinks.json`, `call-graph-slices.json`, `flow-paths-raw.sarif`; `vigolium-results/attack-surface/cross-service-edges.{json,md}` (multi-service only); `vigolium-results/findings-draft/p4-<NNN>-<slug>.md` |
| `D6` | Deep Probe | `probe-lead` | Multi-team probe in staged rounds (Strategist authors code anatomy inline, Backward + Contradiction reasoners, Evidence Harvester owns causal challenge). | `vigolium-results/probe-workspace/<component>/attack-surface-map.md`, `code-anatomy.md`, `probe-summary.md` |
| `D7` | Access Audit | `access-auditor` | Enumerates public routes/operations and records expected vs. actual auth checks per endpoint. | `vigolium-results/attack-surface/authz-matrix.md`; `vigolium-results/attack-surface/authz-coverage-gaps.md`; `vigolium-results/findings-draft/p6-<NNN>-<slug>.md`; `## Authorization Audit` section in KB |
| `D8` | Review Panel | `review-adjudicator` | Clusters drafts, runs chambers (Synthesizer/Attack Ideator/Code Tracer/Devil's Advocate). The Ideator also reasons cross-service taint over `cross-service-edges.json` (folded Cross-Service Taint Step 3–4); the Code Tracer runs an inline same-pattern variant search on every VALID finding (folded Variant Search). Covers state/concurrency + spec-compliance classes. Then the inline FP-elimination tail (fp-check, CRITICAL-only cold-verify via `independent-verifier`, triage pass). | `vigolium-results/chamber-workspace/<chamber-id>/debate.md`; `vigolium-results/findings-draft/p10-<NNN>-<slug>.md` (incl. cross-service + variant drafts with `Origin-Finding:`/`Origin-Pattern:`); `vigolium-results/adversarial-reviews/<slug>-review.md`; `vigolium-results/findings/<id>-<slug>/draft.md`; `## Phase 10 Addendum` section in KB |
| `D9` | Intent Reconciliation | `context-reviewer` | Reconciles every VALID draft against documented intent (SECURITY.md/README/docs/ADRs/inline pragmas + KB Architecture Model + each finding's cited code). Soft-routes strongly-documented-intentional findings to the theoretical bucket via `Triage-Priority: skip`; flags `acknowledged_risks` as `contested` so in-scope classes are not deprioritized. Skip-and-continue. | `vigolium-results/attack-surface/intent-corpus.json`; `vigolium-results/attack-surface/intent-verdicts.json`; `vigolium-results/attack-surface/intent-reconciliation.md`; `Intent-Verdict` annotations on drafts |
| `D10` | PoC Authoring | `poc-author` | Builds executable PoC + evidence for each finalized finding. | `vigolium-results/findings/<id>-<slug>/poc.<ext>` (or `poc.theoretical.md`); `vigolium-results/findings/<id>-<slug>/evidence/` |
| `D11` | Finding Finalize | `finding-writer` | Per-finding disclosure-style report from cold context. | `vigolium-results/findings/<id>-<slug>/report.md` |
| `D12` | Report Compose | `report-composer` | Verifies every finding has a report and writes the consolidated audit report with the deep-mode methodology block. | `vigolium-results/final-audit-report.md` |

## `vigolium-audit run --mode confirm`

Usage: `vigolium-audit run --mode confirm [--from-audit <id>] [--target <url>]`

Phase count: 7 (`V1`, `V1.5`, `V2`-`V6`)

Confirm executes existing PoCs from BOTH `vigolium-results/findings/` and
`vigolium-results/findings-theoretical/` against a live target. Theoretical
findings without PoCs are routed to generated-test fallback instead of being
ignored. When a remote URL is supplied via `--target https://…`, V2 and V3 are
skipped and the URL is treated as the already-running target. Remote mode
also skips local test fallback in V5 by default. `V1.5` (Intent Cross-Check)
runs `context-reviewer` under its strictly annotate-only confirm contract — it
records documented intent against findings but never changes a verdict, bucket,
or directory path and never causes V4/V5 to be skipped.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `V1` | Findings Inventory + Report Repair | (inline + `finding-writer` for missing reports) | Reads candidates from BOTH `vigolium-results/findings/*/` and `vigolium-results/findings-theoretical/*/`. Prefers `report.md`; if only `draft.md` exists, repairs by authoring `report.md`; classifies findings, extracts PoC paths, records `bucket`/`original_bucket`, sorts by severity. | `vigolium-results/confirm-workspace/findings-inventory.json`; repaired per-finding `report.md` when possible |
| `V1.5` | Intent Cross-Check | `context-reviewer` | Confirm contract: scans documented intent (SECURITY.md/README/docs/ADRs/inline pragmas), cross-checks each finding (bounded read of its cited code), annotates `report.md` with `Documented-Intent` fields. Strictly annotate-only — never changes severity/verdict/`Confirm-Status`, never skips V4/V5. Skip-and-continue. | `vigolium-results/confirm-workspace/intent-corpus.json`; `vigolium-results/confirm-workspace/intent-verdicts.json`; `Documented-Intent` annotations on `report.md` |
| `V2` | Environment Discovery | `env-profiler` | Discovers startup strategies, ports, env vars, datastores, migrations, test framework, optional auth scaffolding. | `vigolium-results/confirm-workspace/env-strategies.json`; `vigolium-results/confirm-workspace/auth-spec.json` (only when auth detected) |
| `V3` | Environment Provisioning | `env-builder` | Starts the target locally, applies migrations + seed data, snapshots datastores, seeds test identities, records connection details. | `vigolium-results/confirm-workspace/env-connection.json` (or `healthcheck-failure.log` on a bad boot); `app.pid`; `setup.log`/`migration.log`/`seed.log`; `db-snapshot.*` + `snapshot-spec.json` |
| `V4` | PoC Execution | `poc-runner` | Runs each finding's existing PoC against the target using the actual inventory `dir`, captures evidence, appends a confirmation block to its `report.md`. | `<inventory.dir>/confirm-evidence/`; updated `<inventory.dir>/report.md` |
| `V5` | Test-Based Fallback | `test-locator` | Generates and runs focused reproducer tests for not-reproduced / flaky / blocked / no-PoC / local-only findings, including theoretical findings without PoCs. | `<inventory.dir>/confirm-test.<ext>`; `<inventory.dir>/confirm-test-output.log`; updated `<inventory.dir>/report.md` |
| `V6` | Confirmation Report | `confirm-writer` | Compiles confirmation verdicts from `findings-inventory.json`, stages copies by verdict, preserves each entry's original bucket, and does not move verified theoretical findings automatically. | `vigolium-results/confirmation-report.md`; `vigolium-results/confirm-workspace/report-ready/`; `vigolium-results/confirm-workspace/needs-review/`; `vigolium-results/confirm-workspace/cleanup.log` |

## `vigolium-audit run --mode diff`

Usage: `vigolium-audit run --mode diff [--baseline <ref>]`

Phase count: 1 orchestrator phase, but it dispatches an arbitrary subset of
deep phases internally based on changed files.

Diff requires git history and a prior completed audit unless `--baseline` is
supplied. It exits early if there are no changed files, or if the only
changes are documentation/test files.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `1` | Diff-based Phase Selection | (inline) | Computes `git diff <baseline>..HEAD`, maps changed files to affected deep phases, re-runs each in order, updates the prior audit's phase timestamps in `audit-state.json`. | New entries under the same paths the underlying deep phases use (`findings-draft/diff-*.md`, `attack-surface/` updates, possibly `findings/<id>-<slug>/`); updated `vigolium-results/audit-state.json` |

The mapping the inline command applies:

| Change Type | Phases re-run |
| --- | --- |
| Core source code | `D5` (Code Scan), `D6` (Deep Probe) |
| Auth/security modules | `D4` (Threat Model), `D5`, `D6` |
| Dependencies (lockfiles, manifests) | `D1`/`D2` (Intelligence Pass), `D4`, `D5` |
| Workflow files (`.github/`) | `D5` (Code Scan — Actions audit) |
| Config files | `D5` (Code Scan — inline enrichment) |
| Documentation only | (none — exits early) |
| Test files only | (none — exits early) |

## `vigolium-audit run --mode revisit`

Usage: `vigolium-audit run --mode revisit [--target <path>]`

Phase count: 9 (`1`-`9`)

Revisit is an anti-anchored second/Nth pass on top of an existing
`vigolium-results/` directory. It reuses the round-1 KB, SAST output, and matrices but
redoes the reasoning-heavy phases with fresh sessions and prior-finding
negatives so a new model can surface what the original audit missed. State
lives in `vigolium-results/revisit-audit-state.json`; round-1 artifacts are preserved.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `1` | Deep Probe (fresh teams, anti-anchored) | `probe-lead` | Re-derives hypotheses from durable attack-surface context using prior findings as a negative list. | `vigolium-results/probe-workspace/<component>/` (revisit-tagged); `vigolium-results/findings-draft/r5-<NNN>-<slug>.md` |
| `2` | Enrichment Re-classify | (inline) | Anti-anchored review pass over prior SAST and durable context. | Updated draft verdicts |
| `3` | Review Chambers (fresh, anti-anchored) | `review-adjudicator` | Fresh chamber pass over current attack-surface slices with round-1 finding negatives. | `vigolium-results/chamber-workspace/r<N>-<cluster>/debate.md`; `vigolium-results/findings-draft/p10-<NNN>-<slug>.md` |
| `4` | FP Check | `independent-verifier` | Rechecks revisit-stage drafts and rejects weak findings. | Updated revisit drafts and finding directories; `vigolium-results/adversarial-reviews/<slug>-review.md` |
| `5` | Variant Analysis (new round findings) | `variant-scanner` | Searches for variants of the new revisit findings. | `vigolium-results/findings-draft/p12-<NNN>-<slug>.md` |
| `6` | Variant Analysis on Round-1 CRIT/HIGH | `variant-scanner` | Looks for adjacent variants of round-1 critical/high findings missed by prior passes. | `vigolium-results/findings-draft/p10k-<NNN>-<slug>.md` |
| `7` | PoC Construction (new findings only) | `poc-author` | Builds PoCs and evidence for revisit-stage findings only. | `vigolium-results/findings/<id>-<slug>/poc.<ext>` (or `poc.theoretical.md`); `vigolium-results/findings/<id>-<slug>/evidence/` |
| `8` | Finding Finalization | `finding-writer` | Authors `report.md` for revisit findings. | `vigolium-results/findings/<id>-<slug>/report.md` |
| `9` | Final Report Regeneration | `report-composer` | Regenerates the consolidated report with a "Discoveries by Round" section. | `vigolium-results/final-audit-report.md` (now with `## Discoveries by Round`) |

## `vigolium-audit run --mode reinvest`

Usage: `vigolium-audit run --mode reinvest --agent <other-platform> [<id-list>]`

Phase count: 3 (`1`-`3`)

Reinvest re-verifies CRITICAL and HIGH findings from a prior audit using a
DIFFERENT agent platform / model than the one that originally produced them
— surfacing model-specific blind spots. It does NOT re-run discovery, KB
construction, probe, chamber, or variant phases. Pre-flight uses
`AskUserQuestion` to confirm the user really wants a same-platform retry if
`--agent` matches the prior audit's `agent_sdk`.

The `<id-list>` is an optional comma-separated finding id list (`C1,H1,H3`)
to constrain scope; empty means every CRITICAL and HIGH finding under
`vigolium-results/findings/`.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `1` | Enumerate Findings | (inline) | Lists in-scope `C*-*` / `H*-*` directories, computes the next wave number per finding (`max(existing wave-*-verdict.md) + 1`), reads parent `audit_id`. | (no file output; populates an in-memory work list) |
| `2` | Fan Out Wave-Verifier | `cross-verifier` | One subagent per finding; each reads `report.md` cold and writes a verdict file. | `vigolium-results/findings/<id>-<slug>/wave-<N>-verdict.md` |
| `3` | Consensus Summary | (inline) | Aggregates wave verdicts and writes the cross-agent consensus / disagreement report. | `vigolium-results/reinvest-report.md`; updated `vigolium-results/audit-state.json` (`reinvests[]` block) |

## `vigolium-audit run --mode merge`

Usage: `vigolium-audit run --mode merge --dir <vigolium-audit-tree> --dir <vigolium-audit-tree> [...]`

Phase count: 7 (`M1`-`M7`)

Merge is invoked after the CLI's deterministic file-merge step
(`vigolium-audit merge`) has already combined two-or-more existing `vigolium-results/`
result trees into the current target. The mode handles the LLM-side work:
validating each finding, semantic dedup, auto-fixing safe issues,
quarantining unfixable ones, renumbering by severity, and writing
`vigolium-results/merge-report.md`.

Pre-flight verifies `vigolium-results/audit-state.json` contains a top-level
`merge_metadata` object that the CLI dropped during the file-merge step. It
also writes `vigolium-results/.merge-lock` with the current PID + timestamp; stale
locks are reclaimed.

| Phase | Name | Agent | What it does | Main outputs |
| --- | --- | --- | --- | --- |
| `M1` | Validate Every Finding | (inline) | Checks every `vigolium-results/findings/<ID>-<slug>/` for required files, valid frontmatter, severity prefix sanity, evidence presence. | `vigolium-results/merge-workspace/findings-index.json` |
| `M2` | Semantic Dedup by Root Cause | (inline) | Identifies findings that describe the same root cause across the merged inputs and selects canonical survivors. | `vigolium-results/merge-workspace/dedup-decisions.json` |
| `M3` | Auto-Fix Safe Issues | `finding-writer` | Repairs frontmatter, malformed PoC metadata, naming issues, and report metadata when safely automatable. | Updated files inside `vigolium-results/merge-workspace/` |
| `M4` | Quarantine Unfixable | (inline) | Moves findings that can't be normalized safely into quarantine with a reason note. | `vigolium-results/quarantine/<orig-id>-<slug>/QUARANTINE.md` |
| `M5` | Renumber + Rebuild References | (inline) | Assigns deterministic merged finding ids by severity and rewrites internal references. | `vigolium-results/merge-workspace/rename-map.json` |
| `M6` | Regenerate Summaries | `report-composer` | Writes surviving canonical findings to final `vigolium-results/findings/<merged-id>-<slug>/` and regenerates the consolidated report. | `vigolium-results/findings/<merged-id>-<slug>/`; `vigolium-results/final-audit-report.md` |
| `M7` | Cleanup + merge-report.md | (inline) | Removes the merge workspace, releases `vigolium-results/.merge-lock`, writes the final merge report covering every dedup, fix, and quarantine decision. | `vigolium-results/merge-report.md` |

## Phase graph customization

The orchestrator validates each mode's `phases:` array via Zod, detects
cycles, and topologically sorts. v1 walks the order sequentially —
`parallel_with` is recorded but not yet honored. Phases with `agent: null`
are "inline" and run with the command-def body as the system prompt; phases
with an agent name load that prompt from
[`src/content/agent-defs/<name>.md`](../src/content/agent-defs/).

When customizing modes or adding new ones, any phase referenced in
`depends_on` / `parallel_with` must exist in `phases:` — there are no
hardcoded phase ids in the engine. Phases that declare `requires_git: true`
are skipped automatically when the target has no git history.

Failure policy is `skip-and-continue` by default (`--strict` aborts on first
failure). Failed phases have their `findings-draft/` output quarantined to
`vigolium-results/.archive/<auditId>/<phaseId>/` so retries don't merge against
half-written files.
