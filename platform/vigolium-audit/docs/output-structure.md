# Vigolium-Audit Output Structure

Vigolium-Audit writes all audit artifacts under an `vigolium-results/` directory in the target
repository. This file explains that directory layout and which files are meant
to be read, retained, or treated as transient implementation detail.

For phase-by-phase behavior, see [phase-reference.md](phase-reference.md).

## Top-level layout

```text
vigolium-results/
  audit-state.json
  file-state.json
  revisit-audit-state.json        # only after /vigolium-audit:revisit
  attack-surface/
  findings-draft/
  findings/
  probe-workspace/
  chamber-workspace/
  adversarial-reviews/
  real-env-evidence/
  bypass-analysis/
  codeql-artifacts/
  codeql-queries/
  confirm-workspace/
  merge-workspace/
  quarantine/
  tmp/
  final-audit-report.md
  confirmation-report.md
  merge-report.md
  reinvest-report.md
```

Not every command creates every path. Lite runs create `audit-state.json`,
`attack-surface/lite-recon.md`, severity-prefixed `findings/<C|H|M><N>-<slug>/`
directories with `draft.md` + `poc.*` + `evidence/`, and the candidate drafts
that produced them. Balanced and deep runs add the full `attack-surface/`
corpus, per-finding `report.md`, and `final-audit-report.md`. Confirm, merge,
and revisit each add their own top-level workspace and report file.

Completed `deep`/`confirm` runs, including successful resumes of those modes, are pruned by the CLI
to a delivery-oriented layout. Large/raw workspaces such as
`codeql-artifacts/`, `semgrep-res/`, `findings-draft/`, `probe-workspace/`,
`chamber-workspace/`, `adversarial-reviews/`, `*-prior-round` directories, and
agent-generated helper `scripts/` are removed after success. Failed/aborted runs
keep raw workspaces so they can be resumed or debugged.

## Durable outputs

These paths are the primary outputs to keep after a run:

| Path | Produced by | Description |
| --- | --- | --- |
| `vigolium-results/audit-state.json` | every audit mode | Run history, mode, status, phases, retry metadata, repository identity, model + agent SDK, and (when present) usage totals. The orchestrator reads/writes this on every phase transition. |
| `vigolium-results/file-state.json` | every audit mode | Per-source-file scan record with SHA-256, the audits each file appeared in, and the phases it was scanned by. Used by `/vigolium-audit:diff` to compute incremental scope. |
| `vigolium-results/revisit-audit-state.json` | revisit | Round-N revisit state, kept separately so the original `audit-state.json` from round 1 stays intact. |
| `vigolium-results/attack-surface/` | lite, balanced, deep, diff, revisit, merge | Durable knowledge base used by later phases: recon, advisories, KB, SAST, probes, chamber summaries, authz/concurrency/spec audits, intent reconciliation, and merge summaries. |
| `vigolium-results/attack-surface/knowledge-base-report.md` | balanced, deep, revisit | The central KB document. Many phases append sections to it in-place rather than creating new files (see "knowledge-base-report.md" below). |
| `vigolium-results/findings/` | lite, balanced, deep, revisit, merge | Final finding directories promoted from reviewed drafts (severity-prefixed `<C\|H\|M><N>-<slug>/`). |
| `vigolium-results/final-audit-report.md` | balanced, deep, revisit, merge | Consolidated final report across finalized findings. |
| `vigolium-results/confirmation-report.md` | confirm, deep P15+ followups | Confirmation verdict report for existing findings. |
| `vigolium-results/confirm-workspace/` | confirm | Confirmation inventory, environment/provisioning logs, optional intent verdicts, and regenerated verdict-grouped staging copies. Retained after confirm cleanup. |
| `vigolium-results/merge-report.md` | merge | LLM-side merge report covering dedup, auto-fixes, quarantines, renumbering. |
| `vigolium-results/reinvest-report.md` | reinvest | Cross-agent re-verification consensus / disagreement summary. |

## `audit-state.json`

`vigolium-results/audit-state.json` is the resume and status file. It has this shape:

```json
{
  "schema_version": 1,
  "audits": [
    {
      "audit_id": "2026-05-10T18-22-00Z-3b7c",
      "commit": "8f1c2d…",
      "branch": "main",
      "repository": "owner/repo",
      "mode": "balanced",
      "model": "opus-4.7",
      "agent_sdk": "claude-code",
      "started_at": "2026-05-10T18:22:00Z",
      "completed_at": "2026-05-10T18:51:14Z",
      "status": "complete",
      "phases": {
        "1": {
          "status": "complete",
          "started_at": "2026-05-10T18:22:01Z",
          "completed_at": "2026-05-10T18:24:33Z"
        }
      },
      "usage": {
        "input_tokens": 1248301,
        "output_tokens": 88412,
        "cost_usd": 4.92
      }
    }
  ]
}
```

Phase status values are `pending`, `in_progress`, `complete`, `failed`, and
`skipped`. Audit status values are `in_progress`, `complete`, `failed`, and
`aborted`. Schema enforced by Zod in `src/engine/state.ts` — invalid JSON or
schema drift fails the run rather than silently ignoring.

## `attack-surface/`

`vigolium-results/attack-surface/` is the durable working knowledge base. It is safe to
read directly and is intentionally retained by cleanup phases.

Common files:

| File | Produced by | Description |
| --- | --- | --- |
| `lite-recon.md` | lite L1 | Source snapshot, manifests, frameworks, entry points, git status, scan exclusions. |
| `knowledge-base-report.md` | balanced B1-B2, deep D4 + many later | The central KB. See section below. |
| `commit-recon-report.md` | deep D2 | Commit-archaeology high-risk patches and bypass candidates. |
| `authz-matrix.md` | deep D7 | One row per endpoint with expected vs. actual authorization checks. |
| `authz-coverage-gaps.md` | deep D7 | Endpoints the auditor did not feel confident classifying. |
| `cross-service-edges.json` | deep D8 | Machine-readable cross-service edges; for single-service repos, a stub marker. |
| `cross-service-edges.md` | deep D8 | Human-readable cross-service data-flow report. |
| `intent-corpus.json` | balanced B6, deep D10, revisit P0 | Documented-intent corpus: `intentional_behaviors[]` and `acknowledged_risks[]` extracted from SECURITY.md/README/docs/ADRs/inline pragmas, with quotes and `source:line`. Also consumed by `red-challenger`/`attack-designer`/`probe-lead`. |
| `intent-verdicts.json` | balanced B6, deep D10 | Per-finding reconciliation verdicts (`genuine-vuln` / `intentional-design` / `documented-feature` / `contested`) with the matched corpus entries and routing decision. |
| `intent-reconciliation.md` | balanced B6, deep D10 | Human-readable reconciliation report: project-context summary + per-finding verdict table. The reference artifact for "is this finding intentional architecture / a feature, or a real bug?" |

### `knowledge-base-report.md`

This single markdown file is the spine of every balanced and deep audit. Many
phases append in-place sections rather than creating new files. Typical
sections, in the order they tend to be written:

| Section | Written by |
| --- | --- |
| `## Advisory Intelligence` | balanced B1, deep D1 |
| `## Commit Archaeology` | deep D2 |
| `## Bypass Analysis` | deep D3 (merged from `bypass-analysis/`) |
| `## Architecture Model` | balanced B2, deep D4 |
| `## DFD/CFD Slices` | balanced B2, deep D4 |
| `## Attack Surface` | balanced B2, deep D4 |
| `## Domain Attack Research` | balanced B2, deep D4 |
| `## Spec Gap Candidates` | deep D4 |
| `## Known False-Positive Sources` | balanced B2, deep D4 |
| `## High-Risk DFD Slices` / `## High-Risk CFD Slices` | balanced B2, deep D4 |
| `## Authorization Audit` | deep D7 |
| `## Spec Gap Analysis` | deep D9 |
| `## Cross-Service Taint Propagation` | deep D8 |

Treat the KB as append-only context; downstream agents read it cold and rely
on stable section headings.

## `findings-draft/`

`vigolium-results/findings-draft/` contains candidate markdown findings before final
promotion. Draft names indicate the phase that created them:

```text
vigolium-results/findings-draft/
  l2-001-hardcoded-token.md          # lite L2 secrets
  l3-001-path-traversal.md           # lite L3 SAST
  p4-001-command-injection.md        # deep static analysis
  p5-001-broken-authz.md             # deep authz audit
  p6-001-toctou.md                   # deep state/concurrency audit
  p7-001-state-machine-skip.md       # deep state/concurrency audit
  p7-001-spec-gap.md                 # deep spec-gap analysis
  p8-001-idor.md                     # deep manual probe
  p9-001-cross-service.md            # deep cross-service auditor
  p10-001-idor.md                    # deep review chamber
  p10k-001-known-variant.md          # deep variant analysis on round-1 finds
  p12-001-idor-variant.md            # deep variant hunter
  consolidation-manifest.json        # lite/balanced ID-assignment manifest
```

Drafts use YAML frontmatter:

```md
---
id: p10-001
phase: P10
slug: idor
severity: high
verdict: VALID
---

# Finding body
```

Drafts are retained even after promotion so rejected entries and intermediate
chamber rounds remain inspectable. Treat this directory as evidence and audit
context, not the final report.

## `findings/`

`vigolium-results/findings/<ID>-<slug>/` is the final per-finding layout. `<ID>` follows
the pattern `<Severity><N>` — e.g. `C1`, `H2`, `M3` (uppercase initial,
1-indexed within severity).

```text
vigolium-results/findings/
  C1-sql-injection-login/
    draft.md
    report.md
    poc.py
    evidence/
      exploit.log
      impact.log
    confirm-evidence/
      attempts.log
      env-info.txt
      exploit.log
    confirm-test.py
    confirm-test-output.log
    wave-2-verdict.md           # only after /vigolium-audit:reinvest
```

| File | Description |
| --- | --- |
| `draft.md` | Promoted draft with normalized frontmatter. |
| `report.md` | Final disclosure-style report. The per-finding source of truth for confirmation, reinvest, and the final report assembler. |
| `poc.<ext>` | Executable proof of concept in the most natural language for the target (`.py`, `.sh`, `.js`, `.go`, `.rb`). |
| `poc.theoretical.md` | Written when a real runtime exploit cannot be executed but the chain is documented. |
| `evidence/` | Commands, HTTP exchanges, logs, screenshots, and other proof captured during PoC build. |
| `confirm-evidence/` | Logs from `/vigolium-audit:confirm` PoC execution against a live or remote target. |
| `confirm-test.<ext>` + `confirm-test-output.log` | Test-mapper-generated reproducer test (V5 fallback) and its output. |
| `wave-<N>-verdict.md` | Per-wave reinvest verdict (wave 2+ from `/vigolium-audit:reinvest`). |
| `exploit.<ext>` / `exploit.log` | Optional captured exploit script and run log. |

False-positive findings may be renamed with an `FP-` prefix during
confirmation:

```text
vigolium-results/findings/FP-H2-idor-checkout/
```

## `probe-workspace/`

Per-component probe scratch produced by `probe-lead` (balanced B4, deep
5). Useful for understanding which hypotheses the probe team validated before
chambers consolidate them.

| File | Description |
| --- | --- |
| `probe-workspace/<component>/attack-surface-map.md` | Entry points, trust boundaries, decision points, validation sinks per component. |
| `probe-workspace/<component>/code-anatomy.md` | Annotated layer-by-layer tour of the component. |
| `probe-workspace/<component>/probe-summary.md` | Validated hypotheses with evidence pointers. Read by review-adjudicator (10), concurrency-auditor (7), access-auditor (6), taint-tracer (8) for cross-pollination. |

## `chamber-workspace/`

Review-chamber transcripts — the multi-agent debate output for the deep audit
review phase (10) and the balanced audit's L5-equivalent.

| File | Description |
| --- | --- |
| `chamber-workspace/<chamber-id>/debate.md` | Full debate transcript: Synthesizer hypotheses, Attack Ideator expansions, Devil's Advocate challenges, Tracer evidence, verdict. |
| `chamber-workspace/<chamber-id>/variant-candidates/<slug>.md` | Pre-identified variant candidates handed off to phase 12 (variant-scanner). |
| `chamber-workspace/balanced-chamber/debate.md` | Single-chamber balanced-mode debate (mode-specific id). |
| `chamber-workspace/r<round>-<cluster>/debate.md` | Revisit-round chambers, named by round + cluster id. |

## `adversarial-reviews/`

Independent-verifier output (deep D9 FP-elimination tail). One markdown review
per finding that survived chambers, written from scratch with no chamber context.

```text
vigolium-results/adversarial-reviews/
  C1-sql-injection-login-review.md
  H2-idor-checkout-review.md
```

## `bypass-analysis/`

Per-advisory bypass review produced by `patch-auditor` (deep D3). Files
are merged into the KB `## Bypass Analysis` section after the agent fan-out
completes.

```text
vigolium-results/bypass-analysis/
  CVE-2024-1234-bypass.md
```

## `codeql-artifacts/` and `codeql-queries/`

Static-analysis state used across phases that run CodeQL. These directories can
be very large and are pruned after a successful deep/balanced delivery run;
they are retained only while an audit is in progress, failed, or explicitly kept
for debugging.

| Path | Description |
| --- | --- |
| `codeql-artifacts/db/` | Built CodeQL database. Retained for phases 5/7/8/10 — do not delete after Phase 4. |
| `codeql-artifacts/entry-points.json` | Extracted entry points used by authz, concurrency, and cross-service auditors. |
| `codeql-artifacts/sinks.json` | Extracted sink inventory. |
| `codeql-artifacts/call-graph-slices.json` | Pre-computed call slices for cross-service taint. |
| `codeql-artifacts/flow-paths-raw.sarif` | SARIF source for variant-scanner (gitignored). |
| `codeql-artifacts/flow-paths-all-severities.md` | Human-readable SAST flow report. |
| `codeql-queries/variant-<slug>.ql` | Per-variant query generated by variant-scanner (12). |

## `confirm-workspace/`

`/vigolium-audit:confirm` (V1-V6, with optional V1.5 intent cross-check where
enabled) stores its run inputs, environment/provisioning state, and a
regenerated verdict index under `vigolium-results/confirm-workspace/`. The canonical
finding records remain `vigolium-results/findings/<ID>-<slug>/report.md`; the workspace
contains supporting JSON/logs plus disposable copies grouped by confirmation
outcome.

Typical layout after a completed confirm run:

```text
vigolium-results/confirm-workspace/
  findings-inventory.json
  intent-corpus.json                 # optional V1.5 / context-reviewer output
  intent-verdicts.json               # optional V1.5 / context-reviewer output
  env-strategies.json
  auth-spec.json
  env-connection.json
  app.pid                            # only for local process starts
  setup.log
  migration.log
  seed.log
  healthcheck.log
  healthcheck-failure.log            # only when provisioning/healthcheck fails
  db-snapshot.sql
  db-snapshot.sqlite
  snapshot-spec.json
  cleanup.log
  .lock                              # present only during an active/stale run
  report-ready/                      # regenerated by V6; ship-list copies
    live-verified/
      C1-example/
        report.md
        confirm-evidence/
    test-verified/
    analytical/
    false-positive/
  needs-review/                      # regenerated by V6; followup copies
    not-reproduced/
    flaky/
    blocked/
    no-poc/
    errored/
```

### Workspace files

| File | Produced by | Description |
| --- | --- | --- |
| `findings-inventory.json` | confirm V1 | Extracted finding metadata sorted by severity: ID, slug, title, severity, vulnerability class, PoC path, `Protocol`, `Auth-Required`, and `exploitability_class` (`network-exploitable`, `local-exploitable`, or `non-exploitable`). Also feeds the report's by-class breakdown. |
| `intent-corpus.json` / `intent-verdicts.json` | confirm V1.5 / `context-reviewer` | Documented-intent corpus + per-finding `Documented-Intent` verdicts under the annotate-only confirm contract. Optional — absent if the intent pass is skipped or fails. These annotations do not change confirmation status. |
| `env-strategies.json` | confirm V2 / `env-profiler` | Ranked startup strategies, build steps, ports and fallback ports, env vars, datastores, migrations/seeds, test framework, and multi-tenancy hints. |
| `auth-spec.json` | confirm V2 / `env-profiler` | Auth scaffolding and identities to seed. Written as `{"supported": false}` when no auth wiring is detected. |
| `env-connection.json` | confirm V3 / remote-target setup | Runtime connection record: `status`, session UUID, base URL, method/file used, healthcheck result, actual ports, labelled containers/process PID, cleanup command, seeded `test_identities[]`, datastore snapshot metadata, and provisioning attempts. If provisioning fails, contains `status: "failed"`, attempt errors, and `fallback: "test-only"`. |
| `app.pid` | confirm V3 / `env-builder` | PID of a locally started non-container app, used by cleanup. |
| `setup.log` / `migration.log` / `seed.log` / `cleanup.log` | confirm V3 / cleanup | Build/startup, migration, seed, and teardown logs. Containers/processes should also be labelled/stamped with the confirm session UUID so cleanup is session-scoped. |
| `healthcheck.log` / `healthcheck-failure.log` | confirm V3 / `env-builder` | Healthcheck output. The failure log may include tail output from compose/container logs and setup logs. |
| `db-snapshot.sql` / `db-snapshot.sqlite` / `snapshot-spec.json` | confirm V3 / `env-builder` | Optional pre-PoC datastore snapshot and restore spec used to reset state between PoC variants/findings when isolation is enabled. |
| `.lock` | confirm pre-flight | PID + session metadata guarding against concurrent confirm runs. It should be removed by cleanup; if present after a crash, the next run treats it as stale if the PID is no longer alive. |

### Verdict staging buckets

At V6, `confirm-writer` mirrors each finding directory into exactly one derived
category under `report-ready/` (ship list) or `needs-review/` (followup queue).
These folders are wiped and rebuilt on every confirm run, so they are a
convenience index for reviewers, not the source of truth.
`vigolium-results/findings/` remains authoritative.

| Bucket | Categories | Meaning |
| --- | --- | --- |
| `report-ready/live-verified/` | `live-verified` | Existing PoC executed successfully against the live/remote target. |
| `report-ready/test-verified/` | `test-verified` | V5 generated test demonstrated the vulnerability. |
| `report-ready/analytical/` | `analytical` | `Protocol: non-exploitable`; confirmation is structural rather than behavioural. Excluded from the confirmation-rate denominator. |
| `report-ready/false-positive/` | `false-positive` | `fp-check` determined the original finding was a false positive. This is a positive confirmation of FP status and drains from vulnerability severity counts. |
| `needs-review/not-reproduced/` | `not-reproduced` | PoC and/or generated test ran cleanly but did not demonstrate the issue. (`Confirm-Method` field distinguishes V4 PoC path from V5 test path.) |
| `needs-review/flaky/` | `flaky` | PoC emitted an inconclusive structured status (for example, a race did not trigger deterministically). |
| `needs-review/blocked/` | `blocked` | Environment, reachability, auth-token, interpreter, install, or timeout blocker prevented a verdict. |
| `needs-review/no-poc/` | `no-poc` | No PoC script and no testable fallback path were available. |
| `needs-review/errored/` | `errored` | Confirmation pipeline error; rerun or inspect logs. |

If V4 and V5 both touched a finding, V6 resolves it to one category using this
priority order: `live-verified` > `test-verified` > `false-positive` >
`analytical` > `not-reproduced` > `flaky` > `blocked` > `no-poc` > `errored`.
Each staged copy includes the full finding directory (`report.md`, `poc.*`,
`confirm-evidence/`, `confirm-test*`, etc.) as it existed at report time.

PoC/test results still land back in each canonical finding directory under
`confirm-evidence/` or `confirm-test*` and append `Confirm-*` fields to
`report.md` in-place — there is no aggregate `poc-results.json` like piolium
has.

## `real-env-evidence/`

The independent-verifier (deep D9 FP-elimination tail) optionally captures
live-environment evidence for findings it can re-validate against a running system:

```text
vigolium-results/real-env-evidence/<slug>/
```

## Merge and quarantine

| Path | Produced by | Description |
| --- | --- | --- |
| `vigolium-results/merge-workspace/findings-index.json` | merge M1 | Per-source mapping for findings being merged. |
| `vigolium-results/merge-workspace/dedup-decisions.json` | merge M2 | Semantic-dedup decisions (canonical winners, dropped duplicates). |
| `vigolium-results/merge-workspace/rename-map.json` | merge M5 | Severity-renumbering map applied in M6. |
| `vigolium-results/quarantine/<orig-id>-<slug>/QUARANTINE.md` | merge M4 | Findings excluded from the final merged set with the reason. |

## Transient files

`vigolium-results/tmp/` is scratch space for SARIF/CodeQL byproducts and one-off
artifacts. Cleanup phases remove it after durable artifacts are written.

```text
vigolium-results/tmp/variant.bqrs
vigolium-results/tmp/variant-search.bqrs
vigolium-results/tmp/on-demand.bqrs
```

## Output by mode

| Mode | Primary outputs |
| --- | --- |
| `lite` | `attack-surface/lite-recon.md`, `findings-draft/l2-*.md`, `findings-draft/l3-*.md`, severity-prefixed `findings/<C\|H\|M><N>-<slug>/` (`draft.md`, `poc.*`, `evidence/`) |
| `balanced` | `attack-surface/knowledge-base-report.md` + advisory/KB/SAST/probe/chamber sections, `attack-surface/intent-reconciliation.md`, `findings/<id>-<slug>/`, `findings-theoretical/<id>-<slug>/`, `final-audit-report.md` |
| `deep` | Full `attack-surface/` corpus (incl. `intent-corpus.json` + `intent-reconciliation.md`), `findings/`, `findings-theoretical/`, `file-state.json`, `final-audit-report.md`; raw chamber/SAST workspaces exist only until successful cleanup |
| `confirm` | `confirmation-report.md`, `confirm-workspace/*.json`, verdict-grouped `confirm-workspace/report-ready/` + `needs-review/` staging copies, updated `findings/<id>/report.md`, evidence under `findings/<id>/confirm-evidence/`, optional `confirm-test*` fallback artifacts |
| `diff` | Re-runs a subset of deep phases against a changed-file scope; produces deltas under the same paths the underlying deep phases use |
| `revisit` | `revisit-audit-state.json`, anti-anchored `chamber-workspace/r<N>-*/`, new entries under `findings/`, regenerated `final-audit-report.md` |
| `reinvest` | `findings/<id>/wave-<N>-verdict.md` per finding, top-level `reinvest-report.md` |
| `merge` | `merge-workspace/`, `quarantine/`, normalized `findings/`, regenerated `final-audit-report.md`, `merge-report.md` |
| `status` | (read-only) prints metadata, phase status, and findings counts; writes nothing |

## What to read first

For a completed audit, start with:

1. `vigolium-results/final-audit-report.md`
2. `vigolium-results/findings/<ID>-<slug>/report.md`
3. `vigolium-results/attack-surface/knowledge-base-report.md`
4. `vigolium-results/attack-surface/intent-reconciliation.md` (balanced/deep — why a finding was treated as intentional/feature vs a real bug)
5. `vigolium-results/attack-surface/authz-matrix.md` (if deep)
6. `vigolium-results/audit-state.json`

For confirmation results, start with:

1. `vigolium-results/confirmation-report.md`
2. `vigolium-results/confirm-workspace/report-ready/` and `vigolium-results/confirm-workspace/needs-review/` (verdict-grouped copies for quick triage)
3. `vigolium-results/findings/<ID>-<slug>/report.md` (canonical source; look for the appended `Confirm-*` block)
4. `vigolium-results/findings/<ID>-<slug>/confirm-evidence/` or `confirm-test*` artifacts
5. `vigolium-results/confirm-workspace/findings-inventory.json`

For a reinvest pass, start with:

1. `vigolium-results/reinvest-report.md`
2. `vigolium-results/findings/<ID>-<slug>/wave-<N>-verdict.md`

For a merged audit, start with:

1. `vigolium-results/merge-report.md`
2. `vigolium-results/final-audit-report.md`
3. `vigolium-results/quarantine/` (if anything was quarantined)
