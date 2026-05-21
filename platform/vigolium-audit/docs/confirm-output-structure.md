# Confirm Mode — Output Structure

`vigolium-audit run --mode confirm [--target <url>]` verifies existing findings
in `vigolium-results/findings/` by booting the target (or pointing at a remote
URL), executing each finding's PoC, and falling back to a generated reproducer
test for anything the PoC could not confirm. It walks 7 phases: `V1`, `V1.5`,
`V2`-`V6`. When `--target <url>` is supplied, V2 and V3 are skipped.

This document describes only what confirm mode writes. For the global audit
layout see [output-structure.md](output-structure.md); for phase semantics see
[phase-reference.md](phase-reference.md).

## Top-level layout after a confirm run

```text
vigolium-results/
  confirmation-report.md            # V6 — human-readable verdict report
  audit-state.json                  # updated when present (optional input)
  findings/
    <ID>-<slug>/                    # canonical source of truth (annotated in-place)
      report.md                     # gets Confirm-* + optional Documented-Intent fields
      confirm-evidence/             # V4 PoC run logs
        attempts.log
        env-info.txt
        exploit.log
      confirm-test.<ext>            # V5 generated reproducer (when fallback runs)
      confirm-test-output.log
    FP-<ID>-<slug>/                 # original dir renamed when confirm-fp verdict reached
  confirm-workspace/
    findings-inventory.json         # V1
    intent-corpus.json              # V1.5 — optional
    intent-verdicts.json            # V1.5 — optional
    env-strategies.json             # V2 — skipped on --target
    auth-spec.json                  # V2 — only when auth scaffolding detected
    env-connection.json             # V3 (or synthetic record on --target)
    app.pid                         # V3 — only for local non-container starts
    setup.log
    migration.log
    seed.log
    healthcheck.log
    healthcheck-failure.log         # only when V3 boot fails
    db-snapshot.sql                 # V3 — only when isolation enabled
    db-snapshot.sqlite              # V3 — only when isolation enabled
    snapshot-spec.json              # V3 — restore spec for snapshots
    cleanup.log                     # cleanup trap (EXIT/INT/TERM)
    .lock                           # present only during an active/stale run
    report-ready/                   # V6 — regenerated, derived copies (ship list)
      live-verified/                # PoC ran against live target
        <ID>-<slug>/
          report.md
          poc.<ext>
          confirm-evidence/
      test-verified/                # generated test demonstrated the bug
      analytical/                   # structural agreement (e.g. weak RNG, missing header)
      false-positive/               # drained from severity counts
    needs-review/                   # V6 — regenerated, derived copies (followup queue)
      not-reproduced/               # PoC ran, didn't trigger
      flaky/                        # inconclusive (race didn't fire deterministically)
      blocked/                      # app unreachable / missing auth / interpreter / timeout
      no-poc/                       # no PoC script and no testable fallback
      errored/                      # confirmation pipeline error
```


Confirm mode never creates `attack-surface/`, `findings-draft/`,
`chamber-workspace/`, `codeql-*`, or `final-audit-report.md` — those belong to
the audit modes that produced the findings being confirmed.

## Outputs by phase

| Phase | Agent | Writes |
| --- | --- | --- |
| `V1` Findings Inventory | (inline) | `confirm-workspace/findings-inventory.json` |
| `V1.5` Intent Cross-Check | `context-reviewer` | `confirm-workspace/intent-corpus.json`, `confirm-workspace/intent-verdicts.json`, in-place `Documented-Intent*` fields on each `findings/<ID>-<slug>/report.md`. Skip-and-continue — absent on failure. |
| `V2` Environment Discovery | `env-profiler` | `confirm-workspace/env-strategies.json`; `confirm-workspace/auth-spec.json` only when auth scaffolding is detected. Skipped on `--target`. |
| `V3` Environment Provisioning | `env-builder` | `confirm-workspace/env-connection.json`, `app.pid` (local process only), `setup.log`/`migration.log`/`seed.log`/`healthcheck.log`, optional `db-snapshot.*` + `snapshot-spec.json`. On failure: `healthcheck-failure.log` and `env-connection.json` with `status: "failed"`. Skipped on `--target` (synthetic `env-connection.json` with `status: "remote"` is written instead). |
| `V4` PoC Execution | `poc-runner` (parallel) | `findings/<ID>-<slug>/confirm-evidence/` and appended `Confirm-Status` / `Confirm-Method` / `Confirm-Evidence` fields on the canonical `report.md`. |
| `V5` Test-Based Fallback | `test-locator` (parallel) | `findings/<ID>-<slug>/confirm-test.<ext>` + `confirm-test-output.log`; appended `Confirm-Status` / `Confirm-Test` fields on `report.md`. Skipped on `--target`. |
| `V6` Confirmation Report | `confirm-writer` | `vigolium-results/confirmation-report.md`; regenerated `confirm-workspace/report-ready/` + `needs-review/` staging buckets; `audit-state.json` updates (when present). |

Cleanup (EXIT/INT/TERM trap) writes `confirm-workspace/cleanup.log` and removes
`confirm-workspace/.lock`. Containers are torn down by `vigolium-audit.session=<UUID>`
label; the local `app.pid` is killed if set.

## Canonical artifacts

### `vigolium-results/confirmation-report.md`

The single human-readable deliverable. Section order written by `confirm-writer`:

```markdown
# Confirmation Report

| Field | Value |
| Audit ID | <audit_id or "standalone-confirmation"> |
| Repository | <repository or basename> |
| Confirmed at | <ISO timestamp> |
| Environment | <method_used or "test-only" or "--target URL"> |
| Original audit mode | <mode or "unknown"> |
| Findings staging | confirm-workspace/report-ready/ + needs-review/ |

## Summary
| Verdict         | Count | Findings |
| live-verified   | N | C1, H2, ... |
| test-verified   | N | H3, M1, ... |
| false-positive  | N | ... |
| analytical      | N | ... |
| not-reproduced  | N | M2, ... |
| flaky           | N | ... |
| blocked         | N | ... |
| no-poc          | N | ... |
| errored         | N | ... |

**Confirmation rate**: X/Y findings confirmed (Z%)
  — false-positive and analytical excluded from the denominator.

## Breakdown by Exploitability Class
| Class | Total | live-verified | test-verified | not-reproduced | blocked | analytical |
| network-exploitable | ... |
| local-exploitable   | ... |
| non-exploitable     | ... |

## Pre-Auth Exposure                    # findings where Auth-Required: no — exploitable without credentials
| ID | Title | Severity | Verdict | Vector |
| C1 | ... | CRITICAL | live-verified | unauthenticated HTTP |

## Report-Ready — Live Verified         # per-finding block: vuln class, method, evidence path, timing, observation
## Report-Ready — Test Verified         # per-finding block: vuln class, framework, test file, output log, observation
## Needs-Review — Not Reproduced        # per-finding block: PoC result, test result, reason, recommendation
## Needs-Review — Blocked               # per-finding block: blocker reason
## Documented-Intent Matches            # omitted entirely when intent-verdicts.json is absent
## Environment Details                  # session UUID, provisioning method, port, healthcheck, containers/processes, log paths
## Auth Context                         # seeded test identities table from env-connection.json:test_identities[]
```

The **Pre-Auth Exposure** section reads `Auth-Required: no` off each finding's
`report.md` (set in deep mode by `poc-author`) and lists them with their final
verdict. This is a *cross-cut* index — those findings still live in whatever
report-ready/needs-review bucket their confirmation outcome put them in. It
exists because unauthenticated-exploitable findings are the highest-priority
items for a client report regardless of whether the PoC ran.

### `vigolium-results/findings/<ID>-<slug>/` (annotated in place)

Confirm mode does not move or restructure finding directories — it appends
metadata fields and writes side-by-side evidence files. Per-finding artifacts
contributed by confirm:

| File | Phase | Description |
| --- | --- | --- |
| `report.md` | V1.5/V4/V5 | Gains `Confirm-Status`, `Confirm-Method`, `Confirm-Evidence`, `Confirm-Test`, `Confirm-Notes`, and (optional) `Documented-Intent`, `Documented-Intent-Source`, `Documented-Intent-Quote` fields. The audit's original body is untouched. |
| `confirm-evidence/` | V4 | `attempts.log`, `env-info.txt`, `exploit.log` and any other artifacts the PoC captured against the live/remote target. |
| `confirm-test.<ext>` | V5 | Generated reproducer test (`.py` / `.js` / `.go` / `.rb`) following the project's test framework. |
| `confirm-test-output.log` | V5 | Stdout/stderr of the reproducer test execution. |

A `false-positive` verdict causes the directory to be renamed with an `FP-`
prefix (`FP-H2-idor-checkout/`). False positives are tracked but excluded from
the confirmation-rate denominator.

### `vigolium-results/confirm-workspace/` JSON artifacts

| File | Phase | Shape (key fields) |
| --- | --- | --- |
| `findings-inventory.json` | V1 | `{ session, findings[]: { id, slug, dir, severity, vuln_class, poc_script, poc_status, protocol, auth_required, exploitability_class, confirm_status }, total, with_poc, without_poc, by_severity, by_class }` |
| `intent-corpus.json` | V1.5 | `intentional_behaviors[]` + `acknowledged_risks[]` extracted from SECURITY.md / README / docs / ADRs / inline pragmas, with quotes and `source:line`. Optional. |
| `intent-verdicts.json` | V1.5 | Per-finding `{ id, match: "yes"\|"partial"\|"no"\|"contested", corpus_refs[], confidence, quote }`. Annotate-only — never overrides `Confirm-Status`. Optional. |
| `env-strategies.json` | V2 | Ranked startup strategies, build steps, ports + fallback ports, env vars, datastores, migrations/seeds, test framework, multi-tenancy hints. |
| `auth-spec.json` | V2 | Auth scaffolding and identities to seed; `{"supported": false}` when no auth wiring detected. |
| `env-connection.json` | V3 / `--target` | `{ status: "running"\|"failed"\|"remote", session, base_url, method_used, healthcheck_passed, actual_port, container_ids[], app_pid, cleanup_cmd, test_identities[], snapshot_spec, provisioning_attempts[] }` |
| `snapshot-spec.json` | V3 | Datastore restore commands keyed to `db-snapshot.*` for resetting state between PoC variants. |

### `vigolium-results/confirm-workspace/{report-ready,needs-review}/` staging

V6 mirrors every finding into **exactly one** verdict bucket — wiped and
rebuilt on every confirm run. `vigolium-results/findings/` remains authoritative;
these copies exist so a reviewer can see the verdict at a glance from the
filesystem. `report-ready/` is the ship list; `needs-review/` is the followup
queue.

| Bucket | Meaning |
| --- | --- |
| `report-ready/live-verified/` | PoC executed against the live/remote target with structured `status: confirmed`. |
| `report-ready/test-verified/` | V5 reproducer test demonstrated the vulnerability. |
| `report-ready/analytical/` | `Protocol: non-exploitable` — confirmation is structural, not behavioural. Excluded from confirmation-rate denominator. |
| `report-ready/false-positive/` | `fp-check` determined the original finding was a false positive. |
| `needs-review/not-reproduced/` | PoC/test ran but did not demonstrate the issue. |
| `needs-review/flaky/` | PoC's structured output reported `inconclusive` (e.g., race didn't trigger deterministically). |
| `needs-review/blocked/` | App unreachable, missing interpreter/auth token, install failure, test timeout. |
| `needs-review/no-poc/` | No PoC script and no testable fallback available. |
| `needs-review/errored/` | Confirmation pipeline error. |

Priority order when both V4 and V5 produced a verdict:
`live-verified` > `test-verified` > `false-positive` > `analytical` >
`not-reproduced` > `flaky` > `blocked` > `no-poc` > `errored`.

**Pre-auth axis (orthogonal)**: the `Auth-Required: no` field on a finding's
`report.md` flags exploits reachable without credentials. This does not change
which bucket a finding lands in — it is surfaced in the report's `Pre-Auth
Exposure` cross-cut table so a reader can see which `live-verified` /
`not-reproduced` / `blocked` items are unauthenticated.

### `audit-state.json` updates

When `vigolium-results/audit-state.json` exists, V6 writes two records on the
latest audit entry:

1. `audits[-1].confirmation` — latest-run summary (overwritten):
   `{ session, confirmed_at, environment_method, target_url, results: { live_verified, test_verified, false_positive, analytical, not_reproduced, flaky, blocked, no_poc, errored }, by_class, confirmation_rate }`
2. `audits[-1].confirmation_history[]` — append-only log:
   `{ session, started_at, completed_at, target_url, results }` per run.

If `audit-state.json` is absent (standalone confirmation), both writes are
skipped — confirm mode never creates the file on its own.

## Modes / flags that change the layout

| Flag | Effect |
| --- | --- |
| `--target <url>` | V2 + V3 skipped; `env-connection.json` written with `status: "remote"`, `base_url: <url>`. No `env-strategies.json`, `auth-spec.json`, `app.pid`, `db-snapshot.*`, `setup/migration/seed/healthcheck` logs. V5 also skipped by default in remote mode. |
| V3 fails (`status: "failed"`) | V4 skipped, all findings routed through V5 in `mode: full` (test-only). `healthcheck-failure.log` is written. |
| V1.5 fails (skip-and-continue) | `intent-corpus.json` / `intent-verdicts.json` absent; V6 omits the "Documented-Intent Matches" section. |
| `exploitability_class: non-exploitable` | Finding skips V4 entirely, lands in `report-ready/analytical/`. |
| `exploitability_class: local-exploitable` | Finding skips V4, goes straight to V5 in `mode: local`. |
| `Auth-Required: no` on a finding | Finding additionally appears in the report's `Pre-Auth Exposure` cross-cut table. Bucket placement is unchanged. |

## What to read first

1. `vigolium-results/confirmation-report.md` — the verdict report. Start with the `Pre-Auth Exposure` section if the target has an internet-facing attack surface.
2. `vigolium-results/confirm-workspace/report-ready/` — the ship list. Each subfolder is one verdict tier.
3. `vigolium-results/confirm-workspace/needs-review/` — the followup queue. Everything that did not confirm cleanly.
4. `vigolium-results/findings/<ID>-<slug>/report.md` — canonical source; look for the appended `Confirm-*` block.
5. `vigolium-results/findings/<ID>-<slug>/confirm-evidence/` or `confirm-test*` — proof artifacts.
6. `vigolium-results/confirm-workspace/findings-inventory.json` — what the run was asked to verify and how each finding was classified.
7. `vigolium-results/confirm-workspace/env-connection.json` + `healthcheck-failure.log` — when something went wrong during provisioning.
