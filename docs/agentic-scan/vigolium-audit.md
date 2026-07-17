# Vigolium Audit

Vigolium Audit is Vigolium's embedded, multi-phase whitebox security-audit
harness. It drives either Claude Code or Codex against an application source
tree, validates candidate findings, constructs proofs of concept, and imports
the resulting findings into the same project-scoped database used by native and
agentic scans.

The top-level `vigolium audit` command is an alias for
`vigolium agent audit`. Both use the unified audit dispatcher, which can run the
Vigolium Audit harness, Piolium, or both. See [Piolium Audit](piolium-audit.md)
for the Pi-specific pipeline.

## Quick start

```bash
# Default: balanced intensity, audit driver when its coding-agent CLI is available
vigolium audit --source ./app

# Force the Vigolium Audit harness and Codex, then keep all raw artifacts
vigolium audit --driver audit --agent codex --source ./app --mode deep

# Run a deep audit and immediately confirm the finalized findings
vigolium audit --driver audit --source ./app --modes deep,confirm

# Leave the main database untouched and collect HTML + raw output in one folder
vigolium audit --source ./app -S --output-dir audit-out-{ts}
```

`--source` accepts a local directory, Git URL, local `.zip`/`.tar.*` archive,
or `gs://` source archive. A Git URL is shallow-cloned by default; use
`--commit-depth 0` when deep history analysis is required.

## Driver selection

| `--driver` | Behavior |
|---|---|
| `auto` (default) | Run the Vigolium Audit harness when the resolved Claude/Codex CLI is available; otherwise fall back to Piolium. A mid-run harness failure is reported rather than silently retried with Piolium. |
| `audit` | Run only the embedded Vigolium Audit harness. |
| `piolium` | Run only Piolium. |
| `both` | Run Audit and then Piolium sequentially under one parent `AgenticScan`. |

For `auto` and `both`, each participating driver has its own child run and
session subtree. A post-pass deduplicates equivalent findings across the
project; pass `--no-dedup` to skip it.

The Audit leg resolves its coding agent from `--agent claude|codex`, then
`agent.audit.default_agent`, then the configured olium provider
(`anthropic-*` implies Claude and `openai-*` implies Codex). `--provider`
changes both that hint and its inherited authentication. It does not select the
model used by the external coding-agent CLI; configure that CLI separately.

## Modes and mode chains

Use `vigolium audit --list-modes` for the authoritative mode graph supported by
the embedded runtime.

| Mode | Purpose |
|---|---|
| `lite` | Three source-only phases: quick reconnaissance, native secrets scan, and fast SAST/finalization. |
| `balanced` | Nine phases covering intelligence, threat modeling, built-in SAST, targeted probing, adversarial review, intent reconciliation, PoC work, finding finalization, and the final report. |
| `deep` | Twelve canonical phases with history/patch analysis, structural SAST, systematic probes, authorization and state review, review chambers, intent reconciliation, PoC partitioning, and reporting. |
| `revisit` | A fresh, anti-anchored pass over a completed audit while retaining prior findings as a negative list. |
| `confirm` | Provision or connect to the target, execute existing PoCs, run test fallbacks, and write `confirmation-report.md`. |
| `merge` | Combine compatible audit result trees. |

`--intensity quick` selects `lite`, `balanced` selects `balanced`, and `deep`
resolves to the `deep,confirm` chain.
`--mode` overrides intensity. `--modes a,b,c` runs a chain in order and stops at
the first non-complete mode. Under `auto` or `both`, unsupported modes are
filtered per driver; a mode unknown to every selected driver is rejected.

Driver-specific modes require an explicit driver. For example:

```bash
vigolium audit --driver audit --source ./app --mode reinvest
vigolium audit --driver piolium --source ./app --mode longshot
```

## Current audit pipelines

### Lite: L1–L3

| Phase | Output gate |
|---|---|
| L1 — Quick recon | `attack-surface/lite-recon.md` and `unauthenticated-surface.md` |
| L2 — Secrets scan | `attack-surface/lite-secrets-scan.md`, including an explicit clean result when no secret survives filtering |
| L3 — Fast SAST and finalization | `lite-sast-summary.md`, consolidation manifest, and a `report.md` for every finalized finding |

Lite mode works on a plain source snapshot and does not require Git history.

### Balanced: B1–B9

1. Intelligence gathering
2. Knowledge base and threat model
3. Built-in CodeQL/Semgrep analysis
4. One targeted probe team over attacker-controlled inputs
5. Review chamber, false-positive check, cold verification for critical claims,
   and triage
6. Documented-intent reconciliation
7. Deterministic consolidation, PoC construction, and finding partitioning
8. Per-finding `report.md` finalization
9. Consolidated final report

Balanced mode omits commit archaeology, patch-bypass analysis, custom
structural rules, spec-gap analysis, cross-service taint expansion, and variant
hunting.

### Deep: D1–D12

| Canonical phase | Work performed |
|---|---|
| D1 | Advisory and dependency intelligence |
| D2 | Security-relevant Git history, when history is available |
| D3 | Patch-bypass analysis for identified security patches |
| D4 | Threat model, DFD/CFD slices, and knowledge base |
| D5 | Structural extraction, CodeQL, Semgrep, SAST enrichment, and multi-service edge enumeration |
| D6 | Systematic deep-probe teams over every attacker-input component |
| D7 | Route/handler enumeration and authorization review |
| D8 | State/concurrency and spec review, adversarial chambers, inline cross-service reasoning and variant expansion, then false-positive validation |
| D9 | Reconcile surviving findings with repository-documented intent |
| D10 | Consolidate drafts, author PoCs, and partition executed from theoretical findings |
| D11 | Author a cold-context `report.md` for every finalized finding |
| D12 | Assemble `final-audit-report.md` from both finding buckets |

If local Git history is unavailable, D2 and local patch-bypass work are skipped
explicitly while the source-snapshot phases continue. Cross-service taint and
variant searches are folded into the deep review chambers; they are not
standalone phases.

The engine uses artifact completion gates in addition to phase state. If a
worker exits after producing sufficient output, the next run can resume from
those artifacts instead of discarding valid work. Do not hand-edit
`audit-state.json` during an engine-owned run.

## Integration with swarm and autopilot

Swarm can launch a source audit alongside its network pipeline:

```bash
# Bare --audit means lite for swarm
vigolium agent swarm -t https://example.com --source ./app --audit

vigolium agent swarm -t https://example.com --source ./app --audit deep
```

Autopilot prepares source-aware context before its operator session. Its
`--audit` value is `lite`, `balanced`, `deep`, `mock`, or `off`; source-aware
runs default to an audit unless explicitly disabled.

```bash
vigolium agent autopilot -t https://example.com --source ./app --audit balanced
vigolium agent autopilot -t https://example.com --source ./app --audit off
```

Both commands also expose `--piolium`. When neither harness is explicitly
selected, their resolver may choose Piolium when the Pi runtime is available.

## REST API

Use the unified endpoint:

```bash
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <server-api-key>' \
  -d '{
    "source": "/srv/src/app",
    "driver": "audit",
    "agent": "codex",
    "modes": ["deep", "confirm"],
    "stream": false,
    "keep_raw": true
  }' | jq .
```

Important fields include:

| Field | Description |
|---|---|
| `source` | Required local path, Git URL, `gs://` archive, or local archive |
| `driver` | `auto`, `both`, `audit`, or `piolium`; default `auto` |
| `intensity` | `quick`, `balanced`, or `deep` |
| `mode` / `modes` | One explicit mode or an ordered mode chain; overrides intensity |
| `agent` | `claude` or `codex` for the Audit leg |
| `timeout` | Overall Go-duration override |
| `commit_depth` | Git clone depth; `0` means full history |
| `diff`, `last_commits`, `files` | Limit or prioritize the source review |
| `stream` | Return multiplexed SSE; multi-driver events include a `driver` field |
| `keep_raw` | Retain intermediate Audit artifacts |
| `no_dedup` | Skip the multi-driver project-wide dedup pass |
| `api_key`, `oauth_token`, `oauth_cred_file`, `oauth_cred_json` | Per-request BYOK fields |
| `audit_auth`, `piolium_auth` | Driver-specific BYOK overrides for `auto`/`both` |

The endpoint returns `202 Accepted` for an asynchronous run. Poll
`GET /api/agent/status/:id`, inspect session artifacts, or set `stream: true`.
Agent admission control can return `429 Too Many Requests` after the configured
queue timeout.

See the complete request schema in the [Agent API reference](../api-references/agent.md)
and authentication details in [Audit BYOK](audit-byok.md).

## Output and finding lifecycle

The Audit harness writes beneath `<source>/vigolium-results/`:

```text
vigolium-results/
├── audit-state.json
├── attack-surface/
│   ├── knowledge-base-report.md
│   └── intent-corpus.json
├── codeql-artifacts/
├── semgrep-res/
├── probe-workspace/
├── chamber-workspace/
├── findings-draft/
│   └── consolidation-manifest.json
├── findings/
│   └── H1-example/
│       ├── draft.md
│       ├── report.md
│       ├── poc.py
│       └── evidence/
├── findings-theoretical/
│   └── M1-example/
│       ├── draft.md
│       └── report.md
└── final-audit-report.md
```

`findings/` contains findings whose PoC status met the execution gate.
`findings-theoretical/` preserves valid but unexecuted or unconfirmed findings
without presenting them as demonstrated exploits. The deterministic
consolidation manifest assigns stable severity-prefixed IDs; agents do not copy
or renumber drafts manually.

The driver syncs the result tree into its agent session. Direct CLI audits keep
the source-tree `vigolium-results/` copy by default; use `--clean-raw` to remove
that copy after the run. The session copy remains available either way.

Imported findings use:

- `finding_source: audit`
- `module_type: whitebox`
- an `audit:` module-ID prefix
- `report.md` as the preferred body, with `draft.md` as fallback

Query them with:

```bash
vigolium finding --finding-source audit
curl -s 'http://localhost:9002/api/findings?finding_source=audit' | jq .
```

For Piolium findings, use the same `finding_source=audit` filter and narrow by
the `piolium:` module-ID prefix or `piolium` tag.

## Stateless reports and raw bundles

`-S/--stateless` runs the audit against a temporary database and writes a
self-contained HTML report without changing the main database:

```bash
# Default HTML destination: vigolium-result/vigolium-audit-report.html
vigolium audit --source ./app -S

# Custom report path
vigolium audit --source ./app -S -o reports/app-{ts}.html

# One directory containing the HTML report and raw result tree
vigolium audit --source ./app -S --output-dir audit-out-{ts}
```

`--output-dir` only applies with stateless mode. A relative `-o` path is nested
under that directory; an absolute path or `gs://` destination escapes it.

## Manual import

An existing Audit result tree can be imported independently:

```bash
vigolium import ./vigolium-results

# Import and render an HTML report in one command
vigolium import ./vigolium-results --format html -o audit-report.html
```

The parser reads `audit-state.json`, optional revisit state, both finalized
finding buckets, and draft fallbacks. It prefers each finding's `report.md` and
deduplicates imports by finding hash.

## Configuration

The optional background integration used by swarm and autopilot is configured
under `agent.audit`:

```yaml
agent:
  audit:
    enable: false
    mode: balanced
    sync_interval: 30
    default_agent: ""  # inherit provider; or claude / codex
```

Per-run CLI or REST fields override these defaults. The audit content bundle is
embedded in the Vigolium binary; there is no `plugin_dir` setting to maintain.

## Audit versus native scanning

| Aspect | Native / swarm / autopilot | Vigolium Audit |
|---|---|---|
| Primary input | Live HTTP traffic and targets | Application source tree |
| Main technique | Deterministic modules plus optional agentic probing | Static analysis, repository reasoning, adversarial validation, and PoCs |
| Best at | Runtime injection, exposure, protocol, and response findings | Authorization, business logic, state, data flow, spec, and patch-bypass flaws |
| Output | Project findings and HTTP evidence | Finalized and theoretical finding buckets plus audit reports |

The approaches are complementary: source analysis explains possible exploit
paths, while native and confirmation runs test what is reachable in a live
environment.
