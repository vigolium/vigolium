# Archon-Audit

Archon-audit is Vigolium's embedded **multi-phase whitebox security audit engine**. In swarm it runs as a background process alongside the main scan; in autopilot it runs first, then its output is prepared into stable operator context before the autonomous agent starts. Findings are automatically ingested into the Vigolium database alongside native scanner results.

Archon-audit replaces the legacy vig-audit-agent with richer finding formats (YAML frontmatter, adversarial verdicts, cold-verify overlays) and a more capable multi-phase pipeline.

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Audit Modes](#audit-modes)
- [CLI](#cli)
- [API](#api)
- [Manual Import](#manual-import)
- [Configuration](#configuration)
- [Session Artifacts](#session-artifacts)
- [Finding Format](#finding-format)
- [Finding Ingestion](#finding-ingestion)
- [Architecture](#architecture)
- [Comparison with Native Scanning](#comparison-with-native-scanning)

---

## Quick Start

```bash
# Swarm with background archon-audit (lite mode, default)
vigolium agent swarm -t https://example.com --source ./src --archon

# Swarm with deep 10-phase audit
vigolium agent swarm -t https://example.com --source ./src --archon deep

# Autopilot with archon-audit first
vigolium agent autopilot -t https://example.com --source ./src --archon-mode balanced

# Explicitly disable (overrides config)
vigolium agent swarm -t https://example.com --source ./src --archon off

# Import previously-run archon output
vigolium import /path/to/archon-output/
```

Archon-audit requires `--source` — it audits source code, not network traffic.

---

## How It Works

When `--archon` is set and `--source` is provided:

1. Vigolium extracts the embedded archon-audit harness (agents, commands, skills) to `~/.vigolium/archon-audit/`
2. A **separate Claude Code process** is launched with the archon plugin, targeting the source directory
3. The archon agent runs its own multi-phase pipeline independently
4. Audit state and findings are copied into the Vigolium session directory
5. Progress is tracked in a child `AgenticScan` record (mode=`archon`) linked to the parent run
6. When the audit completes, findings are parsed and ingested into the Vigolium database
7. In autopilot, Archon output is then prepared into stable context and a native plan before the operator starts
8. The `<source>/archon/` directory is removed (copy preserved in session directory)
9. If a foreground run is cancelled first, the archon process is gracefully cancelled via SIGTERM (10s grace period)

```
+---------------------------------------------------------------+
|                  vigolium agent swarm/autopilot                |
|                                                                |
|  +--------------+    +-------------------------------------+  |
|  |  Foreground   |    |  Background (separate process)       |  |
|  |               |    |                                      |  |
|  |  Swarm/       |    |  claude --plugin-dir <archon>        |
|  |  Autopilot    |    |  /archon-audit:archon:{mode}         |
|  |  Pipeline     |    |                                      |  |
|  |               |    |  P1:  Commit Archaeology             |  |
|  |  normalize    |    |  P2:  Patch Bypass Analysis          |  |
|  |  source-      |    |  P3:  Knowledge Base + Threat Model  |  |
|  |   analysis    |    |  P4:  SAST (CodeQL + Semgrep)        |  |
|  |  code-audit   |    |  P5:  Deep Probe + Bug Hunting       |  |
|  |  sast         |    |  P6:  Spec Gap Analysis              |  |
|  |  discover     |    |  P7:  Enrichment + Filtering         |  |
|  |  plan         |    |  P8:  Adversarial Debate Chambers    |  |
|  |  scan         |    |  P9:  Cold Verification              |  |
|  |  triage       |    |  P10: Variant Hunting                |  |
|  |               |    |  P11: PoC + Report Assembly          |  |
|  |               |    |                                      |  |
|  |               |    |  -- state sync every 30s -->         |  |
|  |               |    |  -- findings ingested on done -->    |  |
|  +-------+------+    +------------------+-------------------+  |
|          |                              |                      |
|          v                              v                      |
|  +-----------------------------------------------------+      |
|  |                     Database                          |      |
|  |  findings (source: scanner modules + archon)          |      |
|  |  http_records, agentic_scans                             |      |
|  +-----------------------------------------------------+      |
+---------------------------------------------------------------+
```

---

## Audit Modes

### Lite (3 phases)

Fast pipeline optimized for CI/CD and routine scans. Runs quick recon, secrets scan, and fast SAST.

| Phase | Name | Description |
|-------|------|-------------|
| Q0 | Quick Recon | Architecture inventory, dependency audit |
| Q1 | Secrets Scan | Credential and secret detection |
| Q2 | Fast SAST | Quick CodeQL + Semgrep structural scan |

### Scan (6 phases)

Intermediate audit with SAST, probing, and validation.

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Intelligence | CVE/GHSA/OSV hunting, dependency audit, architecture inventory |
| 2 | Knowledge Base | Threat model, domain attack research, RFC specs |
| 3 | SAST | CodeQL structural + security scan, Semgrep (parallel with P4) |
| 4 | Probe | Targeted deep analysis of high-risk areas (parallel with P3) |
| 5 | Review + FP | Inline verification + false positive elimination |
| 6 | PoC + Report | Proof-of-concept generation and advisory-style report |

### Deep (11 phases)

Comprehensive audit with adversarial review chambers. Best for pre-release audits, compliance, or high-value targets. The legacy `full` mode maps to `deep`.

| Phase | Name | Description |
|-------|------|-------------|
| P1 | Commit Archaeology | Analyze git history for silent security fixes, undisclosed CVEs |
| P2 | Patch Bypass | Test patch completeness, find alternate exploitation paths |
| P3 | Knowledge Base | Build architecture model, trust boundaries, attack surface map |
| P4 | Static Analysis | CodeQL + Semgrep with custom rules |
| P5 | Deep Probe | Multi-hypothesis probing with specialized agents |
| P6 | Spec Gap Analysis | Find gaps between spec/docs and implementation |
| P7 | Enrichment & Filtering | Enrich SAST findings with reachability analysis and data flow |
| P8 | Adversarial Debate | Multi-agent debate chambers validate/disprove findings |
| P9 | Cold Verification | Independent zero-context re-verification |
| P10 | Variant Hunting | Search for variants of confirmed vulnerabilities |
| P11 | Report Assembly | PoC building and advisory-style final report |

---

## CLI

### Flag: `--archon`

Available on both `vigolium agent swarm` and `vigolium agent autopilot`.

| Value | Behavior |
|-------|----------|
| *(not set)* | Disabled (unless enabled in config) |
| `--archon` | Lite mode (3-phase fast audit) |
| `--archon lite` | Lite mode (explicit) |
| `--archon balanced` | Balanced mode (6-phase intermediate audit) |
| `--archon deep` | Deep mode (10-phase comprehensive audit) |
| `--archon off` | Disabled (overrides config) |

### Examples

```bash
# Swarm: targeted scan + background lite audit
vigolium agent swarm \
  -t https://example.com/api \
  --source ./backend \
  --archon

# Swarm: full-scope scan + deep audit
vigolium agent swarm \
  -t https://example.com \
  --source ./backend \
  --discover \
  --archon deep

# Autopilot: autonomous scan + balanced-mode audit
vigolium agent autopilot \
  -t https://example.com \
  --source ./backend \
  --archon balanced

# Disable archon even if config enables it
vigolium agent swarm \
  -t https://example.com \
  --source ./backend \
  --archon off
```

---

## API

The `archon` field is available on both the swarm and autopilot run endpoints.

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `archon` | string | `"lite"`, `"balanced"`, `"deep"`, `"off"`, or omit for config default |

### POST /api/agent/run/swarm

```bash
# Swarm with lite archon-audit
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "discover": true,
    "archon": "lite"
  }' | jq .

# Swarm with deep 10-phase archon-audit
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "discover": true,
    "code_audit": true,
    "archon": "deep"
  }' | jq .
```

### POST /api/agent/run/autopilot

```bash
# Autopilot with deep archon-audit
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "source": "/home/user/src/my-app",
    "archon": "deep"
  }' | jq .
```

### Response

Both endpoints return `202 Accepted` with a run ID. Archon-audit runs as a background process within the agent run — its progress is tracked in a child `AgenticScan` record. Findings are ingested into the database on completion.

```bash
# Query archon findings after run completes
curl -s http://localhost:9002/api/findings?source=archon | jq .
```

---

## Manual Import

Archon output from external runs can be imported directly without running swarm or autopilot:

```bash
vigolium import /path/to/archon-output-harbor/
```

The folder must contain `audit-state.json` and `findings/`. The import:

1. Parses `audit-state.json` for phase tracking and metadata
2. Reads all finding files from `findings/`
3. Applies cold-verify overlays (if `*.cold-verify.md` files exist)
4. Creates an `AgenticScan` record (mode=`archon`)
5. Saves findings with deduplication (skips duplicates by finding hash)
6. Reports counts: total findings, saved, duplicates skipped, severity distribution

---

## Configuration

### YAML Config

```yaml
agent:
  archon:
    enable: false              # Enable by default (overridable with --archon off)
    mode: lite                 # Default mode: lite, scan, or deep
    plugin_dir: ""             # Custom harness path (default: ~/.vigolium/archon-audit/)
    sync_interval: 30          # Seconds between state syncs
```

### Precedence

1. CLI `--archon <value>` / API `"archon": "<value>"` — highest priority
2. Config `agent.archon.enable: true` — used when CLI/API doesn't specify
3. `--archon off` / `"archon": "off"` — overrides config

### Harness Resolution

The archon-audit harness (agents, commands, skills) is resolved in this order:

1. **Config `plugin_dir`** — if set and exists, used directly
2. **Default path** `~/.vigolium/archon-audit/` — checked next
3. **Embedded extraction** — if neither exists, the harness bundled in the Vigolium binary is extracted automatically. A version hash marker detects changes for re-extraction

No manual installation is required — everything ships embedded in the Vigolium binary.

---

## Session Artifacts

Archon-audit writes output to the source directory under `archon/`, which is synced to the session directory:

### Source Directory (temporary, removed after import)

```
<source_path>/
└── archon/
    ├── audit-state.json              # Phase progress tracking
    ├── findings/                     # Per-finding markdown files
    │   ├── p7-001-open-redirect.md   # Phase 7 finding
    │   ├── p8-001-ssrf-webhook.md    # Phase 8 finding
    │   ├── p8-001-ssrf.cold-verify.md  # Cold verification overlay
    │   ├── p10-041-variant.md        # Variant finding
    │   └── ...
    ├── knowledge-base-report.md
    ├── final-audit-report.md
    ├── advisory-report.md
    ├── spec-gap-report.md
    └── attack-pattern-registry.json
```

### Session Directory (persistent)

```
~/.vigolium/agent-sessions/<uuid>/
├── archon-audit/                     # Synced from source
│   ├── audit-state.json
│   ├── findings/
│   ├── final-audit-report.md
│   ├── attack-pattern-registry.json
│   └── ...
├── archon-audit-output.md            # Raw Claude Code process output
├── output.md                         # Main agent output
├── skills/
│   └── vigolium-scanner/
└── CLAUDE.md
```

---

## Finding Format

Archon produces two finding formats depending on the phase.

### Phase 7 Findings (Table-based)

Early-phase findings use a markdown table format:

```markdown
# Phase 7 Enriched Finding: P7-001

## Finding Details

| Field | Value |
|-------|-------|
| **Finding ID** | P7-001 |
| **Title** | Open Redirect via Unvalidated postURI |
| **Severity** | HIGH |
| **Confidence** | HIGH |
| **CWE** | CWE-601 (URL Redirection to Untrusted Site) |

PoC-Status: theoretical

## Code Location

**File**: `src/core/controllers/authproxy_redirect.go`
**Lines**: 73-77

[Detailed analysis...]
```

### Phase 8+ Findings (Frontmatter-based)

Later-phase findings use structured key-value frontmatter with adversarial verdicts:

```markdown
Phase: 8
Sequence: 001
Slug: admin-db-auth-brute-force
Verdict: VALID
Severity-Original: HIGH
Severity-Final: MEDIUM
PoC-Status: pending
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: IsSuperUser forces DB auth unconditionally...

## Summary

Harbor's admin account bypasses account lockout...

## Location

- `src/core/auth/authenticator.go:142`
- `src/core/auth/lock.go:22-51`

[Full analysis with evidence...]
```

### Cold-Verify Overlays

Phase 9 cold verification produces overlay files (`*.cold-verify.md`) that enhance base findings with independent verdicts. The overlay updates adversarial verdict and severity, and appends a "Cold Verification" section to the finding body.

---

## Finding Ingestion

When the audit completes, findings are automatically parsed and stored in the Vigolium database.

### Database Fields

| Archon Field | Database Field | Example |
|---|---|---|
| Finding ID | `module_id` | `archon:p8-001` |
| Title | `module_name` | SSRF via Webhook Job Address |
| Slug | `module_short` | `ssrf-webhook-job` |
| Severity (final) | `severity` | `high` (normalized) |
| Verdict | `confidence` | `firm` (CONFIRMED/VALID) or `tentative` |
| CWE | `cwe_id` | `CWE-918` |
| Full analysis | `description` | Markdown body with evidence |
| First location | `source_file` | `src/jobservice/webhook_job.go` |
| All locations | `matched_at` | `src/jobservice/webhook_job.go:103-120` |
| Metadata | `tags` | `["archon", "phase-8", "valid", "poc-theoretical", "CWE-918"]` |

All findings are stored with:
- `finding_source`: `archon`
- `module_type`: `whitebox`
- `finding_hash`: MD5(auditID + moduleID + findingID) for deduplication

### Confidence Mapping

| Archon Verdict | Database Confidence |
|---|---|
| CONFIRMED, VALID | `firm` |
| All others (POSSIBLE, UNLIKELY, etc.) | `tentative` |

### Querying Archon Findings

```bash
# Via CLI
vigolium finding list --source archon

# Via API
GET /api/findings?source=archon
```

---

## Architecture

### Specialized Agents (24 total)

The archon-audit engine uses a team of specialized agents, each handling a specific aspect of the audit:

| Agent | Phase | Role |
|-------|-------|------|
| advisory-hunter | P1 | CVE/GHSA/OSV intelligence gathering |
| commit-archaeologist | P1 | Git history analysis for silent fixes |
| patch-bypass-checker | P2 | Bypass analysis for identified patches |
| knowledge-base-builder | P3 | Threat model + architecture mapping |
| static-analyzer | P4 | SAST tool coordination (CodeQL, Semgrep) |
| probe-strategist | P5 | Multi-model hypothesis generation |
| code-anatomist | P5 | Code structure analysis |
| backward-reasoner | P5 | Reverse-engineer attack paths |
| contradiction-reasoner | P5 | Spot logical inconsistencies |
| causal-verifier | P5 | Validate causality claims |
| evidence-harvester | P5 | Build proof from code evidence |
| enrichment-filter | P6-7 | Finding classification by exploitability |
| spec-gap-analyst | P6-7 | RFC/spec compliance gap detection |
| chamber-synthesizer | P8 | Debate moderator for adversarial review |
| attack-ideator | P8 | Exploit brainstorming |
| code-tracer | P8 | Deep code path tracing |
| devils-advocate | P8 | Challenge assumptions |
| variant-scout | P8 | Initial variant identification |
| cold-verifier | P9 | Independent zero-context verification |
| variant-hunter | P10 | Deep variant analysis across codebase |
| poc-builder | P11 | Proof-of-concept generation |
| report-assembler | P11 | Final report assembly |

### Bundled Skills

The following security skills are embedded in the Vigolium binary for archon-audit:

- **audit** — Core multi-phase methodology orchestrator
- **codeql** — CodeQL database creation and query execution
- **semgrep** — Semgrep rule management and scanning
- **semgrep-rule-creator** — Custom Semgrep rule generation
- **fp-check** — False positive verification methodology
- **variant-analysis** — Cross-codebase vulnerability variant detection
- **vuln-report** — Advisory-style vulnerability report generation
- **differential-review** — Diff-based security review
- **security-threat-model** — STRIDE/DREAD threat modeling
- **sarif-parsing** — SARIF output parsing and enrichment
- **zeroize-audit** — Memory safety analysis (Rust/C)

### Adversarial Review Chambers (Phase 8)

The deep mode's adversarial debate phase uses a structured format where specialized agents argue for and against the exploitability of each finding:

```
probe-strategist --> generates hypotheses
         |
         +-- attack-ideator (brainstorms exploits)
         +-- backward-reasoner (reverse-engineers paths)
         +-- evidence-harvester (builds proofs)
         |
         +-- chamber-synthesizer (moderates debate)
                  |
                  +-- devils-advocate (challenges claims)
                  +-- contradiction-reasoner (spots inconsistencies)
                  +-- causal-verifier (validates causality)
```

Only findings that survive this adversarial process proceed to cold verification and the final report. This dramatically reduces false positives compared to single-pass analysis.

### Cold Verification (Phase 9)

After the adversarial debate, the cold-verifier agent performs an independent, zero-context re-verification of each finding. It receives no prior verdicts or rationale — only the raw code and finding description. Cold verification overlays update the base finding with an independent severity assessment and verdict, providing a second opinion that catches debate-phase groupthink.

---

## Comparison with Native Scanning

| Aspect | Vigolium Native (Swarm/Autopilot) | Archon-Audit |
|--------|-----------------------------------|--------------|
| **Focus** | Network vulnerabilities (injection, XSS, SSRF, etc.) | Source code vulnerabilities (logic flaws, auth gaps, spec violations) |
| **Method** | Live HTTP scanning with payloads | Static analysis + AI reasoning + adversarial validation |
| **False positive handling** | AI triage phase | Multi-layer: adversarial debate chambers + cold verification |
| **Finding richness** | Standard severity/confidence | Adversarial verdicts, cold-verify overlays, CWE, PoC status |
| **Speed** | Minutes to hours | Minutes (lite) to hours (deep) |
| **Requires** | Target URL | Source code path |
| **Runs as** | Foreground (main pipeline) | Background (separate process) |

The two approaches are complementary. Network scanning finds vulnerabilities that manifest in HTTP responses; archon-audit finds vulnerabilities that require understanding code semantics, business logic, and specification compliance. Running both together provides the most comprehensive assessment.
