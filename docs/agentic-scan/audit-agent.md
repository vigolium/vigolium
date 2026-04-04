# Audit Agent

The audit agent runs a **deep, multi-phase security audit** of application source code in the background while Vigolium's primary agentic scan (swarm or autopilot) runs in the foreground. It is powered by [vig-audit-agent](https://github.com/vigolium/vig-audit-agent), a multi-agent framework with 23 specialized agents and adversarial review chambers designed to eliminate false positives.

The audit agent is complementary to Vigolium's native scanning — Vigolium handles network-level vulnerability detection (injection, XSS, SSRF, etc.) while the audit agent performs deep static analysis, threat modeling, and adversarial validation of findings.

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [CLI](#cli)
- [API](#api)
- [Configuration](#configuration)
- [Audit Modes](#audit-modes)
- [Session Artifacts](#session-artifacts)
- [Finding Ingestion](#finding-ingestion)
- [Architecture](#architecture)

---

## Quick Start

```bash
# Run swarm with background audit agent (lite mode, default)
vigolium agent swarm -t https://example.com --source ./src --audit-agent

# Run swarm with full 11-phase audit
vigolium agent swarm -t https://example.com --source ./src --audit-agent full

# Run autopilot with background audit agent
vigolium agent autopilot -t https://example.com --source ./src --audit-agent

# Explicitly disable (overrides config)
vigolium agent swarm -t https://example.com --source ./src --audit-agent off
```

The audit agent requires `--source` to be set — it audits source code, not network traffic.

---

## How It Works

When `--audit-agent` is set and `--source` is provided:

1. Vigolium starts its normal scan pipeline (swarm phases or autopilot)
2. In parallel, a **separate Claude Code process** is launched with the vig-audit-agent plugin, targeting the source directory
3. The audit agent runs its own multi-phase pipeline independently (intelligence gathering, SAST, deep bug hunting, false positive elimination, etc.)
4. Every 30 seconds (configurable), `security/audit-state.json` is synced from the source directory to the Vigolium session directory under `audit-agent/`
5. When the audit completes, findings from `security/findings/*.md` are parsed and ingested into the Vigolium database
6. If Vigolium finishes first, the audit agent is gracefully cancelled via SIGTERM

```
┌─────────────────────────────────────────────────────────────┐
│                    vigolium agent swarm                       │
│                                                               │
│  ┌─────────────┐    ┌──────────────────────────────────┐     │
│  │  Foreground  │    │  Background (separate process)    │     │
│  │             │    │                                    │     │
│  │  Swarm      │    │  claude --plugin-dir <vig-audit>   │     │
│  │  Pipeline   │    │  /vig-run:lite                     │     │
│  │             │    │                                    │     │
│  │  normalize  │    │  P1: Intelligence Gathering        │     │
│  │  source-    │    │  P2: KB + Threat Model             │     │
│  │   analysis  │    │  P3: SAST (CodeQL + Semgrep)       │     │
│  │  code-audit │    │  P4: Enrichment & Probe            │     │
│  │  sast       │    │  P5: Review + FP Elimination       │     │
│  │  discover   │    │  P6: PoC + Report                  │     │
│  │  plan       │    │                                    │     │
│  │  scan       │    │  ── state sync every 30s ──►       │     │
│  │  triage     │    │  ── findings ingested on done ──►  │     │
│  │             │    │                                    │     │
│  └──────┬──────┘    └──────────────┬─────────────────────┘     │
│         │                          │                           │
│         ▼                          ▼                           │
│  ┌──────────────────────────────────────────────────────┐     │
│  │                    Database                            │     │
│  │  findings (source: scanner modules + audit-agent)      │     │
│  │  http_records, agent_runs                              │     │
│  └──────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## CLI

### Flag: `--audit-agent`

Available on both `vigolium agent swarm` and `vigolium agent autopilot`.

| Value | Behavior |
|-------|----------|
| *(not set)* | Disabled (unless enabled in config) |
| `--audit-agent` | Lite mode (6-phase fast audit) |
| `--audit-agent lite` | Lite mode (explicit) |
| `--audit-agent full` | Full mode (11-phase deep audit) |
| `--audit-agent off` | Disabled (overrides config) |

### Examples

```bash
# Swarm: targeted scan + background audit
vigolium agent swarm \
  -t https://example.com/api \
  --source ./backend \
  --audit-agent

# Swarm: full-scope scan + full audit
vigolium agent swarm \
  -t https://example.com \
  --source ./backend \
  --discover \
  --audit-agent full

# Autopilot: autonomous scan + background audit
vigolium agent autopilot \
  -t https://example.com \
  --source ./backend \
  --audit-agent lite

# Disable audit agent even if config enables it
vigolium agent swarm \
  -t https://example.com \
  --source ./backend \
  --audit-agent off
```

---

## API

The `audit_agent` field is available on both the swarm and autopilot run endpoints. See the full [Agent API reference](../api-references/agent.md) for all fields.

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `audit_agent` | string | `"lite"` (6-phase), `"full"` (11-phase), `"off"` (disable), or omit for config default |

### POST /api/agent/run/swarm

```bash
# Swarm with lite audit agent
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "discover": true,
    "audit_agent": "lite"
  }' | jq .

# Swarm with full 11-phase audit agent
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "discover": true,
    "code_audit": true,
    "audit_agent": "full"
  }' | jq .

# Explicitly disable audit agent (overrides server config)
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "source": "/home/user/src/my-app",
    "audit_agent": "off"
  }' | jq .
```

### POST /api/agent/run/autopilot

```bash
# Autopilot with lite audit agent
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "source": "/home/user/src/my-app",
    "audit_agent": "lite"
  }' | jq .

# Autopilot with full audit agent and custom focus
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "source": "/home/user/src/my-app",
    "focus": "authentication bypass",
    "audit_agent": "full"
  }' | jq .
```

### Response

Both endpoints return `202 Accepted` with a run ID. The audit agent runs as a background process within the agent run — its status is not separately tracked via the API, but its findings are ingested into the database on completion and its state is synced to the session directory.

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "swarm run started"
}
```

Audit agent findings can be queried after the run completes:

```bash
# List findings from the audit agent
curl -s http://localhost:9002/api/findings?source=audit-agent | jq .
```

---

## Configuration

Enable the audit agent globally via `vigolium-configs.yaml`:

```yaml
agent:
  audit_agent:
    enable: true              # default: false
    plugin_dir: ""            # default: ~/.vigolium/vig-audit-agent/plugin (auto-extracted from binary)
    mode: lite                # "lite" (6-phase) or "full" (11-phase), default: "lite"
    sync_interval: 30         # seconds between state syncs, default: 30
```

### Precedence

1. CLI `--audit-agent <value>` / API `"audit_agent": "<value>"` — highest priority
2. Config `agent.audit_agent.enable: true` — used when CLI/API doesn't specify
3. `--audit-agent off` / `"audit_agent": "off"` — overrides config

### Plugin Resolution

The audit agent plugin is resolved in this order:

1. **Config `plugin_dir`** — if set and exists, used directly
2. **Default path** `~/.vigolium/vig-audit-agent/plugin` — checked next
3. **Embedded extraction** — if neither exists, the plugin bundled in the Vigolium binary is extracted to `~/.vigolium/vig-audit-agent/` automatically

No manual installation is required — the embedded plugin ships with the Vigolium binary.

To use a custom or updated version of vig-audit-agent, set `plugin_dir` to your installation:

```yaml
agent:
  audit_agent:
    enable: true
    plugin_dir: ~/my-custom-audit-agent/plugins/vig-auditor-claude
```

---

## Audit Modes

### Lite (6 phases)

Fast parallel pipeline optimized for CI/CD and routine scans. Skips patch bypass analysis, spec gap analysis, cold verification, and variant analysis.

| Phase | Name | Description |
|-------|------|-------------|
| L1 | Intelligence | CVE/GHSA/OSV hunting, dependency audit, architecture inventory |
| L2 | Knowledge Base | Threat model, domain attack research, RFC specs |
| L3 | SAST | CodeQL structural + security scan, Semgrep Pro (parallel with L4) |
| L4 | Lite Probe | Targeted deep analysis of high-risk areas (parallel with L3) |
| L5 | Review + FP | Inline verification + false positive elimination |
| L6 | PoC + Report | Proof-of-concept generation and advisory-style report |

### Full (11 phases)

Comprehensive audit with adversarial review chambers. Best for pre-release audits, compliance, or high-value targets.

| Phase | Name | Description |
|-------|------|-------------|
| P1 | Intelligence Gathering | CVE/GHSA/OSV collection, dependency analysis |
| P2 | Patch Bypass Analysis | Test patch completeness, find alternate paths |
| P3 | Knowledge Base | Threat model, DFD/CFD slices, domain attack playbooks |
| P4 | Static Analysis | CodeQL + Semgrep Pro + SpotBugs (Java) |
| P5 | Enrichment & Filtering | Classify findings by exploitability |
| P6 | Spec Gap Analysis | RFC/spec compliance gaps |
| P7 | Deep Bug Hunting | Review chambers with specialized debate teams |
| P8 | False Positive Elimination | Cold verification (independent zero-context review) |
| P9 | Variant Analysis | Find related vulnerabilities across codebase |
| P10 | Exploitation | PoC building |
| P11 | Reporting | Advisory-style final report |

---

## Session Artifacts

The audit agent writes its artifacts to the source directory under `security/`:

```
<source_path>/
└── security/
    ├── audit-state.json          # Phase progress tracking (synced to session dir)
    ├── knowledge-base-report.md  # Accumulated intelligence
    ├── findings/                 # Per-finding markdown files
    │   ├── C-001.md              # Critical finding
    │   ├── H-001.md              # High finding
    │   ├── M-001.md              # Medium finding
    │   └── ...
    └── final-audit-report.md     # Advisory-style report
```

Vigolium syncs and copies these to its own session directory:

```
<session_dir>/
├── audit-agent/
│   ├── audit-state.json          # Synced every 30s
│   ├── findings/                 # Copied on completion
│   │   ├── C-001.md
│   │   └── ...
│   └── audit-agent-output.txt    # Raw Claude Code output
├── CLAUDE.md                     # Vigolium system prompt
├── skills/                       # Vigolium skills
└── ...                           # Other swarm/autopilot artifacts
```

---

## Finding Ingestion

When the audit agent completes, its findings are automatically parsed and stored in the Vigolium database:

- **Finding files** in `security/findings/*.md` are read
- **Severity** is derived from the filename prefix: `C-` = critical, `H-` = high, `M-` = medium, `L-` = low, `I-` = info
- **Title** is extracted from the first `# heading`
- **Description** is the full markdown content (truncated to 10KB)
- Findings are stored with `finding_source: "audit-agent"` and tagged `["audit-agent"]`
- Findings appear in the same database tables as native scanner findings, queryable via the API and UI

### Querying audit agent findings

```bash
# Via CLI
vigolium finding list --source audit-agent

# Via API
GET /api/findings?source=audit-agent
```

---

## Architecture

### Specialized Agents (23 total)

The audit agent uses a team of specialized agents, each handling a specific aspect of the audit:

| Agent | Phase | Role |
|-------|-------|------|
| advisory-hunter | P1 | CVE/GHSA/OSV intelligence gathering |
| patch-bypass-checker | P2 | Bypass analysis |
| knowledge-base-builder | P3 | Threat model + architecture |
| static-analyzer | P4 | SAST coordination |
| enrichment-filter | P5 | Finding classification |
| spec-gap-analyst | P6 | RFC compliance |
| probe-strategist | P7 | Multi-model hypothesis generation |
| backward-reasoner | P7 | Reverse-engineer attack paths |
| evidence-harvester | P7 | Proof construction |
| chamber-synthesizer | P7 | Debate moderator |
| attack-ideator | P7 | Exploit brainstorming |
| devils-advocate | P7 | Challenge assumptions |
| contradiction-reasoner | P7 | Spot inconsistencies |
| causal-verifier | P7 | Validate causality claims |
| code-tracer | P7 | Deep code path tracing |
| code-anatomist | P7 | Code structure analysis |
| cold-verifier | P8 | Independent zero-context verification |
| variant-scout | P9 | Find vulnerability variants |
| variant-hunter | P9 | Deep variant analysis |
| poc-builder | P10 | Proof-of-concept generation |
| report-assembler | P11 | Final report assembly |
| commit-archaeologist | P1 | Git history analysis |

### Bundled Skills (9)

The following security skills are embedded in the Vigolium binary for the audit agent:

- **audit** — Core 11-phase methodology orchestrator
- **codeql** — CodeQL database creation and query execution
- **semgrep** — Semgrep Pro rule management and scanning
- **fp-check** — False positive verification methodology
- **variant-analysis** — Cross-codebase vulnerability variant detection
- **vuln-report** — Advisory-style vulnerability report generation
- **differential-review** — Diff-based security review
- **security-threat-model** — STRIDE/DREAD threat modeling
- **sarif-parsing** — SARIF output parsing and enrichment

### Review Chambers (Phase 7)

The deep bug hunting phase uses a structured debate format where specialized agents argue for and against the exploitability of each finding:

```
probe-strategist → generates hypotheses
         │
         ├── attack-ideator (brainstorms exploits)
         ├── backward-reasoner (reverse-engineers paths)
         ├── evidence-harvester (builds proofs)
         │
         └── chamber-synthesizer (moderates debate)
                  │
                  ├── devils-advocate (challenges claims)
                  ├── contradiction-reasoner (spots inconsistencies)
                  └── causal-verifier (validates causality)
```

Only findings that survive this adversarial process proceed to the report.

---

## Comparison with Native Scanning

| Aspect | Vigolium Native (Swarm/Autopilot) | Audit Agent |
|--------|-----------------------------------|-------------|
| **Focus** | Network vulnerabilities (injection, XSS, SSRF, etc.) | Source code vulnerabilities (logic flaws, auth gaps, spec violations) |
| **Method** | Live HTTP scanning with payloads | Static analysis + AI reasoning |
| **False positive handling** | AI triage phase | Adversarial review chambers + cold verification |
| **Speed** | Minutes to hours | Hours (lite) to many hours (full) |
| **Requires** | Target URL | Source code path |
| **Runs as** | Foreground (main pipeline) | Background (separate process) |

The two approaches are complementary. Network scanning finds vulnerabilities that manifest in HTTP responses; the audit agent finds vulnerabilities that require understanding code semantics, business logic, and specification compliance.
