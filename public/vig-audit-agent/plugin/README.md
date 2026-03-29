# vig-auditor-claude

Claude Code plugin for full security audit orchestration. Provides `/vig-run:*` commands that delegate all phase methodology to the shared `audit` skill.

## Installation

```bash
claude --plugin-dir ~/.vig-audit-agent/plugins/vig-auditor-claude
```

## Requirements

The `audit` skill (`~/.vig-audit-agent/skills/audit/`) must be present — it is included in this toolkit at `skills/audit/`.

## Usage

Once installed, invoke the audit commands from within Claude Code:

```bash
# Run a full audit on the current repository
/vig-run:run

# Run a full audit scoped to a specific directory
/vig-run:run src/auth/

# Run only a specific phase (e.g., Phase 4 — Static Analysis)
/vig-run:run 4

# Run a fast lite audit (6 phases instead of 11)
/vig-run:lite

# Run a lite audit scoped to a specific directory
/vig-run:lite src/auth/

# Check current audit progress
/vig-run:status

# Run an incremental audit on changes since last audited commit
/vig-run:diff

# Run an incremental audit on a specific commit range
/vig-run:diff abc1234..HEAD
```

## Commands

| Command | Description |
|---------|-------------|
| `/vig-run:run [scope]` | Full 11-phase audit — resumes from last checkpoint if state exists, runs a single phase if specified |
| `/vig-run:lite [scope]` | Fast 6-phase lite audit — fewer agents, single probe round, no variant analysis |
| `/vig-run:status` | Show completed/pending phases, findings count, commit drift |
| `/vig-run:diff` | Incremental audit on changes since last audited commit |

## Phases

All phase methodology is defined in the `audit` skill (`~/.vig-audit-agent/skills/audit/SKILL.md`).

### Full Audit (`/vig-run:run`) — 11 Phases

| Phase | Name |
|-------|------|
| 1 | Intelligence gathering — advisories, commit archaeology, dependencies |
| 2 | Patch bypass analysis — silent fixes, alternate entry points |
| 3 | Knowledge base — threat model, DFD/CFD slices, domain attack research |
| 4 | Static analysis — CodeQL, Semgrep, custom rules, structural extraction |
| 5 | Deep probe — multi-round hypothesis generation with 6-agent teams |
| 6 | Spec gap analysis — RFC/spec compliance |
| 7 | Enrichment and security relevance filter |
| 8 | Review chambers — multi-agent debate for deep bug hunting |
| 9 | P9-LITE FP elimination — inline fp-check + cold verification |
| 10 | Variant analysis |
| 11 | Exploitation and final reporting |

### Lite Audit (`/vig-run:lite`) — 6 Phases

A streamlined pipeline that trades depth for speed. Produces the same output format as the full audit.

| Phase | Name | Maps to Full |
|-------|------|-------------|
| L1 | Intelligence gathering — advisories only | P1 (no commit archaeology) |
| L2 | Knowledge base — threat model, DFD/CFD slices | P3 (skip Mode B/C research) |
| L3 | Static analysis — built-in suites only | P4 (no custom rules) |
| L4 | Lite deep probe — single team, 1 round | P5 (3 agents, no multi-round) |
| L5 | Review chamber + FP check — single chamber, max 2 rounds | P7 + P8 + P9 (inline only) |
| L6 | PoC building + report | P11 |

**Skipped entirely in lite mode**: Patch bypass (P2), Spec gap (P6), Cold verification (P9 Stage 2), Variant analysis (P10)

```
L1 → L2 → [L3 + L4] parallel → L5 → L6
```

## State Management

Audit state is stored in `security/audit-state.json` in the target repository. It tracks phase completion status, timestamps, last audited commit SHA, and session lifecycle events for interruption recovery.

> [!TIP]
> Use `/vig-run:diff` to re-audit only the phases affected by recent commits without repeating completed phases.

## Agents

Five specialized subagents registered under the `vig-run:*` namespace:

| Agent | Phase | Model |
|-------|-------|-------|
| `vig-run:advisory-hunter` | 1 -- Intelligence Gathering | `claude-haiku-4-5-20251001` |
| `vig-run:patch-bypass-checker` | 2 -- Patch Bypass Analysis | `claude-opus-4-6` |
| `vig-run:knowledge-base-builder` | 3 -- Knowledge Base | `claude-opus-4-6` |
| `vig-run:static-analyzer` | 4 -- Static Analysis | `claude-sonnet-4-6` |
| `vig-run:deep-auditor` | 7 -- Deep Bug Hunting | `claude-opus-4-6` |

## Dependencies

**Required:**
- `audit` — 10-phase methodology and references

**Invoked by the `audit` skill:**
- `semgrep`, `codeql` — SAST execution
- `sarif-parsing` — SARIF merging and deduplication
- `fp-check` — false positive elimination
- `variant-analysis` — variant hunting
- `vuln-report` — individual finding reports
- `supply-chain-risk-auditor` — dependency analysis
- `security-threat-model` — formal threat modeling
- `spec-to-code-compliance` — RFC gap analysis
- `sharp-edges`, `wooyun-legacy`, `insecure-defaults`, `last30days` — domain attack research (Modes A/B/C)
- `zeroize-audit` — secret handling in C/C++/Rust
- `ffuf-web-fuzzing` — dynamic testing
- `agentic-actions-auditor` — GitHub Actions review
