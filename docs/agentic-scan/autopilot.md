# Autopilot Mode

Autopilot is vigolium's fully autonomous agentic scan mode. The AI agent gets a mission brief and full tool access, then drives the entire vulnerability assessment — deciding what to scan, interpreting results, and iterating until done.

## Execution Flow

```
vigolium agent autopilot -t https://example.com --source ./src --archon deep
  │
  ├─ Create session directory: ~/.vigolium/agent-sessions/agt-<uuid>/
  ├─ Copy vigolium-scanner skill to session dir
  │
  ├─ [Background] Start archon-audit (if --archon + --source)
  │   ├─ Launch: claude --plugin-dir <archon-harness> --print "/archon-audit:archon:deep"
  │   ├─ Sync audit-state.json + findings every 30s to session dir
  │   ├─ Track progress in child AgentRun (mode=archon)
  │   └─ On completion: import findings → clean up source archon/ dir
  │
  └─ [Foreground] Start autonomous agent
      ├─ Build mission brief (target, source context, instructions)
      ├─ Launch via SDK protocol (full tool access)
      ├─ Agent runs vigolium CLI commands autonomously
      └─ Save output to session dir
```

Both the main agent and archon-audit run concurrently. The main agent focuses on dynamic scanning while archon-audit performs deep source code analysis.

## Autonomous Agent

The main autopilot agent receives a comprehensive mission brief and full CLI tool access. It operates with a recommended 4-phase workflow, but can adapt freely:

1. **Recon** — understand the target (tech stack, endpoints, authentication)
2. **Analysis & Scanning** — run vigolium scans, craft custom payloads
3. **Verification** — confirm findings with targeted requests
4. **Reporting** — summarize results

The agent can run any shell command including `vigolium scan-url`, `vigolium scan-request`, `curl`, `jq`, and standard CLI tools. Findings are saved to the database by the vigolium commands the agent executes.

### Tool Access

The agent runs with full Claude Code SDK tool access:

- **Read, Grep, Glob** — explore source code and configuration
- **Bash** — run vigolium commands, curl, network tools
- **Edit, Write** — create custom scripts or extensions
- **Agent** — spawn sub-agents for parallel research

### Source-Aware Mode

When `--source` is provided, the agent's system prompt includes the source code path and instructions to:
- Read source code to understand application architecture
- Identify routes, auth flows, and vulnerability sinks
- Use code knowledge to craft targeted attacks against the running target

## Background Archon-Audit

The `--archon` flag launches a parallel archon-audit process that performs deep whitebox security analysis independently of the main agent. This is the most powerful configuration for comprehensive assessments.

### Modes

| Mode | Flag | Phases | Typical Duration | Use Case |
|------|------|--------|-----------------|----------|
| Lite | `--archon lite` | 3 | Minutes | Quick code review during short scans |
| Scan | `--archon scan` | 6 | ~1 hour | Standard audit with SAST and validation |
| Deep | `--archon deep` | 11 | Hours | Full security audit with adversarial review |

### Deep Mode Phases (11-phase)

| Phase | Name | Description |
|-------|------|-------------|
| 1 | Commit Archaeology | Analyze git history for silent security fixes, undisclosed CVEs |
| 2 | Patch Bypass | Attempt to bypass identified patches |
| 3 | Knowledge Base | Build architecture model, trust boundaries, attack surface map |
| 4 | SAST | Run CodeQL and Semgrep with custom rules |
| 5 | Deep Probe | Multi-hypothesis probing of high-risk areas |
| 6 | Spec Gap Analysis | Find gaps between spec/docs and implementation |
| 7 | Enrichment | Enrich SAST findings with reachability analysis and data flow |
| 8 | Adversarial Debate | Multi-agent debate chambers validate/disprove findings |
| 9 | Cold Verification | Independent re-verification of chamber findings |
| 10 | Variant Hunting | Search for variants of confirmed vulnerabilities |
| 11 | Report Assembly | Consolidate findings with severity, PoC status, remediation |

### How It Works

1. Vigolium extracts the embedded archon-audit harness (agents, commands, skills) to `~/.vigolium/archon-audit/`
2. Launches a Claude Code process with the archon plugin: `claude --plugin-dir <harness> --print "/archon-audit:archon:{mode}"`
3. The archon agent works in the source directory, writing output to `<source>/archon/`
4. Every 30 seconds, vigolium syncs:
   - `audit-state.json` — phase progress, timestamps, statistics
   - `findings-draft/` — individual finding files as they're produced
5. Progress is tracked in a child `AgentRun` record linked to the parent autopilot run
6. On completion:
   - All findings are parsed and imported into the database
   - Findings include rich metadata: CWE IDs, adversarial verdicts, confidence levels, code locations, reproduction steps
   - The `<source>/archon/` directory is removed (copy preserved in session dir)

### Finding Format

Archon findings are richer than standard scanner findings:

| Field | Example | Stored In |
|-------|---------|-----------|
| Finding ID | `archon:p8-001` | `module_id` |
| Title | SSRF via Webhook Job Address | `module_name` |
| Severity | high (after adversarial review) | `severity` |
| Confidence | firm (CONFIRMED verdict) | `confidence` |
| CWE | CWE-918 | `cwe_id` |
| Full analysis | Markdown with evidence, data flow, repro steps | `description` |
| Source file | `src/jobservice/webhook_job.go` | `source_file` |
| Code locations | `src/jobservice/webhook_job.go:103-120` | `matched_at` |
| Tags | `archon`, `phase-8`, `valid`, `poc-theoretical` | `tags` |

Findings appear in the database with `finding_source=archon` and `module_type=whitebox`.

### Manual Import

Archon output can also be imported manually without running autopilot:

```bash
# Import from a local archon output folder
vigolium import /path/to/archon-output-harbor/

# The folder must contain audit-state.json and findings-draft/
```

This creates an `AgentRun` record (mode=`archon`) and imports all findings.

## Session Directory

Each autopilot run creates a session directory at `~/.vigolium/agent-sessions/agt-<uuid>/`:

```
agt-<uuid>/
├── output.md                    # Main agent raw output
├── archon-audit/                # Synced archon-audit artifacts (if --archon)
│   ├── audit-state.json         # Phase progress
│   ├── findings-draft/          # Finding markdown files
│   ├── final-audit-report.md    # Consolidated report
│   ├── attack-pattern-registry.json
│   └── ...                      # Other archon artifacts
├── archon-audit-output.txt      # Raw archon process output
├── skills/
│   └── vigolium-scanner/        # Embedded scanner skill for agent
└── CLAUDE.md                    # System prompt (for SDK agent discovery)
```

## Configuration

### YAML Config

```yaml
agent:
  audit_agent:
    enable: false              # Enable by default (overridable with --archon off)
    mode: lite                 # Default mode: lite, scan, or deep
    plugin_dir: ""             # Custom harness path (default: ~/.vigolium/archon-audit/)
    sync_interval: 30          # Seconds between state syncs
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--source` | — | Path to application source code |
| `--files` | — | Specific files to include (relative to `--source`) |
| `--focus` | — | Focus area hint (e.g., "API injection", "auth bypass") |
| `--instruction` | — | Custom instruction for the agent |
| `--instruction-file` | — | Load instruction from file |
| `--timeout` | 6h | Maximum session duration |
| `--max-commands` | 100 | Maximum CLI commands the agent can execute |
| `--archon` | — | Background archon-audit mode: `lite`, `scan`, `deep`, or `off` |
| `--agent` | (from config) | Agent backend to use |
| `--resume` | — | Resume from a previous session directory |
| `--browser` | false | Enable browser automation |
| `--dry-run` | false | Render prompt without executing |
| `--show-prompt` | false | Print rendered prompt to stderr |

### API

```
POST /api/agent/run/autopilot
```

```json
{
  "target": "https://example.com",
  "agent": "claude",
  "source": "/path/to/source",
  "focus": "API injection",
  "instruction": "Focus on authentication endpoints",
  "max_commands": 50,
  "timeout": "30m",
  "archon": "deep",
  "stream": true
}
```

## Examples

### Dynamic-only scan (no source code)

```bash
vigolium agent autopilot -t https://example.com
```

The agent performs pure dynamic testing — probing endpoints, analyzing responses, running vigolium scans.

### Source-aware scan

```bash
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/express-app
```

The agent reads source code to identify routes and sinks, then crafts targeted attacks against the running target.

### Full whitebox + dynamic assessment

```bash
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/express-app --archon deep
```

Two agents work in parallel:
- **Main agent**: dynamic scanning with source code context
- **Archon-audit**: 11-phase deep whitebox audit (commit archaeology, SAST, adversarial debate, cold verification, variant hunting)

Findings from both are stored in the same database, queryable via `vigolium finding`.

### CI/CD quick check

```bash
vigolium agent autopilot -t https://staging.example.com \
  --source ./src --archon lite \
  --max-commands 20 --timeout 10m
```

Fast scan with a lite 3-phase code review running in parallel.
