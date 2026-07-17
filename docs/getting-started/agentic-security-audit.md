# Agentic Security Audit

`vigolium agent audit` is Vigolium's unified white-box security-audit command.
It audits source code with one or both supported harnesses and imports the
resulting findings into the active project.

The top-level `vigolium audit` command is an alias.

## Drivers

| Driver | Runtime | Select it with |
|---|---|---|
| `audit` | Embedded vigolium-audit harness driven by the `claude` or `codex` coding CLI | `--driver audit` |
| `piolium` | User-installed Pi runtime and piolium extension | `--driver piolium` |

`--driver auto` is the default. It runs the audit driver when the resolved
coding CLI is available and falls back to piolium only when that CLI is
missing during preflight. It does not hide a mid-run audit failure.

Use `--driver both` to run audit and piolium sequentially under one parent
agentic-scan record. Vigolium keeps per-driver child records and performs a
project-wide finding deduplication pass afterward.

## Prerequisites

For the audit driver, install and authenticate one supported coding CLI:

```bash
claude --version
# or
codex --version
```

Choose it explicitly when needed:

```bash
vigolium audit --source . --driver audit --agent codex
```

For piolium, install Pi and the piolium extension, then authenticate Pi:

```bash
bun install -g @earendil-works/pi-coding-agent
pi install git:git@github.com:vigolium/piolium.git
pi login
```

See [Set Up an AI Provider](setup-agent.md) and the
[audit BYOK guide](../agentic-scan/audit-byok.md) for API-key and OAuth
options.

## Run an Audit

```bash
# Default: balanced mode, automatic driver selection
vigolium audit --source ~/src/your-app

# Force one driver
vigolium audit --driver audit --agent codex --source ~/src/your-app
vigolium audit --driver piolium --source ~/src/your-app

# Run both perspectives
vigolium audit --driver both --source ~/src/your-app --intensity deep
```

`--source` accepts a local directory, git URL, `gs://` source archive, or local
archive. `--commit-depth 0` requests full history when cloning a git URL.

## Modes and Intensity

The portable intensity presets are:

| Intensity | Resolved audit work |
|---|---|
| `quick` | `lite` |
| `balanced` | `balanced` |
| `deep` | `deep,confirm` |

Use `--mode` for one explicit mode, or `--modes` for a chain:

```bash
vigolium audit --source . --mode lite
vigolium audit --source . --modes deep,refresh,confirm --driver audit
vigolium audit --source . --mode longshot --driver piolium
vigolium audit --list-modes
```

Shared modes include `lite`, `balanced`, `deep`, `revisit`, `confirm`, and
`merge`. Some modes are driver-specific; the command validates and routes
them. A mode unknown to both drivers is an error.

## Output and Retention

Audit findings are imported into the active project. Capture the returned
agentic-scan UUID and query exactly that run:

```bash
vigolium finding --agentic-scan <uuid>
vigolium agent session <uuid> --full
```

The audit driver's source-tree output is retained at
`<source>/vigolium-results/` by default. Pass `--clean-raw` to remove that copy
after the session copy has been saved. Each driver's session artifacts remain
under `~/.vigolium/agent-sessions/<uuid>/`.

For a throwaway database plus a self-contained HTML report:

```bash
vigolium audit --source . --stateless
vigolium audit --source . --stateless -o reports/audit-{ts}.html
vigolium audit --source . --stateless --output-dir audit-bundle-{ts}
```

`--output-dir` bundles the HTML report and raw audit tree. It is valid only
with `--stateless`.

## Pair with a Network Scan

Autopilot and swarm can prepare source-audit context before dynamic testing:

```bash
vigolium agent autopilot -t https://example.com --source ./src --audit balanced
vigolium agent swarm -t https://example.com --source ./src --audit deep --triage
```

Use the standalone audit command when you want explicit driver selection,
mode chaining, stateless reports, or source-only review.

## Next Steps

- [Vigolium Audit reference](../agentic-scan/vigolium-audit.md)
- [Piolium reference](../agentic-scan/piolium-audit.md)
- [Audit BYOK](../agentic-scan/audit-byok.md)
- [Agentic Scan](agentic-scan.md)
