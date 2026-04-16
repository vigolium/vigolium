# Scanning Modes Overview

Vigolium supports multiple scanning modes depending on what you have available: just a URL, source code, an AI agent, or all of the above. This document helps you pick the right mode and understand the execution pipeline.

## Scanning Modes at a Glance

| Mode | What You Need | Command | What It Does |
|------|---------------|---------|--------------|
| **Lite** | URL | `vigolium scan -t URL --strategy lite` | Dynamic-assessment only, no discovery |
| **Balanced** | URL | `vigolium scan -t URL` | Discovery + spidering + known-issue-scan + dynamic-assessment |
| **Deep** | URL | `vigolium scan -t URL --strategy deep` | Adds external harvesting to balanced |
| **Whitebox** | URL + source code | `vigolium scan -t URL --source ./app --strategy whitebox` | SAST route extraction + discovery + known-issue-scan + dynamic-assessment |
| **Whitebox (remote)** | URL + git repo | `vigolium scan -t URL --source-url GIT_URL --strategy whitebox` | Same as whitebox, clones the repo first |
| **SAST-only** | Source code | `vigolium scan -t URL --source ./app --only sast` | Static analysis only, no dynamic scanning |
| **Agent** | Source code + AI backend | `vigolium agent query --prompt-template X --source ./app` | AI-powered code review |
| **Extension** | URL + JS/YAML extensions | `vigolium run extension -t URL --ext script.js` | Run only custom extension modules |
| **Full Combined** | URL + source code + AI backend | Multi-step (see [full-scan.md](full-scan.md)) | SAST + agent + dynamic for maximum coverage |

## Decision Guide

```
Do you have application source code?
├── No
│   ├── Quick single-URL test? ──────────── vigolium scan-url <URL>
│   ├── Want fast results? ──────────────── vigolium scan -t URL --strategy lite
│   ├── Standard scan? ─────────────────── vigolium scan -t URL
│   ├── Maximum external recon? ─────────── vigolium scan -t URL --strategy deep
│   └── Custom extension scripts only? ──── vigolium run extension -t URL --ext script.js
│
└── Yes
    ├── Do you have an AI agent configured?
    │   ├── No
    │   │   ├── Static analysis only? ───── vigolium scan -t URL --source ./app --only sast
    │   │   ├── Static + dynamic? ──────── vigolium scan -t URL --source ./app --strategy whitebox
    │   │   └── Remote repo? ──────────── vigolium scan -t URL --source-url GIT_URL --strategy whitebox
    │   │
    │   └── Yes
    │       ├── One-shot code review? ──── vigolium agent query --prompt-template security-code-review --source ./app
    │       └── Full combined scan? ────── See full-scan.md
```

## Phase Execution Pipeline

Phases execute in this order. Each strategy enables a subset of these phases:

```
1. Heuristics Check     Pre-flight probe (detect WAF, redirects, tech stack)
2. External Harvesting  Query Wayback, CommonCrawl, AlienVault OTX, URLScan, VirusTotal
3. Spidering            Browser-based crawling (Chromium), SPA support, form filling
4. SAST                 Static analysis via ast-grep (route extraction, security rules)
5. Discovery            Content discovery (brute-force dirs/files, JS analysis)
6. KnownIssueScan       Known Issue Scan (Nuclei templates + Kingfisher secrets)
7. DynamicAssessment    Active + passive scanner modules against all discovered endpoints
8. Extension            Custom JS/YAML extension modules (when --only extension or --ext is used)
```

## Strategy Comparison

| Phase | Lite | Balanced | Deep | Whitebox |
|-------|:----:|:--------:|:----:|:--------:|
| External Harvesting | - | - | yes | - |
| Discovery | - | yes | yes | yes |
| Spidering | - | yes | yes | - |
| KnownIssueScan | - | yes | yes | yes |
| DynamicAssessment | yes | yes | yes | yes |
| Source-Aware (SAST) | - | - | - | yes |

**Balanced** is the default strategy when `--strategy` is not specified.

## Phase Aliases

Several phases have short aliases that work with `--only` and `--skip`:

| Alias | Canonical Phase |
|-------|-----------------|
| `deparos` | `discovery` |
| `discover` | `discovery` |
| `spitolas` | `spidering` |
| `ext` | `extension` |
| `audit` | `dynamic-assessment` |
| `dast` | `dynamic-assessment` |
| `assessment` | `dynamic-assessment` |

## Phase Control: `--only` and `--skip`

These two flags are **mutually exclusive**. Using both produces an error.

### `--only <phase>` — Run a Single Phase

Disables all other phases and turns off heuristics.

```bash
# Run only content discovery
vigolium scan -t https://example.com --only discovery

# Run only SAST analysis
vigolium scan -t https://example.com --source ./app --only sast

# Run only dynamic-assessment (skip all discovery)
vigolium scan -t https://example.com --only dynamic-assessment
# Run only custom extensions (skip built-in modules)
vigolium scan -t https://example.com --only extension
# Or using the alias:
vigolium scan -t https://example.com --only ext
```

Valid values: `ingestion`, `discovery` (`deparos`, `discover`), `spidering` (`spitolas`), `external-harvest`, `known-issue-scan`, `sast`, `dynamic-assessment` (`dast`, `audit`, `assessment`), `extension` (`ext`)

### `--skip <phase>` — Skip Specific Phases

Disables named phases while keeping all others enabled by the strategy.

```bash
# Skip spidering in a balanced scan
vigolium scan -t https://example.com --skip spidering

# Skip both discovery and known-issue-scan
vigolium scan -t https://example.com --skip discovery --skip known-issue-scan
```

Valid values: `discovery` (`deparos`, `discover`), `external-harvest`, `spidering` (`spitolas`), `known-issue-scan`, `sast`, `dynamic-assessment` (`dast`, `audit`, `assessment`), `extension` (`ext`)

### `vigolium run <phase>` Shortcut

`vigolium run <phase>` is a direct alias for `vigolium scan --only <phase>`:

```bash
# These are equivalent:
vigolium run discovery -t https://example.com
vigolium scan -t https://example.com --only discovery

# Run only extension modules:
vigolium run extension -t https://example.com --ext my-scanner.js
# Equivalent to:
vigolium scan -t https://example.com --only extension --ext my-scanner.js
```

## Scanning Profiles

A **scanning strategy** only toggles phases on/off. A **scanning profile** goes further — it bundles strategy, pace, scope, discovery, spidering, and module configuration into a single YAML file that overrides the main config when selected.

### Using a Profile

```bash
# Use the built-in standard profile
vigolium scan -t https://example.com --scanning-profile standard

# Use a custom profile by name (resolved from profiles_dir)
vigolium scan -t https://example.com --scanning-profile api-pentest

# Use a profile by path
vigolium scan -t https://example.com --scanning-profile ~/profiles/custom.yaml

# List available profiles and strategies
vigolium strategy ls
```

### Creating a Custom Profile

Create a YAML file in `~/.vigolium/profiles/`. The first line can contain a `# description:` comment that appears in `vigolium strategy ls`.

A profile can override any combination of these config sections (omitted sections keep their main config values):

```yaml
# description: Fast API-focused scan with minimal discovery
scanning_strategy:
  default_strategy: lite

scanning_pace:
  concurrency: 100
  rate_limit: 200

discovery:
  mode: files_only

known_issue_scan:
  enrich_targets: false         # host-level only (faster)

dynamic-assessment:
  max_findings_per_module: 10   # cap noisy modules
  enabled_modules:
    active_modules:
      - sqli-error-based
      - xss-reflected-brutelogic
    passive_modules:
      - all

scope:
  path:
    include:
      - "/api/*"
```

Overridable sections: `scanning_strategy`, `scanning_pace`, `discovery`, `spidering`, `known_issue_scan`, `dynamic-assessment`, `external_harvester`, `mutation_strategy`, `scope`.

### Profile Configuration

Set a default profile or change the profiles directory in `vigolium-configs.yaml`:

```yaml
scanning_strategy:
  scanning_profile: ""                    # empty = no profile, use default_strategy
  profiles_dir: ~/.vigolium/profiles/     # directory for profile YAML files
```

### Override Precedence

Profiles slot between CLI flags and the main config file:

1. CLI flags (`--strategy`, `-c`, `--discover-max-time`, etc.)
2. `--scanning-profile` / `scanning_strategy.scanning_profile`
3. Main config file (`vigolium-configs.yaml`)
4. Built-in defaults

## Detailed Guides

- [Blackbox Scanning](blackbox-scan.md) — Dynamic scanning without source code
- [Extension Scanning](extension-scan.md) — Custom JS/YAML extension modules
- [Whitebox Scanning](whitebox-scan.md) — Static analysis with source code
- [Whitebox + Agent Scanning](whitebox-agent-scan.md) — AI-enhanced source code analysis
- [Full Combined Scan](full-scan.md) — Maximum coverage with all capabilities
