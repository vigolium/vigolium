# KnownIssueScan — Known Vulnerability and Secret Detection

KnownIssueScan checks targets for known CVEs, common misconfigurations, and exposed secrets using Nuclei templates and the Kingfisher secret detection engine. It runs after the Discovery phase, leveraging all paths and endpoints discovered in earlier phases to maximize coverage.

## Why KnownIssueScan Matters

Many real-world breaches exploit publicly disclosed vulnerabilities (CVEs) that remain unpatched, or secrets accidentally committed to response bodies. KnownIssueScan systematically tests for these known issues across the entire discovered attack surface — catching low-hanging fruit that custom fuzzing-based modules are not designed to detect.

## How It Works

```
Stored HTTP Records (from phases 0-4)
  │
  ▼
┌─────────────────────────────────────────────────┐
│  Target Enrichment                               │
│  • GetDistinctPaths() from database              │
│  • Enrich targets with discovered paths          │
│    (enrich_targets: true by default)             │
│  • Or host-level only when disabled              │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│  Nuclei Template Engine                          │
│  • CVE detection (known vulnerability checks)    │
│  • Misconfiguration detection                    │
│  • Technology fingerprinting                     │
│  • Custom template support (templates_dir)       │
│  • Tag-based filtering (include/exclude)         │
│  • Severity filtering (critical → info)          │
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│  Kingfisher Secret Detection                     │
│  • Scans stored response bodies                  │
│  • Detects API keys, tokens, credentials         │
│  • Filters out secret_detect passive module      │
│    to avoid duplicates in dynamic-assessment phase│
└────────────────────┬────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────┐
│  Post-Phase Processing                           │
│  DeduplicateFindings() groups findings with      │
│  identical (module_id, severity, matched_at URL) │
└─────────────────────────────────────────────────┘
```

## Configuration

KnownIssueScan is configured in `vigolium-configs.yaml` under the `known_issue_scan` key:

```yaml
known_issue_scan:
  tags: []              # nuclei template tags to include (empty = all)
  exclude_tags: [dos]   # tags to exclude (default: dos)
  severities: []        # filter by severity: critical, high, medium, low, info (empty = all)
  templates_dir: ""     # custom templates directory (empty = built-in)
  enrich_targets: true  # enrich targets with paths from previous phases
```

### Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `tags` | `[]` (all) | Include only templates matching these tags |
| `exclude_tags` | `[dos]` | Exclude templates matching these tags |
| `severities` | `[]` (all) | Filter results by severity level |
| `templates_dir` | built-in | Path to custom Nuclei templates |
| `enrich_targets` | `true` | Append discovered paths to target URLs for broader coverage |

## Runtime Defaults

| Parameter | Default |
|-----------|---------|
| Concurrency | 50 |
| Rate limit | 100 req/s |
| Timeout | 30 minutes |

## Phase Execution Detail

1. Queries distinct paths from the database via `GetDistinctPaths()`.
2. Builds target URLs — either path-enriched (default, `enrich_targets: true`) or host-level only.
3. Runs Nuclei templates against enriched targets with the configured concurrency and rate limits.
4. Runs Kingfisher secret scanning on stored response bodies.
5. Each finding is saved to the database with `ModuleType: "known-issue-scan"` and `FindingSource: "known-issue-scan"`.
6. **Post-phase dedup**: calls `DeduplicateFindings()` to group findings with identical `(module_id, severity, matched_at URL)`.

## CLI Usage

Run only the KnownIssueScan phase:

```bash
vigolium scan --url https://example.com --only known-issue-scan
```

Skip the KnownIssueScan phase:

```bash
vigolium scan --url https://example.com --skip known-issue-scan
```

## Integration

KnownIssueScan runs as Phase 5 in the native scan pipeline, after Discovery and before DynamicAssessment. It consumes the HTTP records and discovered paths stored by earlier phases. Its findings are deduplicated before the DynamicAssessment phase begins, preventing overlap with the active/passive module scanning that follows.

```
Discovery (Phase 4)
  → Paths and records stored in DB
  → KnownIssueScan (Phase 5)
    → Nuclei templates + Kingfisher secrets
    → DeduplicateFindings()
  → DynamicAssessment (Phase 6)
```
