# Known-Issue Scan

The known-issue scan combines Nuclei templates with Vigolium's native,
in-process secret detector. Nuclei checks known CVEs and common
misconfigurations; the secret detector scans stored textual response bodies for
tokens, credentials, and other leaked secrets without launching an external
binary or writing temporary files.

In a full native run, this phase executes after dynamic assessment. It consumes
the records and paths collected by harvesting, spidering, discovery, and active
modules.

## How It Works

1. Resolve the in-scope hosts for the current scan.
2. Read distinct paths from the project database.
3. Build host-level or path-enriched Nuclei targets.
4. Run the selected Nuclei templates under the shared rate limits.
5. Independently scan stored response bodies with `pkg/secretscan`.
6. Group repeated values in live output and deduplicate persisted findings.

The Nuclei and secret-detector legs each receive a fresh phase-duration budget,
but both remain bounded by `--scanning-max-duration` when a total scan cap is
set.

## Configuration

```yaml
known_issue_scan:
  tags: []
  exclude_tags: [dos]
  severities: [critical, high]
  templates_dir: ""
  enrich_targets: true
  severity_overrides:
    config-json-exposure-fuzz: medium
```

| Option | Description |
|---|---|
| `tags` | Include only Nuclei templates with these tags |
| `exclude_tags` | Exclude matching template tags |
| `severities` | Nuclei severity filter; the balanced default is critical/high |
| `templates_dir` | Custom Nuclei template directory |
| `enrich_targets` | Run templates on discovered path prefixes, not only host roots |
| `severity_overrides` | Remap recorded severity by template ID |

When known-issue scan is the only requested phase, Vigolium widens the default
severity selection to all levels. An explicit
`--known-issue-scan-severities` value still wins.

Discovery's inline secret detector is controlled separately:

```yaml
discovery:
  engine:
    disable_secret_scan: false
```

## CLI Usage

```bash
# Isolate the phase
vigolium scan https://example.com --only known-issue-scan
vigolium run known-issue-scan -t https://example.com

# Filter Nuclei templates
vigolium run known-issue-scan -t https://example.com \
  --known-issue-scan-severities critical,high \
  --known-issue-scan-tags cve,rce

# Skip it in a full scan
vigolium scan https://example.com --skip known-issue-scan
```

Aliases accepted by `run`, `--only`, and `--skip` include `cve`, `kis`, and
`known-issues`.
