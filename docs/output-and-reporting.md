# Output and Reporting

Vigolium supports multiple output formats for scan results, discovery data, and spidering output. This guide covers the available formats, result structures, and how to query stored findings.

## Output Formats

The `--format` flag controls the output format. Three formats are available:

### Console (default)

```bash
vigolium scan --target https://example.com
```

Human-readable terminal output with color-coded severity levels. Findings are printed as they are discovered, with a summary table at the end of the scan. This is the default when no `--format` flag is specified.

Severity colors:
- **Critical** — Red
- **High** — Orange/Yellow
- **Medium** — Yellow
- **Low** — Blue
- **Info** — Gray

### JSONL

```bash
vigolium scan --target https://example.com --format jsonl
```

One JSON object per line, machine-readable. Each line is a self-contained JSON document representing a single finding or event. This format is well suited for piping to `jq`, ingesting into SIEMs, or processing with custom scripts.

Example usage with `jq`:

```bash
vigolium scan --target https://example.com --format jsonl | jq 'select(.severity == "high")'
```

### HTML

```bash
vigolium scan --target https://example.com --format html -o report.html
```

Interactive HTML report using an embedded ag-grid table. The report is a self-contained HTML file with sorting, filtering, and search capabilities. The `-o/--output` flag is required when using HTML format.

HTML format is supported for:
- Scan results (findings)
- Discovery phase output (discovered URLs and endpoints)
- Spidering phase output (crawled pages)

## Severity Scale

Findings are classified using five severity levels:

| Severity | Description |
|----------|-------------|
| **Critical** | Exploitable vulnerabilities with severe impact (e.g., RCE, SQL injection with data exfiltration) |
| **High** | Significant vulnerabilities that can lead to data compromise or unauthorized access |
| **Medium** | Vulnerabilities that require specific conditions to exploit or have limited impact |
| **Low** | Minor issues with minimal security impact |
| **Info** | Informational findings, such as technology fingerprints or configuration details |

## Confidence Scale

Each finding includes a confidence level indicating the reliability of the detection:

| Confidence | Description |
|------------|-------------|
| **Certain** | Confirmed with proof. The scanner has verified the vulnerability through direct evidence (e.g., a reflected payload executed, data was extracted). |
| **Firm** | Strong evidence supports the finding. Multiple indicators confirm the issue, but direct proof of exploitation was not obtained. |
| **Tentative** | Based on heuristic or pattern matching. The finding may be a false positive and should be manually verified. |

## Finding Structure

Each finding contains the following fields:

| Field | Description |
|-------|-------------|
| **Module** | The scanner module that produced the finding (e.g., `xss-reflected`, `sqli-error-based`) |
| **Severity** | Critical, High, Medium, Low, or Info |
| **Confidence** | Certain, Firm, or Tentative |
| **URL** | The target URL where the vulnerability was detected |
| **Parameter** | The specific parameter or insertion point that was tested (if applicable) |
| **Evidence** | Proof of the vulnerability — response excerpts, payloads, or other confirming data |
| **Description** | Human-readable explanation of the vulnerability and its potential impact |

## Saving Output

### Using the -o/--output Flag

Write output directly to a file:

```bash
# Save JSONL output
vigolium scan --target https://example.com --format jsonl -o results.jsonl

# Save HTML report
vigolium scan --target https://example.com --format html -o report.html

# Save console output
vigolium scan --target https://example.com -o results.txt
```

### Piping JSONL

JSONL output can be piped to other tools for processing:

```bash
# Filter high and critical findings
vigolium scan --target https://example.com --format jsonl | jq 'select(.severity == "high" or .severity == "critical")'

# Count findings by severity
vigolium scan --target https://example.com --format jsonl | jq -s 'group_by(.severity) | map({severity: .[0].severity, count: length})'

# Extract just URLs with findings
vigolium scan --target https://example.com --format jsonl | jq -r '.url'
```

## Discovery and Spidering Output

The discovery and spidering phases produce their own output alongside scan findings.

### Discovery Output

Discovery output includes URLs and endpoints found through wordlist-based content discovery, Wayback Machine data, and JavaScript analysis. Each discovered URL is reported with its HTTP status code and response metadata.

```bash
# Run only discovery and save results
vigolium scan --target https://example.com --only discovery --format html -o discovery-report.html
```

### Spidering Output

Spidering output includes pages found by the browser-based crawler, along with forms, links, and dynamic content discovered during crawling.

```bash
# Run only spidering and save results
vigolium scan --target https://example.com --only spidering --format html -o spider-report.html
```

Both phases support all three output formats (console, JSONL, HTML).

## OAST Interactions

Out-of-band Application Security Testing (OAST) findings come from DNS and HTTP callback interactions. When a scanner payload triggers an out-of-band request to the OAST server, the interaction is correlated back to the original test case.

OAST findings appear in output with:
- The original request that triggered the out-of-band interaction
- The type of interaction (DNS lookup, HTTP request)
- Timing information (when the callback was received)
- Correlation data linking the interaction to the specific payload

OAST interactions may arrive after the initial scan phase completes, as some out-of-band triggers have delayed execution. Vigolium waits for a configurable period after scanning to collect late-arriving callbacks.

If outbound DNS or HTTP is blocked by a firewall, OAST-based detections will not work. The scanner will still produce findings through other detection methods — OAST simply adds an additional layer of out-of-band detection.

## Querying Results from Database

All scan data is stored in the database (SQLite by default). You can query stored results using CLI commands without re-running scans.

### Listing Findings

```bash
# List all findings
vigolium findings list

# List findings for a specific project
vigolium findings list --project my-project
```

### Listing Traffic

```bash
# List recorded HTTP traffic
vigolium traffic list

# List traffic for a specific project
vigolium traffic list --project my-project
```

Results are scoped to the active project. Use `--project` to specify a project, or set a default with `vigolium project use <name>`. See the [projects documentation](projects.md) for details on multi-tenancy and project scoping.
