# Getting Started with Vigolium

This guide walks you through installing Vigolium, running your first scan, and understanding the results.

## Prerequisites

- **Go 1.26+**
- **git**
- **make**

No C dependencies are required (`CGO_ENABLED=0`).

## Installation

### From Source

```bash
git clone https://github.com/vigolium/vigolium.git
cd vigolium
make deps
make build
```

The binary is output to `bin/vigolium`. Never use `go build` directly -- `make build` injects version metadata and ensures a clean build.

### Install to $GOPATH/bin

```bash
make install
```

This places the `vigolium` binary on your `$PATH` (assuming `$GOPATH/bin` is in your `$PATH`).

Verify the installation:

```bash
vigolium version
```

## Your First Scan

### Quick Single-URL Scan

The fastest way to scan a single URL:

```bash
vigolium scan-url https://example.com
```

### Full Balanced Scan

Run a complete scan with discovery, spidering, and dynamic-assessment phases:

```bash
vigolium scan -t https://example.com
```

### Fast Dynamic-Assessment-Only Scan

Skip discovery and spidering for a faster, dynamic-assessment-only scan:

```bash
vigolium scan -t https://example.com --strategy lite
```

## Understanding Output

By default, Vigolium prints findings to the console. Each finding includes:

- **Severity** -- Critical, High, Medium, Low, or Info
- **Confidence** -- Certain, Firm, or Tentative

### Machine-Readable Output

Use JSONL format for scripting and CI/CD integration:

```bash
vigolium scan -t https://example.com --format jsonl
```

### HTML Reports

Generate a self-contained HTML report:

```bash
vigolium scan -t https://example.com --format html -o report.html
```

## Scanning from Different Input Sources

### From a File of URLs

Create a file with one target per line and pass it with `-T`:

```bash
vigolium scan -T targets.txt
```

### From an OpenAPI Spec

Import endpoints from an OpenAPI/Swagger definition:

```bash
vigolium scan --input api.yaml -I openapi -t https://api.example.com
```

### From a curl Command

Pipe a curl command directly into Vigolium:

```bash
echo 'curl -X POST https://api.example.com/login -d "user=admin&pass=test"' | vigolium scan --input - -I curl -t https://api.example.com
```

## Common Options

| Flag | Description |
|------|-------------|
| `-t, --target` | Target URL (base URL for scope) |
| `-T, --target-file` | File containing target URLs (one per line; repeatable) |
| `--strategy` | Scanning strategy (e.g., `lite` for dynamic-assessment-only) |
| `--only` | Run only specific phases (e.g., `--only discovery,dynamic-assessment`) |
| `--skip` | Skip specific phases (e.g., `--skip spidering`) |
| `-m, --modules` | Fuzzy-select active modules by ID or name |
| `--module-id` | Select exact active or passive module IDs |
| `--module-tag` | Filter modules by tag (e.g., `xss`, `spring`, `light`) |
| `--format` | Output format, including `console`, `jsonl`, `html`, `sqlite`, and `fs` |
| `-o, --output` | Output path (required for file-based report formats) |
| `--scanning-profile` | Use a named profile or YAML profile path |
| `--intensity` | Native scan preset: `quick`, `balanced`, or `deep` |
| `-c, --concurrency` | Number of concurrent scan workers (generated config default 40; raw CLI fallback 50) |
| `-r, --rate-limit` | Maximum HTTP requests per second (default 100) |

## Configuration

Vigolium reads its configuration from `~/.vigolium/vigolium-configs.yaml`. Use `vigolium config set <key> <value>` to update individual settings, or edit the config file directly.

## Next Steps

- [Scanning Strategies](native-scan/strategies.md) -- learn about the available scanning strategies
- [Scanning Modes Overview](native-scan/scanning-modes-overview.md) -- compare all scanning modes
- [Configuration Reference](configuration.md) -- full configuration options
- [Agent Mode](agentic-scan/agent-mode.md) -- AI-powered scanning with autonomous agents
- [Set Up an AI Provider](getting-started/setup-agent.md) -- configure Codex OAuth, API keys, or a local model
- [Server and Ingestion](server-and-ingestion.md) -- run Vigolium as a REST API server
