# Whitebox Agent Benchmark Suite

This document describes the whitebox agent benchmark suite — a fixture-driven test system that validates Vigolium's AI agent pipeline: raw output parsing, finding quality assessment, HTTP record conversion to scannable requests, and end-to-end scanning against vulnerable applications.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Test Layers](#test-layers)
- [Fixture System](#fixture-system)
- [Running Benchmarks](#running-benchmarks)
- [YAML Definition Format](#yaml-definition-format)
- [Generating Fixtures](#generating-fixtures)
- [Adding New Benchmarks](#adding-new-benchmarks)
- [Harness Reference](#harness-reference)
- [CI Integration](#ci-integration)
- [Troubleshooting](#troubleshooting)

---

## Overview

The whitebox agent benchmarks validate the four layers of the agent-driven scanning pipeline:

| Layer | What It Tests | Key Function | Assertion |
|-------|---------------|--------------|-----------|
| **1. Parsing** | `ParseFindings` / `ParseHTTPRecords` extract structured data from raw agent output | `agent.ParseFindings()`, `agent.ParseHTTPRecords()` | Strict |
| **2. Quality** | Agent-reported findings contain expected CWEs, vuln types, and severity distribution | `agent.ParseFindings()` + field inspection | Soft |
| **3. Handoff** | Agent HTTP records convert to `HttpRequestResponse` via `ToHTTPRequestResponse` | `agent.ToHTTPRequestResponse()` | Strict |
| **4. E2E** | Converted HTTP records produce real findings when scanned against Docker apps | Modules' `ScanPerInsertionPoint` / `ScanPerRequest` | Soft |

### Why Fixtures?

AI agent calls are expensive and non-deterministic. Rather than calling the LLM on every test run, the system:

1. Runs the agent once against source code stubs (the same stubs used by the SAST benchmark)
2. Caches the raw output as JSON fixture files
3. Runs all subsequent benchmark tests against those cached fixtures

This gives deterministic, fast, CI-friendly tests while still validating the full pipeline from raw LLM output through to vulnerability detection.

### Strict vs Soft Assertions

- **Strict** (Layers 1 & 3): These layers test our code — the JSON parser and the HRR converter. If they fail, we have a bug. The test should fail.
- **Soft** (Layers 2 & 4): These layers validate agent data quality and end-to-end detection. Agent output quality varies across models and regenerations. Soft assertions log warnings but do not fail the test.

### Relationship to Other Benchmarks

| Benchmark | Build Tag | Tests | Requirements |
|-----------|-----------|-------|--------------|
| SAST (Layers 1-3) | `sast` | Route extraction, SARIF parsing, handoff | ast-grep binary |
| SAST E2E (Layer 4) | `sast_e2e` | Full source-to-scan pipeline | ast-grep binary |
| **Agent (Layers 1-3)** | `agent_benchmark` | Parsing, quality, HRR conversion | None |
| **Agent E2E (Layer 4)** | `agent_benchmark` + `canary` | Scan converted records against Docker apps | Docker |
| **Agent Generate** | `agent_generate` | Populate fixture files from real LLM | Configured agent |

---

## Architecture

```
                  JSON Fixtures
        (test/testdata/agent-fixtures/*.json)
                        │
                        ▼
                ┌───────────────┐
                │ Agent Loader  │
                │  (harness/)   │
                │               │
                │ LoadAgentFixture      │  ← reads JSON
                │ LoadAgentParsing...   │  ← reads YAML, no defaults needed
                │ LoadAgentQuality...   │  ← defaults assertion to "soft"
                │ LoadAgentHandoff...   │  ← defaults record assertion to "strict"
                │ LoadAgentE2E...       │  ← defaults assertion to "soft"
                └───────┬───────┘
                        │
        ┌───────────────┼───────────────┐───────────┐
        ▼               ▼               ▼           ▼
┌───────────┐   ┌───────────┐   ┌───────────┐ ┌───────────┐
│  Layer 1  │   │  Layer 2  │   │  Layer 3  │ │  Layer 4  │
│  Parsing  │   │  Quality  │   │  Handoff  │ │   E2E     │
│           │   │           │   │           │ │           │
│ParseFind- │   │ParseFind- │   │ParseHTTP- │ │ParseHTTP- │
│ings()     │   │ings()     │   │Records()  │ │Records()  │
│ParseHTTP- │   │           │   │           │ │           │
│Records()  │   │Check CWEs │   │ToHTTPReq- │ │Rewrite    │
│           │   │Check types│   │Response() │ │URLs       │
│Assert     │   │Check sev  │   │           │ │           │
│counts     │   │distrib.   │   │Assert     │ │Scan with  │
│Assert     │   │           │   │method,    │ │active     │
│fields     │   │           │   │host,      │ │modules    │
│           │   │           │   │convert-   │ │           │
│           │   │           │   │ible count │ │           │
└─────┬─────┘   └─────┬─────┘   └─────┬─────┘ └─────┬─────┘
      │               │               │             │
      ▼               ▼               ▼             ▼
  Strict          Soft           Strict         Soft
  assertions      assertions     assertions     assertions
```

### Key Design Decisions

1. **Fixture-first**: Agent output is cached as JSON. Tests never call the LLM. This makes all layers fast and deterministic.
2. **One fixture per (stub × template) pair**: Each fixture captures the raw output from running a specific prompt template against a specific source code stub.
3. **YAML-driven definitions**: Test expectations are declared in YAML files. Adding a new test case is a YAML addition, not a code change.
4. **Reuses SAST source stubs**: The same framework stubs in `test/testdata/sast-stubs/` serve as agent input, avoiding duplication.
5. **Shared harness**: Type definitions and loaders live in `test/benchmark/harness/`, following the same pattern as the SAST benchmark (`sast_types.go` / `sast_loader.go`).

---

## Directory Structure

```
test/
├── benchmark/
│   ├── harness/
│   │   ├── agent_types.go             # Agent definition types
│   │   └── agent_loader.go            # Agent fixture + YAML loaders
│   │
│   ├── definitions/
│   │   └── whitebox/
│   │       └── agent/                 # Agent benchmark definitions
│   │           ├── parsing/           #   Layer 1: parsing
│   │           │   ├── gin-findings-parsing.yaml
│   │           │   ├── gin-records-parsing.yaml
│   │           │   ├── flask-findings-parsing.yaml
│   │           │   └── flask-records-parsing.yaml
│   │           ├── quality/           #   Layer 2: finding quality
│   │           │   ├── gin-security-review-quality.yaml
│   │           │   ├── flask-security-review-quality.yaml
│   │           │   ├── express-security-review-quality.yaml
│   │           │   ├── django-security-review-quality.yaml
│   │           │   └── fastapi-security-review-quality.yaml
│   │           ├── handoff/           #   Layer 3: HRR conversion
│   │           │   ├── gin-endpoint-handoff.yaml
│   │           │   ├── flask-endpoint-handoff.yaml
│   │           │   ├── express-endpoint-handoff.yaml
│   │           │   └── fastapi-endpoint-handoff.yaml
│   │           └── e2e/               #   Layer 4: end-to-end scanning
│   │               └── vampi-agent-scan.yaml
│   │
│   └── agent/                         # Go test files
│       ├── helpers.go                 #   Path resolution, search helpers (no build tag)
│       ├── parsing_test.go            #   Layer 1 (build tag: agent_benchmark)
│       ├── quality_test.go            #   Layer 2 (build tag: agent_benchmark)
│       ├── handoff_test.go            #   Layer 3 (build tag: agent_benchmark)
│       ├── e2e_test.go                #   Layer 4 (build tags: agent_benchmark + canary)
│       └── generate_test.go           #   Fixture generator (build tag: agent_generate)
│
└── testdata/
    ├── sast-stubs/                    # Shared source stubs (also used by SAST benchmark)
    │   ├── gin/
    │   ├── flask/
    │   ├── express/
    │   ├── django/
    │   └── fastapi/
    │
    └── agent-fixtures/                # Cached agent output (JSON)
        ├── gin-security-code-review.json
        ├── gin-endpoint-discovery.json
        ├── gin-api-input-gen.json
        ├── flask-security-code-review.json
        ├── flask-endpoint-discovery.json
        ├── flask-api-input-gen.json
        ├── express-security-code-review.json
        ├── express-endpoint-discovery.json
        ├── django-security-code-review.json
        ├── django-endpoint-discovery.json
        ├── fastapi-security-code-review.json
        └── fastapi-endpoint-discovery.json
```

---

## Test Layers

### Layer 1: Parsing

Tests the JSON extraction and parsing logic that converts raw agent text output (which may contain markdown fences, preamble text, or bare arrays) into structured `AgentFinding` or `AgentHTTPRecord` slices.

**What it validates:**

- `agent.ParseFindings()` correctly extracts findings from raw output
- `agent.ParseHTTPRecords()` correctly extracts HTTP records from raw output
- Finding/record counts match the expected values from YAML definitions
- Required fields (title, severity, CWE, method, URL) are non-empty
- Markdown fence stripping works (```` ```json ... ``` ````)
- Bare JSON arrays parse correctly (`[{...}]` without a wrapper object)
- Empty and malformed input returns appropriate errors

**Frameworks covered:**

| Fixture | Schema | Count |
|---------|--------|-------|
| `gin-security-code-review.json` | findings | 3 |
| `gin-endpoint-discovery.json` | http_records | 8 |
| `flask-security-code-review.json` | findings | 4 |
| `flask-endpoint-discovery.json` | http_records | 7 |

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestParsing_All` | Runs all parsing definitions from YAML |
| `TestParsing_GinFindings` | Gin findings parsing |
| `TestParsing_GinRecords` | Gin HTTP records parsing |
| `TestParsing_FlaskFindings` | Flask findings parsing |
| `TestParsing_FlaskRecords` | Flask HTTP records parsing |
| `TestParsing_EmptyOutput` | Empty/whitespace input → error |
| `TestParsing_MalformedJSON` | Invalid JSON → error |
| `TestParsing_MarkdownFences` | JSON inside ``` fences parses correctly |
| `TestParsing_BareArray` | Bare `[{...}]` array parses correctly |

### Layer 2: Quality

Validates that agent-reported findings contain meaningful security information. These are soft assertions — they measure agent quality, not code correctness.

**What it validates:**

- Finding count falls within expected range (`min_findings` / `max_findings`)
- Expected CWE identifiers are present in the findings (searched by `AgentFinding.CWE`)
- Expected vulnerability types appear in finding titles or tags
- Severity distribution meets minimum thresholds (e.g., at least 1 high, at least 2 medium)

**Frameworks covered (5):**

| Fixture | Stub | Expected CWEs | Key Vuln Types |
|---------|------|---------------|----------------|
| `gin-security-code-review.json` | gin | CWE-20 | Input validation |
| `flask-security-code-review.json` | flask | CWE-79 | XSS, reflection |
| `express-security-code-review.json` | express | CWE-79, CWE-798 | XSS, hardcoded credentials |
| `django-security-code-review.json` | django | CWE-79 | XSS, reflection |
| `fastapi-security-code-review.json` | fastapi | CWE-306 | Missing authentication |

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestQuality_All` | Runs all quality definitions from YAML |
| `TestQuality_GinSecurityReview` | Gin quality validation |
| `TestQuality_FlaskSecurityReview` | Flask quality validation |
| `TestQuality_ExpressSecurityReview` | Express quality validation |
| `TestQuality_DjangoSecurityReview` | Django quality validation |
| `TestQuality_FastAPISecurityReview` | FastAPI quality validation |

### Layer 3: Handoff

Tests the conversion of agent-reported HTTP records into Vigolium's internal `HttpRequestResponse` format via `agent.ToHTTPRequestResponse()`. This is the bridge between agent output and the DAST scanning engine.

**What it validates:**

- `agent.ToHTTPRequestResponse()` successfully converts records with method, URL, headers, and body
- Convertible and skipped record counts match expectations
- Specific records can be found by method and URL prefix
- Converted requests have the correct HTTP method
- Host headers are preserved after conversion
- Empty URLs produce an error (not a nil pointer)
- Empty methods default to GET

**Frameworks covered (4):**

| Fixture | Records | Convertible | Validated Records |
|---------|---------|-------------|-------------------|
| `gin-endpoint-discovery.json` | 8 | 8 | GET /users, POST /users, GET /health, GET /api/v2/items |
| `flask-endpoint-discovery.json` | 7 | 7 | GET /users, POST /users, GET /health |
| `express-endpoint-discovery.json` | 8 | 8 | GET /api/v1/users, POST /api/v1/users, POST /login |
| `fastapi-endpoint-discovery.json` | 10 | 10 | GET /users, POST /users, GET /items, OPTIONS /config |

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestHandoff_All` | Runs all handoff definitions from YAML |
| `TestHandoff_GinEndpoints` | Gin endpoint conversion |
| `TestHandoff_FlaskEndpoints` | Flask endpoint conversion |
| `TestHandoff_ExpressEndpoints` | Express endpoint conversion |
| `TestHandoff_FastAPIEndpoints` | FastAPI endpoint conversion |
| `TestHandoff_EmptyURL` | Empty URL → error |
| `TestHandoff_DefaultMethod` | Empty method → GET |

### Layer 4: E2E

Tests the full pipeline: load cached HTTP records from a fixture, rewrite their URLs to point at a running Docker vulnerable app, convert them to HRR, create insertion points, and run active scanner modules. This validates that agent-generated requests actually produce findings against real applications.

**What it validates:**

- Cached HTTP records load and parse correctly
- URL rewriting updates host, scheme, and Host header
- Records convert to HRR and produce insertion points
- Active scanner modules find vulnerabilities when given agent-generated requests
- Minimum finding count meets the (soft) threshold

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestE2E_All` | Runs all E2E definitions from YAML |
| `TestE2E_VAmPI` | VAmPI agent scan (SQLi + XSS modules) |

---

## Fixture System

### Fixture Format

Each fixture is a JSON file with three top-level fields:

```json
{
  "metadata": {
    "stub": "gin",
    "template": "security-code-review",
    "agent_name": "claude",
    "output_schema": "findings",
    "generated_at": "2026-02-15T10:30:00Z",
    "agent_model": "claude-sonnet-4-20250514"
  },
  "raw_output": "```json\n{\"findings\": [{...}]}\n```",
  "parsed": {
    "finding_count": 3,
    "record_count": 0
  }
}
```

| Field | Description |
|-------|-------------|
| `metadata.stub` | Source stub directory name (e.g., `gin`, `flask`) |
| `metadata.template` | Prompt template ID used to generate output |
| `metadata.agent_name` | Agent backend name from config |
| `metadata.output_schema` | Expected output format: `findings` or `http_records` |
| `metadata.generated_at` | UTC timestamp when the fixture was generated |
| `metadata.agent_model` | Model identifier (optional, for provenance) |
| `raw_output` | The complete raw text output from the agent, including any markdown fences or preamble |
| `parsed.finding_count` | Pre-computed finding count (for quick reference) |
| `parsed.record_count` | Pre-computed record count (for quick reference) |

### Fixture Matrix

The current fixture set covers 5 frameworks and 2-3 templates each:

| Stub | Template | Schema | Fixture File |
|------|----------|--------|-------------|
| gin | security-code-review | findings | `gin-security-code-review.json` |
| gin | endpoint-discovery | http_records | `gin-endpoint-discovery.json` |
| gin | api-input-gen | http_records | `gin-api-input-gen.json` |
| flask | security-code-review | findings | `flask-security-code-review.json` |
| flask | endpoint-discovery | http_records | `flask-endpoint-discovery.json` |
| flask | api-input-gen | http_records | `flask-api-input-gen.json` |
| express | security-code-review | findings | `express-security-code-review.json` |
| express | endpoint-discovery | http_records | `express-endpoint-discovery.json` |
| django | security-code-review | findings | `django-security-code-review.json` |
| django | endpoint-discovery | http_records | `django-endpoint-discovery.json` |
| fastapi | security-code-review | findings | `fastapi-security-code-review.json` |
| fastapi | endpoint-discovery | http_records | `fastapi-endpoint-discovery.json` |

### Staleness

Fixtures include a `generated_at` timestamp. The generator (`generate_test.go`) skips fixtures that are less than 30 days old by default. To force regeneration, delete the fixture file and re-run the generator.

---

## Running Benchmarks

### Make Targets

| Command | Layers | Timeout | Requirements |
|---------|--------|---------|--------------|
| `make test-agent-benchmark` | 1 + 2 + 3 | 10 min | None |
| `make test-agent-parsing` | 1 only | 5 min | None |
| `make test-agent-quality` | 2 only | 5 min | None |
| `make test-agent-handoff` | 3 only | 5 min | None |
| `make test-agent-benchmark-e2e` | 1 + 2 + 3 + 4 | 20 min | Docker |
| `make benchmark-agent-generate` | (generator) | 30 min | Configured agent (real LLM) |

### Running Individual Tests

```bash
# All agent layers (1-3, no Docker needed)
make test-agent-benchmark

# Layer 1 only (parsing)
make test-agent-parsing

# Layer 2 only (quality)
make test-agent-quality

# Layer 3 only (handoff)
make test-agent-handoff

# Single framework parsing
go test -tags=agent_benchmark -v -run TestParsing_GinFindings ./test/benchmark/agent/...

# Single framework quality
go test -tags=agent_benchmark -v -run TestQuality_FlaskSecurityReview ./test/benchmark/agent/...

# Single framework handoff
go test -tags=agent_benchmark -v -run TestHandoff_ExpressEndpoints ./test/benchmark/agent/...

# Parsing edge cases
go test -tags=agent_benchmark -v -run TestParsing_MarkdownFences ./test/benchmark/agent/...
go test -tags=agent_benchmark -v -run TestParsing_EmptyOutput ./test/benchmark/agent/...

# Layer 4 E2E (requires Docker + VAmPI running)
make apps-up
make test-agent-benchmark-e2e

# E2E against VAmPI only
go test -tags="agent_benchmark canary" -v -run TestE2E_VAmPI ./test/benchmark/agent/...
```

### Example Output

```
=== RUN   TestParsing_All
=== RUN   TestParsing_All/gin-security-code-review.json
    parsing_test.go:31: [gin-security-code-review.json] Parsed 3 findings
    parsing_test.go:31:   Finding: title="Missing Input Validation on User ID Parameter" severity=medium cwe=CWE-20
    parsing_test.go:31:   Finding: title="Missing Authorization Checks on Admin Endpoints" severity=high cwe=CWE-862
    parsing_test.go:31:   Finding: title="Use of ANY Method on Health Endpoint" severity=low cwe=CWE-749
--- PASS: TestParsing_All/gin-security-code-review.json (0.00s)

=== RUN   TestQuality_All/flask-security-code-review.json
    quality_test.go:25: [flask-security-code-review.json] 4 findings (assertion=soft)
    quality_test.go:25: [flask-security-code-review.json] Found CWE CWE-79: "Reflected Parameter in JSON Response"
    quality_test.go:25: [flask-security-code-review.json] Found vuln type "xss": "Reflected Parameter in JSON Response"
    quality_test.go:25: [flask-security-code-review.json] Severity distribution: map[high:2 medium:2]
--- PASS: TestQuality_All/flask-security-code-review.json (0.00s)

=== RUN   TestHandoff_All/gin-endpoint-discovery.json
    handoff_test.go:27: [gin-endpoint-discovery.json] Parsed 8 records, expecting 8 convertible, 0 skipped
    handoff_test.go:27: [gin-endpoint-discovery.json] Converted: GET http://localhost:8080/users?q=test&page=1 → method=GET host=localhost:8080
--- PASS: TestHandoff_All/gin-endpoint-discovery.json (0.00s)
```

---

## YAML Definition Format

### Parsing Definition (Layer 1)

Each file in `definitions/whitebox/agent/parsing/` declares expected parsing results for one fixture:

```yaml
fixture: gin-security-code-review.json  # File in test/testdata/agent-fixtures/
output_schema: findings                 # "findings" or "http_records"
expected:
  finding_count: 3                      # Exact count of parsed findings
  record_count: 0                       # Exact count of parsed records
  error: false                          # Whether parsing should error
  required_fields:                      # Fields that must be non-empty
    - field: title
      non_empty: true
    - field: severity
      non_empty: true
    - field: cwe
      non_empty: true
```

### Quality Definition (Layer 2)

Each file in `definitions/whitebox/agent/quality/` declares expected quality metrics:

```yaml
fixture: flask-security-code-review.json
source_stub: flask                      # Source stub name (informational)
template: security-code-review          # Template ID (informational)
assertion: soft                         # soft (default) or strict

expected:
  min_findings: 1                       # Minimum finding count
  max_findings: 20                      # Maximum finding count
  expected_cwes:                        # CWE IDs that should appear
    - "CWE-79"
  expected_vuln_types:                  # Strings to search in titles/tags
    - "xss"
  severity_distribution:                # Minimum count per severity level
    medium: 2
    high: 2
```

### Handoff Definition (Layer 3)

Each file in `definitions/whitebox/agent/handoff/` declares expected conversion results:

```yaml
fixture: gin-endpoint-discovery.json
expected:
  convertible_count: 8                  # Records that convert successfully
  skipped_count: 0                      # Records that fail conversion
  records:                              # Specific records to validate
    - method: GET
      url_prefix: "http://localhost:8080/users"
      has_host: true                    # Host header should be present
      assertion: strict                 # strict (default) or soft
    - method: POST
      url_prefix: "http://localhost:8080/users"
      has_host: true
      assertion: strict
```

### E2E Definition (Layer 4)

Each file in `definitions/whitebox/agent/e2e/` declares an end-to-end scan test:

```yaml
fixture: flask-api-input-gen.json       # Fixture with http_records
app:
  name: vampi                           # Target app name
  compose_file: vampi/docker-compose.yaml
  base_url: "http://localhost:5002"     # Base URL of running app
  wait_path: "/"                        # Endpoint to poll for readiness
scan_config:
  modules:                              # Active module IDs to use
    - "sqli-error-based"
    - "xss-reflected"
  max_records: 10                       # Limit records processed (0 = all)
expected:
  min_findings: 1                       # Minimum total findings
  assertion: soft                       # soft (default) or strict
```

---

## Generating Fixtures

Fixture generation runs the real agent against source stubs and writes the JSON fixture files. This is expensive (real LLM API calls) and is designed to be run infrequently.

### Prerequisites

1. A configured agent in `~/.vigolium/vigolium-configs.yaml`:

```yaml
agent:
  default_agent: claude
  agents:
    claude:
      command: claude
      args: ["-p", "-"]
```

2. The agent backend must be installed and authenticated (e.g., Claude CLI, OpenCode, etc.).

### Running the Generator

```bash
# Using the default agent (claude)
make benchmark-agent-generate

# Using a specific agent
VIGOLIUM_AGENT=opencode make benchmark-agent-generate

# Using a custom config path
VIGOLIUM_CONFIG=/path/to/config.yaml make benchmark-agent-generate

# Or directly with go test
go test -tags=agent_generate -v -timeout 30m ./test/benchmark/agent/...
```

### What the Generator Does

For each (stub × template) pair in the matrix:

1. Checks if the fixture file exists and is less than 30 days old. If so, skips.
2. Loads the source stub from `test/testdata/sast-stubs/<stub>/`.
3. Runs `engine.Run()` with the specified prompt template and source code.
4. Captures the raw output.
5. Pre-parses the output to populate `parsed.finding_count` / `parsed.record_count`.
6. Writes the fixture JSON to `test/testdata/agent-fixtures/<stub>-<template>.json`.

### After Generation

After generating fixtures, you should:

1. Review the raw output in each fixture file for correctness.
2. Update the YAML definition counts to match the actual fixture data.
3. Run `make test-agent-benchmark` to verify everything passes.
4. Commit the fixture files — they are checked into the repository.

---

## Adding New Benchmarks

### Adding a New Fixture (New Stub × Template Pair)

1. **Add the pair to the generator matrix** in `test/benchmark/agent/generate_test.go`:

```go
matrix := []struct {
    stub     string
    template string
    schema   string
}{
    // ... existing pairs ...
    {"spring", "security-code-review", "findings"},
}
```

2. **Create the source stub** (if it doesn't exist) at `test/testdata/sast-stubs/spring/`.

3. **Run the generator** to create the fixture:

```bash
VIGOLIUM_AGENT=claude go test -tags=agent_generate -v -run "TestGenerate_AllFixtures/spring" ./test/benchmark/agent/...
```

4. **Create YAML definitions** for each layer you want to test (see below).

### Adding a New Parsing Test (Layer 1)

Create a YAML file at `test/benchmark/definitions/whitebox/agent/parsing/<name>.yaml`:

```yaml
fixture: spring-security-code-review.json
output_schema: findings
expected:
  finding_count: 5
  record_count: 0
  error: false
  required_fields:
    - field: title
      non_empty: true
```

No Go code changes needed — `TestParsing_All` automatically picks up new YAML files.

### Adding a New Quality Test (Layer 2)

Create a YAML file at `test/benchmark/definitions/whitebox/agent/quality/<name>.yaml`:

```yaml
fixture: spring-security-code-review.json
source_stub: spring
template: security-code-review
assertion: soft
expected:
  min_findings: 1
  max_findings: 20
  expected_cwes:
    - "CWE-89"
  expected_vuln_types:
    - "injection"
```

### Adding a New Handoff Test (Layer 3)

Create a YAML file at `test/benchmark/definitions/whitebox/agent/handoff/<name>.yaml`:

```yaml
fixture: spring-endpoint-discovery.json
expected:
  convertible_count: 6
  skipped_count: 0
  records:
    - method: GET
      url_prefix: "http://localhost:8080/api/users"
      has_host: true
      assertion: strict
```

### Adding a New E2E Test (Layer 4)

Create a YAML file at `test/benchmark/definitions/whitebox/agent/e2e/<name>.yaml`:

```yaml
fixture: spring-api-input-gen.json
app:
  name: dvwa
  compose_file: dvwa/docker-compose.yaml
  base_url: "http://localhost:8080"
  wait_path: "/"
scan_config:
  modules:
    - "sqli-error-based"
  max_records: 5
expected:
  min_findings: 1
  assertion: soft
```

---

## Harness Reference

### Agent Types

| Type | Description |
|------|-------------|
| `AgentFixture` | Cached agent output: metadata, raw output, pre-parsed counts |
| `AgentFixtureMetadata` | Provenance: stub, template, agent name, schema, timestamp, model |
| `AgentFixtureParsed` | Pre-computed finding/record counts |
| `AgentParsingDefinition` | Layer 1: fixture path, output schema, expected counts and required fields |
| `AgentParsingExpected` | Finding count, record count, error flag, required fields |
| `AgentRequiredField` | Field name + non-empty constraint |
| `AgentQualityDefinition` | Layer 2: fixture, stub, template, assertion mode, expected quality metrics |
| `AgentQualityExpected` | Min/max findings, expected CWEs, vuln types, severity distribution |
| `AgentHandoffDefinition` | Layer 3: fixture, expected convertible/skipped counts, specific records |
| `AgentHandoffExpected` | Convertible count, skipped count, expected records |
| `AgentExpectedRecord` | Method, URL prefix, has-host flag, assertion mode |
| `AgentE2EDefinition` | Layer 4: fixture, target app config, scan config, expected findings |
| `AgentE2EApp` | App name, compose file, base URL, wait path |
| `AgentE2EScanConfig` | Module IDs, max records |
| `AgentE2EExpected` | Min findings, assertion mode |

### Loader Functions

| Function | Description |
|----------|-------------|
| `LoadAgentFixture(path)` | Load a JSON fixture file |
| `LoadAgentParsingDefinition(path)` | Load one parsing YAML |
| `LoadAgentParsingDefinitionsFromDir(dir)` | Load all parsing YAMLs from directory |
| `LoadAgentQualityDefinition(path)` | Load one quality YAML (defaults assertion to "soft") |
| `LoadAgentQualityDefinitionsFromDir(dir)` | Load all quality YAMLs from directory |
| `LoadAgentHandoffDefinition(path)` | Load one handoff YAML (defaults record assertion to "strict") |
| `LoadAgentHandoffDefinitionsFromDir(dir)` | Load all handoff YAMLs from directory |
| `LoadAgentE2EDefinition(path)` | Load one E2E YAML (defaults assertion to "soft") |
| `LoadAgentE2EDefinitionsFromDir(dir)` | Load all E2E YAMLs from directory |
| `AgentDefinitionsDir()` | Returns path to `definitions/whitebox/agent/` |
| `AgentFixturesDir()` | Returns path to `test/testdata/agent-fixtures/` |

### Test Helpers

| Function | Description |
|----------|-------------|
| `fixturePath(name)` | Resolves to `test/testdata/agent-fixtures/{name}` |
| `definitionsDir()` | Resolves to `test/benchmark/definitions/whitebox/agent` |
| `stubPath(framework)` | Resolves to `test/testdata/sast-stubs/{framework}` |
| `findFindingByCWE(findings, cwe)` | Search findings by CWE identifier |
| `findFindingByVulnType(findings, vulnType)` | Search findings by title or tag substring |
| `findRecordByMethod(records, method, urlPrefix)` | Search records by method and URL prefix |
| `buildSeverityDistribution(findings)` | Count findings per severity level |

### Exported Agent Functions Under Test

| Function | Package | Used In |
|----------|---------|---------|
| `ParseFindings(raw)` | `pkg/agent` | Layers 1, 2 |
| `ParseHTTPRecords(raw)` | `pkg/agent` | Layers 1, 3, 4 |
| `ToHTTPRequestResponse(rec)` | `pkg/agent` | Layers 3, 4 |
| `ToDBFinding(af, moduleID, scanUUID)` | `pkg/agent` | (Available for future use) |

---

## CI Integration

### Recommended Strategy

| Trigger | What to Run | Timeout | Notes |
|---------|------------|---------|-------|
| On every PR | `make test-agent-benchmark` | 10 min | No Docker, no LLM, no external deps |
| Nightly | `make test-agent-benchmark-e2e` | 20 min | Requires Docker apps running |
| Monthly / manual | `make benchmark-agent-generate` | 30 min | Requires configured agent, regenerates fixtures |

### Example GitHub Actions Workflow

```yaml
- name: Run agent benchmarks (Layers 1-3, no external deps)
  run: make test-agent-benchmark
  timeout-minutes: 10

- name: Run agent E2E benchmarks (nightly, Docker)
  if: github.event_name == 'schedule'
  run: |
    make apps-up
    sleep 30
    make test-agent-benchmark-e2e
    make apps-down
  timeout-minutes: 20
```

---

## Troubleshooting

### Fixture file not found

```
failed to load fixture test/testdata/agent-fixtures/gin-security-code-review.json: no such file or directory
```

Fixtures must exist before running tests. Either:
- Check out the repository with LFS (fixtures are committed)
- Run `make benchmark-agent-generate` to regenerate them (requires configured agent)

### Parsing count mismatch

```
expected 3 findings, got 4
```

The fixture was regenerated with a different agent model that produced more findings. Update the YAML definition's `finding_count` to match the actual fixture, or regenerate the fixture.

### Quality soft assertion warnings

```
SOFT ASSERTION FAILED: expected CWE CWE-89 not found in findings
```

This is a soft assertion — the test still passes. It means the agent did not report the expected CWE. This may happen when:
- The fixture was generated with a different model
- The source stub doesn't clearly exhibit the vulnerability
- The prompt template doesn't emphasize that vulnerability class

To fix: either update the YAML expectations or regenerate the fixture with a more capable model.

### Handoff conversion errors

```
[gin-endpoint-discovery.json] Skipped: GET  (error: URL is required)
```

The agent reported an HTTP record with an empty URL. This is expected — some agent outputs include placeholder records. The `skipped_count` in the YAML definition should account for these.

### E2E target app not reachable

```
target app vampi not reachable at http://localhost:5002/, skipping
```

The Docker app must be running before E2E tests. Start it with:

```bash
make vampi-up
# Wait for it to start
make vampi-status
# Then run E2E
make test-agent-benchmark-e2e
```

### Generator fails with "agent not found"

```
agent "claude" not found in configuration
```

The generator requires a configured agent backend. Create or update `~/.vigolium/vigolium-configs.yaml`:

```yaml
agent:
  default_agent: claude
  agents:
    claude:
      command: claude
      args: ["-p", "-"]
```

Verify the agent command is installed and in your PATH.

### Build tag errors

```
No packages found for open file ... This file may be excluded due to its build tags
```

This is a gopls editor warning, not a build error. The agent benchmark files use the `agent_benchmark` build tag, which gopls doesn't include by default. Add it to your editor's gopls configuration:

```json
{
  "gopls": {
    "build.buildFlags": ["-tags=agent_benchmark"]
  }
}
```

Or just run the tests — `go test -tags=agent_benchmark` handles this correctly.
