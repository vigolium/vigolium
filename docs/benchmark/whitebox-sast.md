# Whitebox SAST Benchmark Suite

This document describes the whitebox SAST benchmark suite — a deterministic, CI-friendly test system that validates Vigolium's static analysis toolchain: ast-grep route extraction, SARIF parsing, and the SAST-to-DAST handoff pipeline.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Test Layers](#test-layers)
- [Running Benchmarks](#running-benchmarks)
- [YAML Definition Format](#yaml-definition-format)
- [Source Stubs](#source-stubs)
- [SARIF Fixtures](#sarif-fixtures)
- [Adding New Benchmarks](#adding-new-benchmarks)
- [Harness Reference](#harness-reference)
- [CI Integration](#ci-integration)
- [Troubleshooting](#troubleshooting)

---

## Overview

The whitebox SAST benchmarks validate the three layers of the source-aware scanning pipeline:

| Layer | What It Tests | Key Package |
|-------|---------------|-------------|
| **1. Route Extraction** | ast-grep scans framework source code and extracts routes | `pkg/toolexec/astgrep/` |
| **2. SARIF Parsing** | Semgrep, Trivy, and generic SARIF outputs parse into findings | `pkg/toolexec/sourcetools/` |
| **3. SAST→DAST Handoff** | Extracted routes convert into `HttpRequestResponse` with insertion points | `pkg/httpmsg/` |
| **4. E2E Pipeline** | Full chain from source stub to scannable insertion points | All of the above |

Unlike the existing DAST-focused whitebox benchmarks (DVWA, VAmPI, Juice Shop), these tests require **no Docker containers, no network access, and no running applications**. They validate the SAST toolchain itself using static fixture data.

### Relationship to Other Benchmarks

| Benchmark | Build Tag | Tests | Requirements |
|-----------|-----------|-------|--------------|
| Whitebox (DAST) | `canary` | Active/passive modules against Docker apps | Docker |
| XBOW | `xbow` | DAST modules against CTF-style apps | Docker + XBOW_SOURCE_DIR |
| Blackbox | `blackbox` | DAST modules against external sites | Internet |
| **SAST (Layers 1-3)** | `sast` | Route extraction, SARIF parsing, handoff | ast-grep binary (Layer 1 only) |
| **SAST E2E (Layer 4)** | `sast_e2e` | Full source-to-scan pipeline | ast-grep binary |

---

## Architecture

```
                     YAML Definitions
          (extraction/*.yaml, sarif/*.yaml, handoff/*.yaml)
                            │
                            ▼
                    ┌───────────────┐
                    │  SAST Loader  │
                    │  (harness/)   │
                    │               │
                    │ LoadSASTExtraction │  ← defaults assertion to "strict"
                    │ LoadSASTSARIF      │  ← defaults format to "sarif"
                    │ LoadSASTHandoff    │
                    └───────┬───────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
    ┌───────────┐   ┌───────────┐   ┌───────────┐
    │  Layer 1  │   │  Layer 2  │   │  Layer 3  │
    │ Extraction│   │   SARIF   │   │  Handoff  │
    │           │   │           │   │           │
    │ NewScanner│   │ ReadFixture│  │ ParseRaw  │
    │ ScanDir   │   │ ParseSARIF│   │ Request   │
    │ WithFrame │   │ ParseSemg │   │ CreateAll │
    │ work()    │   │ ParseTrivy│   │ Insertion │
    │ MatchesTo │   │           │   │ Points()  │
    │ Routes()  │   │ ToFinding │   │           │
    └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
          │               │               │
          ▼               ▼               ▼
    Assert routes    Assert findings   Assert method,
    match YAML       match YAML        URI, host,
    expectations     expectations      insertion points

                      ┌───────────┐
                      │  Layer 4  │  (sast_e2e tag)
                      │   E2E     │
                      │           │
                      │ ScanDir → │
                      │ Routes  → │
                      │ HRR     → │
                      │ InsertPts │
                      └───────────┘
```

### Key Design Decisions

1. **YAML-driven**: All test expectations are declared in YAML files. Adding a new framework or fixture is a YAML addition, not a code change.
2. **No external dependencies for Layers 2-3**: SARIF fixtures are static JSON files; handoff tests build raw HTTP requests from route definitions. Only Layer 1 requires the ast-grep binary.
3. **Graceful degradation**: If ast-grep has compatibility issues (e.g., newer versions changing config format), extraction tests skip with a clear message rather than failing the suite.
4. **Fixture-based SARIF testing**: Static `.sarif` files enable deterministic testing without running semgrep or trivy.
5. **Separation of concerns**: Each layer tests exactly one component. Layer 4 (E2E) ties them together.

---

## Directory Structure

```
test/
├── benchmark/
│   ├── harness/
│   │   ├── sast_types.go              # SAST definition types
│   │   └── sast_loader.go             # SAST YAML loaders
│   │
│   ├── definitions/
│   │   └── whitebox/                  # SAST benchmark definitions
│   │       ├── extraction/            #   Layer 1: route extraction
│   │       │   ├── gin-extraction.yaml
│   │       │   ├── fastapi-extraction.yaml
│   │       │   ├── express-extraction.yaml
│   │       │   ├── django-extraction.yaml
│   │       │   ├── flask-extraction.yaml
│   │       │   ├── nextjs-extraction.yaml
│   │       │   ├── nextjs-oopssec-extraction.yaml
│   │       │   ├── nextjs-vulnexamples-extraction.yaml
│   │       │   └── gohttp-extraction.yaml
│   │       ├── sarif/                 #   Layer 2: SARIF parsing
│   │       │   ├── semgrep-normal.yaml
│   │       │   ├── semgrep-multirule.yaml
│   │       │   ├── trivy-normal.yaml
│   │       │   ├── trivy-multirule.yaml
│   │       │   ├── sarif-edge-cases.yaml
│   │       │   └── semgrep-nextjs-vulnexamples.yaml
│   │       └── handoff/               #   Layer 3: route→HRR conversion
│   │           ├── gin-handoff.yaml
│   │           ├── fastapi-handoff.yaml
│   │           ├── express-handoff.yaml
│   │           ├── nextjs-oopssec-handoff.yaml
│   │           └── nextjs-vulnexamples-handoff.yaml
│   │
│   └── sast/                          # Go test files
│       ├── helpers.go                 #   Shared utilities (no build tag)
│       ├── extraction_test.go         #   Layer 1 (build tag: sast)
│       ├── sarif_test.go              #   Layer 2 (build tag: sast)
│       ├── handoff_test.go            #   Layer 3 (build tag: sast)
│       └── e2e_test.go               #   Layer 4 (build tag: sast_e2e)
│
└── testdata/
    ├── sast-stubs/                    # Minimal framework source code
    │   ├── gin/                       #   main.go, go.mod
    │   ├── fastapi/                   #   main.py, requirements.txt
    │   ├── express/                   #   app.js, package.json
    │   ├── django/                    #   urls.py, views.py, manage.py, requirements.txt
    │   ├── flask/                     #   app.py, requirements.txt
    │   ├── nextjs/                    #   app/api/users/route.ts, pages/api/health.ts, package.json
    │   ├── nextjs-oopssec/            #   15 API routes + middleware, package.json
    │   ├── nextjs-vulnexamples/       #   9 routes + database layer + vulnerable/solution variants
    │   └── gohttp/                    #   main.go, go.mod
    │
    └── sast-sarif/                    # SARIF fixture JSON files
        ├── semgrep-normal.sarif
        ├── semgrep-nextjs-vulnexamples.sarif
        ├── semgrep-empty.sarif
        ├── semgrep-multirule.sarif
        ├── trivy-normal.sarif
        ├── trivy-empty.sarif
        ├── trivy-multirule.sarif
        ├── sarif-malformed-1.json
        ├── sarif-malformed-2.json
        └── sarif-severity-mapping.sarif
```

---

## Test Layers

### Layer 1: Route Extraction

Tests the ast-grep scanner's ability to extract HTTP routes from framework source code.

**What it validates:**

- `astgrep.NewScanner()` and `ScanDirWithFramework()` produce matches
- `astgrep.MatchesToRoutes()` converts matches to structured `Route` structs
- Match counts fall within expected bounds
- Specific routes appear with correct method, path, file, and params
- Negative routes (that should NOT appear) are absent
- `astgrep.DetectFramework()` correctly identifies frameworks from manifest files

**Frameworks covered (9):**

| Framework | Source Stub | Routes | Detection |
|-----------|------------|--------|-----------|
| Gin (Go) | `sast-stubs/gin/` | 12 routes (CRUD, groups, Any) | `go.mod` → `gin-gonic/gin` |
| FastAPI (Python) | `sast-stubs/fastapi/` | 11 routes (Path, Query, Body) | `requirements.txt` → `fastapi` |
| Express (JS) | `sast-stubs/express/` | 8 routes (router, groups, all) | `package.json` → `express` |
| Django (Python) | `sast-stubs/django/` | 9 URL patterns + class views | `manage.py` → `django` |
| Flask (Python) | `sast-stubs/flask/` | 7 routes (decorators, add_url_rule) | `requirements.txt` → `flask` |
| Next.js (TS) | `sast-stubs/nextjs/` | 3+ handlers (App/Pages Router) | `package.json` → `next` |
| Next.js OopsSec (TS) | `sast-stubs/nextjs-oopssec/` | 15+ handlers (dynamic routes, middleware) | `package.json` → `next` |
| Next.js VulnExamples (TS) | `sast-stubs/nextjs-vulnexamples/` | 9+ handlers (auth, authz, XSS, secrets) | `package.json` → `next` |
| Go HTTP (Go) | `sast-stubs/gohttp/` | 3 routes (HandleFunc) | No manifest marker |

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestExtraction_All` | Runs all extraction definitions from YAML |
| `TestExtraction_Gin_Routes` | Gin-specific extraction |
| `TestExtraction_FastAPI_Routes` | FastAPI-specific extraction |
| `TestExtraction_Express_Routes` | Express-specific extraction |
| `TestExtraction_Django_Routes` | Django-specific extraction |
| `TestExtraction_Flask_Routes` | Flask-specific extraction |
| `TestExtraction_NextJS_Routes` | Next.js-specific extraction |
| `TestExtraction_NextJS_Oopssec_Routes` | Next.js OopsSec extraction |
| `TestExtraction_NextJS_VulnExamples_Routes` | Next.js VulnExamples extraction |
| `TestExtraction_GoHTTP_Routes` | Go net/http-specific extraction |
| `TestExtraction_DetectFramework` | Framework detection from manifest files |

### Layer 2: SARIF Parsing

Tests the SARIF/JSON parser's ability to correctly extract findings from tool output.

**What it validates:**

- `sourcetools.ParseSARIF()` parses standard SARIF format
- `sourcetools.ParseSemgrepOutput()` parses semgrep's native JSON
- `sourcetools.ParseTrivyOutput()` parses trivy's native JSON
- Finding counts match expectations
- Individual findings have correct rule_id, severity, file_path, start_line
- Severity distributions match (e.g., 2 high, 3 medium, 1 low)
- Empty fixtures return 0 findings without error
- Malformed JSON returns appropriate errors
- SARIF level mapping: error→high, warning→medium, note→low, none→info
- `sourcetools.ToFinding()` produces correct ModuleID, Tags, MatchedAt, FindingHash

**Fixtures (10):**

| Fixture | Tool | Findings | What It Tests |
|---------|------|----------|---------------|
| `semgrep-normal.sarif` | semgrep | 4 | Standard parsing with mixed severity |
| `semgrep-empty.sarif` | semgrep | 0 | Empty result handling |
| `semgrep-multirule.sarif` | semgrep | 11 | Multiple rules (sqli, xss, ssrf, idor, crypto) |
| `semgrep-nextjs-vulnexamples.sarif` | semgrep | 6 | Next.js auth/authz/secrets/XSS (4 high, 2 medium) |
| `trivy-normal.sarif` | trivy | 3 | Vuln + secret + misconfig |
| `trivy-empty.sarif` | trivy | 0 | Empty result handling |
| `trivy-multirule.sarif` | trivy | 5 | All trivy categories |
| `sarif-malformed-1.json` | any | N/A | Missing "runs" key → 0 findings |
| `sarif-malformed-2.json` | any | N/A | Invalid JSON → parse error |
| `sarif-severity-mapping.sarif` | test | 4 | Level mapping validation |

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestSARIF_All` | Runs all SARIF definitions from YAML |
| `TestSARIF_Semgrep_Normal` | Standard semgrep parsing |
| `TestSARIF_Semgrep_Multirule` | Multi-rule diversity |
| `TestSARIF_Trivy_Normal` | Standard trivy parsing |
| `TestSARIF_Trivy_Multirule` | All trivy categories |
| `TestSARIF_EdgeCases` | Severity mapping edge cases |
| `TestSARIF_Empty` | Zero-finding fixtures |
| `TestSARIF_Malformed` | Invalid/incomplete input |
| `TestSARIF_SeverityMapping` | error→high, warning→medium, note→low, none→info |
| `TestSARIF_ToFinding` | RawFinding → database.Finding conversion |

### Layer 3: SAST→DAST Handoff

Tests the conversion of extracted routes into scannable HTTP requests with insertion points.

**What it validates:**

- Routes convert to valid `HttpRequestResponse` via `httpmsg.ParseRawRequest()`
- Method normalization: `ANY`/`HANDLE`/`ALL`/empty → `GET`
- Empty-path routes are correctly skipped
- URL parameters produce `InsertionPoint` objects via `httpmsg.CreateAllInsertionPoints()`
- HTTP method, URI path, and Host header match expectations

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestHandoff_All` | Runs all handoff definitions (gin, fastapi, express, nextjs-oopssec, nextjs-vulnexamples) |
| `TestHandoff_MethodNormalization` | ANY/HANDLE/ALL/"" → GET, standard methods unchanged |
| `TestHandoff_EmptyPathSkipped` | Empty path routes produce skip |
| `TestHandoff_InsertionPointCreation` | URL params → insertion points with correct names and types |

### Layer 4: E2E Pipeline

Tests the complete chain from source code to scannable insertion points.

**What it validates:**

- Source stubs → ast-grep scan → route extraction → HRR construction → insertion point creation
- At least one route per framework successfully produces insertion points

**Test functions:**

| Function | Description |
|----------|-------------|
| `TestSAST_E2E_Extraction_To_Scan` | Full pipeline for gin, fastapi, express |

---

## Running Benchmarks

### Make Targets

| Command | Layers | Timeout | Requirements |
|---------|--------|---------|--------------|
| `make test-sast` | 1 + 2 + 3 | 10 min | ast-grep binary (Layer 1) |
| `make test-sast-extraction` | 1 only | 10 min | ast-grep binary |
| `make test-sast-sarif` | 2 only | 5 min | None |
| `make test-sast-handoff` | 3 only | 5 min | None |
| `make test-sast-e2e` | 4 | 15 min | ast-grep binary |

### Running Individual Tests

```bash
# All SAST layers (1-3)
make test-sast

# Layer 2 only (no external deps)
make test-sast-sarif

# Single framework extraction
go test -tags=sast -v -run TestExtraction_Gin ./test/benchmark/sast/...

# Single SARIF fixture
go test -tags=sast -v -run TestSARIF_Semgrep_Normal ./test/benchmark/sast/...

# Framework detection only
go test -tags=sast -v -run TestExtraction_DetectFramework ./test/benchmark/sast/...

# Severity mapping
go test -tags=sast -v -run TestSARIF_SeverityMapping ./test/benchmark/sast/...

# Handoff method normalization
go test -tags=sast -v -run TestHandoff_MethodNormalization ./test/benchmark/sast/...

# Full E2E pipeline
go test -tags=sast_e2e -v -run TestSAST_E2E ./test/benchmark/sast/...
```

### Example Output

```
=== RUN   TestSARIF_All
=== RUN   TestSARIF_All/semgrep-normal.sarif
    sarif_test.go:26: [semgrep-normal.sarif] Parsed 4 findings
    sarif_test.go:26:   Finding: rule=python.django.security.injection.sql-injection severity=high file=app/views.py line=42
    sarif_test.go:26:   Finding: rule=python.flask.security.xss.reflected-xss severity=medium file=app/routes.py line=15
--- PASS: TestSARIF_All/semgrep-normal.sarif (0.00s)

=== RUN   TestHandoff_All/gin
=== RUN   TestHandoff_All/gin/route_0_GET_/users
=== RUN   TestHandoff_All/gin/route_3_ANY_/health
--- PASS: TestHandoff_All/gin (0.00s)

=== RUN   TestExtraction_DetectFramework
=== RUN   TestExtraction_DetectFramework/gin
=== RUN   TestExtraction_DetectFramework/fastapi
=== RUN   TestExtraction_DetectFramework/django
--- PASS: TestExtraction_DetectFramework (0.00s)
```

---

## YAML Definition Format

### Extraction Definition

Each file in `definitions/whitebox/extraction/` describes expected routes for one framework:

```yaml
framework: gin                     # Framework name (must match SupportedFrameworks)
source_dir: gin                    # Subdirectory under test/testdata/sast-stubs/
detect_framework: true             # Whether DetectFramework() should identify this stub

expected_match_count:
  min: 5                           # Minimum ast-grep matches expected
  max: 30                          # Maximum ast-grep matches expected

expected_routes:
  - method: GET                    # HTTP method (empty = match any)
    path: "/users"                 # Route path
    file: main.go                  # Source file (suffix-matched)
    params: ["q", "page"]          # Expected parameters (optional)
    assertion: strict              # strict (fail) or soft (log only)

  - method: ANY
    path: "/health"
    file: main.go
    assertion: soft                # Soft: log if missing, don't fail

negative_routes:                   # Routes that must NOT appear
  - method: GET
    path: "/nonexistent"
```

### SARIF Definition

Each file in `definitions/whitebox/sarif/` declares expectations for a fixture:

```yaml
fixture: semgrep-normal.sarif      # File in test/testdata/sast-sarif/
tool_name: semgrep                 # Tool name passed to ParseSARIF
format: sarif                      # sarif | semgrep-json | trivy-json

expected:
  finding_count: 4                 # Total expected findings
  error: false                     # Whether parsing should error

  findings:                        # Specific findings to validate
    - rule_id: "python.django.security.injection.sql-injection"
      severity: high
      file_path: "app/views.py"
      start_line: 42

  severity_distribution:           # Severity count expectations
    high: 1
    medium: 2
    low: 1
```

### Handoff Definition

Each file in `definitions/whitebox/handoff/` describes route-to-request conversion:

```yaml
framework: gin
base_url: http://localhost:8080    # Used for Host header

routes:
  - method: GET
    path: "/users"
    params: ["q", "page"]          # Added as query string ?q=FUZZ&page=FUZZ
    expected_request:
      method: GET
      uri: "/users?q=FUZZ&page=FUZZ"
      host: localhost:8080

  - method: ANY                    # Normalized to GET
    path: "/health"
    expected_request:
      method: GET
      uri: "/health"
      host: localhost:8080

  - method: ""                     # Empty path → skip
    path: ""
    expected_skip: true
```

---

## Source Stubs

Source stubs are minimal, syntactically valid framework code in `test/testdata/sast-stubs/`. Each stub exercises key patterns that ast-grep rules should detect:

| Pattern | Example | Why It Matters |
|---------|---------|----------------|
| Basic CRUD routes | `r.GET("/users", h)` | Baseline extraction |
| Path parameters | `/users/:id`, `/users/{user_id}` | Param type detection |
| Route groups/prefixes | `r.Group("/api/v2")` | Path concatenation |
| Multiple methods | `r.Any("/health")` | Method expansion |
| Query/body params | `c.Query("q")`, `Body(...)` | Parameter binding |
| Framework detection | `go.mod`, `requirements.txt`, `package.json` | `DetectFramework()` validation |
| Class-based views | Django `ViewSet` | Method extraction from classes |
| Decorator patterns | `@app.get("/path")` | Python route decorators |
| Export patterns | `export async function GET()` | Next.js App Router |

Each stub directory contains a manifest file (`go.mod`, `requirements.txt`, or `package.json`) that `DetectFramework()` uses to identify the framework. The exception is `gohttp/` — Go's `net/http` has no framework-specific dependency marker, so `detect_framework: false` is set in its YAML.

---

## SARIF Fixtures

SARIF fixtures in `test/testdata/sast-sarif/` are static JSON files that simulate real tool output. They test the parser without requiring semgrep or trivy to be installed.

### Fixture Design

**Normal fixtures** contain realistic findings with proper SARIF structure:

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "semgrep", "rules": [...] } },
    "results": [{
      "ruleId": "python.django.security.injection.sql-injection",
      "message": { "text": "Detected raw SQL query with user input" },
      "locations": [{ "physicalLocation": {
        "artifactLocation": { "uri": "app/views.py" },
        "region": { "startLine": 42 }
      }}]
    }]
  }]
}
```

**Empty fixtures** have zero results — validates the zero-finding path.

**Malformed fixtures** test error handling:
- `sarif-malformed-1.json`: Valid JSON but missing the `"runs"` key
- `sarif-malformed-2.json`: Invalid JSON (parse should error)

**Severity mapping fixture** (`sarif-severity-mapping.sarif`): One finding per SARIF level, validating:

| SARIF Level | Vigolium Severity |
|-------------|-------------------|
| `error` | `high` |
| `warning` | `medium` |
| `note` | `low` |
| `none` | `info` |

---

## Adding New Benchmarks

### Adding a New Framework (Layer 1)

1. **Create a source stub** at `test/testdata/sast-stubs/<framework>/`:

```bash
mkdir -p test/testdata/sast-stubs/spring
```

Write minimal source code that exercises the framework's route patterns. Include a manifest file (e.g., `pom.xml`, `build.gradle`) for `DetectFramework()`.

2. **Create a YAML definition** at `test/benchmark/definitions/whitebox/extraction/<framework>-extraction.yaml`:

```yaml
framework: spring
source_dir: spring
detect_framework: true

expected_match_count:
  min: 3
  max: 20

expected_routes:
  - method: GET
    path: "/api/users"
    file: UserController.java
    assertion: strict

negative_routes:
  - method: GET
    path: "/nonexistent"
```

3. **No Go code changes needed** — `TestExtraction_All` automatically picks up new YAML files.

4. **Run it**:

```bash
go test -tags=sast -v -run "TestExtraction_All/spring" ./test/benchmark/sast/...
```

### Adding a New SARIF Fixture (Layer 2)

1. **Create the fixture** at `test/testdata/sast-sarif/<name>.sarif`.

2. **Create a definition** at `test/benchmark/definitions/whitebox/sarif/<name>.yaml`:

```yaml
fixture: my-tool-output.sarif
tool_name: my-tool
format: sarif

expected:
  finding_count: 3
  error: false
  findings:
    - rule_id: "MY-RULE-001"
      severity: high
  severity_distribution:
    high: 1
    medium: 2
```

3. **Run it**:

```bash
go test -tags=sast -v -run "TestSARIF_All/my-tool-output.sarif" ./test/benchmark/sast/...
```

### Adding a New Handoff Test (Layer 3)

1. **Create a definition** at `test/benchmark/definitions/whitebox/handoff/<framework>-handoff.yaml`:

```yaml
framework: spring
base_url: http://localhost:8080

routes:
  - method: GET
    path: "/api/users"
    params: ["page"]
    expected_request:
      method: GET
      uri: "/api/users?page=FUZZ"
      host: localhost:8080
```

2. **Run it**:

```bash
go test -tags=sast -v -run "TestHandoff_All/spring" ./test/benchmark/sast/...
```

---

## Harness Reference

### SAST Types

| Type | Description |
|------|-------------|
| `SASTExtractionDefinition` | Route extraction test: framework, source_dir, expected routes, bounds |
| `ExpectedRoute` | Route expectation: method, path, file, params, assertion mode |
| `MatchCountBounds` | Min/max bounds for ast-grep match counts |
| `SASTSARIFDefinition` | SARIF parsing test: fixture path, tool name, format, expectations |
| `SARIFExpectation` | Expected results: finding count, error flag, specific findings, severity distribution |
| `ExpectedFinding` | Finding expectation: rule_id, severity, file_path, start_line |
| `SASTHandoffDefinition` | Handoff test: framework, base URL, routes with expected requests |
| `HandoffRoute` | Route conversion expectation: method, path, params, expected request, skip flag |
| `ExpectedRequest` | Expected HTTP request properties: method, URI, host |

### Loader Functions

| Function | Description |
|----------|-------------|
| `LoadSASTExtractionDefinition(path)` | Load one extraction YAML (defaults assertion to "strict") |
| `LoadSASTExtractionDefinitionsFromDir(dir)` | Load all extraction YAMLs from directory |
| `LoadSASTSARIFDefinition(path)` | Load one SARIF YAML (defaults format to "sarif") |
| `LoadSASTSARIFDefinitionsFromDir(dir)` | Load all SARIF YAMLs from directory |
| `LoadSASTHandoffDefinition(path)` | Load one handoff YAML |
| `LoadSASTHandoffDefinitionsFromDir(dir)` | Load all handoff YAMLs from directory |
| `SASTDefinitionsDir()` | Returns path to `definitions/whitebox/` |

### Test Helpers

| Function | Description |
|----------|-------------|
| `stubPath(framework)` | Resolves to `test/testdata/sast-stubs/{framework}` |
| `sarifFixturePath(name)` | Resolves to `test/testdata/sast-sarif/{name}` |
| `definitionsDir()` | Resolves to `test/benchmark/definitions/whitebox` |
| `findRoute(routes, method, path)` | Search routes by method and path |
| `findFinding(findings, ruleID)` | Search findings by rule ID |
| `buildSeverityDistribution(findings)` | Count findings per severity level |
| `normalizeMethod(method)` | ANY/HANDLE/ALL/"" → GET |
| `shouldSkipRoute(route)` | True if route has empty path |

---

## CI Integration

### Recommended Strategy

| Trigger | What to Run | Timeout | Notes |
|---------|------------|---------|-------|
| On every PR | `make test-sast-sarif && make test-sast-handoff` | 5 min | No external deps |
| On every PR | `make test-sast` | 10 min | Requires ast-grep binary |
| Nightly | `make test-sast-e2e` | 15 min | Full pipeline validation |

### Example GitHub Actions Workflow

```yaml
- name: Run SAST benchmarks (Layers 2+3, no external deps)
  run: |
    make test-sast-sarif
    make test-sast-handoff
  timeout-minutes: 5

- name: Run SAST extraction benchmarks (Layer 1)
  run: make test-sast-extraction
  timeout-minutes: 10

- name: Run SAST E2E benchmarks (nightly)
  if: github.event_name == 'schedule'
  run: make test-sast-e2e
  timeout-minutes: 15
```

---

## Troubleshooting

### ast-grep binary not found

```
ScanDirWithFramework failed: create downloader: ...
```

The ast-grep binary is resolved lazily. On first run it either finds `ast-grep` in PATH or downloads it. Ensure internet access is available, or pre-install:

```bash
# macOS
brew install ast-grep

# Or let the scanner download it automatically
go test -tags=sast -v -run TestExtraction_Gin ./test/benchmark/sast/...
```

### ast-grep-config.yaml compatibility issue

```
Skipping: ast-grep ast-grep-config.yaml compatibility issue (known)
```

Some ast-grep versions (notably v0.41.0+) treat `ast-grep-config.yaml` in the rules directory as a rule file, causing a parse error. This is a known issue with the embedded rule extraction in `pkg/toolexec/astgrep/rules.go`. Extraction tests skip gracefully when this occurs. The `DetectFramework` tests always pass regardless, since they do not invoke the scanner.

### SARIF fixture not found

```
failed to read fixture test/testdata/sast-sarif/my-fixture.sarif: no such file or directory
```

Ensure the fixture file exists and the `fixture` field in the YAML definition matches the filename exactly (including extension).

### No insertion points created

If `TestHandoff_InsertionPointCreation` fails with zero insertion points, check that the raw HTTP request contains query parameters. The `CreateAllInsertionPoints()` function requires actual parameters in the request line to generate URL parameter insertion points.

### Definition YAML parse errors

```
failed to parse extraction definition: yaml: line 5: ...
```

Verify YAML syntax. Common issues:
- Indentation must use spaces, not tabs
- Strings with special characters (`{`, `}`, `:`) should be quoted
- Boolean values (`true`/`false`) are case-sensitive in YAML
