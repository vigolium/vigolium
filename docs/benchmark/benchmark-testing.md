# Benchmark Testing

This document covers the benchmark testing system for validating Vigolium's detection capabilities across all scanner modules. It explains the architecture, target applications, how to run benchmarks, how to add new test cases, and how to interpret the coverage report.

## Table of Contents

- [Overview](#overview)
- [Target Applications](#target-applications)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Prerequisites](#prerequisites)
- [Running Benchmarks](#running-benchmarks)
- [YAML Definition Format](#yaml-definition-format)
- [Adding New Test Cases](#adding-new-test-cases)
- [Adding a New Vulnerable App](#adding-a-new-vulnerable-app)
- [Adding a New Blackbox Site](#adding-a-new-blackbox-site)
- [Coverage Report](#coverage-report)
- [Assertion Modes](#assertion-modes)
- [Harness Package Reference](#harness-package-reference)
- [CI Integration](#ci-integration)
- [XBOW Validation Benchmarks](#xbow-validation-benchmarks)
- [Troubleshooting](#troubleshooting)

---

## Overview

The benchmark system validates that Vigolium's active and passive scanner modules detect known vulnerabilities in controlled environments. It uses a **data-driven approach**: YAML files define target applications, endpoints, expected modules, and assertions. A shared Go test harness loads these definitions and drives execution.

### Test Categories

| Category | Build Tag | Targets | Assertions | Requirements |
|----------|-----------|---------|------------|--------------|
| **Whitebox** | `canary` | Docker containers (DVWA, VAmPI, Juice Shop, OopsSec Store, NextJS VulnExamples, etc.) | Strict + Soft | Docker |
| **crAPI** | `canary` | Docker Compose (crAPI — 10 services) | Soft | Docker + `make crapi-up` |
| **XBOW** | `xbow` | CTF-style benchmarks built from source (XSS, SSTI, SQLi, LFI, CmdI, SSRF, XXE) | Strict + Soft | Docker + `XBOW_SOURCE_DIR` |
| **Blackbox** | `blackbox` | External demo sites (Acunetix, PortSwigger, IBM) | Soft only | Internet |
| **SAST** | `sast` | Static analysis pipeline (route extraction, SARIF parsing, handoff) | Strict + Soft | ast-grep binary (Layer 1 only) |
| **Coverage** | `canary` | None (analyzes YAML definitions) | N/A | None |

### Relationship to Existing Tests

The benchmark system complements the existing test tiers:

| Tier | Location | Purpose |
|------|----------|---------|
| Unit tests | `pkg/*/` | Fast, isolated function-level tests |
| E2E tests | `test/e2e/` | HTTP client, server, and pipeline integration |
| Canary tests | `test/e2e/` | Original per-app vulnerability detection tests |
| **Benchmark tests** | `test/benchmark/` | Data-driven module coverage validation (whitebox, blackbox, xbow, SAST) |
| Integration tests | `test/benchmark/xss_scanner/` | Brutelogic XSS gym (external) |

The benchmark system is designed to eventually supersede the per-app canary tests in `test/e2e/` (dvwa_test.go, vampi_test.go, juiceshop_test.go) by providing the same coverage through YAML definitions with less boilerplate.

---

## Target Applications

Vigolium benchmarks against a diverse set of intentionally vulnerable applications. Each application covers different vulnerability categories, tech stacks, and scanning approaches (DAST, SAST, or both).

### DAST Targets (Docker-based)

| Application | Tech Stack | Vulnerability Categories | Docker Source | Port |
|-------------|-----------|--------------------------|---------------|------|
| **DVWA** | PHP / MySQL | SQLi, XSS (reflected + DOM), LFI, Command Injection, CRLF, CSRF | `vulnerables/web-dvwa:latest` | 80 |
| **VAmPI** | Python / Flask | SQLi, NoSQLi, CORS, JWT, Mass Assignment, Info Disclosure | `erev0s/vampi:latest` | 5000 |
| **Juice Shop** | Node.js / Angular | SQLi, XSS, Swagger exposure, JWT, CSRF, Info Disclosure | `bkimminich/juice-shop:latest` | 3000 |
| **crAPI** | Go + Python + Node.js microservices | OWASP API Top 10 (BOLA, BFLA, Mass Assignment, SSRF, SQLi, NoSQLi) | Docker Compose (10 services) | 8888 |
| **OopsSec Store** | Next.js / SQLite | SQLi, XSS, SSRF, LFI, XXE, IDOR, CORS, CSRF, Open Redirect, File Upload | Built from source | 3000 |
| **NextJS VulnExamples** | Next.js / PostgreSQL | Missing Authentication, Missing Authorization, Secrets Exposure, Stored XSS | Built from source | 3000 |
| **Vulnerable Java** | Java / Spring | SQLi, XSS, SSRF, Path Traversal | Docker image | 8080 |
| **Vulnerable Nginx** | Nginx | Misconfigurations, Path Traversal, CRLF, Header Injection | Docker image | 80 |

### NextJS VulnExamples — Detailed Breakdown

Source: [upleveled/security-vulnerability-examples-next-js-postgres](https://github.com/upleveled/security-vulnerability-examples-next-js-postgres)

This application is an educational project demonstrating six categories of security flaws in a Next.js + PostgreSQL stack. It provides both **vulnerable implementations** and **secure solutions** for each category, making it valuable for both positive detection and negative (false positive) testing.

| Example | Vulnerability | Vulnerable Route | Type | What's Wrong |
|---------|--------------|-----------------|------|-------------|
| 1 | Missing Authentication | `GET /api/example-1-.../vulnerable` | Route Handler | No session token check — returns blog posts to anyone |
| 2 | Missing Authentication | `GET /example-2-.../vulnerable` | Server Component | No session check — queries DB and renders directly |
| 3 | Missing Authorization | `GET /api/example-3-.../vulnerable` | Route Handler | Checks auth but returns ALL users' unpublished posts |
| 4 | Missing Authorization | `GET /example-4-.../vulnerable` | Server Component | No auth + returns all users' data |
| 5 | Secrets Exposure | `GET /example-5-.../vulnerable` | Server Component | Leaks `process.env.API_KEY` and password hashes to client |
| 6 | Stored XSS | `GET /example-6-.../vulnerable` | Server Component | `dangerouslySetInnerHTML` with `<img onerror="alert('pwned')">` |

Seed data includes two users (alice/abc, bob/def) and 7 blog posts, including two with XSS payloads.

Each example also has 1-3 **solution variants** that fix the vulnerability. These serve as negative test cases — the scanner should NOT flag them.

### SAST Targets (Static Analysis)

The SAST benchmark suite validates the source-aware scanning pipeline using **source stubs** — minimal, syntactically valid framework code that exercises key patterns. See [whitebox-sast.md](whitebox-sast.md) for full details.

| Framework | Source Stub | Routes | Key Patterns |
|-----------|------------|--------|-------------|
| Gin (Go) | `sast-stubs/gin/` | ~12 routes | CRUD, groups, Any, path params |
| FastAPI (Python) | `sast-stubs/fastapi/` | ~11 routes | Path, Query, Body params |
| Express (JS) | `sast-stubs/express/` | ~8 routes | Router, groups, all |
| Django (Python) | `sast-stubs/django/` | ~9 routes | URL patterns, class views |
| Flask (Python) | `sast-stubs/flask/` | ~7 routes | Decorators, add_url_rule |
| Next.js (TS) | `sast-stubs/nextjs/` | 3+ handlers | App Router, Pages Router |
| Next.js OopsSec (TS) | `sast-stubs/nextjs-oopssec/` | 15+ handlers | Dynamic routes, middleware, body parsing, header extraction |
| **Next.js VulnExamples (TS)** | `sast-stubs/nextjs-vulnexamples/` | 9+ handlers | Missing auth/authz, secrets exposure, XSS, solution variants |
| Go HTTP (Go) | `sast-stubs/gohttp/` | 3 routes | HandleFunc |

The **Next.js VulnExamples** SAST stub is unique because it includes both vulnerable and secure code paths. Its SARIF fixture (`semgrep-nextjs-vulnexamples.sarif`) covers 6 findings across 4 vulnerability categories:

| Finding | Severity | File | Category |
|---------|----------|------|----------|
| `dangerouslySetInnerHTML` with unsanitized DB content | Medium | `example-6-cross-site-scripting/vulnerable/page.tsx` | XSS |
| Route handler missing authentication check | High | `example-1-missing-authentication/vulnerable/route.ts` | Missing AuthN |
| Data access without authorization scoping | High | `example-3-missing-authorization/vulnerable/route.ts` | Missing AuthZ |
| `process.env.API_KEY` passed to client component | High | `example-5-secrets-exposure/vulnerable/page.tsx` | Secrets Exposure |
| `getUsersWithPasswordHash()` result sent to client | High | `example-5-secrets-exposure/vulnerable/page.tsx` | Secrets Exposure |
| `SELECT *` on users table exposes password hashes | Medium | `database/users.ts` | Data Exposure |

### Blackbox Targets (External Sites)

| Site | URL | Vulnerability Categories |
|------|-----|-------------------------|
| **Acunetix TestPHP** | `testphp.vulnweb.com` | SQLi, XSS, LFI, Directory Traversal |
| **Gin & Juice Shop** | `ginandjuice.shop` (PortSwigger) | SQLi, XSS, SSTI, SSRF, Access Control |
| **IBM Testfire** | `demo.testfire.net` | SQLi, XSS, Authentication Bypass |

### XBOW Targets (CTF-style)

13 self-contained vulnerable applications from the validation-benchmarks repository:

| Vuln Type | Count | Benchmarks |
|-----------|-------|------------|
| XSS | 2 | XBEN-013-24, XBEN-047-24 |
| SSTI | 3 | XBEN-009-24, XBEN-053-24, XBEN-076-24 |
| SQLi | 2 | XBEN-083-24, XBEN-071-24 |
| LFI | 2 | XBEN-019-24, XBEN-061-24 |
| Command Injection | 1 | XBEN-073-24 |
| SSRF | 1 | XBEN-020-24 |
| XXE | 2 | XBEN-006-24, XBEN-096-24 |

---

## Architecture

```
                    YAML Definitions
                    (dvwa.yaml, vampi.yaml, nextjs-vulnexamples.yaml,
                     xbow/*.yaml, blackbox/*.yaml, whitebox/*.yaml)
                           │
                           ▼
                   ┌───────────────┐
                   │  Go Harness   │
                   │  (harness/)   │
                   │               │
                   │ LoadDefinition│  ← expands $XBOW_SOURCE_DIR
                   │ SetupTestInfra│
                   │ StartApp...   │  ← routes by app type
                   └───────┬───────┘
                           │
           ┌───────┬───────┼───────┬───────┐
           ▼       ▼       ▼       ▼       ▼
       ┌───────┐┌──────┐┌──────┐┌──────┐┌──────┐
       │docker ││compo-││ xbow ││exter-││Cover-│
       │       ││se    ││      ││nal   ││age   │
       │testcon││wait  ││build ││check ││      │
       │tainers││for   ││start ││avail ││scan  │
       │-go    ││base  ││port  ││      ││YAMLs │
       │       ││url   ││stop  ││      ││      │
       └───┬───┘└──┬───┘└──┬───┘└──┬───┘└──────┘
           └───────┴───────┴───────┘
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
        ┌──────────┐┌──────────┐
        │  Active  ││ Passive  │
        │  Runner  ││  Runner  │
        │          ││          │
        │ Resolve  ││ Fetch URL│
        │ module   ││ Attach   │
        │ Build RR ││ response │
        │ (GET or  ││          │
        │  POST)   ││ Call     │
        │ Call     ││ ScanPer* │
        │ ScanPer* ││          │
        └──────────┘└──────────┘
              │            │
              ▼            ▼
        Apply Assertion (strict/soft/negative)
```

### Key Design Decisions

1. **YAML-driven**: Test cases are defined in YAML, not Go code. Adding a new test case is a one-line YAML addition.
2. **Module resolution by ID**: Test cases reference modules by their registry ID (e.g., `active-sqli-error-based`). The harness resolves them from `modules.DefaultRegistry`.
3. **Scan type dispatch**: The harness checks `module.ScanScopes()` to dispatch to the correct method:
   - `ScanScopeInsertionPoint`: Creates insertion points via `httpmsg.CreateAllInsertionPoints()`, filters by `AllowedInsertionPointTypes()`, calls `ScanPerInsertionPoint()` for each.
   - `ScanScopeRequest`: Calls `ScanPerRequest()` once with the full request.
   - `ScanScopeHost`: Calls `ScanPerHost()` once.
4. **Passive fetch-then-scan**: Passive tests fetch the URL first using the HTTP client, attach the raw response to the `HttpRequestResponse`, then pass it to the passive module.
5. **App-specific auth**: Some apps (e.g., DVWA) require authentication before vulnerability pages work. The `SetupAppAuth()` function dispatches per-app setup (DB init, CSRF token extraction, login) and returns headers (cookies) to inject into all test cases.
6. **Network init safety**: `network.Init()` is called once per process via `sync.Once` to avoid LevelDB close/reopen issues when running multiple test functions sequentially.

---

## Directory Structure

```
test/benchmark/
├── harness/                        # Shared Go library (not a test package)
│   ├── types.go                    # BenchmarkDefinition, TestCase, AppConfig structs
│   ├── sast_types.go               # SAST definition types
│   ├── sast_loader.go              # SAST YAML loaders
│   ├── harness.go                  # TestInfra, YAML loader, module resolver, assertions
│   ├── container.go                # Docker container lifecycle (testcontainers-go + compose)
│   ├── compose.go                  # Docker Compose CLI lifecycle (build/start/port/stop)
│   ├── external.go                 # External site availability checks
│   ├── passive_helper.go           # Fetch-then-scan helper for passive modules
│   ├── oast_helper.go              # OAST mocking for active scanning
│   ├── report.go                   # Coverage report generator
│   └── harness_test.go             # Unit tests for the harness itself
│
├── definitions/                    # YAML benchmark definitions (DAST)
│   ├── dvwa.yaml                   # DVWA: XSS, SQLi, LFI, cmd injection, passive checks
│   ├── vampi.yaml                  # VAmPI: SQLi, NoSQLi, CORS, passive checks
│   ├── juiceshop.yaml              # Juice Shop: SQLi, XSS, Swagger, JWT, passive checks
│   ├── crapi.yaml                  # crAPI: OWASP API Top 10 with auth flow
│   ├── oopssec-store.yaml          # OopsSec Store: SQLi, XSS, SSRF, LFI, XXE, IDOR, CORS
│   ├── nextjs-vulnexamples.yaml    # NextJS VulnExamples: missing auth/authz, secrets, XSS
│   ├── vulnerable-java.yaml        # DataDog vulnerable-java
│   ├── vulnerable-nginx.yaml       # Detectify vulnerable-nginx
│   ├── blackbox/
│   │   ├── acunetix.yaml           # testphp.vulnweb.com
│   │   ├── ginandjuice.yaml        # ginandjuice.shop (PortSwigger)
│   │   └── testfire.yaml           # demo.testfire.net (IBM AppScan)
│   ├── whitebox/                   # SAST benchmark definitions
│   │   ├── extraction/             #   Layer 1: route extraction
│   │   │   ├── gin-extraction.yaml
│   │   │   ├── fastapi-extraction.yaml
│   │   │   ├── express-extraction.yaml
│   │   │   ├── django-extraction.yaml
│   │   │   ├── flask-extraction.yaml
│   │   │   ├── nextjs-extraction.yaml
│   │   │   ├── nextjs-oopssec-extraction.yaml
│   │   │   ├── nextjs-vulnexamples-extraction.yaml
│   │   │   └── gohttp-extraction.yaml
│   │   ├── sarif/                  #   Layer 2: SARIF parsing
│   │   │   ├── semgrep-normal.yaml
│   │   │   ├── semgrep-multirule.yaml
│   │   │   ├── semgrep-nextjs-vulnexamples.yaml
│   │   │   ├── trivy-normal.yaml
│   │   │   ├── trivy-multirule.yaml
│   │   │   └── sarif-edge-cases.yaml
│   │   └── handoff/                #   Layer 3: route-to-HRR conversion
│   │       ├── gin-handoff.yaml
│   │       ├── fastapi-handoff.yaml
│   │       ├── express-handoff.yaml
│   │       ├── nextjs-oopssec-handoff.yaml
│   │       └── nextjs-vulnexamples-handoff.yaml
│   └── xbow/                       # XBOW CTF-style validation benchmarks
│       ├── xbow-xss-013.yaml
│       ├── xbow-ssti-009.yaml
│       ├── ...                      # 13 XBOW definitions total
│       └── xbow-xxe-096.yaml
│
├── whitebox/                       # Docker-based tests (build tag: canary)
│   ├── active_test.go              # Data-driven active module test runner
│   ├── passive_test.go             # Data-driven passive module test runner
│   ├── crapi_test.go               # crAPI with auth flow handling
│   └── debug_test.go               # Debug helpers for direct module invocation
│
├── blackbox/                       # External site tests (build tag: blackbox)
│   ├── active_test.go              # Active scanning with rate limiting
│   └── passive_test.go             # Passive analysis
│
├── sast/                           # SAST pipeline tests (build tag: sast / sast_e2e)
│   ├── helpers.go                  # Shared utilities (no build tag)
│   ├── extraction_test.go          # Layer 1: route extraction
│   ├── sarif_test.go               # Layer 2: SARIF parsing
│   ├── handoff_test.go             # Layer 3: route-to-HRR conversion
│   └── e2e_test.go                 # Layer 4: full pipeline
│
├── xbow/                           # XBOW validation tests (build tag: xbow)
│   └── xbow_test.go                # Data-driven runner with per-vuln-type functions
│
├── coverage/
│   └── report_test.go              # Module coverage matrix generator
│
└── xss_scanner/                    # Pre-existing Brutelogic XSS gym
    └── brutelogic_test.go

test/testdata/
├── sast-stubs/                     # Minimal framework source code for SAST
│   ├── gin/
│   ├── fastapi/
│   ├── express/
│   ├── django/
│   ├── flask/
│   ├── nextjs/
│   ├── nextjs-oopssec/             # 15 API routes + middleware
│   ├── nextjs-vulnexamples/        # 9 routes + database layer + vulnerable/solution variants
│   └── gohttp/
│
├── sast-sarif/                     # SARIF fixture JSON files
│   ├── semgrep-normal.sarif
│   ├── semgrep-nextjs-vulnexamples.sarif
│   ├── ...                          # 10 fixtures total
│   └── sarif-severity-mapping.sarif
│
└── vulnerable-apps/                # Docker Compose configs for vulnerable apps
    ├── crapi/
    ├── oopssec-store/
    ├── nextjs-vulnexamples/         # Next.js + PostgreSQL (built from GitHub)
    ├── vulnerable-java/
    └── vulnerable-nginx/
```

---

## Prerequisites

### Whitebox Tests

- **Docker**: Required for testcontainers-go to start vulnerable app containers
- **Docker images**: Pulled automatically on first run
  - `vulnerables/web-dvwa:latest`
  - `erev0s/vampi:latest`
  - `bkimminich/juice-shop:latest`
- **Docker Compose**: Required for apps that build from source (OopsSec Store, NextJS VulnExamples)

### crAPI Tests

- **Docker Compose**: crAPI requires 10 services (PostgreSQL, MongoDB, multiple microservices)
- **Manual startup**: crAPI must be started before running tests:
  ```bash
  make crapi-up          # Start crAPI (takes ~2 minutes)
  make crapi-status      # Verify all services are healthy
  ```

### SAST Tests

- **ast-grep binary**: Required for Layer 1 (route extraction). Auto-downloaded on first run, or install manually:
  ```bash
  brew install ast-grep   # macOS
  ```
- **No Docker needed**: Layers 2-3 use static fixture data only

### XBOW Validation Benchmarks

- **Docker with Compose**: Required to build and run benchmark containers
- **XBOW source directory**: The `validation-benchmarks` repository checked out locally
- **`XBOW_SOURCE_DIR` environment variable**: Must point to the root of the validation-benchmarks checkout (e.g., `/path/to/validation-benchmarks`). Set via environment or passed through the Makefile.
- **Disk space**: Each benchmark builds a Docker image from source. Pre-build with `make xbow-build` to cache layers.

### Blackbox Tests

- **Internet connectivity**: Required to reach external demo sites
- **No Docker needed**: Tests run against public websites

---

## Running Benchmarks

### Make Targets

| Command | What it runs | Requirements |
|---------|-------------|--------------|
| `make test-benchmark-whitebox` | DVWA, VAmPI, Juice Shop, OopsSec, VulnExamples (Docker) | Docker |
| `make test-benchmark-blackbox` | Acunetix, Gin&Juice, Testfire (external) | Internet |
| `make test-benchmark-all` | All whitebox + blackbox | Docker + Internet |
| `make test-benchmark-crapi` | crAPI only | Docker + `make crapi-up` |
| `make test-benchmark-coverage` | Generate coverage report | None |
| `make test-sast` | SAST Layers 1-3 (extraction + SARIF + handoff) | ast-grep binary |
| `make test-sast-extraction` | Layer 1 only | ast-grep binary |
| `make test-sast-sarif` | Layer 2 only | None |
| `make test-sast-handoff` | Layer 3 only | None |
| `make test-sast-e2e` | Layer 4 (full pipeline) | ast-grep binary |
| `make test-xbow` | All 13 XBOW validation benchmarks | Docker + `XBOW_SOURCE_DIR` |
| `make test-xbow-ssti` | 3 SSTI benchmarks | Docker + `XBOW_SOURCE_DIR` |
| `make test-xbow-xss` | 2 XSS benchmarks | Docker + `XBOW_SOURCE_DIR` |
| `make test-xbow-sqli` | 2 SQLi benchmarks | Docker + `XBOW_SOURCE_DIR` |
| `make test-xbow-lfi` | 2 LFI benchmarks | Docker + `XBOW_SOURCE_DIR` |
| `make test-xbow-cmdi` | 1 CmdI benchmark | Docker + `XBOW_SOURCE_DIR` |
| `make test-xbow-ssrf` | 1 SSRF benchmark | Docker + `XBOW_SOURCE_DIR` |
| `make test-xbow-xxe` | 2 XXE benchmarks | Docker + `XBOW_SOURCE_DIR` |
| `make xbow-build` | Pre-build all XBOW Docker images | Docker + `XBOW_SOURCE_DIR` |

### Running Individual App Benchmarks

```bash
# DVWA active modules only
go test -v -tags=canary -run TestWhitebox_DVWA_Active ./test/benchmark/whitebox/...

# VAmPI passive modules only
go test -v -tags=canary -run TestWhitebox_VAmPI_Passive ./test/benchmark/whitebox/...

# Juice Shop all (active + passive)
go test -v -tags=canary -run "TestWhitebox_JuiceShop" ./test/benchmark/whitebox/...

# NextJS VulnExamples active modules
go test -v -tags=canary -run TestWhitebox_NextJSVulnExamples_Active ./test/benchmark/whitebox/...

# NextJS VulnExamples passive modules
go test -v -tags=canary -run TestWhitebox_NextJSVulnExamples_Passive ./test/benchmark/whitebox/...

# OopsSec Store all
go test -v -tags=canary -run "TestWhitebox_OopssecStore" ./test/benchmark/whitebox/...

# crAPI (requires `make crapi-up`)
go test -v -tags=canary -run TestWhitebox_CrAPI ./test/benchmark/whitebox/...
```

### Running SAST Benchmarks

```bash
# All SAST layers
make test-sast

# Layer 2 only (no external deps)
make test-sast-sarif

# NextJS VulnExamples extraction
go test -tags=sast -v -run TestExtraction_NextJS_VulnExamples ./test/benchmark/sast/...

# NextJS VulnExamples handoff
go test -tags=sast -v -run TestHandoff_NextJS_VulnExamples ./test/benchmark/sast/...

# NextJS VulnExamples SARIF fixture
go test -tags=sast -v -run "TestSARIF_All/semgrep-nextjs-vulnexamples" ./test/benchmark/sast/...

# Full E2E pipeline
go test -tags=sast_e2e -v -run TestSAST_E2E ./test/benchmark/sast/...
```

### Running XBOW Validation Benchmarks

```bash
# Run all xbow benchmarks
make test-xbow

# Run by vulnerability type
make test-xbow-ssti
make test-xbow-xss
make test-xbow-sqli

# Run a single benchmark by name
XBOW_SOURCE_DIR=/path/to/validation-benchmarks \
  go test -v -tags=xbow -timeout 15m -run "TestXbow_All/xbow-ssti-053" ./test/benchmark/xbow/...

# Override the source directory
make test-xbow XBOW_SOURCE_DIR=/custom/path/to/validation-benchmarks

# Pre-build all containers (recommended before first run)
make xbow-build
```

### Running Individual Blackbox Benchmarks

```bash
# Acunetix testphp.vulnweb.com
go test -v -tags=blackbox -run TestBlackbox_Acunetix ./test/benchmark/blackbox/...

# PortSwigger ginandjuice.shop
go test -v -tags=blackbox -run TestBlackbox_GinAndJuice ./test/benchmark/blackbox/...

# IBM Testfire
go test -v -tags=blackbox -run TestBlackbox_Testfire ./test/benchmark/blackbox/...
```

### Running All Benchmarks for a Specific Module

To check a specific module's detection across all apps, filter by test case ID:

```bash
# All SQLi error-based tests across all whitebox apps
go test -v -tags=canary -run "sqli-error" ./test/benchmark/whitebox/...

# All security headers tests
go test -v -tags=canary -run "security-headers" ./test/benchmark/whitebox/...

# All missing-authentication tests (NextJS VulnExamples)
go test -v -tags=canary -run "missing-authn" ./test/benchmark/whitebox/...
```

---

## YAML Definition Format

Each YAML file describes one target application and its test cases.

### Full Schema

```yaml
# Application configuration
app:
  name: dvwa                          # Unique app identifier
  type: docker                        # docker | compose | external | xbow
  image: "vulnerables/web-dvwa:latest"  # Docker image (type: docker)
  port: 80                            # Container port
  exposed_port: "80/tcp"              # Override port format (optional)
  wait_endpoint: "/"                  # Endpoint to poll for readiness
  startup_timeout: 120s               # Max wait for container startup
  base_url: "http://127.0.0.1:8888"  # Base URL (type: compose | external)
  compose_file: "path/to/compose.yaml"  # Docker Compose file (type: compose)
  build_context: "${XBOW_SOURCE_DIR}/benchmarks/XBEN-053-24"  # Path to docker-compose.yml dir (type: xbow)
  service_name: app                   # Docker Compose service to get port from (type: xbow)
  internal_port: 80                   # Port inside the container (type: xbow)
  env:                                # Environment variables (type: docker)
    vulnerable: "1"
  rate_limit: 2                       # Requests per second (type: external)

# Optional authentication flow (executed before test cases)
setup:
  auth_flow:
    - name: login                     # Step name (for logging)
      method: POST
      path: "/api/auth/login"
      headers:
        Content-Type: "application/json"
      body: '{"email":"admin@example.com","password":"Admin!123"}'
      extract:
        token: "$.token"              # JSONPath to extract from response

# Test cases
test_cases:
  - id: "dvwa-xss-reflected"         # Unique test case ID
    endpoint: "/vuln?param=test"      # URL path (appended to base URL)
    method: GET                       # HTTP method (default: GET)
    headers:                          # Additional headers (optional)
      Authorization: "Bearer {{token}}"
    body: ""                          # Request body (optional)
    modules:                          # Module IDs to test (from DefaultRegistry)
      - "active-xss-light-url-params"
    vuln_types:                       # Expected vulnerability types (informational)
      - "xss-reflected"
    assertion: strict                 # strict | soft | negative
    min_findings: 1                   # Minimum expected findings (default: 1)
    scan_mode: active                 # active | passive
    timeout: 30s                      # Per-test timeout (blackbox only)
    description: "Reflected XSS in name parameter"
```

### App Types

| Type | Container Management | Base URL |
|------|---------------------|----------|
| `docker` | Testcontainers-go starts/stops container automatically | Auto-assigned (mapped port) |
| `compose` | Must be started externally (`make crapi-up`) | Specified in `base_url` |
| `xbow` | Docker Compose CLI builds from source, starts/stops automatically | Auto-discovered via `docker compose port` |
| `external` | No containers — uses public websites | Specified in `base_url` |

### Scan Modes

| Mode | What Happens |
|------|-------------|
| `active` | Harness creates `HttpRequestResponse` from URL, resolves active module, calls `ScanPerRequest`/`ScanPerHost` |
| `passive` | Harness fetches URL with HTTP client first (to get actual response), then passes full request+response to passive module's `ScanPerRequest`/`ScanPerHost` |

---

## Adding New Test Cases

The simplest way to expand coverage is to add test cases to existing YAML definitions.

### Example: Add a new SQLi test to DVWA

Edit `test/benchmark/definitions/dvwa.yaml`:

```yaml
test_cases:
  # ... existing cases ...

  - id: "dvwa-sqli-blind"
    endpoint: "/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
    method: GET
    modules: ["active-sqli-time-based-params"]
    vuln_types: ["sqli-time-based"]
    assertion: soft
    min_findings: 1
    scan_mode: active
    description: "Blind SQL injection in id parameter"
```

### Example: Add a passive module check

```yaml
  - id: "dvwa-mixed-content"
    endpoint: "/"
    method: GET
    modules: ["passive-mixed-content-detect"]
    assertion: soft
    min_findings: 0
    scan_mode: passive
    description: "Mixed content detection on main page"
```

### Guidelines

- **Use `strict` assertion** only when you're confident the module will detect the vulnerability (e.g., DVWA SQLi with error-based detection).
- **Use `soft` assertion** for new/experimental test cases or apps with protections that may block detection.
- **Use `negative` assertion** for endpoints that should NOT trigger findings (false positive testing).
- **Module IDs** must match exactly what's registered in `pkg/modules/default_registry.go`. Run `go test -v -run TestResolveActiveModules ./test/benchmark/harness/...` to verify module resolution.

### Finding Available Module IDs

```bash
# List all active module IDs
go test -v -run TestGenerateCoverageReport ./test/benchmark/harness/... 2>&1 | grep "active-"

# Or check the registry directly
grep 'Register' pkg/modules/default_registry.go
```

---

## Adding a New Vulnerable App

### Docker-based (Whitebox)

1. **Create a YAML definition** at `test/benchmark/definitions/<app>.yaml`:

```yaml
app:
  name: webgoat
  type: docker
  image: "webgoat/webgoat:latest"
  port: 8080
  wait_endpoint: "/WebGoat"
  startup_timeout: 120s

test_cases:
  - id: "webgoat-sqli"
    endpoint: "/WebGoat/SqlInjection/attack5a?account=test&operator=test&injection=test"
    method: GET
    modules: ["active-sqli-error-based"]
    assertion: soft
    min_findings: 1
    scan_mode: active
```

2. **No Go code changes needed** — the existing `TestWhitebox_Active` runner automatically picks up new YAML files from the definitions directory.

3. **Run it**:
```bash
go test -v -tags=canary -run "TestWhitebox_Active/webgoat" ./test/benchmark/whitebox/...
```

### Docker Compose-based (Built from Source)

For apps that need to be built from source or require multiple services (like NextJS VulnExamples):

1. **Place the Docker Compose file** in `test/testdata/vulnerable-apps/<app>/docker-compose.yaml`.

   Example (`nextjs-vulnexamples/docker-compose.yaml`):
   ```yaml
   services:
     db:
       image: postgres:16-alpine
       environment:
         - POSTGRES_DB=myapp
         - POSTGRES_USER=myapp
         - POSTGRES_PASSWORD=myapp
       healthcheck:
         test: ["CMD-SHELL", "pg_isready -U myapp"]
         interval: 5s
         timeout: 5s
         retries: 5

     app:
       build:
         context: https://github.com/org/repo.git
       ports:
         - "3000:3000"
       environment:
         - PGHOST=db
         - PGDATABASE=myapp
       depends_on:
         db:
           condition: service_healthy
   ```

2. **Create a YAML definition** with `type: xbow`:
   ```yaml
   app:
     name: my-nextjs-app
     type: xbow
     build_context: test/testdata/vulnerable-apps/my-nextjs-app
     service_name: app
     internal_port: 3000
     port: 3000
     wait_endpoint: "/"
     startup_timeout: 180s
   ```

3. **Add a dedicated test function** in `test/benchmark/whitebox/active_test.go`:
   ```go
   func TestWhitebox_MyApp_Active(t *testing.T) {
       if testing.Short() {
           t.Skip("Skipping benchmark test in short mode")
       }
       defPath := filepath.Join(harness.DefinitionsDir(), "my-app.yaml")
       def, err := harness.LoadDefinition(defPath)
       require.NoError(t, err, "Failed to load my-app definition")
       runActiveDefinition(t, def)
   }
   ```

4. **Optionally add SAST coverage** — create a source stub and YAML definitions for the whitebox SAST pipeline (see [whitebox-sast.md](whitebox-sast.md)).

---

## Adding a New Blackbox Site

1. **Create a YAML definition** at `test/benchmark/definitions/blackbox/<site>.yaml`:

```yaml
app:
  name: hackazon
  type: external
  base_url: "http://hackazon.webscantest.com"
  rate_limit: 2    # Requests per second (be conservative with external sites)

test_cases:
  - id: "hackazon-xss"
    endpoint: "/search?searchString=test"
    method: GET
    modules: ["active-xss-light-url-params"]
    assertion: soft    # Always soft for blackbox
    min_findings: 1
    scan_mode: active
```

2. **Important rules for blackbox definitions**:
   - **All assertions must be `soft`** — external sites may change, go down, or add protections.
   - **Set `rate_limit`** to be respectful (2 req/sec is a good default).
   - The test runner automatically skips if the site is unreachable.

3. **Run it**:
```bash
go test -v -tags=blackbox -run "TestBlackbox_Active/hackazon" ./test/benchmark/blackbox/...
```

---

## Coverage Report

The coverage report compares all module IDs referenced in YAML definitions against the full `DefaultRegistry`.

### Generate the Report

```bash
make test-benchmark-coverage
```

Or directly:

```bash
go test -v -tags=canary -run TestBenchmark_CoverageReport ./test/benchmark/coverage/...
```

This outputs a markdown table to stdout and writes `test/benchmark/coverage-report.md`.

### Sample Output

```
# Vigolium Module Benchmark Coverage

**Total test cases:** 85+

**Active modules:** 20/36 (56%)

**Passive modules:** 14/17 (82%)

## Coverage Matrix

| Module ID | Type | Covered | Apps |
|-----------|------|---------|------|
| active-authn-bypass | active | Yes | nextjs-vulnexamples |
| active-code-exec | active | Yes | dvwa, crapi |
| active-cors-misconfiguration | active | Yes | vampi, juiceshop, crapi, oopssec-store, nextjs-vulnexamples |
| active-sqli-error-based | active | Yes | dvwa, vampi, juiceshop, oopssec-store, ... |
| passive-security-headers-missing | passive | Yes | dvwa, vampi, juiceshop, crapi, oopssec-store, nextjs-vulnexamples |
| passive-ssr-data-exposure | passive | Yes | oopssec-store, nextjs-vulnexamples |
| ...

## Uncovered Modules

- `active-http-request-smuggling` (active)
- `active-race-interference` (active)
- `passive-anomaly-ranking` (passive)
- ...
```

### Understanding Coverage

- **Covered** means at least one YAML test case references the module ID.
- **Coverage does NOT mean detection** — a soft-asserted test case counts as covered even if the module finds nothing.
- Some modules are intentionally deferred (see [Hard-to-Benchmark Modules](#hard-to-benchmark-modules)).

---

## Assertion Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `strict` | Test fails if `len(findings) < min_findings` | Known vulnerabilities in controlled Docker apps |
| `soft` | Logs a warning but test passes regardless | Experimental tests, blackbox sites, modern apps with protections |
| `negative` | Test fails if `len(findings) > 0` | False positive testing — endpoints that should NOT trigger |

### Choosing the Right Assertion

```
Is this a Docker app with a known, reliably detectable vuln?
├─ Yes → strict
└─ No
    ├─ Is this an external site or might detection fail?
    │   └─ Yes → soft
    └─ Should this endpoint have NO findings?
        └─ Yes → negative
```

---

## Harness Package Reference

The `test/benchmark/harness/` package is a shared Go library (not a test package) that provides the core benchmark infrastructure.

### Key Types

| Type | Description |
|------|-------------|
| `BenchmarkDefinition` | Root struct parsed from YAML — contains `AppConfig` and `[]TestCase` |
| `AppConfig` | Target application configuration (image, port, type, env, build_context, service_name, internal_port) |
| `ComposeApp` | Running Docker Compose project (project name, directory, base URL) |
| `TestCase` | Single test case (endpoint, modules, assertion, scan mode) |
| `TestInfra` | Test infrastructure (HTTP client, host errors, rate limiter, scan context) |
| `TestResult` | Outcome of a single test case execution |
| `CoverageReport` | Module coverage matrix |
| `SASTExtractionDefinition` | Route extraction test: framework, source_dir, expected routes, bounds |
| `SASTSARIFDefinition` | SARIF parsing test: fixture path, tool name, format, expectations |
| `SASTHandoffDefinition` | Handoff test: framework, base URL, routes with expected requests |

### Key Functions

| Function | Description |
|----------|-------------|
| `LoadDefinition(path)` | Load a single YAML definition file |
| `LoadDefinitionsFromDir(dir)` | Load all YAML files from a directory |
| `SetupTestInfra()` | Initialize HTTP client, rate limiter, scan context |
| `SetupTestInfraWithOAST()` | Initialize with OAST mock provider |
| `StartContainer(ctx, config)` | Start a Docker container via testcontainers-go |
| `StartAppFromDefinition(ctx, app)` | Start an app based on its type (docker/compose/xbow/external) |
| `StartComposeApp(ctx, app)` | Build and start an xbow Docker Compose project from source |
| `RunActiveTestCase(t, tc, baseURL, infra)` | Execute an active test case |
| `RunPassiveTestCase(t, tc, baseURL, infra)` | Execute a passive test case (fetch + scan) |
| `FetchForPassiveScan(url, headers, infra)` | Fetch a URL and return HRR with response attached |
| `SetupAppAuth(t, appName, baseURL)` | Perform app-specific auth/setup, return headers to inject |
| `MergeHeaders(authHeaders, tcHeaders)` | Merge auth headers into test case headers |
| `SetupDVWA(t, baseURL)` | Initialize DVWA DB, login, return session cookies |
| `ResolveActiveModules(ids)` | Look up active modules from DefaultRegistry |
| `ResolvePassiveModules(ids)` | Look up passive modules from DefaultRegistry |
| `ApplyAssertion(t, tc, moduleID, findings)` | Check findings against assertion mode |
| `GenerateCoverageReport(dirs...)` | Generate module coverage matrix |
| `FormatCoverageMarkdown(report)` | Render coverage report as markdown |
| `CheckExternalAvailability(t, url)` | Skip test if external site is unreachable |
| `LoadSASTExtractionDefinitionsFromDir(dir)` | Load all extraction YAMLs |
| `LoadSASTSARIFDefinitionsFromDir(dir)` | Load all SARIF YAMLs |
| `LoadSASTHandoffDefinitionsFromDir(dir)` | Load all handoff YAMLs |

### Active Test Case Flow

```go
// 1. Build HttpRequestResponse from URL (GET or POST with optional headers/body)
if tc.Method == "POST" && tc.Body != "" {
    rr, err = buildPOSTRequest(baseURL + tc.Endpoint, tc.Body, tc.Headers)
} else {
    rr, err = buildRequestWithHeaders(baseURL + tc.Endpoint, tc.Headers)
}

// 2. Resolve module by ID
mods := modules.GetActiveModulesByIDs(tc.Modules)

// 3. Dispatch based on module's ScanScope
switch {
case mod.ScanScopes().Has(modkit.ScanScopeInsertionPoint):
    // Create insertion points and scan each one
    points, _ := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
    for _, ip := range points {
        if mod.AllowedInsertionPointTypes().Contains(ip.Type()) {
            findings, _ = mod.ScanPerInsertionPoint(rr, ip, httpClient, scanCtx)
        }
    }
case mod.ScanScopes().Has(modkit.ScanScopeRequest):
    findings, err = mod.ScanPerRequest(rr, httpClient, scanCtx)
case mod.ScanScopes().Has(modkit.ScanScopeHost):
    findings, err = mod.ScanPerHost(rr, httpClient, scanCtx)
}

// 4. Apply assertion
ApplyAssertion(t, tc, mod.ID(), findings)
```

### Passive Test Case Flow

```go
// 1. Fetch URL to get actual response (with optional auth headers)
rr, err := FetchForPassiveScan(baseURL + tc.Endpoint, tc.Headers, infra)
//    Internally: Execute request → respChain.FullResponse() → rr.WithResponse(httpResp)

// 2. Resolve passive module
mods := modules.GetPassiveModulesByIDs(tc.Modules)

// 3. Pass full request+response to passive module
findings, err = mod.ScanPerRequest(rr, scanCtx)

// 4. Apply assertion
ApplyAssertion(t, tc, mod.ID(), findings)
```

---

## CI Integration

### Recommended CI Strategy

| Trigger | What to Run | Timeout |
|---------|------------|---------|
| On every PR | `make test-sast-sarif && make test-sast-handoff` | 5 min |
| On every PR | `make test-benchmark-whitebox` (DVWA + VAmPI only) | 15 min |
| Nightly | `make test-benchmark-all` (all whitebox + blackbox) | 30 min |
| Nightly | `make test-sast` (all SAST layers) | 10 min |
| Weekly | `make test-benchmark-crapi` (requires crAPI up) | 20 min |
| Weekly | `make test-xbow` (requires XBOW_SOURCE_DIR) | 30 min |
| Weekly | `make test-sast-e2e` (full pipeline) | 15 min |
| On release | `make test-benchmark-coverage` | 1 min |

### Example GitHub Actions Workflow

```yaml
- name: Run SAST benchmarks (no external deps)
  run: |
    make test-sast-sarif
    make test-sast-handoff
  timeout-minutes: 5

- name: Run whitebox benchmarks
  run: |
    make test-benchmark-whitebox
  timeout-minutes: 15

- name: Run blackbox benchmarks (nightly only)
  if: github.event_name == 'schedule'
  run: |
    make test-benchmark-blackbox
  timeout-minutes: 20
  continue-on-error: true  # Blackbox may fail due to external site issues

- name: Run XBOW validation benchmarks (weekly)
  if: github.event_name == 'schedule'
  run: |
    make xbow-build
    make test-xbow
  timeout-minutes: 30
  env:
    XBOW_SOURCE_DIR: ${{ github.workspace }}/validation-benchmarks
```

---

## XBOW Validation Benchmarks

XBOW benchmarks are CTF-style, self-contained vulnerable applications sourced from the [validation-benchmarks](https://github.com/anthropics/validation-benchmarks) repository. Each benchmark is a Docker Compose project with its own source code, Dockerfile, and docker-compose.yml. Unlike the whitebox benchmarks (which pull pre-built images from Docker Hub), XBOW apps are **built from source** via `docker compose build`.

### How It Works

The `xbow` app type in the harness triggers a Docker Compose CLI lifecycle managed by `harness/compose.go`:

1. **Build**: `docker compose -f <dir>/docker-compose.yml -p xbow-<name> build --build-arg FLAG=test`
2. **Start**: `docker compose ... up -d --wait`
3. **Port discovery**: `docker compose ... port <service> <internal_port>` — parses the ephemeral host port
4. **Health check**: Polls `wait_endpoint` until it responds with status < 500
5. **Test execution**: Runs active test cases (GET or POST) through the standard harness
6. **Teardown**: `docker compose ... down -v --remove-orphans`

Each benchmark uses a unique project name (`xbow-<name>`) to prevent container name collisions when running in parallel.

### YAML Definition Format (XBOW)

XBOW definitions use the `build_context`, `service_name`, and `internal_port` fields instead of `image` and `port`:

```yaml
app:
  name: xbow-ssti-053
  type: xbow
  build_context: "${XBOW_SOURCE_DIR}/benchmarks/XBEN-053-24"
  service_name: app             # which docker-compose service to get port from
  internal_port: 80             # port inside the container
  wait_endpoint: "/ping"
  startup_timeout: 180s

test_cases:
  - id: "xbow-053-ssti-jinja"
    endpoint: "/?username=test"
    method: GET
    modules: ["active-reflected-ssti"]
    vuln_types: ["ssti"]
    assertion: strict
    min_findings: 1
    scan_mode: active
    description: "Jinja2 SSTI via username query parameter (XBEN-053-24)"
```

POST-based test cases include `body` and `headers`:

```yaml
test_cases:
  - id: "xbow-073-cmdi-ping"
    endpoint: "/ping"
    method: POST
    body: "ip_address=127.0.0.1"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
    modules: ["active-code-exec"]
    vuln_types: ["code-exec"]
    assertion: strict
    min_findings: 1
    scan_mode: active
```

The `${XBOW_SOURCE_DIR}` environment variable is expanded via `os.ExpandEnv()` when the YAML is loaded. The Makefile sets it automatically, or it can be set in your shell.

### Phase 1 Benchmarks (13 total)

| ID | XBOW | Vuln Type | Endpoint | Service:Port | Module | Assertion |
|----|------|-----------|----------|-------------|--------|-----------|
| xbow-xss-013 | XBEN-013-24 | XSS | `GET /page?name=test` | web:5000 | `active-xss-light-url-params` | soft |
| xbow-xss-047 | XBEN-047-24 | XSS | `GET /page?url=test` | web:5000 | `active-xss-light-url-params` | soft |
| xbow-ssti-009 | XBEN-009-24 | SSTI | `GET /greet/?name=test` | web:8000 | `active-reflected-ssti` | strict |
| xbow-ssti-053 | XBEN-053-24 | SSTI | `GET /?username=test` | app:80 | `active-reflected-ssti` | strict |
| xbow-ssti-076 | XBEN-076-24 | SSTI | `GET /greet?name=test` | web:5000 | `active-reflected-ssti` | strict |
| xbow-sqli-083 | XBEN-083-24 | SQLi | `GET /?category=test` | web:80 | `active-sqli-error-based` | strict |
| xbow-sqli-071 | XBEN-071-24 | SQLi | `POST /send.php` | app:80 | `active-sqli-error-based` | soft |
| xbow-cmdi-073 | XBEN-073-24 | CmdI | `POST /ping` | web:80 | `active-code-exec` | strict |
| xbow-lfi-019 | XBEN-019-24 | LFI | `GET /resource?filename=test.txt` | lfi_static_resource:80 | `active-lfi-generic` | strict |
| xbow-lfi-061 | XBEN-061-24 | LFI | `GET /post.php?id=test` | web:80 | `active-lfi-generic` | strict |
| xbow-ssrf-020 | XBEN-020-24 | SSRF | `GET /redirect.php?url=...` | ssrf-demo-app:80 | `active-ssrf-detection` | soft |
| xbow-xxe-006 | XBEN-006-24 | XXE | `POST /addbook` (XML) | app:80 | `active-xxe-generic` | soft |
| xbow-xxe-096 | XBEN-096-24 | SQLi | `POST /jobs` (JSON) | libraryv1:5000 | `active-sqli-error-based` | soft |

### Test Runner Structure

The test runner at `test/benchmark/xbow/xbow_test.go` (build tag `xbow`) provides:

| Test Function | What it runs |
|---------------|-------------|
| `TestXbow_All` | All definitions in `definitions/xbow/` |
| `TestXbow_XSS` | Only `xbow-xss-*.yaml` |
| `TestXbow_SSTI` | Only `xbow-ssti-*.yaml` |
| `TestXbow_SQLi` | Only `xbow-sqli-*.yaml` |
| `TestXbow_CmdI` | Only `xbow-cmdi-*.yaml` |
| `TestXbow_LFI` | Only `xbow-lfi-*.yaml` |
| `TestXbow_SSRF` | Only `xbow-ssrf-*.yaml` |
| `TestXbow_XXE` | Only `xbow-xxe-*.yaml` |

Tests are skipped automatically if `XBOW_SOURCE_DIR` is not set or the directory is inaccessible.

### Adding a New XBOW Benchmark

1. Identify the XBEN benchmark in the validation-benchmarks repo. Read its `docker-compose.yml` to find the service name, internal port, and health check endpoint.

2. Create a YAML definition at `test/benchmark/definitions/xbow/xbow-<type>-<num>.yaml`:

```yaml
app:
  name: xbow-<type>-<num>
  type: xbow
  build_context: "${XBOW_SOURCE_DIR}/benchmarks/XBEN-<num>-24"
  service_name: <service>        # from docker-compose.yml
  internal_port: <port>          # from docker-compose.yml ports section
  wait_endpoint: "/"             # from healthcheck or "/" as default
  startup_timeout: 180s

test_cases:
  - id: "xbow-<num>-<type>-<param>"
    endpoint: "/vulnerable?param=test"
    method: GET                  # or POST
    modules: ["active-<module-id>"]
    vuln_types: ["<vuln-type>"]
    assertion: strict            # or soft for uncertain detections
    min_findings: 1
    scan_mode: active
    description: "Description (XBEN-<num>-24)"
```

3. Run it:
```bash
make test-xbow XBOW_SOURCE_DIR=/path/to/validation-benchmarks
```

No Go code changes are needed — the test runner automatically picks up new YAML files.

---

## Troubleshooting

### Container startup fails

```
Failed to start container vulnerables/web-dvwa:latest: ...
```

- Ensure Docker is running: `docker info`
- Pull the image manually: `docker pull vulnerables/web-dvwa:latest`
- Check available disk space and memory

### Module not found

```
active modules not found: [active-nonexistent-module]
```

- Verify the module ID in `pkg/modules/default_registry.go`
- Module IDs are case-sensitive and use kebab-case (e.g., `active-sqli-error-based`)

### crAPI tests skip

```
crAPI not available (run 'make crapi-up' first)
```

- Start crAPI manually: `make crapi-up`
- Wait for all services: `make crapi-status` (all should show "healthy")
- crAPI takes 2-3 minutes to fully start

### XBOW tests skip

```
XBOW_SOURCE_DIR not set; skipping xbow benchmarks
```

- Set the environment variable: `export XBOW_SOURCE_DIR=/path/to/validation-benchmarks`
- Or pass it via make: `make test-xbow XBOW_SOURCE_DIR=/path/to/validation-benchmarks`

### XBOW build fails

```
xbow app xbow-ssti-053: build failed: ...
```

- Ensure Docker is running and has sufficient resources (CPU, memory, disk)
- Try building the image directly: `cd $XBOW_SOURCE_DIR/benchmarks/XBEN-053-24 && docker compose build --build-arg FLAG=test`
- Pre-build all images with `make xbow-build` to isolate build issues from test failures

### XBOW port discovery fails

```
xbow app xbow-ssti-053: port discovery failed: no port mapping found
```

- The docker-compose service may not have started. Check: `docker compose -p xbow-xbow-ssti-053 ps`
- Verify the `service_name` and `internal_port` in the YAML match the docker-compose.yml
- Some benchmarks (XBEN-083-24, XBEN-071-24) have database services that need time to initialize. Increase `startup_timeout` if needed.

### Blackbox tests skip

```
External site http://testphp.vulnweb.com is unreachable
```

- Check internet connectivity
- The site may be temporarily down — blackbox tests are designed to gracefully skip

### ast-grep compatibility issue

```
Skipping: ast-grep ast-grep-config.yaml compatibility issue (known)
```

- Some ast-grep versions (v0.41.0+) treat `ast-grep-config.yaml` as a rule file, causing a parse error. Extraction tests skip gracefully. Other SAST layers (SARIF, handoff) are unaffected.

### No findings from a strict-asserted test

If a test that should find vulnerabilities returns 0 findings:

1. Run the test with verbose logging: `go test -v -tags=canary -run TestName ...`
2. Check if the endpoint is accessible from the container
3. For DVWA: ensure auth setup completed successfully (look for "DVWA setup: verified access to vulnerability pages" in logs). Without auth, all `/vulnerabilities/` endpoints redirect to `/login.php`.
4. Check that the module's `ScanScope` matches how the endpoint should be scanned:
   - `PerInsertionPoint` modules (SQLi, LFI) require URL parameters to create insertion points
   - `PerRequest` modules (XSS, code-exec) handle insertion points internally
   - `PerHost` modules (CORS) are called once per unique host
5. Try the `TestDebug_DirectVsHarness` test to compare direct module invocation:
   ```bash
   go test -v -tags=canary -run TestDebug ./test/benchmark/whitebox/...
   ```
6. Consider changing the assertion to `soft` if the detection is unreliable

---

## Hard-to-Benchmark Modules

Some modules require specialized infrastructure that is impractical for automated benchmarks:

| Module | Reason | Workaround |
|--------|--------|------------|
| `active-http-request-smuggling` | Requires specific server configurations (CL.TE, TE.CL) | Manual testing with custom servers |
| `active-race-interference` | Needs concurrent request handling with precise timing | Dedicated race condition test harness |
| `active-xml-saml-security` | Needs SAML IdP setup | Test against SAML-vulnerable test apps |
| `passive-anomaly-ranking` | Needs large traffic corpus for statistical analysis | Replay captured traffic |
| `passive-oauth-facebook-detect` | Needs Facebook OAuth flow | Mock OAuth server |
| `passive-serialized-object-detect` | Needs apps with Java/.NET serialization | Custom test server |

These modules should be tested through dedicated test files rather than the YAML-driven benchmark system.
