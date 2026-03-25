# Whitebox Benchmark & Agent Integration Improvement Plan

> Generated: 2026-03-03 | Status: Draft

---

## Table of Contents

1. [Current State Summary](#1-current-state-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [What Each Component Does](#3-what-each-component-does)
4. [Identified Gaps](#4-identified-gaps)
5. [Improvement Recommendations](#5-improvement-recommendations)
6. [Priority Roadmap](#6-priority-roadmap)

---

## 1. Current State Summary

### Test Tiers

| Tier | Build Tag | Make Target | Dependencies | What It Tests |
|------|-----------|-------------|--------------|---------------|
| Whitebox/Canary | `canary` | `test-canary` | Docker | Active + passive modules against 5 Docker vulnerable apps |
| Blackbox | `blackbox` | manual | Internet | Scanner against 3 external live sites (soft assertions) |
| XBOW | `xbow` | `test-xbow` | Docker + source | 13 challenge apps across 7 vuln categories |
| SAST Extraction | `sast` | `test-sast-extraction` | None | Route extraction from 7 framework stubs |
| SAST SARIF | `sast` | `test-sast-sarif` | None | Parsing Semgrep/OSV-Scanner SARIF (9 fixtures) |
| SAST Handoff | `sast` | `test-sast-handoff` | None | Route → HRR conversion (3 frameworks) |
| SAST E2E | `sast_e2e` | `test-sast-e2e` | `ast-grep` | Full source → route → HRR pipeline |
| Agent Parsing (L1) | `agent_benchmark` | `test-agent-parsing` | None | Raw LLM output → structured data |
| Agent Quality (L2) | `agent_benchmark` | `test-agent-quality` | None | CWEs, vuln types, severity correctness |
| Agent Handoff (L3) | `agent_benchmark` | `test-agent-handoff` | None | HTTP records → scanner-consumable HRR |
| Agent E2E (L4) | `agent_benchmark,canary` | `test-agent-benchmark-e2e` | Docker | Agent records → live scan → findings |

### Vulnerable Apps

| App | Image | Test Cases | Assertion Style |
|-----|-------|------------|-----------------|
| DVWA | `vulnerables/web-dvwa` | 12 | Mostly `strict` |
| VAmPI | `erev0s/vampi` | 37 | Mostly `soft` |
| Juice Shop | `bkimminich/juice-shop` | 20 | Mixed |
| Vulnerable Java | `ghcr.io/datadog/vulnerable-java-application` | 8 | Mostly `soft` |
| Vulnerable Nginx | `detectify/vulnerable-nginx` | 7 | Mostly `soft` |
| crAPI | `crapi/*` (compose) | 15 | Mixed |

### Agent Integration Pipeline

```
Prompt Template (YAML frontmatter + Go text/template)
    → Context Enrichment (source code, DB findings, endpoints, module list)
        → Agent Execution (pipe stdin/stdout OR ACP protocol)
            → Output Parsing (JSON extraction with 3 fallback strategies)
                → Database Ingestion (findings or HTTP records)
                    → Optional: Loop (analyze → scan → repeat until convergence)
```

- 10 built-in prompt templates
- 7 agent backends (Claude, Codex, OpenCode, Gemini — ACP + pipe modes)
- 12 cached agent fixtures across 5 frameworks × 3 templates

### SAST Pipeline

```
Source Code Stubs (7 frameworks)
    → ast-grep Route Extraction
        → Route → HRR Handoff (3 frameworks have definitions)
            → Insertion Point Creation
                → Scanner Module Execution
```

---

## 2. Architecture Overview

### Benchmark Harness (`test/benchmark/harness/`)

The harness is the backbone — 12 files providing:

- **types.go** — `BenchmarkDefinition` (app config + test cases), `TestResult`, `CoverageReport`
- **sast_types.go** — `SASTExtractionDefinition`, `SASTSARIFDefinition`, `SASTHandoffDefinition`
- **agent_types.go** — `AgentFixture`, `AgentParsingDefinition`, `AgentQualityDefinition`, `AgentHandoffDefinition`, `AgentE2EDefinition`
- **harness.go** — `SetupTestInfra()`, `RunActiveTestCase()`, `RunPassiveTestCase()`, `ApplyAssertion()`
- **container.go / compose.go** — Docker lifecycle management via testcontainers-go
- **dvwa_setup.go** — DVWA-specific auth (CSRF token, DB setup, login, security=low)
- **oast_helper.go** — `MockOASTProvider` for blind vulnerability probe recording
- **report.go** — Coverage matrix generation (modules vs definitions)

### Agent Engine (`pkg/agent/`)

| File | Role |
|------|------|
| `engine.go` | Central orchestrator: resolve agent → build prompt → execute → parse → ingest |
| `loop.go` | Multi-iteration analyze→scan→repeat with convergence detection |
| `context.go` | Lazy context enrichment (only fetches variables declared in template) |
| `runner.go` | Pipe protocol: spawn subprocess, pipe prompt to stdin |
| `acp_runner.go` | ACP protocol: structured bidirectional communication |
| `acp_client.go` | ACP client: auto-approve permissions, read files (scoped), block writes |
| `parser.go` | JSON extraction (direct → strip fences → balanced brace scan) |
| `prompt.go` | Template loading, caching, frontmatter parsing, rendering |
| `types.go` | All type definitions |

### Context Variables Available to Agent

| Variable | Source | Limit |
|----------|--------|-------|
| `PreviousFindings` | DB findings table | 50 results |
| `DiscoveredEndpoints` | DB HTTP records | 100 results |
| `ScanStats` | DB scan statistics | 1 aggregate |
| `ModuleList` | In-memory module registry | All modules |
| `AvailableCommands` | Hardcoded CLI reference | Static text |
| `SourceCode` | Disk walk of `--repo`/`--files` | No limit (problem) |
| `Language` | Auto-detected from extensions | Single value |

---

## 3. What Each Component Does

### Whitebox Benchmark Tests

**Active tests** (`whitebox/active_test.go`): For each Docker app, starts the container, runs app-specific auth setup, then executes all active test cases. Each test case specifies an endpoint, HTTP method, optional body, which scanner modules to invoke, and the expected assertion (strict/soft/negative).

**Passive tests** (`whitebox/passive_test.go`): Same structure but fetches each URL with a real HTTP client and runs passive analysis modules (header checks, content analysis, etc.).

**Test flow**: YAML definition → Docker container start → auth setup → module dispatch → finding count → assertion check.

### SAST Benchmarks

**Extraction**: Given a framework stub directory, runs `ast-grep` to extract routes. Validates expected routes found, methods correct, match counts within bounds, negative routes absent.

**SARIF**: Parses Semgrep/OSV-Scanner output files. Validates finding count, severity mapping, required fields.

**Handoff**: Converts extracted routes to HRR objects. Validates method normalization (ANY→GET), URI construction, host header presence, insertion point creation from URL params.

### Agent Benchmarks (4 Layers)

**L1 Parsing**: Loads cached agent fixture, runs `ParseFindings()`/`ParseHTTPRecords()`, validates count and required fields non-empty.

**L2 Quality**: Validates agent findings contain expected CWEs (e.g., CWE-79 for Flask), expected vuln types, severity distribution within min/max bounds.

**L3 Handoff**: Converts agent HTTP records to HRR objects via `ToHTTPRequestResponse()`. Validates convertible count, specific records found by method/URL prefix.

**L4 E2E**: Parses agent HTTP records → rewrites URLs to Docker app → creates insertion points → runs scanner modules → asserts scanner finds real vulns. Currently only 1 definition (VAmPI).

---

## 4. Identified Gaps

### 4.1 Missing Vulnerability Categories

| Vulnerability | OWASP Category | Available Target | Status |
|---------------|----------------|------------------|--------|
| IDOR/BOLA | API1:2023 | VAmPI, crAPI | No module or test |
| CSRF | A01:2021 | DVWA | No module or test |
| Insecure Deserialization | A08:2021 | SARIF fixtures reference it | No active module test |
| File Upload | A04:2021 | Flask stub has `/upload` | No scanner test |
| Mass Assignment | API6:2023 | VAmPI, crAPI | No module or test |
| GraphQL Vulnerabilities | Various | None | No app, no module |
| WebSocket Security | Various | None | No app, no module |
| Rate Limiting Bypass | API4:2023 | crAPI, VAmPI | No test |
| RegexDOS | CWE-1333 | VAmPI (email) | No module test |
| Prototype Pollution | CWE-1321 | Juice Shop | No module test |
| Session Fixation | A07:2021 | DVWA | No test |
| Multipart Form Injection | Various | None | No insertion point test |

### 4.2 SAST Pipeline Gaps

- **Handoff definitions**: Only 3 of 7 frameworks (Gin, FastAPI, Express). Missing: Django, Flask, Next.js, Go net/http.
- **Missing framework stubs**: No Java/Spring Boot, PHP/Laravel, Ruby/Rails, C#/ASP.NET, Rust/Actix.
- **Go net/http**: Framework autodetection disabled (`detect_framework: false`).
- **Next.js**: Minimal extraction (App Router support incomplete).

### 4.3 Agent Integration Gaps

1. **No context window management** — `collectSourceFiles()` concatenates entire repo, no size limit or truncation.
2. **No scan→agent feedback loop** — Scanner findings from agent HTTP records are counted but not fed back to the agent in subsequent loop iterations.
3. **Title-only deduplication** — Semantically equivalent findings with different wording treated as new.
4. **No finding validation** — Agent severity/confidence ingested as-is, no calibration against scanner results.
5. **ACP terminal no-ops** — `interactive-scan` template expects shell access, but ACP mode stubs all terminal ops.
6. **Thin E2E coverage** — Only 1 agent E2E definition (VAmPI).
7. **Missing fixtures** — `api-input-gen` only for Gin/Flask; 3 frameworks lack attack payload fixtures.
8. **No cost/token tracking** — No visibility into LLM API costs, especially risky in loops.
9. **Auto-approve all ACP permissions** — Security concern; no granular permission control.
10. **Hardcoded context limits** — `PreviousFindings` capped at 50, `DiscoveredEndpoints` at 100, not configurable.
11. **Hardcoded CLI reference** — `AvailableCommands` is a static string that doesn't reflect actual CLI state.

### 4.4 Test Infrastructure Gaps

1. **OAST is mock-only** — `MockOASTProvider` records probes but never validates actual OOB callback receipt.
2. **Too few negative tests** — `assertion: negative` barely used; no false positive regression detection.
3. **Soft assertion dominance** — Most non-DVWA tests use `soft` (log-only). Regressions go unnoticed.
4. **crAPI underutilized** — 15 test cases for an app with 30+ documented vulnerabilities.
5. **Single XML insertion point test** — Only Juice Shop XXE tests `INS_PARAM_XML`.
6. **Coverage report incomplete** — Only scans top-level definitions; misses agent/sast/xbow definitions.
7. **No CI integration for agent benchmarks** — `agent_benchmark` tag not in standard CI make targets.

---

## 5. Improvement Recommendations

### R1. Expand Vulnerability Coverage (High Priority)

**R1.1 — Add IDOR/BOLA Testing**

Both VAmPI and crAPI have well-documented BOLA vulnerabilities. This is OWASP API Security #1.

- Create a new active module or test cases that:
  - Authenticate as User A, then access User B's resources
  - Test horizontal privilege escalation on VAmPI user endpoints
  - Test vehicle/mechanic report access in crAPI
- Add benchmark definitions with two auth contexts (user A token, user B token)
- Harness change: support `auth_contexts` map in YAML, not just a single auth flow

**R1.2 — Add CSRF Testing**

- DVWA has a dedicated CSRF challenge at security=low
- Add passive module test cases for missing CSRF tokens
- Add active test cases that replay requests without Origin/Referer headers

**R1.3 — Add File Upload Testing**

- The Flask SAST stub already has `/upload`
- Add a vulnerable file upload endpoint to VAmPI or create a dedicated upload test container
- Test: unrestricted file type, path traversal in filename, oversized files

**R1.4 — Add Mass Assignment Testing**

- VAmPI: Register with `{"admin": true}` and verify privilege escalation
- crAPI: Modify user fields beyond intended scope
- Requires authorization-aware assertions (check response for elevated privileges, not just finding count)

### R2. Strengthen Assertion Quality (High Priority)

**R2.1 — Promote Soft → Strict Assertions**

Audit every `soft` assertion and determine if it should be `strict`. The current state means regressions in VAmPI (37 tests), Juice Shop (20), vulnerable-java (8), and vulnerable-nginx (7) are invisible in CI.

Recommendation: For any test case where the scanner currently detects the vulnerability reliably (>90% of runs), promote to `strict`. Keep `soft` only for flaky or aspirational tests.

**R2.2 — Add Negative Test Cases**

For each vulnerable app, add endpoints that should NOT trigger findings:

```yaml
- name: vampi-safe-users-list
  endpoint: /users/v1
  method: GET
  modules: [active-sqli-error-based, active-xss-reflected]
  assertion: negative  # Must NOT produce findings — catches false positives
```

Target: at least 3-5 negative test cases per app.

**R2.3 — Add Finding Quality Assertions**

Beyond just "count >= N", validate finding attributes:

- Severity matches expected level
- Module ID is correct
- Finding title/description contains expected keywords
- No duplicate findings for the same insertion point

This requires extending `ApplyAssertion()` in the harness to support field-level checks.

### R3. Improve Agent Integration (High Priority)

**R3.1 — Add Context Window Management**

This is the most critical agent gap. For large repos, the current approach will fail silently or produce degraded results.

- Add a `max_context_tokens` config option (default: 100K tokens, ~75K words)
- Implement file prioritization: rank files by relevance (route handlers > models > utilities > tests)
- Use a token counter (approximate: 1 token ≈ 4 chars) to truncate
- Consider a two-pass approach: first pass identifies relevant files, second pass includes full content
- Add `--max-files` and `--max-file-size` CLI flags

**R3.2 — Close the Scan→Agent Feedback Loop**

Currently in loop mode, scanner findings from agent-generated HTTP records are counted but not fed back. This means the agent can't learn from scan results.

Change `loop.go` to:
1. After `ScanFunc` runs, collect the scanner findings (not just count)
2. Append scanner findings to `accumulatedFindings` with a `[scanner-confirmed]` tag
3. In the next iteration's context, the agent sees both its own findings AND scanner-confirmed results
4. This enables the agent to generate more targeted payloads based on what the scanner actually found

**R3.3 — Improve Finding Deduplication**

Replace exact title matching with a normalized key:
- Lowercase + strip whitespace
- Or hash on `(cwe, file, line_number)` for code review findings
- Or hash on `(module_id, endpoint, parameter)` for scan findings

**R3.4 — Add Finding Validation Layer**

When agent findings are ingested, cross-reference with scanner capabilities:
- If agent reports SQLi on an endpoint, and the scanner has an SQLi module, auto-queue a targeted scan
- After scan, adjust agent finding confidence: "tentative" → "confirmed" or "false-positive"
- Store validation status in DB

**R3.5 — Expand Agent E2E Coverage**

Add agent E2E definitions for all Docker apps:

```
definitions/whitebox/agent/
  vampi-agent-scan.yaml        ← exists
  dvwa-agent-scan.yaml         ← new
  juiceshop-agent-scan.yaml    ← new
  vulnerable-java-agent-scan.yaml  ← new
  crapi-agent-scan.yaml        ← new
```

Each should test the full pipeline: cached fixture → URL rewrite → scanner modules → finding assertions.

**R3.6 — Generate Missing Agent Fixtures**

Run `make benchmark-agent-generate` to fill gaps:
- `express-api-input-gen.json`
- `django-api-input-gen.json`
- `fastapi-api-input-gen.json`

These are needed for complete L2/L3 agent benchmark coverage.

### R4. Expand SAST Coverage (Medium Priority)

**R4.1 — Add Missing Framework Stubs**

| Framework | Language | Priority | Rationale |
|-----------|----------|----------|-----------|
| Spring Boot | Java | High | vulnerable-java is a benchmark target; no SAST extraction test |
| Laravel | PHP | High | DVWA is PHP; PHP is widely deployed |
| Rails | Ruby | Medium | Common web framework |
| ASP.NET | C# | Medium | Enterprise-common |
| Actix/Axum | Rust | Low | Growing adoption |

**R4.2 — Complete Handoff Definitions**

Add handoff YAML definitions for the 4 missing frameworks: Django, Flask, Next.js, Go net/http. These are needed to validate the full source→route→HRR→scan pipeline.

**R4.3 — Fix Go net/http Autodetection**

`detect_framework: false` means users must manually specify the framework. Implement pattern matching for `http.HandleFunc`, `http.Handle`, `mux.HandleFunc` to auto-detect standard library HTTP servers.

### R5. Improve OAST Testing (Medium Priority)

**R5.1 — Add Real OAST Validation**

The mock provider only records probe generation. For real blind vulnerability detection:

- Option A: Integrate with Interactsh client in test mode — start a local Interactsh server, generate real callback URLs, verify callbacks arrive after payload injection
- Option B: Use a lightweight HTTP callback server in tests — start an `httptest.Server`, use its URL as the OAST callback, assert the server received a request

This would validate the entire blind detection chain: payload generation → injection → callback → finding.

**R5.2 — Add More OAST Test Cases**

Currently OAST is tested on:
- VAmPI: 1 OAST probe test
- Vulnerable Java: 2 OAST tests (SSRF, proxy pingback)

Add OAST tests for: blind SQLi (via DNS), blind XXE (via HTTP callback), blind SSRF (via DNS), blind command injection (via DNS/HTTP).

### R6. Maximize crAPI Coverage (Medium Priority)

crAPI has 30+ documented vulnerabilities but only 15 test cases. Add:

| Vulnerability | crAPI Endpoint | Type |
|---------------|----------------|------|
| BOLA on vehicles | `GET /api/v2/vehicle/{id}/location` | Active |
| BOLA on mechanic reports | `GET /api/v2/mechanic/report/{id}` | Active |
| Mass assignment on registration | `POST /api/auth/signup` with `admin: true` | Active |
| Excessive data exposure on video | `GET /api/v2/community/posts/{id}` | Passive |
| Broken function-level auth | `PUT /api/v2/admin/coupon/validate` | Active |
| SSRF on mechanic | `POST /api/v2/merchant/contact_mechanic` | Active |
| Unrestricted file upload | `POST /api/v2/user/videos` | Active |
| User enumeration on login | `POST /api/auth/login` with invalid creds | Passive |
| JWT key confusion | Various authenticated endpoints | Active |
| NoSQL injection on coupon | `POST /api/v2/coupon/validate-coupon` | Active |

### R7. Test Infrastructure Improvements (Lower Priority)

**R7.1 — Unified CI Make Targets**

Add a single `make test-all-benchmarks` that runs all benchmark tiers in sequence:
```makefile
test-all-benchmarks: test-sast test-agent-benchmark test-canary test-benchmark-coverage
```

Ensure `agent_benchmark` tests run in CI, not just manually.

**R7.2 — Improve Coverage Report**

Extend `report.go` to scan ALL definition directories (not just top-level):
- `definitions/whitebox/agent/`
- `definitions/whitebox/extraction/`
- `definitions/whitebox/sarif/`
- `definitions/whitebox/handoff/`
- `definitions/xbow/`
- `definitions/blackbox/`

Generate a unified coverage matrix showing module coverage across all test tiers.

**R7.3 — Add Benchmark Regression Tracking**

Store benchmark results in a JSON/SQLite file over time:
- Track finding counts per test case per run
- Detect regressions: if a previously-strict test suddenly finds 0 results
- Generate trend reports: "XSS detection rate over last 10 runs"

**R7.4 — Add Flakiness Detection**

Run each benchmark 3x and flag tests with inconsistent results. These should stay `soft` until stabilized. Tests with 100% pass rate across 3 runs can be promoted to `strict`.

### R8. Agent Prompt Template Improvements (Lower Priority)

**R8.1 — Add Framework-Specific Templates**

Current templates are generic. Add specialized templates:
- `spring-security-review` — Focus on Spring Security filters, CSRF config, CORS config, authentication providers
- `django-security-review` — Focus on Django middleware, ORM injection, template injection, settings.py
- `nodejs-security-review` — Focus on Express middleware, prototype pollution, package vulnerabilities

**R8.2 — Add Multi-Turn Agent Support**

The current chat completions endpoint concatenates all messages into a single prompt. Implement proper multi-turn:
- Maintain conversation history per session
- Allow the agent to ask clarifying questions
- Support "show me file X" follow-up requests within a session

**R8.3 — Add Token Budget to Templates**

Each template should declare an expected token budget:
```yaml
token_budget: 100000  # Maximum context tokens
priority_files:
  - "routes.*"
  - "handlers.*"
  - "middleware.*"
  - "auth.*"
```

The engine would prioritize files matching these patterns when truncating.

---

## 6. Priority Roadmap

### Phase 1: Foundation (Immediate)

| # | Task | Impact | Effort |
|---|------|--------|--------|
| R2.1 | Promote soft→strict assertions where reliable | Catch regressions | Low |
| R2.2 | Add 3-5 negative test cases per app | Catch false positives | Low |
| R3.6 | Generate missing agent fixtures (3 frameworks) | Complete L2/L3 coverage | Low |
| R7.1 | Add agent benchmarks to CI | Prevent silent breakage | Low |

### Phase 2: Coverage Expansion (Short-term)

| # | Task | Impact | Effort |
|---|------|--------|--------|
| R1.1 | Add IDOR/BOLA testing | OWASP API #1 coverage | Medium |
| R3.1 | Add context window management | Unblock large repo analysis | Medium |
| R3.5 | Add agent E2E for all Docker apps | 5x E2E coverage | Medium |
| R4.2 | Complete SAST handoff definitions (4 frameworks) | Full pipeline testing | Low |
| R6 | Expand crAPI to 25+ test cases | 2x crAPI coverage | Medium |

### Phase 3: Deep Integration (Medium-term)

| # | Task | Impact | Effort |
|---|------|--------|--------|
| R3.2 | Close scan→agent feedback loop | Smarter iterative analysis | Medium |
| R3.4 | Add finding validation layer | Reduce false positives | High |
| R4.1 | Add Spring Boot + Laravel stubs | Cover 2 major frameworks | Medium |
| R5.1 | Add real OAST validation | Validate blind detection chain | High |
| R1.2 | Add CSRF testing | Common web vuln coverage | Medium |

### Phase 4: Advanced (Longer-term)

| # | Task | Impact | Effort |
|---|------|--------|--------|
| R1.3 | File upload testing | New vuln category | Medium |
| R1.4 | Mass assignment testing | API-specific vuln category | Medium |
| R7.3 | Benchmark regression tracking | Long-term quality signal | Medium |
| R8.1 | Framework-specific agent templates | Better agent accuracy | Medium |
| R8.2 | Multi-turn agent support | Richer analysis sessions | High |
| R8.3 | Token budget in templates | Predictable agent behavior | Low |

---

## Appendix A: Vulnerability Coverage Matrix

### Active Modules Tested

| Vulnerability | DVWA | VAmPI | JuiceShop | VulnJava | VulnNginx | crAPI | XBOW |
|---------------|------|-------|-----------|----------|-----------|-------|------|
| SQLi Error-Based | ✅ | ✅ | ✅ | — | — | ✅ | ✅ |
| SQLi Time-Based | — | ✅(soft) | — | — | — | — | — |
| XSS Reflected | ✅ | ✅ | ✅ | — | — | — | ✅ |
| XSS DOM | ✅(soft) | — | — | — | — | — | — |
| LFI/Path Traversal | ✅ | — | — | ✅ | — | — | ✅ |
| Command Injection | ✅(soft) | — | — | ✅ | — | ✅ | ✅ |
| SSRF | — | — | — | ✅ | — | ✅ | ✅ |
| CRLF | ✅ | ✅ | ✅ | ✅ | ✅ | — | — |
| NoSQLi | — | ✅ | — | — | — | ✅ | — |
| CORS | — | ✅ | ✅ | — | — | ✅ | — |
| JWT | — | ✅ | — | — | — | ✅ | — |
| Host Header | — | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Open Redirect | — | ✅ | — | — | — | — | — |
| XXE | — | — | ✅ | — | — | — | ✅ |
| SSTI | — | — | ✅ | — | — | — | ✅ |
| Path Normalization | — | — | ✅ | — | ✅ | — | — |
| Nginx Off-by-Slash | — | — | — | — | ✅ | — | — |
| OAST Probe | — | ✅ | — | ✅ | — | — | — |
| IDOR/BOLA | — | — | — | — | — | — | — |
| CSRF | — | — | — | — | — | — | — |
| File Upload | — | — | — | — | — | — | — |
| Mass Assignment | — | — | — | — | — | — | — |
| Deserialization | — | — | — | — | — | — | — |

### SAST Framework Coverage

| Framework | Extraction | Handoff | E2E | Agent Fixtures |
|-----------|------------|---------|-----|----------------|
| Gin (Go) | ✅ | ✅ | ✅ | 3/3 templates |
| Flask (Python) | ✅ | — | — | 3/3 templates |
| FastAPI (Python) | ✅ | ✅ | ✅ | 2/3 templates |
| Express (Node.js) | ✅ | ✅ | ✅ | 2/3 templates |
| Django (Python) | ✅ | — | — | 2/3 templates |
| Next.js (TS) | ✅(minimal) | — | — | — |
| Go net/http | ✅(no autodetect) | — | — | — |
| Spring Boot (Java) | — | — | — | — |
| Laravel (PHP) | — | — | — | — |
| Rails (Ruby) | — | — | — | — |

---

## Appendix B: File Reference

### Benchmark Harness
- `test/benchmark/harness/harness.go` — Core test infrastructure
- `test/benchmark/harness/types.go` — Benchmark definition types
- `test/benchmark/harness/sast_types.go` — SAST definition types
- `test/benchmark/harness/agent_types.go` — Agent definition types
- `test/benchmark/harness/sast_loader.go` — SAST YAML loaders
- `test/benchmark/harness/agent_loader.go` — Agent YAML loaders
- `test/benchmark/harness/oast_helper.go` — Mock OAST provider
- `test/benchmark/harness/container.go` — Docker container management
- `test/benchmark/harness/compose.go` — Docker Compose management
- `test/benchmark/harness/dvwa_setup.go` — DVWA auth setup
- `test/benchmark/harness/report.go` — Coverage report generation

### Agent Engine
- `pkg/agent/engine.go` — Central orchestrator
- `pkg/agent/loop.go` — Iterative loop engine
- `pkg/agent/context.go` — Context enrichment
- `pkg/agent/runner.go` — Pipe protocol execution
- `pkg/agent/acp_runner.go` — ACP protocol execution
- `pkg/agent/acp_client.go` — ACP client implementation
- `pkg/agent/parser.go` — Output parsing
- `pkg/agent/prompt.go` — Template management
- `pkg/agent/types.go` — Type definitions

### Definitions
- `test/benchmark/definitions/*.yaml` — Vulnerable app definitions (6 files)
- `test/benchmark/definitions/whitebox/extraction/*.yaml` — Route extraction (7 files)
- `test/benchmark/definitions/whitebox/sarif/*.yaml` — SARIF parsing (5 files)
- `test/benchmark/definitions/whitebox/handoff/*.yaml` — Route handoff (3 files)
- `test/benchmark/definitions/whitebox/agent/*.yaml` — Agent benchmarks (14 files)
- `test/benchmark/definitions/xbow/*.yaml` — XBOW challenges (13 files)
- `test/benchmark/definitions/blackbox/*.yaml` — External sites (3 files)

### Test Suites
- `test/benchmark/whitebox/active_test.go` — Whitebox active module tests
- `test/benchmark/whitebox/passive_test.go` — Whitebox passive module tests
- `test/benchmark/sast/extraction_test.go` — Route extraction tests
- `test/benchmark/sast/sarif_test.go` — SARIF parsing tests
- `test/benchmark/sast/handoff_test.go` — Route handoff tests
- `test/benchmark/agent/parsing_test.go` — Agent L1 parsing tests
- `test/benchmark/agent/quality_test.go` — Agent L2 quality tests
- `test/benchmark/agent/handoff_test.go` — Agent L3 handoff tests
- `test/benchmark/agent/e2e_test.go` — Agent L4 E2E tests
- `test/benchmark/agent/generate_test.go` — Agent fixture generation
