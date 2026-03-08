# Benchmark Improvement Plan

## Current State Overview

The benchmark system is a YAML-driven framework for validating scanner modules against real vulnerable applications.

### Architecture (4 layers)

```
YAML Definitions  →  Go Harness  →  Test Runners  →  Docker/External Targets
(what to test)       (how to run)    (when to run)    (what to scan)
```

1. **YAML definitions** (`test/benchmark/definitions/`) declare target app config + test cases (endpoint, method, modules, assertion type)
2. **Harness library** (`test/benchmark/harness/`) loads definitions, manages container lifecycle, builds HTTP requests, dispatches scan modules, evaluates assertions
3. **Test runners** (Go test files with build tags) drive the harness: `canary` for Docker apps, `blackbox` for external sites, `xbow` for validation benchmarks, `integration` for XSS gym
4. **Container infrastructure** — Docker containers or external sites provide real vulnerable targets

### Current Testing Tiers

| Tier | Tag | Targets | Assertions | CI Blocking |
|---|---|---|---|---|
| Whitebox | `canary` | 6 Docker apps (DVWA, VAmPI, JuiceShop, crAPI, vulnerable-java, vulnerable-nginx) | Strict + Soft | Yes (strict) |
| Blackbox | `blackbox` | 3 external sites (Acunetix, GinAndJuice, Testfire) | Soft only | No |
| XBOW | `xbow` | 13 Docker Compose stacks | Soft | No |
| Integration | `integration` | Brutelogic XSS gym (37 cases) | Strict | Yes |

**~176 total test cases** across all tiers.

---

## Gap Analysis

The scanner has **42 registered active modules + 24 passive modules = 66 total**. The benchmarks only exercise about **22 active + 12 passive ≈ 34 modules**. That's roughly **50% module coverage**.

### 1. Critical Active Modules with ZERO Test Cases

| Module | Severity | Why it's missing |
|---|---|---|
| `active-sqli-boolean-blind` | Critical | Only error-based and time-based SQLi tested |
| `active-insecure-deserialization` | Critical | No Java/PHP deserialization app |
| `active-http-request-smuggling` | High | Needs specific proxy/backend setup |
| `active-file-upload-scan` | High | No app with file upload endpoints |
| `active-graphql-scan` | Medium | No GraphQL endpoint in any test app |
| `active-idor-detection` | High | Needs multi-user auth setup |
| `active-forbidden-bypass` | High | Needs protected endpoints |
| `active-mass-assignment` | Medium | crAPI has this vuln but no test case written |
| `active-csrf-verify` | High | No test cases |
| `active-default-credentials` | High | DVWA has defaults but no benchmark |
| `active-spring-actuator-misconfig` | High | No Spring app in test suite |
| `active-xml-saml-security` | Critical | No SAML endpoint |
| `active-race-interference` | Medium | Needs stateful endpoints |
| `active-http-method-tampering` | Medium | No test cases |
| `active-xss-light-path` | High | Only `url-params` variant tested |
| `active-xss-light-param-discovery` | High | Not tested |

### 2. Passive Modules with ZERO Coverage (14 of 24)

- `passive-csrf-detect`
- `passive-openredirect-params`
- `passive-idor-params-detect`
- `passive-error-message-detect`
- `passive-base64-data-detect`
- `passive-serialized-object-detect`
- `passive-crypto-weakness-detect`
- `passive-mixed-content-detect`
- `passive-cacheable-https-detect`
- `passive-password-autocomplete-detect`
- `passive-anomaly-ranking`
- `passive-input-reflection-detect`
- `passive-oauth-facebook-detect`

### 3. Missing Application Archetypes

The test apps are mostly traditional web apps / REST APIs. Missing entirely:

- **GraphQL API** — needed for `active-graphql-scan`
- **Spring Boot app** — needed for `active-spring-actuator-misconfig`, deserialization
- **Nginx reverse proxy** — vulnerable-nginx exists but benchmark doesn't cover `active-nginx-off-by-slash`, `active-nginx-path-escape` adequately
- **File upload app** — needed for `active-file-upload-scan`
- **SAML/SSO provider** — needed for `active-xml-saml-security`
- **Multi-user auth app** — needed for IDOR/access control testing

### 4. Insertion Point Type Coverage

The scanner supports **16 insertion point types** but benchmarks only exercise **2-3**:

- **Well tested**: URL params (`INS_PARAM_URL`), some POST body (`INS_PARAM_BODY`)
- **Never tested**: Cookie injection (`INS_PARAM_COOKIE`), Header injection (`INS_HEADER`), XML params (`INS_PARAM_XML`), Multipart (`INS_PARAM_MULTIPART_ATTR`), Path folder (`INS_URL_PATH_FOLDER`), JSON nested values

### 5. Assertion Strength Imbalance

- VAmPI: 33 test cases, almost all **soft** (never fails)
- JuiceShop: 20 cases, mostly **soft**
- Only DVWA has meaningful **strict** assertions (7 strict)
- Soft tests provide signal in logs but **don't catch regressions**

### 6. No OAST (Out-of-Band) Validation

- `active-oast-probe`, `active-proxy-pingback`, `active-ssrf-detection` (OOB variant) all rely on callbacks
- The `MockOASTProvider` records probes but **can't verify actual blind exploitation**
- Blind SSRF, blind XXE, blind RCE remain unvalidated

### 7. Almost No False-Positive Testing

- Only **2 negative test cases** across all definitions
- No systematic scanning of clean/safe apps to validate precision
- A scanner's precision matters as much as recall

### 8. Limited HTTP Method Coverage

- Most tests: **GET**, some **POST**
- Very few PUT/PATCH/DELETE (only VAmPI)
- No HEAD/OPTIONS/TRACE testing

### 9. No Performance Baselines

- `TestResult` has `Duration` but it's never asserted against thresholds
- No way to detect if a module suddenly becomes 10x slower

### 10. Unregistered but Existing Modules

These module packages exist in the codebase but are **not registered** (commented out or not imported):

- `active-xss-scanner` (commented out)
- `active-open-redirect`
- `active-sqli-time-based-header`
- `active-sqli-time-based-params`
- `active-swagger-disclose`
- `active-proxy`

---

## Summary Scorecard

| Area | Current | Gap |
|---|---|---|
| Module coverage | ~34 of 66 registered | **32 modules (48%) untested** |
| App diversity | 6 Docker + 3 external + 13 XBOW | Missing GraphQL, Spring, upload, SAML, multi-user |
| Insertion points | 2-3 of 16 types | **13 types never exercised** |
| Assertion quality | Mostly soft | Need strict for stable detections |
| False positive testing | 2 negative cases | Need systematic FP validation |
| OOB/OAST | Mock only | Can't verify blind exploitation |
| HTTP methods | GET + some POST | PUT/PATCH/DELETE/OPTIONS gaps |
| Auth scenarios | Basic cookie/JWT | No OAuth, multi-role, session |
| Performance | Duration tracked, not asserted | No regression baselines |

---

## Recommended Priority Order

1. **Add test cases for high/critical untested modules** — biggest bang for buck, no new apps needed for some (e.g., `active-mass-assignment` on crAPI, `active-default-credentials` on DVWA)
2. **Add new vulnerable apps** covering missing archetypes (GraphQL, Spring Boot, file upload)
3. **Promote stable soft assertions to strict** to actually catch regressions in CI
4. **Expand insertion point coverage** — add test cases with cookies, headers, JSON body, multipart, XML
5. **Add false-positive benchmarks** — scan clean apps and assert zero findings
6. **Build OAST validation infrastructure** — callback server for blind vuln verification
7. **Add performance baselines** — assert max duration per module
8. **Expand HTTP method coverage** — PUT/PATCH/DELETE/OPTIONS/TRACE tests
9. **Add multi-user auth scenarios** — enable IDOR and access control testing
10. **Register and benchmark the 6 unregistered modules** that already exist in the codebase
