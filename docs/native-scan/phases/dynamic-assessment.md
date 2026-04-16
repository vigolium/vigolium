# Dynamic Assessment — Active Vulnerability Scanning

The dynamic-assessment phase is the scanning layer that sends modified requests to detect vulnerabilities. It receives traffic from all input sources (crawling, spidering, content discovery, manual ingestion) and systematically injects payloads at every insertion point to identify security issues.

CLI aliases: `audit`, `dast`, `assessment`.

## How It Works

```
HttpRequestResponse (from any source)
  │
  ▼
┌──────────────────────────────────────────────────┐
│  Executor (worker pool)                           │
│  1. Fetch baseline response                       │
│  2. Scope filtering + static file exclusion       │
│  3. Extract insertion points from request          │
│  4. Dispatch to matching modules                   │
└────────────────┬──────────────┬───────────────────┘
                 │              │
        ┌────────┘              └────────┐
        ▼                                ▼
┌───────────────────┐      ┌───────────────────────┐
│  Active Modules    │      │  Passive Modules       │
│  Send modified     │      │  Analyze existing      │
│  requests with     │      │  request/response      │
│  injected payloads │      │  without new traffic   │
└────────┬──────────┘      └──────────┬────────────┘
         │                            │
         └──────────┬─────────────────┘
                    ▼
             ResultEvent findings
```

## Insertion Points

Active modules inject payloads at specific locations in the request:

| Insertion Point | Description |
|-----------------|-------------|
| URL parameters | Query string values (`?key=PAYLOAD`) |
| Body parameters | POST body values |
| Cookies | Cookie values |
| Headers | HTTP header values |
| JSON values | Values within JSON request bodies |
| XML values/attributes | Values and attributes in XML bodies |
| URL path components | Folder and filename segments |
| Parameter names | Parameter key names (URL and body) |
| Entire body | Full request body replacement |

Each insertion point provides `BuildRequest(payload)` to construct the modified request and `PayloadOffsets(payload)` to locate where the payload appears in the response.

## Module Types

### Active Modules

Active modules send modified requests and analyze responses to detect vulnerabilities. Three scan granularities:

| Method | Scope | Use Case |
|--------|-------|----------|
| `ScanPerInsertionPoint` | Per parameter | Injection bugs (XSS, SQLi, XXE) |
| `ScanPerRequest` | Per unique request | Logic flaws, access control |
| `ScanPerHost` | Per host | Host-level checks, once per target |

Each module declares which `ScanScope` and `InsertionPointType` it handles. The executor only dispatches matching work.

### Passive Modules

Passive modules analyze request/response pairs without generating traffic:

| Method | Scope | Use Case |
|--------|-------|----------|
| `ScanPerRequest` | Per request/response | Header checks, secret detection |
| `ScanPerHost` | Per host | Aggregate analysis, anomaly ranking |

Modules implementing the `Flusher` interface run finalization logic at scan end (e.g., anomaly baseline ranking).

## DiffScan Framework

Most injection-based modules use the shared DiffScan framework for differential response analysis:

1. **Probe** — defines break strings and escape payloads for a vulnerability class
2. **Attack** — tracks state across multiple probe attempts (baseline vs. current)
3. **ResponseSnapshot** — captures fingerprinted response attributes for comparison
4. **Reflection detection** — identifies how injected payloads manifest in responses
5. **Quantitative measurements** — statistical response changes (timing, size, keyword frequency)

A vulnerability is confirmed when injected payloads cause measurable, consistent deviations from the baseline response.

## Built-In Scan Checks

### Active
- Reflected XSS (context-aware: HTML, JS, attribute contexts)
- SQL injection (error-based, blind differential)
- XML external entity injection (XXE)
- Server-side request forgery (SSRF)
- OS command injection
- Path traversal

### Passive
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Cookie security (HttpOnly, Secure, SameSite flags)
- CORS misconfiguration
- DOM-based XSS (JavaScript source analysis)
- Secret/API key exposure
- Source map detection
- Content-Type mismatch
- Mixed content
- OAuth misconfiguration

## Per-Module Finding Cap

To prevent noisy modules from flooding results, the executor caps findings emitted per module. Once a module reaches the limit, additional findings from that module are suppressed for the remainder of the scan.

```bash
# Override the default cap (default: 15)
vigolium scan -t https://example.com --max-findings-per-module 25

# Disable the cap (unlimited findings)
vigolium scan -t https://example.com --max-findings-per-module 0
```

Configuration in `vigolium-configs.yaml`:

```yaml
dynamic-assessment:
  max_findings_per_module: 15    # 0 = unlimited
```

## Rate Limiting and Deduplication

- **Per-host rate limiting** — configurable request rate per target
- **Request deduplication** — prevents sending identical modified requests
- **Baseline caching** — caches baseline responses to avoid redundant fetches
- **Response buffer pooling** — recycles 32KiB buffers to reduce GC pressure
- **Body size enforcement** — drop, truncate, or skip scanning for oversized responses
