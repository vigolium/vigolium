# Deep Probe Summary: URL-loading query runners (json/csv/excel/url) and HTTP data sources

Status: complete
Loops: 1
Total hypotheses: 17
Validated: 16
Needs-Deeper: 1
Stop reason: covered all entry points

## Validated Hypotheses

### PH-01: Cloud metadata credential exfiltration via JSON URL fetch (SSRF guard disabled)
- Reasoning-Model: Pre-Mortem
- Target: `redash/query_runner/json_ds.py:157` — `JSON.run_query`
- Attack input: YAML query with `url: http://169.254.169.254/latest/meta-data/...`
- Code path: `json_ds.py:157` → `json_ds.py:200` → `json_ds.py:219` → `query_runner/__init__.py:375` → `utils/requests_session.py:19`
- Sanitizers on path: `UnacceptableAddressException` — bypassable if `ENFORCE_PRIVATE_ADDRESS_BLOCK` is false
- Security consequence: SSRF to metadata/internal services; potential credential exfiltration
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-02: Response-controlled pagination pivots to internal host (next_url SSRF)
- Reasoning-Model: Pre-Mortem / TRIZ / Causal
- Target: `redash/query_runner/json_ds.py:253` — `UrlPagination.next`
- Attack input: pagination `next` value in attacker-controlled response
- Code path: `json_ds.py:200` → `json_ds.py:253` → `json_ds.py:219` → `query_runner/__init__.py:375`
- Sanitizers on path: `UnacceptableAddressException` — bypassable if SSRF guard disabled
- Security consequence: response-driven SSRF pivot to internal hosts
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-03: CSV/Excel redirect policy bypass via direct requests
- Reasoning-Model: Pre-Mortem / TRIZ / Causal
- Target: `redash/query_runner/csv.py:48` — `CSV.run_query` (also `excel.py:45`)
- Attack input: URL that 302-redirects to internal host
- Code path: `csv.py:62`/`excel.py:60` → `requests_or_advocate.get`
- Sanitizers on path: `UnacceptableAddressException` — bypassable if SSRF guard disabled
- Security consequence: redirect-based SSRF bypassing global redirect policy
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-04: URL runner accepts absolute URLs when base_url unset
- Reasoning-Model: Pre-Mortem
- Target: `redash/query_runner/url.py:12` — `Url.run_query`
- Attack input: absolute URL (e.g., internal Docker API)
- Code path: `url.py:12` → `query_runner/__init__.py:375`
- Sanitizers on path: `UnacceptableAddressException` — bypassable if SSRF guard disabled
- Security consequence: direct SSRF to internal services
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-05: JQL runner used as internal API proxy when base URL misconfigured
- Reasoning-Model: Pre-Mortem
- Target: `redash/query_runner/jql.py:168` — `JiraJQL.run_query`
- Attack input: JSON query targeting internal API via misconfigured base URL
- Code path: `jql.py:168` → `query_runner/__init__.py:375`
- Sanitizers on path: `UnacceptableAddressException` — bypassable if SSRF guard disabled
- Security consequence: internal API access through data source misconfiguration
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-06: Elasticsearch runner exposes system indices to query authors
- Reasoning-Model: Pre-Mortem
- Target: `redash/query_runner/elasticsearch2.py:59` — `ElasticSearch2.run_query`
- Attack input: JSON query with `index: ".security"`
- Code path: `elasticsearch2.py:67` → `elasticsearch2.py:48` → `query_runner/__init__.py:375`
- Sanitizers on path: none
- Security consequence: sensitive index data exfiltration if backend allows access
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-07: Drill runner allows filesystem reads via Drill storage plugins
- Reasoning-Model: Pre-Mortem
- Target: `redash/query_runner/drill.py:91` — `Drill.run_query`
- Attack input: SQL query referencing `dfs.` filesystem tables
- Code path: `drill.py:91` → `query_runner/__init__.py:375`
- Sanitizers on path: none
- Security consequence: host file disclosure through Drill
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-08: SSRF guard is config-gated (global)
- Reasoning-Model: TRIZ / Causal
- Target: `redash/utils/requests_session.py:13` — `requests_or_advocate` selection
- Attack input: any URL query when `ENFORCE_PRIVATE_ADDRESS_BLOCK=false`
- Code path: `query_runner/__init__.py:375` → `requests_session.request` → `requests` (no SSRF guard)
- Sanitizers on path: none when flag disabled
- Security consequence: system-wide SSRF exposure for URL-loading runners
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-09: Absolute URL overrides base_url scoping in JSON runner
- Reasoning-Model: TRIZ / Causal
- Target: `redash/query_runner/json_ds.py:200` — `_get_all_results`
- Attack input: YAML query with absolute `url` despite configured base_url
- Code path: `json_ds.py:200` → `json_ds.py:219` → `query_runner/__init__.py:375`
- Sanitizers on path: `UnacceptableAddressException` — bypassable if SSRF guard disabled
- Security consequence: host scoping bypass; SSRF to arbitrary hosts
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-10: Error/timing oracle enables adaptive host discovery
- Reasoning-Model: Game-Theory
- Target: `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response`
- Attack input: repeated URL probes to internal IP ranges
- Code path: `get_response` → distinct error messages returned to callers (e.g., `url.py:26`, `json_ds.py:160`)
- Sanitizers on path: none (error strings returned directly)
- Security consequence: network scanning/host discovery in internal network
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

## NEEDS-DEEPER

### PH-05 (Round 3): Base URL trust confounded by access-control policy
- Why unresolved: Requires inspection of data source creation/edit permissions to determine if non-admins can set `base_url`.
- Suggested follow-up: Review handlers/policies for data source CRUD and RBAC to confirm whether `base_url` is admin-only.

## Coverage Summary
| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|------------|:-:|:-:|:-:|
| `redash/query_runner/url.py:12` — `Url.run_query` | PH-04 | PH-02/PH-05 | PH-02 |
| `redash/query_runner/json_ds.py:157` — `JSON.run_query` | PH-01 | PH-04/PH-05 | PH-04 |
| `redash/query_runner/json_ds.py:200` — `JSON._get_all_results` | PH-02 | PH-01/PH-04 | PH-01/PH-04 |
| `redash/query_runner/json_ds.py:219` — `JSON._get_json_response` | PH-01 | PH-02/PH-05 | PH-02 |
| `redash/query_runner/csv.py:48` — `CSV.run_query` | PH-03 | PH-03/PH-05 | PH-03 |
| `redash/query_runner/excel.py:45` — `Excel.run_query` | PH-03 | PH-03/PH-05 | PH-03 |
| `redash/query_runner/jql.py:168` — `JiraJQL.run_query` | PH-05 | NONE | NONE |
| `redash/query_runner/elasticsearch2.py:59` — `ElasticSearch2.run_query` | PH-06 | NONE | NONE |
| `redash/query_runner/drill.py:91` — `Drill.run_query` | PH-07 | NONE | NONE |
| `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response` | PH-01 | PH-02/PH-05 | PH-02 |
| `redash/utils/requests_session.py:19` — `ConfiguredSession.request` | PH-01/PH-03 | PH-03 | PH-03 |
