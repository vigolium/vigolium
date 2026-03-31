# Evidence — URL/HTTP query runners

## [HARVESTER] PH-01 (Round 1): Cloud metadata credential exfiltration via JSON URL fetch (SSRF guard disabled)

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/json_ds.py:157` — `JSON.run_query` parses YAML and calls `_run_json_query`.
2. `redash/query_runner/json_ds.py:168-197` — `_run_json_query` validates query fields then calls `_get_all_results` with `query["url"]`.
3. `redash/query_runner/json_ds.py:200-216` — `_get_all_results` uses `urljoin(base_url, url)` and calls `_get_json_response` in loop.
4. `redash/query_runner/json_ds.py:219-221` — `_get_json_response` calls `BaseHTTPQueryRunner.get_response`.
5. `redash/query_runner/__init__.py:375-385` — `get_response` issues HTTP request via `requests_session.request`.
6. `redash/utils/requests_session.py:13-17` — `requests_or_advocate` is `requests` when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is false.
7. `redash/utils/requests_session.py:19-23` — `ConfiguredSession.request` forwards to `requests_or_advocate.Session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: only enforced when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is true; with it disabled `requests` is used and no private-address block applies.

**Verdict rationale**: The JSON runner forwards user-controlled URLs into `get_response`. Private-address blocking depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`; when disabled, no code-level SSRF guard remains, so metadata URLs can be fetched.

---

## [HARVESTER] PH-02 (Round 1): Response-controlled pagination pivots to internal host (next_url SSRF)

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/json_ds.py:157` — `JSON.run_query` → `_run_json_query`.
2. `redash/query_runner/json_ds.py:200-216` — `_get_all_results` calls `_get_json_response` and then `pagination.next` when enabled.
3. `redash/query_runner/json_ds.py:253-259` — `UrlPagination.next` extracts `next_url` from response (`_apply_path_search`) and `urljoin(url, next_url)`.
4. `redash/query_runner/json_ds.py:219-221` — `_get_json_response` → `BaseHTTPQueryRunner.get_response`.
5. `redash/query_runner/__init__.py:375-385` — `get_response` issues HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: private-address blocking only if `ENFORCE_PRIVATE_ADDRESS_BLOCK` is true; otherwise `requests` is used.

**Verdict rationale**: `UrlPagination.next` accepts absolute `next_url` values and overwrites the host via `urljoin` without validation. With private-address blocking disabled, follow-up pagination requests can reach internal hosts.

---

## [HARVESTER] PH-03 (Round 1): CSV/Excel runners follow open redirects to internal resources

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/csv.py:48-62` — `CSV.run_query` parses YAML and calls `requests_or_advocate.get(url=path, ...)`.
2. `redash/query_runner/excel.py:45-61` — `Excel.run_query` does the same direct `requests_or_advocate.get` call.
3. `redash/utils/requests_session.py:13-17` — `requests_or_advocate` is `requests` when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is false.
4. `requests_or_advocate.get(...)` — HTTP request follows default redirect behavior (sink).

**Sanitizers on path**:
- `redash/query_runner/csv.py:102-104` / `redash/query_runner/excel.py:100-102` — `UnacceptableAddressException` — **Bypassable**: only enforced when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is true; otherwise `requests` is used.

**Verdict rationale**: CSV/Excel bypass `ConfiguredSession` redirect controls by calling `requests_or_advocate.get` directly. With private-address blocking disabled, redirects can reach internal targets.

---

## [HARVESTER] PH-04 (Round 1): URL query runner allows arbitrary absolute URLs when base_url is unset

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/url.py:12-25` — `Url.run_query` accepts absolute URLs when `base_url` is empty/None and concatenates into `url`.
2. `redash/query_runner/url.py:26` — calls `BaseHTTPQueryRunner.get_response(url)`.
3. `redash/query_runner/__init__.py:375-385` — `get_response` issues HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: disabled when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is false.

**Verdict rationale**: With no configured base URL, absolute URLs are accepted and forwarded to the HTTP client. Private-address blocking is configuration-dependent.

---

## [HARVESTER] PH-05 (Round 1): JQL runner used as an internal API proxy when base URL misconfigured

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/jql.py:168-170` — `JiraJQL.run_query` builds `jql_url` from `configuration["url"]`.
2. `redash/query_runner/jql.py:189` — calls `BaseHTTPQueryRunner.get_response(jql_url, params=query)`.
3. `redash/query_runner/__init__.py:375-385` — `get_response` issues HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: only active when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is true.

**Verdict rationale**: The runner trusts the configured base URL and does not validate host/scheme. If configuration is pointed at an internal API and private-address blocking is disabled, requests are sent to that internal host.

---

## [HARVESTER] PH-06 (Round 1): Elasticsearch runner exposes system indices to untrusted query authors

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/elasticsearch2.py:59-62` — `ElasticSearch2.run_query` builds query and calls `get_response`.
2. `redash/query_runner/elasticsearch2.py:67-72` — `_build_query` uses user-provided `index` to build `url = "/{}/_search"`.
3. `redash/query_runner/elasticsearch2.py:48-52` — `get_response` prefixes with `configuration["url"]` and calls `BaseHTTPQueryRunner.get_response`.
4. `redash/query_runner/__init__.py:375-385` — HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- None for index validation in this runner.

**Verdict rationale**: The runner directly accepts the `index` parameter from the query and constructs the request URL without restrictions, allowing system indices if the backend permits them.

---

## [HARVESTER] PH-07 (Round 1): Drill runner reads server-side files via filesystem storage plugin

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/drill.py:91-96` — `Drill.run_query` builds SQL payload using user `query` and posts to `configuration["url"]/query.json`.
2. `redash/query_runner/__init__.py:375-385` — HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- None in the runner for SQL content.

**Verdict rationale**: The runner forwards raw SQL to Drill without validation. If Drill’s filesystem plugins allow local file access, queries like `dfs.` can read server files.

---

## [HARVESTER] PH-01 (Round 2): Response-driven pagination pivots to attacker-chosen host

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/json_ds.py:200-216` — `_get_all_results` calls `pagination.next` when pagination is configured.
2. `redash/query_runner/json_ds.py:253-259` — `UrlPagination.next` extracts `next_url` and applies `urljoin(url, next_url)`.
3. `redash/query_runner/json_ds.py:219-221` — `_get_json_response` → `BaseHTTPQueryRunner.get_response`.
4. `redash/query_runner/__init__.py:375-385` — HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`.

**Verdict rationale**: Pagination uses a response-controlled `next_url` with no host validation. With private-address blocking disabled, a response can pivot subsequent requests to internal hosts.

---

## [HARVESTER] PH-02 (Round 2): SSRF guard depends on runtime config toggle

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/__init__.py:375-385` — `BaseHTTPQueryRunner.get_response` uses `requests_session.request`.
2. `redash/utils/requests_session.py:13-17` — `requests_or_advocate` resolves to `requests` when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is false.
3. `redash/utils/requests_session.py:19-23` — `ConfiguredSession.request` calls through to `requests_or_advocate.Session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: only present when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is true.

**Verdict rationale**: Private-address blocking is entirely configuration-dependent; disabling the setting swaps in `requests` with no private-address enforcement.

---

## [HARVESTER] PH-03 (Round 2): CSV/Excel redirect policy bypass via direct requests

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/csv.py:62` — `CSV.run_query` uses `requests_or_advocate.get` directly.
2. `redash/query_runner/excel.py:60` — `Excel.run_query` uses `requests_or_advocate.get` directly.
3. `redash/utils/requests_session.py:19-23` — Redirect policy enforcement exists only in `ConfiguredSession.request` (not used here).

**Sanitizers on path**:
- `redash/query_runner/csv.py:102-104` / `redash/query_runner/excel.py:100-102` — `UnacceptableAddressException` — **Bypassable**: depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`.

**Verdict rationale**: CSV/Excel bypass the centralized `ConfiguredSession` redirect setting. If redirects are followed by default and private-address blocking is disabled, redirect-based SSRF is possible.

---

## [HARVESTER] PH-04 (Round 2): Absolute URL overrides configured base URL in JSON runner

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/json_ds.py:200-203` — `_get_all_results` reads `base_url` from configuration and applies `urljoin(base_url, url)`.
2. `redash/query_runner/json_ds.py:219-221` — `_get_json_response` → `BaseHTTPQueryRunner.get_response`.
3. `redash/query_runner/__init__.py:375-385` — HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`.

**Verdict rationale**: `urljoin` accepts absolute URLs and replaces the base host without validation. Thus, a query can override the configured base URL.

---

## [HARVESTER] PH-05 (Round 2): Error/timing oracle enables adaptive host discovery

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/__init__.py:395-405` — `get_response` sets distinct error strings for HTTPError, UnacceptableAddressException, and RequestException.
2. `redash/query_runner/url.py:26-28` — `Url.run_query` returns the error directly to the caller.
3. `redash/query_runner/json_ds.py:160-165` — `JSON.run_query` returns errors from `_run_json_query` to the caller.

**Sanitizers on path**:
- None; error strings are returned directly to query authors.

**Verdict rationale**: Distinct exception branches create observable differences in error messages (and likely timing), enabling adaptive probing based on response classification.

---

## [HARVESTER] PH-01 (Round 3): Pagination next_url pivots host in JSON runner

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/json_ds.py:253-259` — `UrlPagination.next` extracts `next_url` from response and applies `urljoin(url, next_url)`.
2. `redash/query_runner/json_ds.py:219-221` — `_get_json_response` → `BaseHTTPQueryRunner.get_response`.
3. `redash/query_runner/__init__.py:375-385` — HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`.

**Verdict rationale**: `UrlPagination.next` trusts response-provided URLs and allows absolute host changes. With private-address blocking disabled, internal hosts are reachable.

---

## [HARVESTER] PH-02 (Round 3): SSRF guard is confounded by config flag

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/__init__.py:375-385` — `BaseHTTPQueryRunner.get_response` calls `requests_session.request`.
2. `redash/utils/requests_session.py:13-17` — `requests_or_advocate` selection is controlled by `ENFORCE_PRIVATE_ADDRESS_BLOCK`.
3. `redash/utils/requests_session.py:19-23` — `ConfiguredSession.request` delegates to `requests_or_advocate.Session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: only enforced when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is true.

**Verdict rationale**: The private-address block is a runtime toggle; disabling it removes the only code-level SSRF guard.

---

## [HARVESTER] PH-03 (Round 3): CSV/Excel redirect policy bypasses global redirect control

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/csv.py:62` — direct `requests_or_advocate.get` call.
2. `redash/query_runner/excel.py:60` — direct `requests_or_advocate.get` call.
3. `redash/utils/requests_session.py:19-23` — redirect control exists only in `ConfiguredSession.request` (not used here).

**Sanitizers on path**:
- `redash/query_runner/csv.py:102-104` / `redash/query_runner/excel.py:100-102` — `UnacceptableAddressException` — **Bypassable**: depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`.

**Verdict rationale**: The CSV/Excel runners bypass the centralized redirect policy, so redirect-based pivots remain possible when private-address blocking is disabled.

---

## [HARVESTER] PH-04 (Round 3): Absolute URL overrides base_url scoping in JSON runner

**Verdict**: VALIDATED

**Code path**:
1. `redash/query_runner/json_ds.py:200-203` — `_get_all_results` performs `urljoin(base_url, url)` with no validation.
2. `redash/query_runner/json_ds.py:219-221` — `_get_json_response` → `BaseHTTPQueryRunner.get_response`.
3. `redash/query_runner/__init__.py:375-385` — HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`.

**Verdict rationale**: Absolute URLs from the query replace the configured base URL due to `urljoin` behavior, enabling host override.

---

## [HARVESTER] PH-05 (Round 3): Base URL trust is confounded by external access-control policy

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `redash/query_runner/json_ds.py:200-203` — `_get_all_results` uses `base_url = configuration.get("base_url")` and `urljoin(base_url, url)`.
2. `redash/query_runner/json_ds.py:219-221` — `_get_json_response` → `BaseHTTPQueryRunner.get_response`.
3. `redash/query_runner/__init__.py:375-385` — HTTP request via `requests_session.request` (sink).

**Sanitizers on path**:
- `redash/query_runner/__init__.py:399-401` — `UnacceptableAddressException` — **Bypassable**: depends on `ENFORCE_PRIVATE_ADDRESS_BLOCK`.

**Verdict rationale**: The runner trusts `base_url` from configuration and applies no additional validation. Whether non-admins can set this configuration (the confounder) is outside the provided files.

**Deepening note**: Need to confirm data source creation/edit permissions and whether non-admin roles can set `base_url` in Redash configuration APIs/UI.

---
