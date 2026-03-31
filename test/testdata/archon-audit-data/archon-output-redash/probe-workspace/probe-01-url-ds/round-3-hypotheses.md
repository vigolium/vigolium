# Round 3 Hypotheses — URL data sources

## PH-01: Pagination next_url pivots host in JSON runner

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Cross-Model CROSS-01
- **Target**: `redash/query_runner/json_ds.py:253` — `UrlPagination.next`
- **Attacker starting position**: authenticated-user (can run JSON query runner)
- **Causal argument**: The apparent protection is base URL scoping in the JSON runner, but bypassing it does not affect whether attacker input reaches the HTTP request because `UrlPagination.next` consumes a response-controlled `next_url` and then hands it to `urljoin` without validation. If `next_url` is absolute, `urljoin` will switch hosts, so the response (not the base URL) causally determines the destination.
- **Real risk**: Response-driven pagination lets an attacker pivot to internal hosts even when the initial URL is benign.
- **Attack input**: A JSON query with `pagination: {"type":"url", "path":"next"}` against an attacker-controlled endpoint that replies with `{ "next": "http://169.254.169.254/latest/meta-data/" }`.
- **Security consequence**: SSRF to internal services/metadata.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm whether `urljoin` is used without a host allowlist and whether `next_url` accepts absolute URLs in `UrlPagination.next`.

---

## PH-02: SSRF guard is confounded by config flag

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-02
- **Target**: `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response`
- **Attacker starting position**: authenticated-user
- **Causal argument**: Safety relies on an external configuration (`ENFORCE_PRIVATE_ADDRESS_BLOCK`) implemented in the requests layer, not on code within the query runners. If that setting is disabled (alternate deployment, tests, misconfig), the same request path allows internal destinations with no other guard, so the “protection” is confounded by environment.
- **Real risk**: Disabling the private-address block restores full SSRF across URL/JSON/Jira/Elasticsearch/Drill runners.
- **Attack input**: Query URL `http://169.254.169.254/latest/meta-data/` or `http://localhost:2375/` when the flag is off.
- **Security consequence**: Internal service access and credential leakage.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify how `requests_or_advocate` behaves when the flag is disabled and whether any runner-specific validation still blocks private IPs.

---

## PH-03: CSV/Excel redirect policy bypasses global redirect control

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-03
- **Target**: `redash/query_runner/csv.py:62` — `CSV.run_query`
- **Attacker starting position**: authenticated-user
- **Causal argument**: The global redirect policy is enforced in `ConfiguredSession.request`, but CSV/Excel runners call `requests_or_advocate.get` directly. If that call follows redirects by default, the supposed redirect protection is not causally connected to these requests, enabling a redirect pivot to internal hosts even when global redirects are disabled.
- **Real risk**: Redirect-based SSRF in CSV/Excel runners bypasses redirect restrictions.
- **Attack input**: CSV query URL `https://attacker.example/redirect` returning `302 Location: http://169.254.169.254/latest/meta-data/`.
- **Security consequence**: SSRF to internal endpoints via redirect chaining.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Check whether `requests_or_advocate.get` honors the global redirect setting or follows redirects unconditionally.

---

## PH-04: Absolute URL overrides base_url scoping in JSON runner

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Cross-Model CROSS-04
- **Target**: `redash/query_runner/json_ds.py:203` — `JSON._get_all_results`
- **Attacker starting position**: authenticated-user
- **Causal argument**: The apparent protection is a configured `base_url`, but bypassing it does not alter the request path because `urljoin(base_url, url)` accepts absolute URLs from the query. An absolute `url` replaces the base host, so the base URL is not causally necessary for safety.
- **Real risk**: JSON runner can reach arbitrary hosts even when a base URL is set, undermining intended scoping.
- **Attack input**: YAML query with `url: "http://169.254.169.254/latest/meta-data/"` (absolute), `method: "get"`.
- **Security consequence**: SSRF to internal services despite configured base URL.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm whether absolute URLs are accepted without validation and whether any UI or API layer strips schemes.

---

## PH-05: Base URL trust is confounded by external access-control policy

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Trust-Assumption
- **Target**: `redash/query_runner/json_ds.py:203` — `JSON._get_all_results`
- **Attacker starting position**: authenticated-user with data source edit/create capability (or misconfigured role)
- **Causal argument**: Safety assumes the configured `base_url` is valid and safe, but that trust is external to the code. If a deployment allows non-admins (or compromised admins) to set data source configuration, the base URL can be pointed at internal infrastructure. The code itself adds no independent restriction, so the protection is confounded by RBAC policy.
- **Real risk**: Misconfigured permissions turn the JSON runner into a general internal proxy.
- **Attack input**: Create/update JSON data source with `base_url: "http://127.0.0.1:2375"`, then query with `url: "/containers/json"`.
- **Security consequence**: Access to internal services reachable from Redash.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Check Redash permission model for data source creation/editing and whether non-admins can modify `base_url`.

---

## Coverage Check

| Round 1+2 Finding | Intervention tested? | Counterfactual tested? | Confounder tested? | New hypothesis? |
|-------------------|:-:|:-:|:-:|:-:|
| None | N/A | N/A | N/A | N/A |

| Cross-Model Seed | Causal analysis done? | Hypothesis generated? |
|-----------------|:-:|:-:|
| CROSS-01 | YES | PH-01 |
| CROSS-02 | YES | PH-02 |
| CROSS-03 | YES | PH-03 |
| CROSS-04 | YES | PH-04 |

| Trust Assumption | Confounder test done? | Hypothesis generated? |
|----------------|:-:|:-:|
| `redash/query_runner/url.py:24` — Query string is a relative path when `base_url` configured | YES | NO — assumption is partly enforced by scheme check but does not alone enable host pivot |
| `redash/query_runner/json_ds.py:175` — `method` in query is usable for HTTP | YES | NO — code enforces GET/POST allowlist |
| `redash/query_runner/json_ds.py:176` — YAML `params/headers/data/auth/json/verify` are trusted | YES | NO — trust is local to query authors; no external confounder identified |
| `redash/query_runner/json_ds.py:203` — `base_url` from configuration is valid | YES | PH-05 |
| `redash/query_runner/csv.py:55` — YAML contains `url` and `user-agent` fields | YES | NO — failures fall back to empty values without external dependency |
| `redash/query_runner/excel.py:51` — YAML contains `url` and `user-agent` fields | YES | NO — failures fall back to empty values without external dependency |
| `redash/query_runner/jql.py:170` — `configuration["url"]` is valid Jira base URL | YES | NO — invalid config is an admin error; no alternate path identified |
| `redash/query_runner/elasticsearch2.py:49` — `configuration["url"]` is valid base URL | YES | NO — invalid config is an admin error; no alternate path identified |
| `redash/query_runner/elasticsearch2.py:68` — Query JSON contains expected `index` and optional `result_fields` | YES | NO — input validation issue but not an external confounder |
| `redash/query_runner/drill.py:92` — `configuration["url"]` is a Drill base URL | YES | NO — invalid config is an admin error; no alternate path identified |
| `redash/utils/requests_session.py:13` — Settings determine SSRF protection implementation | YES | PH-02 |
