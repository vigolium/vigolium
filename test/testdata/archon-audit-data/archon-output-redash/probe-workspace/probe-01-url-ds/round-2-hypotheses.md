# Round 2 Hypotheses — URL-loading query runners + HTTP data sources

## PH-01: Response-driven pagination pivots to attacker-chosen host

- **Reasoning-Model**: TRIZ
- **Target**: `redash/query_runner/json_ds.py:253` — `UrlPagination.next`
- **Attacker starting position**: authenticated-user with permission to run JSON data source queries
- **Attack input / strategy**: Submit YAML query with `pagination: {type: url, path: "links.next"}` and a URL under attacker control. Return a JSON body where `links.next` is `http://169.254.169.254/latest/meta-data/` (or any internal host). The runner follows the response-provided `next_url` and fetches the internal resource in the next pagination step.
- **Tension / Game**: Compatibility with APIs that publish pagination `next_url` vs enforcing a fixed allowlist for follow-on requests.
- **What was sacrificed / Information accumulated**: Host allowlist continuity across pagination. The next request is authorized by untrusted response data instead of the original query constraints.
- **Security consequence**: SSRF pivot during pagination to internal endpoints; attacker-controlled response can redirect subsequent fetches.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Inspect `urljoin` usage in `_get_all_results` to confirm absolute `next_url` override behavior and whether any allowlist hooks exist upstream.

---

## PH-02: SSRF guard depends on runtime config toggle

- **Reasoning-Model**: TRIZ
- **Target**: `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response`
- **Attacker starting position**: authenticated-user with permission to run URL/JSON/CSV/Excel queries
- **Attack input / strategy**: Run a URL/JSON query pointing to `http://169.254.169.254/latest/meta-data/` (or `http://127.0.0.1:2375/`). If `ENFORCE_PRIVATE_ADDRESS_BLOCK=false`, requests proceed without private-address blocking.
- **Tension / Game**: Configurability and compatibility with internal deployments vs enforcing a non-bypassable SSRF guard.
- **What was sacrificed / Information accumulated**: Hard security invariant (“never reach private addresses”) is conditional on a setting; disabling restores unrestricted fetch capability.
- **Security consequence**: Full SSRF against internal services when the setting is disabled.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify how `requests_or_advocate` is selected and whether any other layers enforce private-address blocking when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is off.

---

## PH-03: CSV/Excel redirect policy bypass via direct requests

- **Reasoning-Model**: TRIZ
- **Target**: `redash/query_runner/csv.py:48` — `CSV.run_query`
- **Attacker starting position**: authenticated-user with permission to run CSV/Excel queries
- **Attack input / strategy**: YAML query with `url: "http://attacker.example/redirect"` where the attacker-controlled endpoint returns `302 Location: http://169.254.169.254/latest/meta-data/`. CSV/Excel use `requests_or_advocate.get` directly (no `ConfiguredSession` redirect policy), so redirects may be followed even when `REQUESTS_ALLOW_REDIRECTS=false` for other query runners.
- **Tension / Game**: Simplicity (direct `requests_or_advocate.get`) vs centralized security policy enforcement (redirect controls in `ConfiguredSession`).
- **What was sacrificed / Information accumulated**: Consistent redirect enforcement; CSV/Excel paths may follow redirects to blocked or internal destinations.
- **Security consequence**: Redirect-based SSRF bypass or policy inconsistency between query runners.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm default `allow_redirects` behavior in `requests_or_advocate.get` and whether it revalidates redirects against private-address policy.

---

## PH-04: Absolute URL overrides configured base URL in JSON runner

- **Reasoning-Model**: TRIZ
- **Target**: `redash/query_runner/json_ds.py:200` — `JSON._get_all_results`
- **Attacker starting position**: authenticated-user with permission to run JSON data source queries
- **Attack input / strategy**: Configure a JSON data source with `base_url: https://api.allowed.example/`, then submit YAML query with `url: "http://internal.service.local/admin"`. `urljoin(base_url, url)` will select the absolute URL, bypassing any implicit host restriction.
- **Tension / Game**: Flexibility (accepting absolute URLs in queries) vs enforcing data-source scoping to a configured host.
- **What was sacrificed / Information accumulated**: Host allowlist tied to `base_url`; absolute URLs can jump to arbitrary hosts.
- **Security consequence**: SSRF to arbitrary hosts even when a base URL is configured for the data source.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm how `base_url` is stored/validated and whether any upstream validation forbids absolute URLs in JSON queries.

---

## PH-05: Error/timing oracle enables adaptive host discovery

- **Reasoning-Model**: Game-Theory
- **Target**: `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response`
- **Attacker starting position**: authenticated-user with permission to run URL/JSON/CSV/Excel queries
- **Attack input / strategy**: Issue a sequence of queries to candidate hosts/IPs (e.g., `http://10.0.0.1:80/`, `http://10.0.0.2:80/`, ...). Classify responses by error string (private-address block vs connection error vs HTTP status) and response time. Use the resulting signal to prioritize likely live services and refine the scan.
- **Tension / Game**: Helpful error reporting for operators vs minimizing information disclosure across repeated interactions.
- **What was sacrificed / Information accumulated**: Distinct error modes and timing expose which targets are routable, responsive, or blocked.
- **Security consequence**: Enables adaptive internal network mapping or service discovery (if private-address blocking is disabled or bypassed).
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Validate the exact error strings/timing differences for connection refused vs timeout vs HTTP status, and whether upstream handlers expose them to the user.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| `redash/query_runner/url.py:12` — `Url.run_query` | PH-02 / YES — SSRF guard depends on config | PH-05 / YES — error/timing oracle on repeated probes |
| `redash/query_runner/json_ds.py:157` — `JSON.run_query` | PH-04 / YES — absolute URL overrides base_url | PH-05 / YES — repeated probe oracle via get_response |
| `redash/query_runner/json_ds.py:200` — `JSON._get_all_results` | PH-01 / YES — response-driven next_url host pivot | PH-05 / YES — repeated probe oracle via pagination |
| `redash/query_runner/json_ds.py:219` — `JSON._get_json_response` | PH-02 / YES — relies on get_response SSRF guard | PH-05 / YES — error/timing oracle |
| `redash/query_runner/csv.py:48` — `CSV.run_query` | PH-03 / YES — redirect policy bypass | PH-05 / YES — error/timing oracle |
| `redash/query_runner/excel.py:45` — `Excel.run_query` | PH-03 / YES — redirect policy bypass | PH-05 / YES — error/timing oracle |
| `redash/query_runner/jql.py:168` — `JiraJQL.run_query` | NO — base URL is admin-configured and not query-controlled | NO — no adaptive interaction mechanism described in anatomy |
| `redash/query_runner/elasticsearch2.py:59` — `ElasticSearch2.run_query` | NO — base URL is admin-configured and not query-controlled | NO — no adaptive interaction mechanism described in anatomy |
| `redash/query_runner/drill.py:91` — `Drill.run_query` | NO — base URL is admin-configured and not query-controlled | NO — no adaptive interaction mechanism described in anatomy |
| `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response` | PH-02 / YES — SSRF guard config toggle | PH-05 / YES — error/timing oracle |
| `redash/utils/requests_session.py:19` — `ConfiguredSession.request` | PH-03 / YES — redirect policy centralization | NO — not an interactive mechanism by itself |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| SSRF guard relies on ENFORCE_PRIVATE_ADDRESS_BLOCK; disabling restores unrestricted URL fetch. | PH-02 / YES — tension confirmed |
| URL validation is partial: pagination next_url from response body can redirect to different host; allowlist not enforced. | PH-01 / YES — tension confirmed |
| CSV/Excel use requests_or_advocate.get directly (no ConfiguredSession redirect policy), potentially differing redirect handling from BaseHTTPQueryRunner paths. | PH-03 / YES — tension confirmed |
| Query runner parsing does not enforce URL scheme allowlist (http/https only) or host allowlist. | PH-04 / YES — tension confirmed |

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| Response differentiation in `BaseHTTPQueryRunner.get_response` (status vs exception) | PH-05 / YES — adaptive scanning oracle |
| Pagination state accumulation in `UrlPagination.next` / `TokenPagination.next` | PH-01 / NO — used for TRIZ host pivot; not a learning oracle by itself |
