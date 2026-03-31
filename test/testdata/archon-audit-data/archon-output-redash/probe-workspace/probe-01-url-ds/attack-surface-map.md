# Attack Surface Map: URL-loading query runners (json/csv/excel/url) and HTTP data sources

## Entry Points
- `redash/query_runner/url.py:12` — `Url.run_query` — accepts query string path (relative or absolute depending on base_url), constructs URL and fetches HTTP response.
- `redash/query_runner/json_ds.py:157` — `JSON.run_query` — accepts YAML query with `url`, `method`, `params`, `headers`, `data`, `json`, `verify`, optional `pagination` and `fields`.
- `redash/query_runner/json_ds.py:200` — `JSON._get_all_results` — accepts URL (from query) and follows pagination `next_url` via response body.
- `redash/query_runner/json_ds.py:219` — `JSON._get_json_response` — performs HTTP request via BaseHTTPQueryRunner.
- `redash/query_runner/csv.py:48` — `CSV.run_query` — accepts YAML query containing `url`, `user-agent`, CSV read args.
- `redash/query_runner/excel.py:45` — `Excel.run_query` — accepts YAML query containing `url`, `user-agent`, Excel read args.
- `redash/query_runner/jql.py:168` — `JiraJQL.run_query` — accepts JSON query; target base URL from data source configuration.
- `redash/query_runner/elasticsearch2.py:59` — `ElasticSearch2.run_query` — accepts JSON query; target base URL from data source configuration.
- `redash/query_runner/drill.py:91` — `Drill.run_query` — accepts SQL query; target base URL from data source configuration.
- `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response` — generic HTTP client path used by multiple HTTP query runners.
- `redash/utils/requests_session.py:19` — `ConfiguredSession.request` — wraps requests/advocate with redirect policy.

## Trust Boundary Crossings
- User-supplied URL in JSON/CSV/Excel/URL query runners -> outbound HTTP request to arbitrary network target (worker process boundary).
- Pagination `next_url` from HTTP response body -> subsequent outbound HTTP request (response-controlled follow-on request).
- Admin-configured base URLs for HTTP data sources (Jira/Elasticsearch/Drill) -> outbound HTTP request to configured target.

## Auth / AuthZ Decision Points
- `redash/query_runner/__init__.py:365` — `BaseHTTPQueryRunner.get_auth` — decides whether to include configured basic-auth credentials and whether auth is required.
- (Upstream) Query execution permissions and data source access checks occur in API handlers/worker enqueue (not in this component’s files).

## Validation / Sanitization Functions
- `redash/utils/requests_session.py:13` — `requests_or_advocate` selection — enforces private-address blocking when `ENFORCE_PRIVATE_ADDRESS_BLOCK` is enabled.
- `redash/query_runner/__init__.py:375` — `BaseHTTPQueryRunner.get_response` — uses `requests_session.request` and handles `UnacceptableAddressException`.
- `redash/query_runner/url.py:17` — `Url.run_query` — blocks absolute URLs when base_url configured (relative URL enforcement).
- `redash/query_runner/json_ds.py:191` — `JSON._run_json_query` — limits HTTP method to GET/POST.
- `redash/query_runner/json_ds.py:194` — `JSON._run_json_query` — validates `fields` is list.
- `redash/query_runner/json_ds.py:236` — `RequestPagination.from_config` — validates pagination config type.
- `redash/query_runner/json_ds.py:253` — `UrlPagination.next` — uses `urljoin` to build next URL.
- `redash/query_runner/json_ds.py:262` — `TokenPagination.next` — prevents infinite pagination loop (token stable check).

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| API handler | Worker | Query text and params are from authenticated user with execute permissions | HTTP: YES | (Out of scope) scheduled refresh jobs may bypass per-request context |
| Worker | Query Runner | Query is validated by runner-specific parsing | JSON/CSV/Excel/URL: PARTIAL | `url` and pagination `next_url` are not allowlisted |
| Query Runner | HTTP client | SSRF protections enforced by requests_or_advocate / ConfiguredSession | Depends on ENFORCE_PRIVATE_ADDRESS_BLOCK: NO | If ENFORCE_PRIVATE_ADDRESS_BLOCK=false or direct requests usage |
| HTTP client | External URL | Redirects revalidated and blocked for private IPs | ConfiguredSession: YES | CSV/Excel use requests_or_advocate.get directly; still advocate but no shared session config |
| Response parser | Result set | Response format is trusted for pagination/field mapping | NO | Pagination `next_url` sourced from response body |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)
- SSRF guard relies on `ENFORCE_PRIVATE_ADDRESS_BLOCK`; disabling restores unrestricted URL fetch.
- URL validation is partial: pagination `next_url` from response body can redirect to different host; allowlist not enforced.
- CSV/Excel use `requests_or_advocate.get` directly (no ConfiguredSession redirect policy), potentially differing redirect handling from BaseHTTPQueryRunner paths.
- Query runner parsing does not enforce URL scheme allowlist (http/https only) or host allowlist.
