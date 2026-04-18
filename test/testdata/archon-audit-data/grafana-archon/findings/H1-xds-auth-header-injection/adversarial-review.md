# Adversarial Review: X-DS-Authorization Header Injection

## Step 1 -- Restate and Decompose

**Restated claim**: An authenticated Grafana user (Viewer role) can send the HTTP header `X-DS-Authorization` with an arbitrary value to the datasource proxy endpoint. The backend proxy reads this header and uses its value to overwrite the `Authorization` header on the outbound request to the backend datasource. This allows the user to substitute the configured datasource credentials with attacker-supplied ones.

### Sub-claims

- **Sub-claim A**: Attacker controls the `X-DS-Authorization` HTTP header value sent to `GET /api/datasources/proxy/uid/<uid>/*`.
  - Status: **SUPPORTED** -- Standard HTTP header, fully attacker-controlled on authenticated API calls.

- **Sub-claim B**: The `X-DS-Authorization` header is NOT stripped from the inbound request before reaching the director function at `ds_proxy.go:230`.
  - Status: **SUPPORTED** -- Verified. `wrapDirector` (reverse_proxy.go:70-82) strips headers from `AuthHTTPHeaderListFromContext`, which includes `Authorization` but NOT `X-DS-Authorization`. No other middleware strips this header.

- **Sub-claim C**: The director function reads `X-DS-Authorization` and overwrites the outbound `Authorization` header.
  - Status: **SUPPORTED** -- Verified at ds_proxy.go:230-234. The code reads `X-DS-Authorization`, deletes it from the request, and sets `Authorization` to its value.

All sub-claims are supported.

## Step 2 -- Independent Code Path Trace

### Entry point
Route: `/api/datasources/proxy/uid/{uid}/{datasource_proxy_route}` -> `HTTPServer.ProxyDataSourceRequestWithUID` -> `DataProxy.ProxyDatasourceRequestWithUID`

### Proxy setup (ds_proxy.go:137-142)
The `proxy.director` function is passed to `proxyutil.NewReverseProxy`, which wraps it via `wrapDirector`.

### Execution order in wrapDirector (reverse_proxy.go:70-82):
1. `AuthHTTPHeaderListFromContext` headers are deleted (includes `Authorization`, NOT `X-DS-Authorization`)
2. Original director `d(req)` runs (this is `proxy.director`)
3. `PrepareProxyRequest(req)` runs

### Inside proxy.director (ds_proxy.go:173+):
1. URL rewriting (lines 174-176)
2. BasicAuth credential setting (lines 220-228) -- sets `Authorization` from stored creds
3. **X-DS-Authorization override (lines 230-234)** -- reads `X-DS-Authorization`, deletes it, overwrites `Authorization`
4. User header, cookies, user-agent (lines 236-239)

### Validation/sanitization on path:
- **Authentication**: Required (route is behind auth middleware)
- **Authorization**: Requires `datasources:query` permission (default Viewer role has this)
- **Header stripping**: `Authorization` is stripped by wrapDirector, but `X-DS-Authorization` is NOT
- **No validation of X-DS-Authorization value**: No format checks, no allowlisting

## Step 3 -- Protection Surface Search

| Layer | Control | Blocks Attack? |
|-------|---------|---------------|
| Language | Go type system | No -- string header value, no type enforcement |
| Framework | None | No relevant framework protection |
| Middleware (wrapDirector) | Strips auth headers from AuthHTTPHeaderList | **No** -- X-DS-Authorization is not in the list |
| Application (RBAC) | Requires `datasources:query` permission | **Partial** -- limits to users with query access, but Viewer role has this by default |
| Application (datasource access) | User must have access to the specific datasource | **Partial** -- limits scope but does not prevent header injection |
| Documentation | No documentation found about security implications of X-DS-Authorization | No |
| Design intent | This is an **intentional feature** introduced in PR #4832 (2016) | See analysis below |

### Critical context: This is intentional design

The `X-DS-Authorization` mechanism is used by Grafana's own frontend (`backend_srv.ts:310-313`). The frontend renames `Authorization` -> `X-DS-Authorization` for datasource plugin requests to avoid conflicting with Grafana's session auth. The backend reverses this transformation. This is a deliberate feature, not an oversight.

## Step 4 -- Real-Environment Reproduction

**PoC-Status: theoretical**

Reproduction blocked: Setting up a multi-tenant Prometheus/Loki backend with tenant-specific auth headers to demonstrate cross-tenant access would require significant infrastructure (multi-tenant datasource + multiple valid auth tokens). The code path is unambiguously confirmed through static analysis, but the actual security impact (cross-tenant data access) requires a specific deployment topology.

The code path itself (header read -> header overwrite) is trivially confirmed by reading the source.

## Step 5 -- Prosecution and Defense Briefs

### Prosecution Brief

The vulnerability is real and the code path is confirmed:

1. `ds_proxy.go:230-234` unconditionally reads `X-DS-Authorization` and overwrites `Authorization` on outbound requests
2. No middleware, no framework control, and no application logic strips `X-DS-Authorization` from inbound requests
3. `wrapDirector` (reverse_proxy.go:72-76) explicitly strips `Authorization` but not `X-DS-Authorization`, creating a bypass path
4. Any user with `datasources:query` (Viewer by default) can exploit this
5. In deployments where backend datasources are only reachable through the Grafana proxy (network isolation), this allows an authenticated user to send arbitrary credentials to an otherwise-protected service
6. The header is deleted after reading (line 232), making exploitation difficult to detect in proxy logs

### Defense Brief

1. **Intentional design**: This is a deliberate feature introduced in 2016 (commit c9d6321f382, PR #4832). The Grafana frontend actively uses this mechanism (`backend_srv.ts:310-313`). It is not an accidental code path.

2. **Limited attack surface**: The attacker must already be authenticated to Grafana AND have query access to the specific datasource. They cannot use this to access datasources they don't have permission to proxy.

3. **Attacker needs valid credentials**: Overriding the `Authorization` header requires the attacker to PROVIDE valid credentials for the backend datasource. If the attacker already has those credentials, they may not need the proxy (unless network isolation applies).

4. **Deployment-specific impact**: The "cross-tenant" scenario requires:
   - A shared multi-tenant backend datasource
   - Authorization-header-based tenant isolation on that datasource
   - The backend datasource to be reachable ONLY through the Grafana proxy
   - The attacker to possess valid credentials for other tenants
   This is a narrow deployment topology.

5. **Feature, not bug**: Grafana treats this as a feature that allows datasource plugins to pass per-user or per-request authentication. Removing it would break legitimate functionality.

## Step 6 -- Severity Challenge

Starting at MEDIUM:

- **Upgrade signals**: Remotely triggerable (yes), trust boundary crossing (credential override, yes)
- **Downgrade signals**:
  - Requires authentication (not unauthenticated)
  - This is an **intentional feature** used by Grafana's own frontend
  - Impact depends on specific deployment topology (multi-tenant, network-isolated backend)
  - Attacker must possess valid credentials for the target tenant
  - Has been in Grafana since 2016 without being classified as a vulnerability

**Challenged severity: MEDIUM** (downgrade from HIGH)

The finding describes a real design concern, but the intentional nature of the feature and the narrow deployment conditions required for exploitation reduce it from HIGH to MEDIUM. This is closer to a "secure by design" discussion than an exploitable vulnerability.

## Step 7 -- Verdict

**Adversarial-Verdict: CONFIRMED**

The code path exists exactly as described, and there is no protection that blocks an authenticated user from sending `X-DS-Authorization` to override backend credentials. However, the severity is overrated because this is intentional Grafana design, not an oversight.

**Adversarial-Rationale**: Code path at ds_proxy.go:230-234 unambiguously reads X-DS-Authorization and overwrites outbound Authorization with no stripping or validation; however, this is an intentional feature used by Grafana's own frontend (backend_srv.ts:310-313), reducing practical severity.

**Severity-Final: MEDIUM** (downgraded from HIGH due to intentional design and deployment-specific impact)

**PoC-Status: theoretical** (code path confirmed statically; multi-tenant exploitation scenario not reproduced)
