Phase: 7
Sequence: 022
Slug: ds-proxy-parser-differential
Verdict: VALID
Rationale: The datasource proxy performs URL path unescaping (url.PathUnescape) AFTER route matching, creating a parser differential where the backend receives a decoded path that differs from what route authorization checked. While CVE-2025-3454 patched the primary bypass vector and exploitation requires specific plugin route configurations with non-normalizing backends, the differential remains exploitable in constrained scenarios.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-2/debate.md

## Summary

The Grafana datasource proxy performs route matching (for plugin route authorization and credential injection) on the percent-encoded URL path, then decodes the path via `url.PathUnescape()` before forwarding it to the backend datasource. This creates a parser differential: a `%2F` (encoded slash) in the proxy path is treated as a literal string during route matching but decoded to `/` before reaching the backend. If the backend datasource interprets the decoded path differently from what the route match authorized, the attacker can potentially reach backend endpoints that were not intended to be accessible through the matched route.

This is a residual issue from the CVE-2025-3454 patch, which added `CleanRelativePath` to address double-slash bypass but did not address percent-encoded slash differentials.

## Location

- **Primary**: `pkg/api/pluginproxy/ds_proxy.go:209-218` -- PathUnescape after route matching
- **Route matching**: `pkg/api/pluginproxy/ds_proxy.go:305-322` -- CleanRelativePath + HasPrefix matching on encoded form
- **Entry point**: `GET/POST /api/datasources/proxy/uid/:uid/*` (authenticated, datasources.ActionQuery RBAC)

## Attacker Control

- **Input**: Proxy path segment of the URL (everything after `/api/datasources/proxy/uid/:uid/`)
- **Authentication required**: Any authenticated user with `datasources.ActionQuery` permission (Viewer role by default)
- **Injection technique**: `%2F` in path segments is matched as literal during route authorization but decoded to `/` before backend forwarding

## Trust Boundary Crossed

TB4 -- Datasource Proxy. Route-level authorization checks a path that differs from what the backend receives. If the backend uses path-based access controls, the attacker may reach endpoints that the route auth was not designed to permit.

## Impact

- **Route authorization bypass**: For datasource plugins that define routes with path-based restrictions, the encoded form may match an authorized route while the decoded form reaches a different backend endpoint
- **Constrained exploitation**: Most built-in datasources define no routes (no route-based restriction to bypass). Most backend HTTP servers normalize `%2F` to `/` before routing (making the differential invisible to the backend). Exploitation requires a datasource plugin with path-restricted routes AND a backend that preserves raw path encoding.
- **CVE-2025-3454 residual**: The primary double-slash bypass was patched. This is a narrower attack surface.

## Evidence

**Code path** (director function):
```
ds_proxy.go:209  req.URL.RawPath = util.JoinURLFragments(proxy.targetUrl.Path, proxy.proxyPath)
ds_proxy.go:212  unescapedPath, err := url.PathUnescape(req.URL.RawPath)
ds_proxy.go:218  req.URL.Path = unescapedPath
```

**Route matching** (validateRequest):
```
ds_proxy.go:305  r1, err := plugins.CleanRelativePath(proxy.proxyPath)  // operates on encoded form
ds_proxy.go:309  r2, err := plugins.CleanRelativePath(route.Path)
ds_proxy.go:322  if !strings.HasPrefix(r1, r2) { continue }  // prefix match on encoded form
```

**Differential**: Route matching checks `CleanRelativePath(proxy.proxyPath)` against `CleanRelativePath(route.Path)` using `strings.HasPrefix`. If `proxy.proxyPath = "api%2Fv1%2Fquery"`, CleanRelativePath returns `"api%2Fv1%2Fquery"` (no slash normalization). This may match a route prefix like `""` (empty route = match all). The backend then receives `"api/v1/query"` after PathUnescape.

## Reproduction Steps

1. Identify a datasource plugin that defines routes with path restrictions (e.g., a custom plugin with route `Path: "api/v1"` and `ReqRole: Editor`)
2. As a Viewer user with datasources.ActionQuery, send: `curl -H "Cookie: grafana_session=<session>" http://grafana:3000/api/datasources/proxy/uid/<ds-uid>/api%2Fv1%2Fadmin`
3. Route matching: `CleanRelativePath("api%2Fv1%2Fadmin")` may not match the `"api/v1"` route prefix (because `%2F` != `/`), falling through to allow the request without route-level auth
4. Backend receives: path decoded to `api/v1/admin` -- potentially a restricted endpoint
5. Note: actual exploitability depends on specific plugin route definitions and backend path normalization behavior
