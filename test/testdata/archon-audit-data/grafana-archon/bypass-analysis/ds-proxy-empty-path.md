# Bypass Analysis: Datasource Proxy Empty Path Route Bypass

- **Commit**: 9e399e0b19a713c665baa7e06bcfb5af16774ebb
- **Component**: `pkg/api/pluginproxy/ds_proxy.go` (DataSourceProxy.validateRequest)
- **PR**: #116274, referencing issue #116273
- **Tag**: [undisclosed]
- **Cluster ID**: ds-proxy-route-matching

## Patch Summary

The vulnerability is in the datasource proxy's route validation logic in `validateRequest()`. When a plugin defines a "catch-all" route with an empty `Path` field (e.g., `Path: ""`) and a required role (e.g., `ReqRole: Admin`), the route matching failed to match incoming requests because:

1. `plugins.CleanRelativePath("")` returns `"."` (Go's `filepath.Clean` normalizes empty/root paths to `.`)
2. `strings.HasPrefix("api/v2/some-path", ".")` evaluates to `false`
3. The catch-all route is skipped entirely
4. The for loop falls through without matching any route
5. `validateRequest()` returns `nil` (success) -- the request is proxied without any route-level access control

**Pre-patch exploit**: A Viewer-role user could access any path on a datasource that defines an admin-only catch-all route (empty `Path`), because the empty-path route never matched. The request would be proxied directly to the upstream datasource without the intended role check.

**Fix mechanism**: After calling `CleanRelativePath`, if the result is `"."` but the original input was not literally `"."`, the code now normalizes the result to `""`. Since `strings.HasPrefix(anything, "")` is always `true`, the catch-all route now correctly matches all incoming paths, and the subsequent `hasAccessToRoute` check enforces the required role.

## Bypass Verdict: **Sound**

The fix correctly addresses the root cause for the specific bug class (empty-path / dot-normalization mismatch in catch-all routes). No bypass was found for the patched logic.

## Evidence and Analysis

### Bypass vectors tested

| Vector | Result |
|--------|--------|
| Empty string input (`""`) | Correctly normalized to `""`, matches catch-all route |
| Slash inputs (`"/"`, `"//"`) | `CleanRelativePath` returns `"."`, patch normalizes to `""` -- matches correctly |
| Dot-slash (`"./"`) | Same as above, correctly handled |
| Parent traversal (`"../"`) | `CleanRelativePath` cleans to `"."`, patch normalizes to `""` -- no escape |
| URL-encoded dot (`"%2e"`) | Not decoded by `CleanRelativePath` (operates on raw string), treated as literal `%2e` -- matches catch-all correctly |
| Literal `"."` proxyPath with `"."` routePath | Both remain `"."`, `HasPrefix(".", ".")` is `true` -- correctly matches |
| Plugin proxy path (sibling) | `PluginProxy` in `pluginproxy.go` uses `web.NewTree().Match()` (tree-based pattern matching), not `CleanRelativePath` + prefix matching -- **not affected** by this bug class |

### Pre-existing design note (not a bypass of this patch)

The route matching uses `strings.HasPrefix` without path-segment boundary enforcement. This means a route with `Path: "api"` will match `proxyPath: "apifoo"` (not just `"api/something"`). This is a pre-existing design characteristic, not introduced or worsened by this patch, and its exploitability depends on specific plugin route configurations. This could theoretically cause a route meant for `api/*` to incorrectly capture requests to `api-different-prefix/*`, applying the wrong route's access control. However, this would typically result in *over-matching* (applying access control that would not otherwise apply), which is a restrictive error rather than a permissive one.

### How `proxyPath` reaches this code

The `proxyPath` is extracted from the HTTP request URL via regex in `datasourceproxy.go`:

```
var proxyPathRegexp = regexp.MustCompile(`^\/api\/datasources\/proxy\/([\d]+|uid\/[\w-]+)\/?`)
func extractProxyPath(originalRawPath string) string {
    return proxyPathRegexp.ReplaceAllString(originalRawPath, "")
}
```

A request to `/api/datasources/proxy/1/` produces `proxyPath=""`, and `/api/datasources/proxy/1/api/v2/secrets` produces `proxyPath="api/v2/secrets"`. The attacker controls this path suffix.

### Scope of affected routes

Only datasource plugin routes with empty `Path` fields (catch-all routes) and non-empty `ReqRole` or `ReqAction` were affected. Routes with non-empty `Path` values were never impacted because their `CleanRelativePath` output would not be `"."`.

## Files Analyzed

- `/Users/bytedance/Desktop/oss-to-run/grafana/pkg/api/pluginproxy/ds_proxy.go` -- patched file, `validateRequest()` method
- `/Users/bytedance/Desktop/oss-to-run/grafana/pkg/api/pluginproxy/ds_proxy_test.go` -- regression tests added
- `/Users/bytedance/Desktop/oss-to-run/grafana/pkg/api/pluginproxy/pluginproxy.go` -- sibling PluginProxy (not affected, uses different matching)
- `/Users/bytedance/Desktop/oss-to-run/grafana/pkg/services/datasourceproxy/datasourceproxy.go` -- upstream caller, proxyPath extraction
- `/Users/bytedance/Desktop/oss-to-run/grafana/pkg/plugins/filepath.go` -- `CleanRelativePath` implementation
