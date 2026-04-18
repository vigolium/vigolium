# Bypass Analysis: Datasource Proxy Path Normalization (07d136f6)

**Patch summary**: The commit adds `CleanRelativePath` normalization to `proxy.proxyPath` before comparing it with `route.Path` via `strings.HasPrefix` in `validateRequest()`. Previously, paths like `//api//admin` bypassed the route-matching logic because `strings.HasPrefix("//api//admin", "api/admin")` returns `false`, causing the route to not match. When no route matches, execution falls through to `return nil` (line 347), silently allowing the request. The fix normalizes both sides so `//api//admin` becomes `api/admin` and correctly matches the restricted route.

**Advisory**: None (undisclosed fix) [undisclosed]

**Cluster ID**: ds-proxy-path-normalization

**Bypass verdict**: sound (with minor residual concerns)

---

## Analysis

### 1. What was fixed

The vulnerability was an authorization bypass in the datasource proxy route access control. Plugin routes define path prefixes (e.g., `api/admin`) with associated role requirements (e.g., `ReqRole: Admin`). The `validateRequest()` function iterates routes and uses `strings.HasPrefix(proxy.proxyPath, route.Path)` to match. By inserting extra slashes (`//api//admin`), an attacker could prevent the route from matching the access-controlled path, causing the request to fall through the route loop without hitting `hasAccessToRoute()`. The request was then proxied to the backend datasource without authorization checks.

### 2. CleanRelativePath mechanism

The fix calls `plugins.CleanRelativePath()` on both sides:

```go
func CleanRelativePath(path string) (string, error) {
    cleanPath := filepath.Clean(filepath.Join("/", path))
    rel, err := filepath.Rel("/", cleanPath)
    ...
    return rel, nil
}
```

This function:
- Joins with `/` to make it absolute
- Calls `filepath.Clean` which collapses `//`, resolves `.` and `..`, removes trailing slashes
- Converts back to relative via `filepath.Rel`

### 3. Bypass vector evaluation

| Vector | Assessment |
|--------|------------|
| **Double slashes (`//`)** | Fixed. `filepath.Clean` collapses multiple slashes. `//api//admin` -> `api/admin`. |
| **Dot segments (`../`, `./`)** | Fixed. `filepath.Clean` resolves `.` and `..` segments. `./api/../api/admin` -> `api/admin`. |
| **URL-encoded slashes (`%2F`)** | Not bypassable at the validation layer. `proxyPath` comes from `EscapedPath()` which preserves `%2F` as literal text. `filepath.Clean` treats `%2F` as three literal characters, not a separator. `api%2Fadmin` cleans to `api%2Fadmin` which does NOT match prefix `api/admin`, so the restricted route does NOT match. However, the downstream backend will also receive `%2F` literally (via `RawPath`), so the backend would interpret it as a single path segment `api%2Fadmin` not `api/admin`. No bypass. |
| **Backslash (`\`)** | On Unix (where Grafana typically runs), `filepath.Clean` does not treat `\` as a separator. `api\admin` stays as `api\admin` and would not match `api/admin`. Same as `%2F` case -- falls through without matching, but backend also receives the backslash literally. No bypass on Unix. On Windows, `filepath.Clean` normalizes `\` to `/`, so `api\admin` would correctly match `api/admin`. |
| **Unicode normalization** | Go's `filepath.Clean` does not perform Unicode normalization. However, route paths are ASCII, and incoming URL paths would have non-ASCII characters percent-encoded by the HTTP layer. No bypass. |
| **Case sensitivity** | `strings.HasPrefix` is case-sensitive, matching `filepath.Clean` behavior. Route paths are defined by plugins in lowercase. HTTP path routing upstream would need to deliver the path to this handler, which is case-sensitive. No bypass. |
| **Trailing dot (`api/admin.`)** | `filepath.Clean` does NOT strip trailing dots (unlike Windows filesystem APIs). `api/admin.` would not match `api/admin` prefix. No bypass. |
| **Null byte injection** | Go strings can contain null bytes, but `filepath.Clean` does not strip them. `api/admin\x00` would not match `api/admin` via `HasPrefix` (it actually would since HasPrefix checks if the prefix is present at the start). However, route paths don't contain nulls, and HTTP parsers reject null bytes in URLs per RFC. No practical bypass. |

### 4. Residual concern: fallthrough on no-match

The structural design of `validateRequest()` has a residual concern. When no route matches, the function returns `nil` (success) for most datasource types (non-Prometheus, non-ES). This means if someone crafts a path that evades ALL route matching after cleaning, the request is still proxied. This is by design -- not all datasource proxy requests need route-based auth. But it means the fix only protects paths that DO match a route after normalization. This is correct behavior but worth noting.

### 5. Dot-path edge case handling

The patch also handles the edge case where `CleanRelativePath` returns `"."` for empty or relative-to-root inputs (lines 316-321 in current code). This prevents `"."` from matching route paths that start with `"."` literally, and instead treats empty-equivalent paths correctly.

### 6. Plugin proxy comparison

The **plugin proxy** (`pluginproxy.go`) uses `web.NewTree().Match()` for route matching (a proper router/tree matcher) and returns HTTP 404 when no route matches. This is structurally safer than the datasource proxy's `strings.HasPrefix` + fallthrough design. The datasource proxy was not refactored to use tree matching, but the normalization fix addresses the specific vulnerability.

## Conclusion

The fix is **sound** for the specific vulnerability (double-slash path normalization bypass). `CleanRelativePath` correctly handles the known evasion vectors: double slashes, dot segments, and relative path tricks. URL-encoded slashes (`%2F`) are not a bypass because they are preserved literally through both the validation and proxying layers, maintaining consistency. The fix was also backported with proper dot-path edge case handling.

No practical bypass was identified.
