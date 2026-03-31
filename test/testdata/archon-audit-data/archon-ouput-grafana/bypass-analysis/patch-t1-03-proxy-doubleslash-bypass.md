# Bypass Analysis: CVE-2025-3454 — Datasource Proxy Double-Slash Path Bypass

**Cluster ID:** PATCH-T1-03
**Severity:** MEDIUM (5.0)
**Bypass Verdict:** sound (with caveats noted below)

---

## Patch Summary

**Vulnerability:** The datasource proxy route matching in `pkg/api/pluginproxy/ds_proxy.go` compared `proxy.proxyPath` directly against `route.Path` using `strings.HasPrefix()`. An attacker could insert double slashes (e.g., `//api//admin`) to make the prefix check fail, bypassing route-level role restrictions (e.g., `ReqRole: Admin`) while still having the request proxied to the backend datasource at the normalized path.

**Fix (two commits):**

1. **Commit `1f707d16ed5`** (April 2025, "Apply security patch 357-202503311017"): Replaced raw `strings.HasPrefix(proxy.proxyPath, route.Path)` with `strings.HasPrefix(r1, r2)` where both `r1` and `r2` are normalized via `plugins.CleanRelativePath()`. This function calls `filepath.Clean(filepath.Join("/", path))` followed by `filepath.Rel("/", ...)`, which collapses `//`, resolves `..`, and strips leading slashes.

2. **Commit `9e399e0b19a`** (January 2026, "Proxy fallback routes must match all inputs #116274"): Fixed a regression from the first patch. When `CleanRelativePath("")` returns `"."`, an empty-path fallback route (used as a catch-all with Admin role) would fail to match any input. The fix maps `"."` back to `""` when the original path was not literally `"."`, ensuring fallback routes still enforce their required role.

**Backported to:** release-12.0.1, release-11.6.1, release-11.2.9 (and cherry-picked to release-12.2.4 through 12.3.2).

---

## Bypass Hypothesis Testing

### 1. Are `%2F` encoded slashes handled the same as literal slashes?

**Result: Not a bypass vector.**

The `proxyPath` is extracted via `extractProxyPath(c.Req.URL.EscapedPath())`. The `EscapedPath()` method preserves `%2F` encoding -- it does NOT decode them to `/`. Subsequently, `filepath.Clean` treats `%2F` as literal characters (not path separators). So a path like `api%2Fadmin` cleans to `api%2Fadmin`, which will NOT match a route path of `api/admin`. The encoding-preserving pipeline means `%2F` cannot be used to bypass the route check AND still reach the intended backend path as a decoded slash -- the backend datasource would also receive the literal `%2F`.

### 2. Does the route matching normalize `..` sequences?

**Result: Handled correctly.**

`filepath.Clean` resolves `..` sequences. Input `api/v1/../../admin` cleans to `admin`. Input `../api/admin` cleans to `api/admin`. Since route paths are also cleaned, the comparison is consistent. Traversal via `..` cannot bypass a route prefix check.

### 3. Is `//api/v1/targets` treated equivalently to `/api/v1/targets` after fix?

**Result: Yes, correctly handled.**

`CleanRelativePath("//api//admin")` returns `"api/admin"`, which correctly matches against a route path of `"api/admin"`. This was the primary vulnerability, and the test at line 281-287 of `ds_proxy_test.go` validates this case.

### 4. Are backslash (`\`) separators rejected?

**Result: Not a bypass vector on Linux/macOS (standard deployment).**

On Unix systems, `filepath.Clean` does NOT treat `\` as a path separator. Input `api\admin` cleans to `api\admin`, which will not match `api/admin`. If Grafana were deployed on Windows, `filepath.Clean` would normalize `\` to `/`, and the match would succeed, which is actually the correct behavior for that platform.

### 5. Do all proxy entry points (UID and ID) apply same normalization?

**Result: Yes, both are covered.**

Both `ProxyDataSourceRequest` (ID-based, line 441-442 of api.go) and `ProxyDataSourceRequestWithUID` (UID-based, line 428-429 of api.go) ultimately call `p.proxyDatasourceRequest()` which calls `getProxyPath()` and passes the result to `NewDataSourceProxy`, which stores it in `proxy.proxyPath`. The `validateRequest()` method is called from `HandleRequest()` on both paths. The normalization applies uniformly.

Note: The ID-based proxy endpoints are gated behind feature flag `FlagDatasourceLegacyIdApi` and are marked deprecated, but when enabled they share the identical code path.

### 6. Fallback route (empty path) bypass?

**Result: Fixed by second commit, now sound.**

The first patch introduced a regression: `CleanRelativePath("")` returns `"."`, so `strings.HasPrefix("api/v2/leak", ".")` is `false`, meaning a fallback route with `Path: ""` and `ReqRole: Admin` would never match, allowing any path to skip the role check and fall through to the unprotected default. The second commit (`9e399e0b19a`) fixes this by mapping `"."` back to `""` when the original was not literally `"."`, restoring correct behavior: `strings.HasPrefix("api/v2/leak", "")` is `true`, so the route matches and the Admin role check is enforced.

### 7. Sibling resource proxy endpoint?

**Result: Not affected.**

The `/api/datasources/uid/:uid/resources/*` endpoint uses `CallDatasourceResourceWithUID`, which goes through the plugin client's `CallResource` method rather than the `DataSourceProxy` route matching system. It does not share the `validateRequest()` code path.

### 8. Config-gated or default-state gaps?

**Result: No gaps.**

The fix is unconditional. `CleanRelativePath` is always called in `validateRequest()` regardless of configuration. There are no feature flags controlling whether normalization is applied.

---

## Residual Observations

1. **OSS validator is a no-op.** The `OSSDataSourceRequestValidator.Validate()` always returns nil. Datasource URL validation relies entirely on the plugin route matching logic. Enterprise builds may have a non-trivial validator, but this could not be verified.

2. **`proxyPath` is used raw in the proxied request.** While `validateRequest()` now cleans the path for comparison purposes, the actual `proxy.proxyPath` used in `req.URL.RawPath` (line 200, 209 of ds_proxy.go) is NOT cleaned. This means a request with `//api//admin` would be validated against the cleaned `api/admin` route (correctly blocked if role insufficient), but if allowed, the backend would receive `//api//admin`. This is intentional -- the proxy should forward the original path to the backend datasource. However, it means the security boundary exists solely at the route matching layer.

3. **`filepath.Clean` is OS-dependent.** On Windows, backslashes would be normalized to forward slashes. This could theoretically cause differential behavior between the route matching (which would see `api/admin`) and downstream processing. This is a low-risk edge case since Grafana server deployments on Windows are uncommon.

---

## Evidence

- **Primary fix:** `pkg/api/pluginproxy/ds_proxy.go` lines 304-324 (current state)
- **CleanRelativePath implementation:** `pkg/plugins/filepath.go` lines 158-167
- **Proxy path extraction:** `pkg/services/datasourceproxy/datasourceproxy.go` lines 139-147 (uses `EscapedPath()`, preserving `%2F` encoding)
- **Route registration:** `pkg/api/api.go` lines 428-442 (both UID and ID endpoints)
- **Test coverage:** `ds_proxy_test.go` includes double-slash test (line 281) and fallback route regression tests (116273 suite)
