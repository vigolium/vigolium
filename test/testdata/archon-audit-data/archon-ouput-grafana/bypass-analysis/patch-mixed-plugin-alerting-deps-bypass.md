# Bypass Analysis: Mixed Patches (Plugin, Alerting, Dependencies)

## Cluster: Plugin, Alerting, and Dependency Patches
**Patches analyzed**: PATCH-T3-06, PATCH-T2-07, PATCH-T4-02, PATCH-T4-04

---

## PATCH-T3-06: CVE-2024-6322 -- Plugin Datasource ReqActions Bypass

### Patch Summary

The vulnerability was that plugin route `ReqAction` fields were not enforced during datasource proxy authorization. Users with query-level datasource access could access plugin-defined routes that required higher privileges (e.g., `datasources:write`), because the `DataSourceProxy.validateRequest()` only checked `ReqRole` (org role), not `ReqAction` (RBAC action).

**Fix history:**
1. Commit `53f94ac50dd` (2024-04-30): Initial fix adding `hasAccessToRoute` to `DataSourceProxy`, gated by `FlagAccessControlOnCall`.
2. Commit `0bc8992dfab` (2024-05-06): Reverted due to issues.
3. Commit `0072e4a92d8` (2024-05-21): Re-applied fix with `FlagDatasourceProxyDisableRBAC` escape hatch (opt-out flag).
4. Subsequently evolved: The feature flag was removed entirely. The current code unconditionally enforces `ReqAction` via `hasAccessToRoute()`.

**Current fix mechanism:**
- `DataSourceProxy.hasAccessToRoute()` at `pkg/api/pluginproxy/ds_proxy.go:350-367` checks `ReqAction` first, using `GetDataSourceRouteEvaluator()` which scopes the RBAC check to the specific datasource UID (`datasources:uid:<UID>`).
- `PluginProxy.hasAccessToRoute()` at `pkg/api/pluginproxy/pluginproxy.go:132-145` does the same for app plugins using `GetPluginRouteEvaluator()` scoped to `plugins:id:<ID>`.

### Bypass Verdict: **sound**

### Evidence

1. **Feature flag gate removed**: The `FlagDatasourceProxyDisableRBAC` flag no longer exists in the codebase (removed from `toggles_gen.go`, `registry.go`, and `ds_proxy.go`). The fix is unconditional.

2. **Scoping is correct**: `GetDataSourceRouteEvaluator()` in `pkg/services/pluginsintegration/pluginaccesscontrol/accesscontrol.go:111-116` properly scopes known datasource actions (query, read, write, delete, permissions, caching, alerting) to `datasources:uid:<UID>`. Unknown actions fall through to unscoped `EvalPermission(action)`, which is acceptable since those would be custom actions without datasource-level granularity.

3. **Both proxy types covered**: The fix applies to both `DataSourceProxy` (datasource plugin routes) and `PluginProxy` (app plugin routes). Both follow the same pattern: check `ReqAction` first with scoped evaluator, fall back to `ReqRole` check.

4. **No alternate entry points identified**: The datasource proxy is the sole entry point for proxied plugin requests. The `/apis/...` routes for the new app platform use a different authorization mechanism (Kubernetes-style RBAC) and do not share this code path.

5. **No `ReqOrgRole` or similar sibling fields**: The only route authorization fields are `ReqAction` (string) and `ReqRole` (org role enum). Both are handled.

---

## PATCH-T2-07: CVE-2025-3415 -- DingDing Integration Info Disclosure

### Patch Summary

The DingDing alerting integration's `url` field (which contains an access token in the query string: `https://oapi.dingtalk.com/robot/send?access_token=xxx`) was not treated as a secret. When users retrieved contact point configurations, the URL was returned in plaintext rather than being redacted.

**Fix (commit `910eb1dd9e6`):**
1. Marked `url` as `Secure: true` in `available_channels.go` so the UI and API know to treat it as a secret field.
2. Added `patchNewSecureFields()` to `alertmanager.go` and `testreceivers.go` to move the encrypted `url` value from `SecureSettings` back into `Settings` before handing it to the DingDing notifier (whose config parser reads from `Settings.url`).

**Subsequent evolution (commit `246b73f4efe`, 2026-03-04):**
The `patchNewSecureFields` workaround was removed because the upstream `grafana/alerting` library now natively reads from both `Settings` and `SecureSettings`. The DingDing v1 schema in `grafana/alerting` library (version `v0.0.0-20260312173859`) now has `Secure: true, Protected: true` on the URL field, and `NewConfig()` calls `decryptFn("url", settings.URL)` to read from secure settings.

### Bypass Verdict: **sound**

### Evidence

1. **Schema-level enforcement**: The upstream `grafana/alerting` library's DingDing v1 schema marks `url` with `Secure: true` and `Protected: true`. The `GetSecretFieldsPaths()` method used by `Integration.Redact()` will include this field, ensuring redaction on all read paths.

2. **Redaction is systematic**: The `Integration.Redact()` method in `pkg/services/ngalert/models/receivers.go:320-338` iterates over all paths from `GetSecretFieldsPaths()` and all keys in `SecureSettings`, redacting values uniformly. This is not DingDing-specific -- it applies to all integration types.

3. **Access control layer**: The receiver access control system in `pkg/services/ngalert/accesscontrol/receivers.go` distinguishes between "read redacted" and "read decrypted" access. Users without `ActionAlertingReceiversReadSecrets` permission only receive redacted receivers. This applies across all API surfaces (REST, provisioning, k8s API).

4. **Test receivers endpoint**: The `testreceivers.go` code also properly handles secure settings (previously via `patchNewSecureFields`, now natively through the library).

5. **Other integrations**: Examined the `contact_points.go` type definitions -- integrations like Discord, Slack, PagerDuty, etc. already use `Secret` type for their sensitive fields (webhook URLs, API keys). DingDing was the outlier that used plain `string` for its URL. This has been corrected at the schema level.

6. **No notification log leakage**: Notification logs and alert history do not store contact point configuration details, so there is no secondary disclosure path.

---

## PATCH-T4-02: CVE-2024-45338 -- golang.org/x/net HTML DoS

### Patch Summary

CVE-2024-45338 affects `golang.org/x/net/html` versions before `v0.33.0`. The vulnerability allows non-linear parsing of case-insensitive content, enabling denial of service via crafted HTML input.

### Bypass Verdict: **sound** (dependency updated past fixed version)

### Evidence

1. **Current version is safe**: Grafana's `go.mod` declares `golang.org/x/net v0.51.0`, which is well above the fixed version `v0.33.0`.

2. **Limited attack surface even if vulnerable**: The only import of `golang.org/x/net/html` in the Grafana Go codebase is in `pkg/tsdb/graphite/query.go:21`. The `parseGraphiteError()` function (line 285-305) uses `html.NewTokenizer()` to strip HTML tags from Graphite error responses. This processes server-side error responses from the Graphite backend, not user-supplied input. An attacker would need to control the Graphite server's HTTP 500 response body to trigger this, which requires a compromised or malicious backend datasource -- a scenario that already implies significant compromise.

3. **Authentication required**: Graphite queries require datasource access permissions. Unauthenticated users and public dashboards would not be able to trigger this code path unless the public dashboard is configured with a Graphite datasource and the Graphite server returns crafted HTML errors.

---

## PATCH-T4-04: CVE-2025-29786 -- expr-lang/expr DoS

### Patch Summary

CVE-2025-29786 affects `expr-lang/expr` versions before `v1.17.0`, allowing memory exhaustion through unbounded expression parsing input.

### Bypass Verdict: **sound** (not reachable in Grafana)

### Evidence

1. **Not a runtime dependency**: `expr-lang/expr` does not appear in Grafana's main `go.mod`. It only appears in:
   - `.citools/src/cog/go.mod` (CI tooling, version `v1.17.7` which is above the fix)
   - `go.work.sum` (transitive checksum, version `v1.17.2` which is also above the fix)

2. **No code usage in Grafana**: Searching the entire `pkg/` directory for `expr.Compile`, `expr.Eval`, `expr.Run`, or imports of `expr-lang/expr` returns zero results. Grafana does not use this library in its production code.

3. **Alerting expressions use a different system**: Grafana alerting expressions use the `pkg/expr/` package which implements its own expression evaluation engine (SSE - Server Side Expressions) based on math operations and data frame transformations, not the `expr-lang/expr` library.

---

## Summary Table

| Patch ID | CVE | Bypass Verdict | Key Finding |
|----------|-----|---------------|-------------|
| PATCH-T3-06 | CVE-2024-6322 | sound | Fix is unconditional (feature flag removed), properly scoped to datasource UID, covers both proxy types |
| PATCH-T2-07 | CVE-2025-3415 | sound | DingDing URL marked secure at schema level in upstream library, systematic redaction applies to all integrations |
| PATCH-T4-02 | CVE-2024-45338 | sound | golang.org/x/net upgraded to v0.51.0 (fix threshold: v0.33.0), limited attack surface (Graphite error parsing only) |
| PATCH-T4-04 | CVE-2025-29786 | sound | expr-lang/expr is not used in Grafana production code, only in CI tooling at a fixed version |
