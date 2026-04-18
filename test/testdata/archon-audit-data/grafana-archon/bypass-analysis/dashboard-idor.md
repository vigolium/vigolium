# Bypass Analysis: Dashboard Permissions IDOR (Missing Scope)

**Cluster ID**: dashboard-permissions-idor
**Undisclosed tag**: [undisclosed]
**Commits**: 393de2d7c66be26f25af38f29a14141f2e5be5e3, 1fa4fdf0adcb67eeccd91abfdd045b0e8e15484b

## Patch Summary

The dashboard permissions API endpoints (`GET /api/dashboards/uid/:uid/permissions` and `POST /api/dashboards/uid/:uid/permissions`) were protected by `authorize(ac.EvalPermission(dashboards.ActionDashboardsPermissionsRead))` **without** a resource scope parameter. This meant that any user holding the global `dashboards.permissions:read` permission (not scoped to a specific dashboard) could read or modify permissions for **any** dashboard by iterating UIDs, constituting a classic IDOR vulnerability.

The fix adds the missing scope binding:
- UID routes: `dashUIDScope := dashboards.ScopeDashboardsProvider.GetResourceScopeUID(ac.Parameter(":uid"))` passed as second argument to `EvalPermission`
- ID routes (deprecated): `dashIDScope := dashboards.ScopeDashboardsProvider.GetResourceScope(ac.Parameter(":dashboardId"))` -- these routes were subsequently removed entirely

Commit 393de2d7 (Jan 2, 2026) added the scope parameters to the `EvalPermission` calls for both UID and ID routes. Commit 1fa4fdf0 (Jan 7, 2026) restructured the route registration, moving `dashUIDScope` declaration to the outer group and removing the deprecated `/id/:dashboardId` routes entirely.

## Bypass Verdict: **sound**

## Evidence and Analysis

### Alternate Entry Points
- `GetDashboardPermissionList` and `UpdateDashboardPermissions` are only registered once each in `pkg/api/api.go` (lines 490-491). No other route mounts these handlers.
- The deprecated `/id/:dashboardId` route group was fully removed, eliminating a potential secondary path.
- The K8s-style app SDK dashboard API (`apps/dashboard/`) does not expose a permissions subresource (the swagger comment references `/access` but it is not implemented as a route).
- `getDashboardACL` and `dashboardPermissionsService` are only called from `pkg/api/dashboard_permission.go` -- no other API surface.

### Sibling Endpoints (Folder Permissions)
- Folder permission endpoints in `pkg/api/folder.go` (lines 33-35) already include proper scope binding:
  ```
  folderPermissionRoute.Get("/", authorize(accesscontrol.EvalPermission(folder.ActionFoldersPermissionsRead, uidScope)), ...)
  folderPermissionRoute.Post("/", authorize(accesscontrol.EvalPermission(folder.ActionFoldersPermissionsWrite, uidScope)), ...)
  ```
- No analogous gap exists for folders.

### Remaining Scope-less Dashboard Checks
- `dashboardRoute.Get("/ids/:ids", authorize(ac.EvalPermission(dashboards.ActionDashboardsRead)), ...)` at line 500 is scope-less, but this endpoint converts internal IDs to UIDs -- it does not expose sensitive permission data. The lack of scope here is by design (bulk lookup operation). This is a low-risk observation, not a bypass.

### Config-gated / Compatibility Concerns
- The fix is unconditional -- no feature flags, no config gates. The scope is always evaluated.
- The scope provider resolves `:uid` from URL parameters at request time, which is the standard Grafana access control pattern used by all other dashboard endpoints (read, delete, write, versions).

### Parser Differentials / Normalization
- The `:uid` parameter is extracted by Macaron router and used directly as a scope identifier. The same parameter value is used by both the authorization middleware and the handler function (`web.Params(c.Req)[":uid"]`), so there is no differential parsing opportunity.

### Handler-level Authorization
- The handler functions (`GetDashboardPermissionList`, `UpdateDashboardPermissions`) do not perform additional scope-level authorization -- they rely entirely on the route middleware. This is consistent with the Grafana pattern where `authorize()` middleware is the single enforcement point. The fix correctly addresses the single enforcement point.

## Residual Risk

None identified. The fix is structurally sound:
1. Both read and write permission endpoints now include resource scope binding
2. The deprecated ID-based route was removed entirely
3. No alternate API paths exist to the same handler functions
4. Sibling resources (folders) were already correctly scoped
5. The fix is unconditional with no feature flag dependencies
