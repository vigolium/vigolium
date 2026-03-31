# Bypass Analysis: PATCH-T1-01 -- CVE-2026-21721 + CVE-2025-3260

**Cluster ID:** T1-01 (dashboard-permission-scope-binding)
**Commits:** `1fa4fdf0adc` (T1-01a), `5a62f35f5b6` (T1-01b)
**Severity:** HIGH (8.1 / 8.3)
**Component:** `pkg/api/api.go` -- dashboard route registration

---

## Patch Summary

### Pre-patch state

Four dashboard permission and version/restore routes lacked resource-scoped authorization:

1. `GET /api/dashboards/uid/:uid/permissions` -- checked `dashboards.permissions:read` action globally (no scope)
2. `POST /api/dashboards/uid/:uid/permissions` -- checked `dashboards.permissions:write` action globally (no scope)
3. `GET /api/dashboards/uid/:uid/versions` -- checked `dashboards:write` globally (no scope) [T1-01a only]
4. `POST /api/dashboards/uid/:uid/restore` -- checked `dashboards:write` globally (no scope) [T1-01a only]
5. Identical issues on the deprecated `/api/dashboards/id/:dashboardId/` variant

A user with `dashboards.permissions:read` on *any* dashboard (e.g., `dashboards:uid:*` via wildcard, or on dashboard A) could read permissions for *any other* dashboard B by calling `GET /api/dashboards/uid/<dashboardB>/permissions`. The middleware only verified the user possessed the action, not that they possessed it for the specific resource.

### Fix mechanism

Both commits add resource scope parameters to `ac.EvalPermission()`:

- `dashUIDScope = dashboards.ScopeDashboardsProvider.GetResourceScopeUID(ac.Parameter(":uid"))` -- produces template `dashboards:uid:{{ index .URLParams ":uid" }}`
- `dashIDScope = dashboards.ScopeDashboardsProvider.GetResourceScope(ac.Parameter(":dashboardId"))` -- produces template `dashboards:id:{{ index .URLParams ":dashboardId" }}`

The middleware (`accesscontrol.Middleware`) injects the URL parameter value into the scope template, then `Evaluate()` checks the user's permissions against the resolved scope. If the user lacks `dashboards.permissions:read` scoped to `dashboards:uid:<target>`, the request is denied.

Commit T1-01a also added the `dashUIDScope` variable declaration but did NOT apply it to `/versions`, `/restore`, `/versions/:id` routes. Commit T1-01b (merged via PR #116885) applied scope to the `/permissions` sub-routes only. By the current HEAD, all six routes under `/uid/:uid` carry the `dashUIDScope` binding.

---

## Bypass Verdict: **sound**

The fix is complete for the routes it targets. No bypass was identified.

---

## Evidence and Analysis by Bypass Vector

### 1. Alternate entry points

**Finding: No unprotected alternate entry points.**

All dashboard sub-routes under `/api/dashboards/uid/:uid/` now carry the `dashUIDScope` binding:

| Route | Action | Scope | Line |
|-------|--------|-------|------|
| `GET /uid/:uid` | `dashboards:read` | `dashUIDScope` | 485 |
| `DELETE /uid/:uid` | `dashboards:delete` | `dashUIDScope` | 486 |
| `GET /uid/:uid/versions` | `dashboards:write` | `dashUIDScope` | 489 |
| `POST /uid/:uid/restore` | `dashboards:write` | `dashUIDScope` | 490 |
| `GET /uid/:uid/versions/:id` | `dashboards:write` | `dashUIDScope` | 491 |
| `GET /uid/:uid/permissions` | `dashboards.permissions:read` | `dashUIDScope` | 494 |
| `POST /uid/:uid/permissions` | `dashboards.permissions:write` | `dashUIDScope` | 495 |

The public dashboards API (`pkg/services/publicdashboards/api/api.go`) also uses a properly scoped `uidScope` parameter for its routes (lines 79-100).

The deprecated `/id/:dashboardId` route group has been fully removed from the current codebase -- no residual unscoped paths exist via that vector.

### 2. Config-gated checks

**Finding: Not applicable.**

The `authorize()` middleware is unconditionally applied. There is no feature flag or configuration option that disables scope evaluation.

### 3. Default-state gaps

**Finding: Not applicable.**

Scope binding is active by default via route registration. No explicit activation is required.

### 4. Compatibility / legacy code paths

**Finding: Legacy `/id/:dashboardId` path fully removed.**

The deprecated `/id/:dashboardId` route group is no longer present in the current `api.go`. This eliminates the risk of a legacy path bypassing the scope check that was present in the T1-01a patch.

### 5. Parser differentials / encoding bypass

**Finding: No encoding bypass possible.**

The scope template `dashboards:uid:{{ index .URLParams ":uid" }}` is populated by `web.Params(c.Req)`, which returns the route parameter as extracted by the HTTP router. The router handles URL decoding before parameter extraction, so the `:uid` value is already decoded. The same decoded value is used both:
- In the scope template for authorization
- In the handler (`web.Params(c.Req)[":uid"]`) to look up the dashboard

Since both the authorization check and the business logic use the same parameter source, there is no differential to exploit. Path traversal via `%2f` encoding is not relevant because the UID is used as a database lookup key, not a filesystem path.

### 6. Missing normalization (case, Unicode)

**Finding: Not a concern.**

Dashboard UIDs are opaque identifiers stored and compared as exact strings. The scope comparison in `evaluator.go:match()` uses strict equality (`scope == target`) or prefix matching with `*`. There is no case-insensitive comparison that could be exploited.

### 7. Folder-level transitive permissions

**Finding: By design, not a bypass.**

The `NewDashboardUIDScopeResolver` resolves a `dashboards:uid:<uid>` scope into both the dashboard scope and the parent folder scope(s) via `resolveDashboardScope()` (lines 170-194 in `accesscontrol.go`). This means a user with `dashboards.permissions:read` scoped to `folders:uid:<folderUID>` CAN read permissions for dashboards within that folder. This is the intended RBAC inheritance model in Grafana, not a bypass -- folder administrators are expected to manage dashboards within their folders.

### 8. Wildcard scope grants

**Finding: Expected behavior.**

A user with `dashboards.permissions:read` scoped to `dashboards:uid:*` can read permissions for all dashboards. This is valid RBAC behavior for admin-level roles, not a bypass of the fix.

---

## Notes

- The two commits partially overlap: T1-01a added scope to the `/permissions` routes and declared the scope variables; T1-01b appears to have been developed in parallel against a branch where the `/permissions` scope was not yet applied. Both converge to the same correct state.
- The `GetDashboardUIDs` route (`GET /api/dashboards/ids/:ids`) uses `dashboards:read` without a resource scope. This is a bulk lookup endpoint that takes a comma-separated list of IDs, making per-resource scoping impractical. The handler itself should filter results based on user permissions. This is a separate concern from the CVE being fixed.
