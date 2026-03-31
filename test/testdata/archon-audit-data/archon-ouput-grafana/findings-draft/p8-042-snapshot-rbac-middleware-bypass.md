Phase: 8
Sequence: 042
Slug: snapshot-rbac-middleware-bypass
Verdict: VALID
Rationale: RBAC middleware for snapshot delete/create is constructed but the returned handler is never invoked with the request context, making the permission check dead code; any authenticated user with a known deleteKey can delete snapshots without ActionSnapshotsDelete permission; deleteKey entropy (190-bit) limits practical exploitability.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The snapshot RBAC middleware functions `SnapshotPublicModeOrCreate` (auth.go:238) and `SnapshotPublicModeOrDelete` (auth.go:255) contain a bug where the RBAC permission check is constructed but never invoked. The code `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))` returns a `web.Handler` function, but this function is never called with the request context `(c)`. The correct invocation should be `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))(c)`. As a result, any authenticated user (including Viewer role) who knows a snapshot's deleteKey can delete it via `GET /api/snapshots-delete/:deleteKey` without the required `ActionSnapshotsDelete` permission.

## Location

- **Primary**: `pkg/middleware/auth.go:266` -- `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))` -- handler constructed but never called with `(c)`
- **Primary**: `pkg/middleware/auth.go:249` -- Same bug for `ActionSnapshotsCreate`
- **Route**: `pkg/api/api.go:615` -- `r.Get("/api/snapshots-delete/:deleteKey", reqSnapshotPublicModeOrDelete, ...)`
- **Handler**: `pkg/api/dashboard_snapshot.go` -- `DeleteDashboardSnapshotByDeleteKey` (no redundant RBAC check)

## Attacker Control

- **Input**: deleteKey in URL path parameter (`GET /api/snapshots-delete/:deleteKey`)
- **Required knowledge**: deleteKey (190-bit random string)
- **Minimum privilege**: Any authenticated user (Viewer role)

## Trust Boundary Crossed

RBAC authorization boundary. The permission check `ActionSnapshotsDelete` is intended to restrict snapshot deletion to users with explicit delete permission. The bug causes this check to be silently skipped, allowing any authenticated user to perform the action.

## Impact

- **Authorization bypass**: Any authenticated user can delete snapshots without `ActionSnapshotsDelete` permission
- **Data destruction**: Deletion of shared dashboard snapshots (potentially disruptive to operational workflows)
- **Limited by deleteKey entropy**: 190-bit random string must be known to attacker; obtainable via API response interception, log file access, or shared URLs
- **Create path**: Same bug at auth.go:249 may allow unauthorized snapshot creation (may have redundant handler-level check)

## Evidence

1. `auth.go:255-268`: `SnapshotPublicModeOrDelete` function:
   ```go
   func SnapshotPublicModeOrDelete(cfg *setting.Cfg, ac2 ac.AccessControl) web.Handler {
       return func(c *contextmodel.ReqContext) {
           if cfg.SnapshotPublicMode { return }
           if !c.IsSignedIn { notAuthorized(c); return }
           ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))
           // BUG: returned web.Handler is never called with (c)
       }
   }
   ```
2. `auth.go:249`: Same pattern for `SnapshotPublicModeOrCreate`
3. `api.go:615`: Route wires `reqSnapshotPublicModeOrDelete` as middleware
4. `dashboard_snapshot.go`: `DeleteDashboardSnapshotByDeleteKey` handler has NO redundant RBAC check

## Reproduction Steps

1. Create a dashboard snapshot as an Admin user and note the deleteKey from the API response
2. As a Viewer-role user (who does NOT have `ActionSnapshotsDelete` permission):
   ```
   GET /api/snapshots-delete/<deleteKey> HTTP/1.1
   Cookie: grafana_session=<viewer_session>
   ```
3. Expected: 200 OK -- snapshot deleted successfully
4. This should have been rejected with 403 Forbidden due to missing `ActionSnapshotsDelete` permission
5. Verify snapshot is deleted: `GET /api/snapshots/<key>` returns 404

Note: The deleteKey is a 190-bit entropy random string. Practical exploitation requires obtaining this key through legitimate channels (API response, logs, shared URLs).

---

## Phase 9 Stage 1 FP-Check Result

**Verdict: DUPLICATE → DROP**
**Rationale**: p8-042 duplicates p8-001 (`snapshot-rbac-middleware-never-invoked`). Both trace to the same root cause: `SnapshotPublicModeOrDelete` at `pkg/middleware/auth.go:255-268` constructs the RBAC handler but never invokes it with `(c)`. p8-001 is the authoritative finding with the complete analysis and higher severity (HIGH). p8-042 should be excluded from Phase 10 variant analysis and final report.
**Canonical finding**: p8-001
**Status-Updated**: DUPLICATE
