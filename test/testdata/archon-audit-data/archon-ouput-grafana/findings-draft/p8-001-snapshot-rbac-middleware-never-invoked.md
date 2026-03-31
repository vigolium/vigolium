Phase: 8
Sequence: 001
Slug: snapshot-rbac-middleware-never-invoked
Verdict: VALID
Rationale: The SnapshotPublicModeOrDelete middleware constructs an RBAC evaluation handler via ac.Middleware(ac2)(ac.EvalPermission(...)) but never invokes the returned web.Handler with the request context (c). The RBAC check for ActionSnapshotsDelete is architecturally present but silently discarded, allowing any authenticated user to delete snapshots via the REST API deleteKey endpoint. No blocking protections were found by the Advocate across all 5 defense layers.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-1-p8/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Go unit test proves the RBAC handler returned by ac.Middleware(ac2)(ac.EvalPermission(...)) is constructed but never invoked with (c), allowing any authenticated user to bypass permission checks on snapshot delete/create endpoints.
Severity-Final: HIGH

## Summary

The `SnapshotPublicModeOrDelete` middleware at `pkg/middleware/auth.go:255-268` contains a Go expression evaluation bug where the RBAC permission check is constructed but never executed. The function calls `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))` which returns a `web.Handler` (i.e., `func(*contextmodel.ReqContext)`), but this returned function is immediately discarded -- it is never called with `(c)` to actually perform the RBAC evaluation.

The correct pattern would be `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))(c)` -- note the trailing `(c)` which invokes the handler. The same bug exists in `SnapshotPublicModeOrCreate` at line 238-250.

As a result, any authenticated user (Viewer, Editor, or even Anonymous with anonymous auth enabled) can:
1. Delete any snapshot via `GET /api/snapshots-delete/:deleteKey` without `ActionSnapshotsDelete` permission
2. Create snapshots via `POST /api/snapshots/` without `ActionSnapshotsCreate` permission (though the create handler has partial internal role-based checks)

## Location

- **Primary (delete)**: `pkg/middleware/auth.go:255-268` -- `SnapshotPublicModeOrDelete` function, line 266
- **Primary (create)**: `pkg/middleware/auth.go:236-250` -- `SnapshotPublicModeOrCreate` function, line 249
- **RBAC Middleware definition**: `pkg/services/accesscontrol/middleware.go:30-70` -- `Middleware` function (shows the curried pattern)
- **Route registration (delete)**: `pkg/api/api.go:615` -- `r.Get("/api/snapshots-delete/:deleteKey", reqSnapshotPublicModeOrDelete, ...)`
- **Route registration (create)**: `pkg/api/api.go:610` -- `r.Post("/api/snapshots/", reqSnapshotPublicModeOrCreate, ...)`
- **Handler (no redundant RBAC)**: `pkg/api/dashboard_snapshot.go:164-186` -- `DeleteDashboardSnapshotByDeleteKey`

## Attacker Control

The attacker controls the `deleteKey` URL parameter in `GET /api/snapshots-delete/:deleteKey`. The deleteKey is a high-entropy value (190 bits), but it can be obtained via:
- Snapshot creation API response (which includes the deleteKey)
- Shared snapshot URLs that include the deleteKey
- Log files that record snapshot operations
- The K8s API deletekey subresource (`GET .../snapshots/{name}/deletekey`)

The attacker must be authenticated (any role -- Viewer is sufficient). If anonymous authentication is enabled, even unauthenticated users can exploit this (the middleware only checks `c.IsSignedIn`, not RBAC).

## Trust Boundary Crossed

RBAC authorization boundary (TB-4). The RBAC system is designed to enforce fine-grained permissions (`ActionSnapshotsDelete`, `ActionSnapshotsCreate`) on snapshot operations. This middleware bug bypasses the entire RBAC evaluation, collapsing the permission check to a simple "is authenticated" test. A Viewer-role user who should only have read access gains delete capability.

## Impact

- **Authorization bypass**: Any authenticated user can delete snapshots without the `ActionSnapshotsDelete` permission
- **Data loss**: Snapshots may contain historical dashboard states, audit-relevant data, or compliance snapshots
- **RBAC model violation**: The presence of the RBAC permission in the codebase gives a false sense of security -- operators configuring RBAC rules for snapshot management will believe their rules are enforced
- **Affected endpoints**: `GET /api/snapshots-delete/:deleteKey` (delete) and `POST /api/snapshots/` (create, partial bypass)

## Evidence

1. `auth.go:266`: `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))` -- expression evaluates to a `web.Handler` that is discarded
2. `middleware.go:30-70`: `Middleware` returns `func(Evaluator) web.Handler` -- the inner handler at line 32-63 contains the actual RBAC check, which is never reached
3. `api.go:615`: Route uses `reqSnapshotPublicModeOrDelete` as middleware -- the handler runs but RBAC is skipped
4. `dashboard_snapshot.go:164-186`: The `DeleteDashboardSnapshotByDeleteKey` handler has no internal RBAC check -- it relies entirely on the middleware
5. Contrast with correct usage at `api.go:526-527`: `authorize(ac.EvalPermission(...))` which properly registers the RBAC evaluator as a middleware handler

## Reproduction Steps

1. Set up Grafana with default configuration (SnapshotPublicMode = false)
2. Create a Viewer-role user
3. As an Admin, create a snapshot and note the deleteKey from the response
4. As the Viewer user, call `GET /api/snapshots-delete/:deleteKey` with the deleteKey
5. Expected: 403 Forbidden (Viewer lacks ActionSnapshotsDelete permission)
6. Actual: 200 OK -- snapshot is deleted without RBAC check

To verify the bug at the code level:
- Add `(c)` at the end of `auth.go:266`: `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))(c)`
- Verify that Viewer users now receive 403 Forbidden
