# Round 4 Evidence

---

### PH-19: Contact Point Export Decrypt Bypass via Provisioning Read Permission
**Status: NEEDS-DEEPER**

**Evidence:**
1. `authorization.go:311-321`: Export endpoint uses `EvalAny` with permissions including `ActionAlertingReceiversRead` (non-secret read).
2. `api_provisioning.go:171`: `Decrypt: c.QueryBoolWithDefault("decrypt", false)` -- the decrypt param is passed through.
3. `contactpoints.go:95-136`: `GetContactPoints()` passes `q.Decrypt` to `GetReceivers()`.
4. The `GetReceivers()` in `receiver_svc.go:189` likely has its own authorization check for decrypt operations.
5. Need to trace `GetReceivers` to confirm if decrypt is separately authorized or if the route-level auth is sufficient.

**What's needed**: Read `receiver_svc.go:189` to check if decrypt=true requires additional auth checks within the service layer.

**Severity**: MEDIUM (if decrypt bypasses service-level auth)

---

### PH-20: VictorOps URL Redaction Completeness
**Status: NEEDS-DEEPER**

**Evidence:**
1. VictorOps `URL` field is typed as `Secret` in `contact_points.go:299`.
2. The `Secret` type should result in the field being registered as a secret path in the schema.
3. `Redact()` at `receivers.go:322-338` iterates `GetSecretFieldsPaths()` from the schema version.
4. If the schema correctly marks the VictorOps URL path, it will be redacted.
5. The external alerting library (`github.com/grafana/alerting`) is not locally available, so the schema implementation cannot be directly verified.

**What's needed**: Access to the alerting library to verify VictorOps schema paths.

**Severity**: LOW (likely correctly implemented given the `Secret` type annotation)

---

### PH-21: SnapshotPublicModeOrCreate/Delete RBAC Check Never Invoked
**Status: VALIDATED -- CRITICAL BUG**

**Evidence:**
1. `auth.go:249`: `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsCreate))` -- this constructs the RBAC handler but NEVER calls it with the request context `c`.
2. `middleware.go:30-32`: `ac.Middleware(ac2)` returns `func(Evaluator) web.Handler`. Calling with evaluator returns `web.Handler` which is `func(c *contextmodel.ReqContext)`. The returned handler is discarded.
3. **Correct code would be**: `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsCreate))(c)`
4. **Same bug at line 266**: `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))` -- also never invoked.
5. **Impact**: When SnapshotPublicMode is disabled and a user IS signed in:
   - `SnapshotPublicModeOrCreate` (auth.go:249) -- the RBAC check for `ActionSnapshotsCreate` is NEVER evaluated. ANY signed-in user can create snapshots regardless of RBAC permissions.
   - `SnapshotPublicModeOrDelete` (auth.go:266) -- the RBAC check for `ActionSnapshotsDelete` is NEVER evaluated. ANY signed-in user can delete snapshots via deleteKey.
6. Note: The REST create path at `dashboard_snapshot.go:92-97` has its OWN RBAC check (`hs.AccessControl.Evaluate`), so the create path has redundant protection. But the delete-by-deleteKey path at `api.go:615` relies ONLY on `reqSnapshotPublicModeOrDelete`.
7. **Attack**: A Viewer user (who should NOT have `ActionSnapshotsDelete`) can call `GET /api/snapshots-delete/:deleteKey` and the middleware passes because:
   - SnapshotPublicMode is false -> doesn't bypass
   - User IS signed in -> doesn't trigger notAuthorized
   - RBAC check is constructed but NOT invoked -> passes without checking permission
   - The handler `DeleteDashboardSnapshotByDeleteKey` executes the deletion

**Code path**:
```
GET /api/snapshots-delete/:deleteKey
  -> SnapshotPublicModeOrDelete middleware (auth.go:255-268)
    -> cfg.SnapshotPublicMode is false -> continue
    -> c.IsSignedIn is true -> continue
    -> ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete)) -> returns handler but NEVER called
    -> middleware returns without blocking
  -> DeleteDashboardSnapshotByDeleteKey executes -> snapshot deleted
```

**Severity**: HIGH -- Any authenticated user (even Viewer) can delete snapshots via deleteKey without RBAC permission.
