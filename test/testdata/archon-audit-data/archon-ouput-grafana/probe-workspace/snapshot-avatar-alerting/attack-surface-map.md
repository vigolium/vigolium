# Attack Surface Map: Snapshot Auth Bypass, Avatar Anonymous Bypass, Alerting Contact Point Secrets

## Entry Points

### Snapshot (REST API)
- `pkg/api/dashboard_snapshot.go:72` -- `CreateDashboardSnapshot()` -- POST /api/snapshots/ -- create snapshot
- `pkg/api/dashboard_snapshot.go:112` -- `GetDashboardSnapshot()` -- GET /api/snapshots/:key -- retrieve snapshot by key (NO auth middleware in api.go:611)
- `pkg/api/dashboard_snapshot.go:164` -- `DeleteDashboardSnapshotByDeleteKey()` -- GET /api/snapshots-delete/:deleteKey -- delete by deleteKey (reqSnapshotPublicModeOrDelete)
- `pkg/api/dashboard_snapshot.go:197` -- `DeleteDashboardSnapshot()` -- DELETE /api/snapshots/:key -- delete by key (authorize RBAC)
- `pkg/api/dashboard_snapshot.go:267` -- `SearchDashboardSnapshots()` -- GET /dashboard/snapshots -- list snapshots
- `pkg/api/dashboard_snapshot.go:52` -- `GetSharingOptions()` -- GET /api/snapshot/shared-options/ -- sharing settings

### Snapshot (K8s API)
- `pkg/registry/apis/dashboard/snapshot/routes.go:105` -- create handler -- POST .../snapshots/create -- K8s snapshot create
- `pkg/registry/apis/dashboard/snapshot/routes.go:257` -- deleteWithKey handler -- DELETE .../snapshots/delete/:deleteKey -- K8s delete by deleteKey (NO org check)
- `pkg/registry/apis/dashboard/snapshot/routes.go:336` -- settings handler -- GET .../snapshots/settings -- K8s sharing settings

### Avatar
- `pkg/api/avatar/avatar.go:104` -- `Handler()` -- GET /avatar/:hash -- avatar proxy (reqSignedIn, anon bypass)

### Alerting Contact Points
- `pkg/services/ngalert/provisioning/contactpoints.go:95` -- `GetContactPoints()` -- GET contact points with redaction
- `pkg/services/ngalert/provisioning/contactpoints.go:140` -- `getContactPointDecrypted()` -- internal decrypted access
- `pkg/services/ngalert/provisioning/contactpoints.go:162` -- `CreateContactPoint()` -- POST create contact point

## Trust Boundary Crossings

### Snapshot cross-org via K8s API
- K8s delete-by-deleteKey (routes.go:257-283) has RBAC check but NO org check. The `DeleteWithKey()` function at `pkg/services/dashboardsnapshots/service.go:223` fetches snapshot by deleteKey without org filter, then deletes it. Any authenticated user with `ActionSnapshotsDelete` permission in ANY org can delete snapshots from OTHER orgs if they know the deleteKey.

### Snapshot GET unauthenticated
- `pkg/api/api.go:611`: `r.Get("/api/snapshots/:key", routing.Wrap(hs.GetDashboardSnapshot))` -- NO auth middleware at all. Any user with a valid snapshot key can retrieve snapshot data without authentication.

### Avatar anonymous bypass
- `pkg/api/api.go:605`: Uses `reqSignedIn` which allows anonymous access when `[auth.anonymous] enabled = true`. Should use `reqSignedInNoAnonymous`.
- `pkg/middleware/auth.go:216`: `requireLogin := !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- when AllowAnonymous=true and ReqNoAnonynmous=false, requireLogin=false.

### Alerting contact point secrets
- `pkg/services/ngalert/models/receivers.go:322-338` -- `Integration.Redact()` relies on `Config.GetSecretFieldsPaths()` to know which fields are secrets. If a field is not in the schema's secret paths, it won't be redacted.
- VictorOps URL is typed as `Secret` in definitions (contact_points.go:299), so it should be redacted.

## Parser / Serialization Functions
- `pkg/api/dashboard_snapshot.go:74` -- `web.Bind(c.Req, &cmd)` -- JSON body parsing for snapshot create
- `pkg/registry/apis/dashboard/snapshot/routes.go:143` -- `web.Bind(wrap.Req, &cmd)` -- JSON body parsing for K8s snapshot create
- `pkg/api/avatar/avatar.go:105` -- `web.Params(ctx.Req)[":hash"]` -- URL path param extraction

## Auth / AuthZ Decision Points
- `pkg/api/api.go:611` -- GetDashboardSnapshot -- **NO auth middleware** (unauthenticated access by design)
- `pkg/api/api.go:605` -- Avatar -- `reqSignedIn` (bypassed by anonymous auth)
- `pkg/api/api.go:610` -- CreateSnapshot -- `reqSnapshotPublicModeOrCreate`
- `pkg/api/api.go:612` -- DeleteSnapshot by key -- `authorize(ac.EvalPermission(dashboards.ActionSnapshotsDelete))`
- `pkg/api/api.go:615` -- DeleteSnapshot by deleteKey -- `reqSnapshotPublicModeOrDelete`
- `pkg/registry/apis/dashboard/snapshot/routes.go:120` -- K8s create -- RBAC `ActionSnapshotsCreate` + org namespace check
- `pkg/registry/apis/dashboard/snapshot/routes.go:266` -- K8s deleteWithKey -- RBAC `ActionSnapshotsDelete` only (NO org check)
- `pkg/api/dashboard_snapshot.go:218` -- REST DeleteDashboardSnapshot -- org check `queryResult.OrgID != c.OrgID`
- `pkg/middleware/auth.go:238-251` -- SnapshotPublicModeOrCreate -- allows unauthenticated if SnapshotPublicMode=true
- `pkg/middleware/auth.go:255-268` -- SnapshotPublicModeOrDelete -- allows unauthenticated if SnapshotPublicMode=true

## Validation / Sanitization Functions
- `pkg/api/avatar/avatar.go:107` -- `validMD5.MatchString(hash)` -- validates hash is 32-char hex
- `pkg/api/dashboard_snapshot.go:119` -- key length check `len(key) == 0`
- `pkg/api/dashboard_snapshot.go:170` -- deleteKey length check
- `pkg/registry/apis/dashboard/snapshot/routes.go:131-140` -- namespace org check (create only)
- `pkg/services/ngalert/models/receivers.go:322-338` -- `Integration.Redact()` -- redacts secrets by schema path

## KB Domain Research Highlights

### Snapshot Auth / Multi-Tenant Isolation (from KB Domain Research)
- Cross-org snapshot deletion: K8s API delete-by-deleteKey lacks org check
- deleteKey leakage: 190-bit entropy, requires log/API leak vector
- SnapshotPublicMode: unauthenticated delete by design via deleteKey bearer
- REST API GET /api/snapshots/:key has NO auth middleware

### Anonymous Auth Bypass (from KB)
- reqSignedIn bypass via anonymous: Avatar endpoint + any reqSignedIn route when anon enabled
- `requireLogin = !AllowAnonymous || forceLogin || ReqNoAnonymous` -- core bypass logic
- Anonymous user gets Viewer-equivalent org access
- ~39 routes use `reqSignedIn` vs ~7 using `reqSignedInNoAnonymous`

### Alerting Contact Points (from KB)
- CVE-2025-3415: DingDing API key leaked to Viewer (patched)
- CVE-2024-11741: VictorOps config leaked (patched)
- SSRF via admin-controlled webhook URLs (by design)
- VictorOps URL field typed as `Secret` in schema -- should be properly redacted
- Redaction relies on `GetSecretFieldsPaths()` from schema; missing paths = unredacted secrets
