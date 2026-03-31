# Deep Probe Summary: Snapshot Auth Bypass, Avatar Anonymous Bypass, Alerting Contact Point Secrets

**Status**: complete
**Rounds**: 4
**Total hypotheses generated**: 21
**Validated**: 12
**NEEDS-DEEPER**: 4
**Invalidated**: 3
**Stop reason**: Comprehensive coverage achieved across all components; diminishing returns on remaining surface

## Attack Surface Map Reference
`security/probe-workspace/snapshot-avatar-alerting/attack-surface-map.md`

## Validated Hypotheses

### PH-21: SnapshotPublicModeOrCreate/Delete RBAC Check Never Invoked
- **Input path**: `GET /api/snapshots-delete/:deleteKey` -> `pkg/middleware/auth.go:255-268` -> `SnapshotPublicModeOrDelete`
- **Assumption broken**: Code assumes `ac.Middleware(ac2)(ac.EvalPermission(...))` evaluates the RBAC check, but it only constructs the handler without invoking it with the request context `(c)`.
- **Attack input**: Any authenticated user (including Viewer) calls `GET /api/snapshots-delete/:deleteKey` with a known deleteKey.
- **Code path**: `pkg/middleware/auth.go:266` -> constructs `web.Handler` but never calls it -> middleware passes -> `pkg/api/dashboard_snapshot.go:164` executes deletion
- **Sanitizers on path**: None -- the RBAC middleware is constructed but never executed
- **Security consequence**: RBAC bypass -- any authenticated user can delete snapshots via deleteKey without `ActionSnapshotsDelete` permission. Same bug at line 249 for create (though create has redundant RBAC check in handler).
- **Severity estimate**: HIGH
- **Evidence file**: `round-4-evidence.md`

### PH-01: K8s Snapshot Delete-by-DeleteKey Cross-Org Deletion
- **Input path**: `DELETE .../snapshots/delete/:deleteKey` -> `pkg/registry/apis/dashboard/snapshot/routes.go:272-275` -> `DeleteWithKey()`
- **Assumption broken**: Code assumes RBAC is sufficient tenant isolation; deleteKey lookup has no org filter
- **Attack input**: Known deleteKey belonging to a different org
- **Code path**: `routes.go:275` -> `pkg/services/dashboardsnapshots/service.go:223-240` -> `database.go:89-108` (no org WHERE clause) -> `database.go:83` (DELETE by deleteKey, no org)
- **Sanitizers on path**: RBAC check for ActionSnapshotsDelete present at routes.go:266 -- but no org check
- **Security consequence**: Cross-org snapshot deletion (requires 190-bit entropy deleteKey knowledge)
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`

### PH-03: Avatar Anonymous Bypass for DoS
- **Input path**: `GET /avatar/:hash` -> `pkg/api/api.go:605` -> `pkg/api/avatar/avatar.go:104`
- **Assumption broken**: `reqSignedIn` assumed to require authentication, but anonymous auth bypasses it
- **Attack input**: Many concurrent requests with unique 32-char hex hashes (each triggers 2 outbound HTTP to Gravatar)
- **Code path**: `api.go:605` (reqSignedIn bypassed) -> `avatar.go:104` -> `avatar.go:155` -> `avatarFetch()` -> 2x `performGet()` outbound HTTP
- **Sanitizers on path**: LRU cache (2000 entries) limits stored entries; `validMD5` regex limits hash format -- but 16^32 possible hashes far exceed cache
- **Security consequence**: Unauthenticated DoS via outbound connection exhaustion and goroutine pressure
- **Severity estimate**: HIGH (when anonymous auth enabled)
- **Evidence file**: `round-1-evidence.md`

### PH-04: reqSignedIn Routes Accessible to Anonymous Users
- **Input path**: Multiple routes in `pkg/api/api.go` using `reqSignedIn`
- **Assumption broken**: `reqSignedIn` allows anonymous access when `[auth.anonymous] enabled = true`
- **Attack input**: Unauthenticated requests to `/render/*`, `/api/gnet/*`, and ~39 other routes
- **Code path**: `pkg/middleware/auth.go:202-234` -> `requireLogin = !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -> false when AllowAnonymous=true
- **Sanitizers on path**: None for most routes; render has concurrent limit of 30
- **Security consequence**: Anonymous users get Viewer-equivalent access to rendering, grafana.net proxy, and multiple index/dashboard pages
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`, `round-2-evidence.md`

### PH-09: Render Endpoint Anonymous Access (Resource Exhaustion)
- **Input path**: `GET /render/*` -> `pkg/api/api.go:599` -> `pkg/api/render.go:18`
- **Assumption broken**: Render endpoint uses `reqSignedIn` instead of `reqSignedInNoAnonymous`
- **Attack input**: Unauthenticated render requests with attacker-controlled path, width, height, timeout
- **Code path**: `api.go:599` (reqSignedIn bypassed) -> `render.go:80-99` -> `RenderService.Render()` -> headless browser operation
- **Sanitizers on path**: `RendererConcurrentRequestLimit` defaults to 30
- **Security consequence**: Anonymous DoS via concurrent rendering operations (headless browser spawning)
- **Severity estimate**: MEDIUM (rate-limited; requires anonymous auth)
- **Evidence file**: `round-2-evidence.md`

### PH-10: Gnet Proxy Anonymous Access with Token Leakage
- **Input path**: `ANY /api/gnet/*` -> `pkg/api/api.go:602` -> `pkg/api/grafana_com_proxy.go:52`
- **Assumption broken**: `reqSignedIn` allows anonymous access; proxy injects `GrafanaComSSOAPIToken`
- **Attack input**: Unauthenticated requests proxied to grafana.com API with instance's SSO token
- **Code path**: `api.go:602` (reqSignedIn bypassed) -> `grafana_com_proxy.go:52-57` -> `ReverseProxyGnetReq()` injects Bearer token at line 45
- **Sanitizers on path**: Destination hardcoded to `GrafanaComAPIURL`; Cookie/Auth headers stripped from inbound
- **Security consequence**: Anonymous users can make authenticated requests to grafana.com API; potential SSO token leakage
- **Severity estimate**: LOW-MEDIUM (requires anonymous auth + configured SSO token)
- **Evidence file**: `round-2-evidence.md`

### PH-11: K8s Snapshot DeleteKey Subresource Cross-Org Exposure
- **Input path**: `GET .../snapshots/{name}/deletekey` -> `pkg/registry/apis/dashboard/snapshot/sub_deletekey.go:55`
- **Assumption broken**: K8s namespace scoping does not enforce org filter at the store level
- **Attack input**: Known snapshot key (name) from a different org
- **Code path**: `sub_deletekey.go:55-82` -> `SnapshotLegacyStore.Get()` at `snapshot_legacy_store.go:121-135` -> `GetDashboardSnapshot` with no org filter
- **Sanitizers on path**: K8s RBAC requires `ActionSnapshotsDelete`; attacker needs high-entropy snapshot key
- **Security consequence**: Cross-org deleteKey exposure (enables PH-01 attack chain)
- **Severity estimate**: LOW-MEDIUM
- **Evidence file**: `round-2-evidence.md`

### PH-12: K8s Snapshot Standard DELETE Cross-Org Deletion
- **Input path**: `DELETE .../snapshots/{name}` -> K8s API -> `pkg/registry/apis/dashboard/snapshot/snapshot_legacy_store.go:60`
- **Assumption broken**: K8s namespace scoping does not enforce org filter in the legacy store
- **Attack input**: Known snapshot key (name) from a different org
- **Code path**: `snapshot_legacy_store.go:60-83` -> `GetDashboardSnapshot` (no org filter) -> `DeleteDashboardSnapshot` (delete by deleteKey, no org filter)
- **Sanitizers on path**: K8s RBAC requires `ActionSnapshotsDelete`; attacker needs high-entropy snapshot key
- **Security consequence**: Cross-org snapshot deletion via standard K8s DELETE
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-2-evidence.md`

### PH-13: K8s Snapshot GET Cross-Org Read (Metadata Only)
- **Input path**: `GET .../snapshots/{name}` -> K8s API -> `pkg/registry/apis/dashboard/snapshot/snapshot_legacy_store.go:121`
- **Assumption broken**: K8s namespace scoping does not enforce org filter in the store
- **Attack input**: Known snapshot key from a different org
- **Code path**: `snapshot_legacy_store.go:121-135` -> `GetDashboardSnapshot` (no org filter) -> `storage_without_create.go:51-57` (strips deleteKey + dashboard)
- **Sanitizers on path**: `storageWrapper.Get()` strips deleteKey and dashboard content; only metadata returned
- **Security consequence**: Cross-org snapshot metadata leakage (name, timestamps, external flag)
- **Severity estimate**: LOW
- **Evidence file**: `round-2-evidence.md`

### PH-15: External Snapshot Delete SSRF via Stored URL
- **Input path**: Snapshot deletion triggers `pkg/services/dashboardsnapshots/service.go:149` -> `client.Get(externalUrl)`
- **Assumption broken**: `ExternalDeleteURL` from database is used without URL validation
- **Attack input**: Compromised external snapshot server returns crafted `DeleteUrl` (e.g., internal network address)
- **Code path**: `service.go:149-179` -> `client.Get(externalUrl)` with no URL validation
- **Sanitizers on path**: None -- no IP validation, no protocol restriction
- **Security consequence**: SSRF to internal network on snapshot deletion (response not returned to attacker)
- **Severity estimate**: LOW-MEDIUM (requires compromised external server)
- **Evidence file**: `round-3-evidence.md`

### PH-16: K8s Delete Amplifies SSRF via Cross-Org External Snapshot
- **Input path**: K8s DELETE of cross-org external snapshot -> `snapshot_legacy_store.go:69-73` -> `DeleteExternalDashboardSnapshot()`
- **Assumption broken**: Cross-org delete (PH-12) combined with external snapshot delete triggers SSRF
- **Attack input**: Known key of an external snapshot from a different org
- **Code path**: `snapshot_legacy_store.go:60-83` (no org filter) -> `service.go:149` (SSRF via ExternalDeleteURL)
- **Sanitizers on path**: None for org filter; ExternalDeleteURL unvalidated
- **Security consequence**: Cross-org triggered SSRF
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-3-evidence.md`

### PH-05: K8s Snapshot Create Leaks DeleteKey in Response
- **Input path**: `POST .../snapshots/create` -> `pkg/registry/apis/dashboard/snapshot/routes.go:224-232`
- **Assumption broken**: DeleteKey in response enables cross-org deletion if intercepted
- **Attack input**: N/A (response to authorized user)
- **Code path**: `routes.go:225-231` -> JSON response includes `DeleteKey: cmd.DeleteKey`
- **Sanitizers on path**: HTTPS transport protects in transit; but logs, proxies may cache
- **Security consequence**: DeleteKey leakage enables PH-01 attack chain
- **Severity estimate**: LOW (by design; risk in combination)
- **Evidence file**: `round-1-evidence.md`

## NEEDS-DEEPER (unresolved, for Phase 8 chambers)

### PH-07/PH-14: Test Receiver Error Message May Contain Secret URLs
- **Why unresolved**: The `alertingNotify.TestReceiversResult` from the external `github.com/grafana/alerting` library includes error strings that are passed through to the API response without sanitization. Standard Go HTTP client errors include the URL in error messages. The external library source was not available locally to confirm.
- **Suggested follow-up**: Clone the `github.com/grafana/alerting` library and trace the error construction in the `TestReceivers` function to confirm whether webhook URLs (which may contain API keys) appear in error messages returned to the API caller.

### PH-19: Contact Point Export Decrypt Auth Bypass
- **Why unresolved**: The export endpoint at `api_provisioning.go:167-183` accepts `decrypt=true` query parameter. Route-level auth uses `EvalAny` with permissions including non-secret read permissions. Need to verify whether the `receiverService.GetReceivers()` has additional decrypt authorization at the service layer.
- **Suggested follow-up**: Trace `receiver_svc.go:189` `GetReceivers()` to verify if `decrypt=true` requires additional authorization checks (e.g., `ActionAlertingReceiversReadSecrets`).

### PH-20: VictorOps URL Redaction Completeness
- **Why unresolved**: VictorOps URL is typed as `Secret` in the API definitions, but the actual schema version marking in the external alerting library could not be verified locally.
- **Suggested follow-up**: Verify VictorOps integration schema in `github.com/grafana/alerting` library to confirm `GetSecretFieldsPaths()` includes the URL field.

### PH-06: SnapshotPublicMode Unauthenticated Deletion
- **Why unresolved**: By design when SnapshotPublicMode is enabled. Confirm this is documented and intentional.
- **Suggested follow-up**: Review whether SnapshotPublicMode documentation adequately warns about unauthenticated deletion capability.

## KB Domain Research Used

### Snapshot Auth / Multi-Tenant Isolation
- KB identified K8s API delete-by-deleteKey lacking org check (DFD-7). Probing confirmed this and extended it to discover the SAME org filter gap in the K8s standard DELETE and GET paths (PH-12, PH-13), plus the RBAC middleware invocation bug (PH-21).
- KB identified deleteKey leakage vectors; probing confirmed deleteKey in API responses and via the K8s deletekey subresource.

### Anonymous Auth Bypass
- KB identified avatar endpoint using reqSignedIn (DFD-8). Probing confirmed this and extended it to discover render endpoint (PH-09) and gnet proxy (PH-10) also using reqSignedIn.
- KB auth control flow diagram (CFD-1) directly mapped the bypass logic at auth.go:216.

### Alerting Contact Points
- KB identified CVE-2025-3415 (DingDing) and CVE-2024-11741 (VictorOps) as patched. Probing explored residual leakage via test-receiver error messages (PH-07/PH-14) and export decrypt auth (PH-19).
- KB attack scenario AS-12 (contact point secret leakage via test) aligned with PH-07/PH-14 findings.
