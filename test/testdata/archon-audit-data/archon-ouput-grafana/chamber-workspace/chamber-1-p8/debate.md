# Review Chamber: chamber-1-p8

Cluster: Authentication & Authorization (Phase 8)
DFD Slices: Auth/OIDC/JWT pipeline, RBAC scope binding, Snapshot K8s API org isolation, Cloud Migration org isolation
NNN Range: p8-001 to p8-019
Started: 2026-03-21T10:00:00Z
Status: CLOSED

## Prior Phase Coverage (Duplicate Exclusions)

The following pre-validated hypotheses are ALREADY covered by prior Phase 7/9 findings and will be marked DUPLICATE if re-raised:
- PH-19 (renderer JWT forgery) = p7-041 (VALID, HIGH, PoC executed)
- PH-01/03 (JWT null-exp bypass) = p7-003 + p7-075/076/077 (VALID, MEDIUM)
- PH-09 (Generic OAuth no sig verification) = p7-004 (VALID, MEDIUM)
- PH-12 (K8s snapshot cross-org via standard DELETE) = covered as PH-01 variant in probe
- EF-010 overlaps p7-001 + p7-004
- EF-011 overlaps p7-001
- EF-012 = p7-003

## Pre-Seeded Hypotheses (from Deep Probes, NOT yet covered by prior findings)

### H-00a: Snapshot RBAC Middleware Constructed But Never Invoked (PH-21 snapshot probe)
- Source: security/probe-workspace/snapshot-avatar-alerting/probe-summary.md
- Code: `pkg/middleware/auth.go:255-268` -- `SnapshotPublicModeOrDelete` constructs `ac.Middleware(ac2)(ac.EvalPermission(...))` but never calls the returned handler with `(c)`
- Consequence: Any authenticated Viewer can delete snapshots via deleteKey without ActionSnapshotsDelete permission
- Severity estimate: HIGH

### H-00b: Auth Proxy Empty Whitelist Accepts All IPs (PH-14 + PH-17 auth probe)
- Source: security/probe-workspace/auth-oidc-jwt-rbac/probe-summary.md
- Code: `pkg/services/authn/clients/proxy.go:200-203` -- `isAllowedIP` returns true when `len(c.acceptedIPs) == 0`
- Combined with PH-17: `getProxyHeader` reads header without origin validation -- full auth bypass
- Consequence: When auth proxy enabled without whitelist, any client can impersonate any user
- Severity estimate: CRITICAL (when auth proxy enabled without IP whitelist)

### H-00c: K8s Snapshot Delete-by-DeleteKey Cross-Org (EF-003 / PH-01 snapshot probe)
- Source: EF-003, security/probe-workspace/snapshot-avatar-alerting/probe-summary.md
- Code: `pkg/registry/apis/dashboard/snapshot/routes.go:275` -- no org filter on deleteKey lookup
- Consequence: Cross-org snapshot deletion when deleteKey is known
- Severity estimate: HIGH (but high-entropy deleteKey reduces practical risk)

### H-00d: Cloud Migration CancelSnapshot Missing OrgID (EF-004)
- Source: EF-004
- Code: `pkg/services/cloudmigration/cloudmigration.go:33`, `xorm_store.go:228`
- Consequence: Cross-org migration snapshot cancellation
- Severity estimate: HIGH (but requires admin + UUID knowledge)

### H-00e: OAuth State CSRF Forgeable with Default secret_key (PH-13 auth probe)
- Source: security/probe-workspace/auth-oidc-jwt-rbac/probe-summary.md
- Code: `pkg/services/authn/clients/oauth.go:363-375`
- Consequence: OAuth CSRF protection bypassed on default-key instances
- Severity estimate: MEDIUM-HIGH

---

## Round 1 -- Ideation

### [IDEATOR] Generated Hypotheses -- 2026-03-21T10:05:00Z

Building on pre-seeded hypotheses. Focus on chaining, escalation, and newly discovered attack surfaces.

**H-01: Snapshot RBAC Middleware Never Invoked -- Any Viewer Deletes Snapshots via REST API deleteKey Endpoint**

Extends H-00a. The `SnapshotPublicModeOrDelete` middleware at `pkg/middleware/auth.go:255-268` constructs `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))` but never calls the returned web.Handler with `(c)`. The expression evaluates to a `web.Handler` function value which is immediately discarded. This means the RBAC check is architecturally present but never executed.

- Attack: Any authenticated user (Viewer, Editor) calls `GET /api/snapshots-delete/:deleteKey`. The middleware at `api.go:615` (reqSnapshotPublicModeOrDelete) runs but only checks `c.IsSignedIn` -- the RBAC evaluation is silently skipped. The request proceeds to `DeleteDashboardSnapshotByDeleteKey` which deletes the snapshot.
- Entry point: `GET /api/snapshots-delete/:deleteKey` (api.go:615)
- Sink: `dashboard_snapshot.go:164` DeleteDashboardSnapshotByDeleteKey
- Same bug at line 249 for `SnapshotPublicModeOrCreate` -- affects `POST /api/snapshots/` (api.go:610)
- Preconditions: Authenticated user (any role), knowledge of deleteKey
- Severity: HIGH -- RBAC bypass on snapshot operations

**H-02: K8s Snapshot API Delete Cross-Org -- CVE-2024-1313 Fix Not Ported**

Extends H-00c. The legacy REST API at `dashboard_snapshot.go:218` checks `queryResult.OrgID != c.OrgID` after fetching a snapshot by deleteKey. The K8s API path at `routes.go:275` and `snapshot_legacy_store.go:60-83` does NOT perform this check. The K8s standard DELETE at `snapshot_legacy_store.go:60` calls `GetDashboardSnapshot` with only `Key: name` (no org filter), then deletes without org verification.

- Attack: User in Org-B makes K8s API DELETE to `/apis/dashboard.grafana.app/v0alpha1/namespaces/org-B/snapshots/{key}` where `{key}` is a snapshot key belonging to Org-A. The K8s namespace scope does not enforce org isolation at the store layer.
- K8s API is registered unconditionally via the apiserver aggregation (register.go:787-808). The `kubernetesSnapshots` feature flag only controls REST-to-K8s routing, not K8s API availability.
- Preconditions: Authenticated user with ActionSnapshotsDelete, knowledge of target snapshot key (high entropy)
- Severity: MEDIUM -- cross-org deletion but requires high-entropy key knowledge and K8s API access

**H-03: Cloud Migration CancelSnapshot Cross-Org State Corruption**

Extends H-00d. The `CancelSnapshot(ctx, sessionUid, snapshotUid)` service interface at `cloudmigration.go:33` lacks orgID. The API handler at `api.go:615-641` does not pass `c.OrgID`. The SQL at `xorm_store.go:228` executes `UPDATE cloud_migration_snapshot SET status=? WHERE session_uid=? AND uid=?` without org filter.

- Attack: Admin in Org-B calls `POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/cancel` using session_uid and snapshot_uid belonging to Org-A. The cancellation succeeds cross-org because the WHERE clause has no org_id constraint.
- Beyond cancellation: the `cancelFunc()` at line 812 is a global singleton on the service. Calling cancel terminates the in-flight migration for ANY org, not just the caller's org.
- Preconditions: Admin access (ActionMigrationSnapshotCreate), knowledge of target session_uid and snapshot_uid (both UUIDs)
- Severity: MEDIUM -- cross-org DoS on migration operations, requires admin + UUID knowledge

**H-04: Auth Proxy Empty Whitelist -- Complete Authentication Bypass**

Extends H-00b. When `[auth.proxy] enabled = true` is set by the operator AND `whitelist = ` remains empty (the default), `isAllowedIP()` at `proxy.go:200-203` returns true for ALL IPs. Combined with PH-17, any network client can send `X-WEBAUTH-USER: admin` header and authenticate as any user including GrafanaAdmin.

- Attack: Attacker sends `GET /api/dashboards/home` with `X-WEBAUTH-USER: admin` header. The auth proxy client authenticates the request as the admin user. With `auto_sign_up = true` (default), the user is created if it doesn't exist.
- The auth proxy is disabled by default (`enabled = false`), so this requires explicit operator configuration. However, the empty whitelist default creates a security trap: operators enabling auth proxy without setting a whitelist get NO protection.
- Preconditions: Auth proxy enabled by operator, whitelist not configured (default empty)
- Severity: CRITICAL when misconfigured; overall HIGH due to non-default configuration requirement

**H-05: OAuth State CSRF with Default secret_key**

Extends H-00e. OAuth state hash = `SHA256(state + SecretKey + ClientSecret)`. On instances with default `SecretKey = SW2YcwTIb9zpOOhoPsMm`, the attacker needs the OAuth ClientSecret to forge the state hash. ClientSecret is typically confidential, but:
- It may be leaked via configuration management, log files, or browser dev tools
- Some OAuth providers return it in the redirect flow (non-standard)
- In internal deployments, the client_secret may be a shared organizational secret

- Attack: Attacker with knowledge of default SecretKey + ClientSecret crafts an OAuth login URL with forged state. Victim clicks the link and is authenticated with attacker's OAuth identity (login CSRF).
- Preconditions: Default secret_key unchanged, OAuth client_secret known to attacker
- Severity: MEDIUM -- login CSRF (not session hijack), requires knowledge of client_secret

**H-06: K8s Snapshot Standard DELETE Triggers SSRF via External Snapshot URL**

Chain: H-02 (cross-org K8s DELETE) + PH-15 (external snapshot SSRF). At `snapshot_legacy_store.go:69-73`, when deleting a snapshot via K8s DELETE, if the snapshot has `ExternalDeleteURL != ""`, the code calls `dashboardsnapshots.DeleteExternalDashboardSnapshot(snap.ExternalDeleteURL)` which performs an HTTP GET to the stored URL. The URL is controlled by the original snapshot creator.

- Attack: Attacker creates an external snapshot with `ExternalDeleteURL = http://169.254.169.254/latest/meta-data/iam/security-credentials/`. When any user (including cross-org via H-02) deletes this snapshot, the Grafana server makes an HTTP GET to the SSRF target.
- This is a stored SSRF -- the URL is persisted in the database and triggered by a different user's delete action.
- Preconditions: External snapshots enabled, attacker can create snapshot with arbitrary ExternalDeleteURL, victim deletes the snapshot
- Severity: MEDIUM -- stored blind SSRF (no response returned to attacker), requires external snapshot feature

**H-07: Enriched Findings EF-010/011/012 Duplicate Assessment**

EF-010 (Generic OAuth no sig verification) = same root cause as p7-004 (VALID, MEDIUM). The enriched finding adds no new code path or attack surface beyond what was already analyzed.

EF-011 (OIDC post-sig exp/iss/aud missing) = same root cause as p7-001 (VALID, MEDIUM). Already covers social_base.go:385-449.

EF-012 (JWT exp optional) = exact duplicate of p7-003 (VALID, MEDIUM). Already covers validation.go:55-136.

Recommendation: Mark all three as DUPLICATE.

---

## Round 2 -- Tracing

### [TRACER] Evidence for H-01 through H-07 -- 2026-03-21T10:15:00Z

**H-01 Trace: Snapshot RBAC Middleware Never Invoked**

EVIDENCE CONFIRMED -- REACHABLE

1. `pkg/middleware/auth.go:255-268`: `SnapshotPublicModeOrDelete` function body:
   ```
   func(c *contextmodel.ReqContext) {
       if cfg.SnapshotPublicMode { return }
       if !c.IsSignedIn { notAuthorized(c); return }
       ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))
       // ^^^ Returns web.Handler but never calls it with (c)
   }
   ```
   The expression `ac.Middleware(ac2)` returns `func(Evaluator) web.Handler`.
   Calling it with `(ac.EvalPermission(...))` returns `web.Handler` (i.e., `func(*contextmodel.ReqContext)`).
   This `web.Handler` value is DISCARDED -- never invoked with `(c)`.

2. `pkg/services/accesscontrol/middleware.go:30-40`: Confirms `Middleware` returns a curried function. The inner handler contains the actual RBAC evaluation at line 63 (`ok, err := ac.Evaluate(...)`) which is never reached.

3. `pkg/api/api.go:615`: Route definition: `r.Get("/api/snapshots-delete/:deleteKey", reqSnapshotPublicModeOrDelete, routing.Wrap(hs.DeleteDashboardSnapshotByDeleteKey))`

4. Same bug at line 249 for `SnapshotPublicModeOrCreate`:
   ```
   ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsCreate))
   // Also discarded
   ```
   Route: `api.go:610`: `r.Post("/api/snapshots/", reqSnapshotPublicModeOrCreate, hs.getCreatedSnapshotHandler())`

5. Attacker path: Any user with IsSignedIn=true (Viewer, Editor, Anonymous-with-anon-enabled) reaches `DeleteDashboardSnapshotByDeleteKey` without RBAC check.

6. `dashboard_snapshot.go:164-186`: The handler itself does NOT have a secondary RBAC check. It looks up the snapshot by deleteKey and calls `hs.dashboardsnapshotsService.DeleteDashboardSnapshot`.

7. For create (line 249): The handler `getCreatedSnapshotHandler` at `dashboard_snapshot.go:86-120` does have some authorization logic internally (checking OrgRole and SnapshotEnabled), but the RBAC permission `ActionSnapshotsCreate` is never evaluated.

**Verdict: REACHABLE -- confirmed RBAC bypass on delete path. Create path has partial internal checks but RBAC is still bypassed.**

---

**H-02 Trace: K8s Snapshot Delete Cross-Org**

EVIDENCE CONFIRMED -- REACHABLE

1. `routes.go:260-275`: The K8s delete-by-deleteKey handler:
   - Line 266: RBAC check `accessControl.Evaluate(ctx, user, ac.EvalPermission(dashboards.ActionSnapshotsDelete))` -- this is correctly evaluated (unlike H-01)
   - Line 275: `dashboardsnapshots.DeleteWithKey(ctx, key, service)` -- deletes by deleteKey

2. `service.go:222-240`: `DeleteWithKey` function:
   - Line 224: `query := &GetDashboardSnapshotQuery{DeleteKey: key}` -- NO org filter
   - Line 225: `GetDashboardSnapshot(ctx, query)` -- fetches by deleteKey only
   - NO comparison of `queryResult.OrgID` vs requester's orgID

3. `database.go:89-108`: `GetDashboardSnapshot` uses xorm `sess.Get(&snapshot)` with only Key or DeleteKey set -- no org_id in WHERE clause.

4. Contrast with legacy REST API at `dashboard_snapshot.go:218`: `if queryResult.OrgID != c.OrgID` -- this check IS present in the legacy path.

5. K8s API registration: `register.go:787-808` registers snapshot storage unconditionally. The `kubernetesSnapshots` feature flag (experimental, disabled by default, Expression: "false") only controls REST-to-K8s routing, NOT whether the K8s API endpoint is available.

6. The K8s endpoint at `/apis/dashboard.grafana.app/v0alpha1/namespaces/{namespace}/snapshots/delete/{deleteKey}` is accessible to authenticated users with ActionSnapshotsDelete.

7. The `snapshot_legacy_store.go:60-83` standard DELETE path also lacks org check.

**Verdict: REACHABLE -- confirmed cross-org deletion. Mitigated by: (a) high-entropy deleteKey (190 bits), (b) K8s API requires authentication + ActionSnapshotsDelete permission, (c) feature is experimental.**

---

**H-03 Trace: Cloud Migration CancelSnapshot Cross-Org**

EVIDENCE CONFIRMED -- REACHABLE

1. `cloudmigration.go:33`: `CancelSnapshot(ctx context.Context, sessionUid string, snapshotUid string) error` -- no orgID parameter.

2. `api.go:615-641`: API handler extracts `sessUid` and `snapshotUid` from URL params. Does NOT pass `c.OrgID` to service.

3. `cloudmigrationimpl/cloudmigration.go:796-824`: Service implementation calls `s.cancelFunc()` at line 812 -- this is a GLOBAL singleton cancel function. It cancels the in-flight migration for ANY org.

4. `xorm_store.go:228`: `UPDATE cloud_migration_snapshot SET status=? WHERE session_uid=? AND uid=?` -- no org_id filter.

5. API route registration at `api.go:68`: `cloudMigrationRoute.Post("/migration/:uid/snapshot/:snapshotUid/cancel", routing.Wrap(cma.CancelSnapshot))`

6. Route group requires `ActionMigrationSnapshotCreate` permission (admin-level).

7. UUIDs are not guessable, but `sessionUid` and `snapshotUid` may be obtained via other API endpoints or log files.

**Verdict: REACHABLE -- confirmed cross-org cancel. Mitigated by: (a) admin-only access, (b) UUID knowledge required, (c) cloud migration is a non-default feature.**

---

**H-04 Trace: Auth Proxy Empty Whitelist**

EVIDENCE CONFIRMED -- REACHABLE

1. `proxy.go:200-203`: `isAllowedIP` returns true when `len(c.acceptedIPs) == 0`.

2. `conf/defaults.ini:962-968`: Auth proxy defaults: `enabled = false`, `whitelist = ` (empty).

3. `proxy.go:76-113`: `Authenticate` function flow:
   - Line 79: `if !c.isAllowedIP(r)` -- passes when whitelist empty
   - Line 83: `getProxyHeader(r, c.cfg.AuthProxy.HeaderName, ...)` -- reads `X-WEBAUTH-USER` header
   - Line 105: `proxyClient.AuthenticateProxy(ctx, r, username, additional)` -- authenticates as the header-specified user
   - Line 106-108: Returns identity on success

4. `proxy.go:115-116`: `IsEnabled` returns `c.cfg.AuthProxy.Enabled` -- must be explicitly enabled.

5. No URL validation, no HMAC, no additional secret -- the header value alone determines the authenticated identity.

**Verdict: REACHABLE -- but requires non-default configuration (auth proxy enabled). The empty whitelist default creates a security trap. Auth proxy is disabled by default.**

---

**H-05 Trace: OAuth State CSRF**

EVIDENCE CONFIRMED -- PARTIAL

1. `oauth.go:279`: `state, hashedState, err := genOAuthState(c.cfg.SecretKey, oauthCfg.ClientSecret)`

2. `oauth.go:363-374`: State hash is `SHA256(state + SecretKey + ClientSecret)`.

3. `conf/defaults.ini:387`: `secret_key = SW2YcwTIb9zpOOhoPsMm`.

4. Forgery requires BOTH SecretKey (known default) AND ClientSecret (typically confidential).

5. The state parameter is generated with 32 bytes of `crypto/rand` (line 364), but the hash verification at the callback only validates `hashOAuthState(state, secret, seed) == storedHash`. Forgery means pre-computing the hash for a chosen state value.

6. Impact: Login CSRF -- forces victim to authenticate with attacker's OAuth account. This is a medium-severity issue (not full account takeover).

**Verdict: PARTIAL -- technically forgeable with default SecretKey, but requires ClientSecret knowledge. Login CSRF only (not session hijack).**

---

**H-06 Trace: K8s DELETE Triggers SSRF**

EVIDENCE CONFIRMED -- REACHABLE (CHAIN)

1. `snapshot_legacy_store.go:69-73`: `if snap.ExternalDeleteURL != "" { err := dashboardsnapshots.DeleteExternalDashboardSnapshot(snap.ExternalDeleteURL) }`

2. `service.go:149-179`: `DeleteExternalDashboardSnapshot(externalUrl)` performs `client.Get(externalUrl)` with no URL validation.

3. Chain: H-02 (cross-org delete) enables triggering the SSRF from a different org.

4. The ExternalDeleteURL is set at snapshot creation time and stored in the database.

5. The SSRF is blind -- the HTTP GET response is not returned to the attacker.

**Verdict: REACHABLE but CHAINED -- requires H-02 + external snapshots. Blind SSRF with high preconditions.**

---

**H-07 Trace: Duplicate Assessment**

EF-010, EF-011, EF-012 confirmed as duplicates of p7-001, p7-003, p7-004 respectively.

**Verdict: DUPLICATE**

---

## Round 3 -- Challenge

### [ADVOCATE] Defense Briefs -- 2026-03-21T10:25:00Z

**H-01 Defense Brief: Snapshot RBAC Middleware**

Layer 1 -- Framework Protection: No framework-level RBAC enforcement for this specific middleware pattern. The `ac.Middleware` function is designed to be used differently -- as a route middleware via `authorize()`, not as an inline call.

Layer 2 -- Configuration: No configuration mitigates this bug. If `SnapshotPublicMode = false` (default), the RBAC bypass is active.

Layer 3 -- Input Validation: The deleteKey parameter is validated only as a URL path segment. No additional authentication check.

Layer 4 -- Handler-Level Protection: The `DeleteDashboardSnapshotByDeleteKey` handler at `dashboard_snapshot.go:164-186` does NOT have a redundant RBAC check. It relies entirely on the middleware. However, the handler does check: (a) `queryResult.OrgID != c.OrgID` at line 218 -- this is NOT in the deleteKey path, it is in a different handler. Let me re-check.

Actually, looking at `dashboard_snapshot.go` more carefully:
- `DeleteDashboardSnapshotByDeleteKey` (line 164) is the handler for the deleteKey endpoint. It calls `dashboardsnapshots.DeleteWithKey(ctx, key, svc)` at line 175 -- which does NOT check org.
- The org check at line 218 is in `DeleteDashboardSnapshot` (a different handler for `DELETE /api/snapshots/:key`).

So the deleteKey handler has NO org check AND the RBAC middleware is not invoked.

Layer 5 -- Network/Deployment: No network-level protection. The endpoint is on the standard Grafana port.

**Conclusion: NO blocking protection found. The RBAC bypass is real.**

Note on Create path (line 249): The `getCreatedSnapshotHandler` does have internal checks:
- Checks `hs.Cfg.SnapshotEnabled` (default true)
- Checks if external snapshots are allowed
- But does NOT check ActionSnapshotsCreate permission

The RBAC bypass for create has lower impact because snapshot creation is typically a benign operation, but it still violates the permission model.

---

**H-02 Defense Brief: K8s Snapshot Cross-Org Delete**

Layer 1 -- K8s Namespace Scoping: K8s namespaces are used for org isolation. However, the `SnapshotLegacyStore.Delete()` at `snapshot_legacy_store.go:60-83` does NOT filter by the namespace-derived orgID. The namespace is used for API routing but not enforced at the store level.

Layer 2 -- RBAC: The routes.go handler at line 266 correctly evaluates `ActionSnapshotsDelete`. This means the attacker needs snapshot delete permission in their own org.

Layer 3 -- Key Entropy: The snapshot key (used as the K8s resource name) is a high-entropy string. Discovery requires: (a) API list access (which IS org-scoped at `snapshot_legacy_store.go:85-95`), (b) log file access, (c) shared URL, (d) brute force (impractical for 190-bit keys).

Layer 4 -- Feature Flag: `kubernetesSnapshots` is experimental/disabled. The K8s API is registered unconditionally, but direct K8s API access requires knowing the API path and having authentication.

Layer 5 -- Practical Impact: Snapshot deletion is a DoS-only impact (no data exfiltration). The deleted snapshot content is lost.

**Conclusion: Real vulnerability but with high preconditions (key knowledge). Practical severity is MEDIUM, not HIGH.**

---

**H-03 Defense Brief: Cloud Migration CancelSnapshot**

Layer 1 -- RBAC: Requires `ActionMigrationSnapshotCreate` which maps to admin-only.

Layer 2 -- UUID Guessability: Both sessionUid and snapshotUid are UUIDs (v4, 122 bits of entropy). Not guessable. Would need: (a) API access to list sessions (which IS org-scoped), (b) log leakage, (c) network interception.

Layer 3 -- Feature Availability: Cloud migration is an enterprise/cloud feature. Not available in OSS Grafana.

Layer 4 -- Impact: CancelSnapshot only changes snapshot status to "canceled" and calls the global cancelFunc. The cancel terminates in-flight upload but does not delete data or expose credentials. The impact is DoS on migration operations.

Layer 5 -- Global cancelFunc: The `s.cancelFunc()` is indeed global -- but in practice, only one migration can run at a time. The race window is very narrow.

**Conclusion: Real vulnerability but extremely high preconditions (admin + UUID + enterprise feature + timing window). Recommend MEDIUM or lower.**

---

**H-04 Defense Brief: Auth Proxy Empty Whitelist**

Layer 1 -- Default Configuration: Auth proxy is disabled by default (`enabled = false`). The vulnerability requires explicit operator action to enable.

Layer 2 -- Documentation: Grafana documentation explicitly recommends configuring the whitelist when using auth proxy. The empty default is documented behavior.

Layer 3 -- Deployment Context: Auth proxy is designed for use behind a reverse proxy that sets the header. In standard deployments, the reverse proxy is the only client that can set the header, and external requests with the header are stripped by the reverse proxy.

Layer 4 -- IP Restriction Alternative: Operators can use network-level firewall rules to restrict access to the Grafana port.

Layer 5 -- Counter-argument: The empty whitelist default is a security trap. An operator following the "minimum configuration" approach (only setting `enabled = true` and `header_name`) gets zero protection. The secure default should be to require whitelist configuration.

**Conclusion: The vulnerability IS real when auth proxy is enabled without whitelist. However, auth proxy is disabled by default and the attack requires specific misconfiguration. This is a "security trap" design issue, not a direct vulnerability. Severity should be HIGH (not CRITICAL) due to the non-default requirement.**

---

**H-05 Defense Brief: OAuth State CSRF**

Layer 1 -- ClientSecret Requirement: The forgery requires knowledge of the OAuth ClientSecret, which is a confidential credential stored in the Grafana configuration. This is a significant barrier.

Layer 2 -- SameSite Cookie: Grafana session cookies are SameSite=Lax by default. This prevents cross-site POST-initiated OAuth flows from carrying session cookies, limiting CSRF exploitation.

Layer 3 -- Login CSRF Impact: Even if successful, login CSRF only forces the victim to authenticate with the attacker's OAuth account. The impact is limited to: session riding (attacker monitors victim's actions under attacker's account). This does not steal the victim's credentials or data.

Layer 4 -- Default SecretKey: The default SecretKey issue is already covered by p7-064 (secrets manager default key) and p7-065 (session token default key). The OAuth state forgery is a variant of the "default secret_key" pattern.

Layer 5 -- State Nonce: Even with a forged hash, the attacker needs to predict or control the random state nonce (32 bytes of crypto/rand). The state is set in the session cookie before redirect and must match on callback. The attacker would need to set their own state cookie in the victim's browser, which requires a separate same-site write gadget.

**Conclusion: Multiple blocking protections exist. The ClientSecret requirement alone is nearly blocking. Combined with SameSite=Lax and the limited login CSRF impact, this is LOW to MEDIUM at best. Recommend DROP or MEDIUM.**

---

**H-06 Defense Brief: K8s DELETE SSRF Chain**

Layer 1 -- Chain Preconditions: Requires H-02 (cross-org delete, needs key knowledge) + external snapshots enabled + attacker-created external snapshot with malicious URL.

Layer 2 -- Blind SSRF: The HTTP GET response is not returned to the attacker. Only blind SSRF (useful for internal network scanning or IMDS credential theft on cloud deployments).

Layer 3 -- External Snapshot Creation: Creating an external snapshot requires: (a) authentication, (b) external snapshot endpoint configured, (c) the ExternalDeleteURL is set by the external snapshot server response, not directly by the attacker. The attacker would need to compromise the external snapshot server to control the URL.

Layer 4 -- Existing Coverage: The external snapshot SSRF pattern was already identified in PH-15/PH-16 of the snapshot probe. The cross-org amplification adds marginal additional risk.

**Conclusion: Too many preconditions for independent finding. The blind SSRF via external snapshot URL is real but low-impact due to (a) blind nature, (b) attacker cannot directly control ExternalDeleteURL, (c) requires external snapshot infrastructure compromise. Recommend DROP or consolidate with H-02.**

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-03-21T10:35:00Z

**Prosecution summary**: The Tracer confirmed that `ac.Middleware(ac2)(ac.EvalPermission(dashboards.ActionSnapshotsDelete))` at `auth.go:266` constructs a web.Handler that is immediately discarded without invoking it with `(c)`. The RBAC evaluation at `middleware.go:63` is never reached. Any user with `IsSignedIn=true` can call `GET /api/snapshots-delete/:deleteKey` and delete snapshots without `ActionSnapshotsDelete` permission. The handler at `dashboard_snapshot.go:164` has no redundant RBAC check.

**Defense summary**: The Advocate found NO blocking protections. No framework protection, no handler-level RBAC check, no configuration mitigation. The same bug exists at line 249 for the create middleware.

**Pre-FP Gate**:
1. Attacker control verified: YES -- authenticated user controls deleteKey URL parameter
2. Framework protection searched (all 5 layers): YES -- none found
3. Trust boundary crossing confirmed: YES -- RBAC boundary bypassed (Viewer gains Admin-level snapshot delete)
4. Normal attacker position: YES -- any authenticated Viewer
5. Ships to production: YES -- auth.go and api.go are production code

**Pre-FP Gate: all checks passed**

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: The RBAC middleware for snapshot delete is architecturally present but never invoked due to a Go expression evaluation bug -- the returned web.Handler is discarded without calling it with `(c)`. Any authenticated Viewer can delete snapshots via the REST API deleteKey endpoint, bypassing the ActionSnapshotsDelete permission requirement. No blocking protections exist.

**Finding draft written to**: security/findings-draft/p8-001-snapshot-rbac-middleware-never-invoked.md
**Note**: Overlaps with p8-042 from Chamber 3 (same root cause, this version is more detailed with HIGH severity vs MEDIUM). Consolidation needed at Phase 10.
**Registry updated**: AP-042 updated (existing pattern, confirmed instances updated)

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-03-21T10:36:00Z

**Prosecution summary**: The Tracer confirmed that the K8s API `Delete()` at `snapshot_legacy_store.go:60-83` and `DeleteWithKey()` at `routes.go:275` both lack the `queryResult.OrgID != c.OrgID` check present in the legacy REST API at `dashboard_snapshot.go:218`. The `GetDashboardSnapshot` query at `database.go:89-108` uses only `Key` or `DeleteKey` with no org filter. Cross-org deletion is possible with key knowledge.

**Defense summary**: The Advocate correctly identified high-entropy key requirement, experimental feature flag, and DoS-only impact as mitigating factors. RBAC check is correctly evaluated (unlike H-01). The K8s API is registered unconditionally but requires authentication.

**Pre-FP Gate**:
1. Attacker control verified: YES -- user controls the deleteKey/name URL parameter
2. Framework protection searched: YES -- K8s namespace scoping does NOT enforce org at store level
3. Trust boundary crossing: YES -- org isolation boundary crossed
4. Normal attacker position: YES -- authenticated user with snapshot delete permission
5. Ships to production: YES -- snapshot_legacy_store.go is production code (K8s API registered unconditionally)

**Pre-FP Gate: all checks passed**

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Cross-org snapshot deletion via K8s API is confirmed -- the CVE-2024-1313 fix was applied to the legacy REST API but not ported to the K8s API path. Practical exploitability is reduced by high-entropy key requirement (190 bits) and the need for K8s API access. Impact is DoS-only (snapshot data loss). Downgraded from HIGH to MEDIUM per severity calibration.

**Finding draft written to**: security/findings-draft/p8-002-k8s-snapshot-cross-org-delete.md
**Registry updated**: AP-002 K8s Store Missing Org Filter

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-03-21T10:37:00Z

**Prosecution summary**: The Tracer confirmed that `CancelSnapshot` at `cloudmigration.go:33` lacks orgID, the SQL at `xorm_store.go:228` has no org_id constraint, and the global `cancelFunc()` terminates any in-flight migration regardless of org.

**Defense summary**: The Advocate identified strong mitigating factors: admin-only access, UUID non-guessability, cloud/enterprise-only feature, and DoS-only impact (no data exfiltration).

**Pre-FP Gate**:
1. Attacker control verified: YES -- admin controls sessionUid and snapshotUid URL parameters
2. Framework protection searched: YES -- RBAC requires admin, but org isolation missing
3. Trust boundary crossing: YES -- org isolation boundary crossed
4. Normal attacker position: PARTIAL -- requires Admin role (not normal attacker for most threat models)
5. Ships to production: YES -- cloud migration service is production code

**Pre-FP Gate: check-4 ambiguous -- admin-only requirement is significant precondition**

The Admin-only requirement is a significant precondition. In multi-tenant Grafana deployments, each org has its own admins who are mutually untrusted. The cross-org cancel is a real vulnerability in this threat model.

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Cross-org migration snapshot cancellation is confirmed via missing orgID in the CancelSnapshot service interface and SQL UPDATE. The global cancelFunc enables DoS on any in-flight migration. Severity is MEDIUM due to admin-only requirement, UUID knowledge prerequisite, and cloud/enterprise-only feature availability.

**Finding draft written to**: security/findings-draft/p8-003-cloud-migration-cancel-cross-org.md
**Registry updated**: AP-003 Service Interface Missing OrgID Parameter

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-03-21T10:38:00Z

**Prosecution summary**: The Tracer confirmed that `isAllowedIP()` returns true for all IPs when the whitelist is empty (default), and `getProxyHeader` reads the configured auth header without additional validation. When auth proxy is enabled without a whitelist, any network client can authenticate as any user.

**Defense summary**: The Advocate correctly noted that auth proxy is disabled by default, documentation recommends whitelist configuration, and the intended deployment model assumes a trusted reverse proxy. However, the Advocate acknowledged that the empty whitelist default creates a "security trap" for operators following minimum configuration.

**Pre-FP Gate**:
1. Attacker control verified: YES -- attacker controls the X-WEBAUTH-USER header value
2. Framework protection searched: YES -- no protection beyond the whitelist (which is empty by default)
3. Trust boundary crossing: YES -- authentication boundary completely bypassed
4. Normal attacker position: YES -- any network client (when misconfigured)
5. Ships to production: YES -- proxy.go is production code

**Pre-FP Gate: all checks passed**

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: When auth proxy is explicitly enabled without configuring the IP whitelist (which defaults to empty), any network client can impersonate any user including GrafanaAdmin via the auth proxy header. This is a complete authentication bypass. Severity is HIGH rather than CRITICAL because auth proxy is disabled by default (requires explicit operator misconfiguration). The empty whitelist default is a dangerous security trap.

**Finding draft written to**: security/findings-draft/p8-004-auth-proxy-empty-whitelist-bypass.md
**Registry updated**: AP-004 Empty Allowlist Defaults to Allow-All

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-03-21T10:39:00Z

**Prosecution summary**: The Tracer confirmed that OAuth state hash uses the default SecretKey `SW2YcwTIb9zpOOhoPsMm` and the ClientSecret as inputs. With knowledge of both, the state hash can be forged.

**Defense summary**: The Advocate identified multiple blocking protections: (a) ClientSecret knowledge required (typically confidential), (b) SameSite=Lax cookies limit CSRF, (c) login CSRF impact only (not account takeover), (d) the state nonce is random and set in session cookie. The Advocate also noted this is a variant of the already-covered default secret_key pattern.

**Pre-FP Gate**:
1. Attacker control verified: PARTIAL -- requires knowledge of ClientSecret
2. Framework protection searched: YES -- SameSite=Lax provides partial protection
3. Trust boundary crossing: YES -- OAuth CSRF protection bypassed
4. Normal attacker position: NO -- requires client_secret knowledge (privileged position)
5. Ships to production: YES

**Pre-FP Gate: failed on check-4: requires ClientSecret knowledge which is not a normal attacker position**

**Verdict: DROP**
**Severity: --**
**Rationale**: OAuth state CSRF forgery requires knowledge of both the default SecretKey and the OAuth ClientSecret. The ClientSecret is a confidential credential that an external attacker would not normally possess. Combined with SameSite=Lax cookie protection and the limited impact of login CSRF (not account takeover), the overall risk is LOW. Additionally, the default SecretKey issue is already covered by prior findings p7-064 and p7-065. Dropped per policy (Low severity equivalent).

**Finding draft written to**: --
**Registry updated**: no new pattern (variant of default secret_key, already in p7-064/p7-065)

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-03-21T10:40:00Z

**Prosecution summary**: The Tracer confirmed the chain: K8s DELETE triggers SSRF via ExternalDeleteURL. The SSRF is blind (no response returned).

**Defense summary**: The Advocate identified multiple blocking factors: (a) requires H-02 preconditions (key knowledge), (b) ExternalDeleteURL is set by the external snapshot server, not directly controllable by the attacker, (c) blind SSRF only, (d) requires external snapshot infrastructure compromise.

**Pre-FP Gate**:
1. Attacker control verified: NO -- ExternalDeleteURL is set by the external snapshot server response, not directly by the attacker
2. Framework protection searched: YES
3. Trust boundary crossing: YES (if reachable)
4. Normal attacker position: NO -- requires compromising external snapshot server
5. Ships to production: YES

**Pre-FP Gate: failed on check-1: attacker does not directly control ExternalDeleteURL**

**Verdict: DROP**
**Severity: --**
**Rationale**: The SSRF chain requires compromising the external snapshot server to control ExternalDeleteURL, plus H-02 preconditions. The attacker does not directly control the SSRF target URL. This is a theoretical chain with too many preconditions for a standalone finding. The external snapshot SSRF pattern is already noted in probe PH-15/PH-16.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-03-21T10:41:00Z

**Prosecution summary**: N/A -- these are duplicate assessments.

**Defense summary**: N/A.

**Pre-FP Gate**: N/A

**Verdict: DUPLICATE**
**Severity: --**
**Rationale**: EF-010 = p7-004, EF-011 = p7-001, EF-012 = p7-003. All three are exact duplicates of Phase 7 findings already confirmed as VALID MEDIUM.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 | VALID | HIGH | p8-001-snapshot-rbac-middleware-never-invoked.md |
| H-02 | VALID | MEDIUM | p8-002-k8s-snapshot-cross-org-delete.md |
| H-03 | VALID | MEDIUM | p8-003-cloud-migration-cancel-cross-org.md |
| H-04 | VALID | HIGH | p8-004-auth-proxy-empty-whitelist-bypass.md |
| H-05 | DROP | -- | -- |
| H-06 | DROP | -- | -- |
| H-07 | DUPLICATE | -- | -- (EF-010/011/012 = p7-001/003/004) |

Findings written: 4
Patterns added to registry: 4
Variant candidates: 0

Chamber closed: 2026-03-21T10:45:00Z
