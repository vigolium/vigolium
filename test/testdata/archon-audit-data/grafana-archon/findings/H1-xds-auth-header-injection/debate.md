# Review Chamber: chamber-1

Cluster: Data Exposure & Credential Leak
DFD Slices: DFD-2 (Datasource Proxy), DFD-3 (Public Dashboard Exposure), DFD-10 (Query History)
NNN Range: p8-001 to p8-019
Started: 2026-04-11T10:00:00Z
Status: CLOSED

---

## Pre-seeded Hypotheses from Deep Probe

The following hypotheses were validated by probe teams and are pre-seeded for this chamber.

### H-00a: X-DS-Authorization Header Injection (Probe Team 02, PH-C01)
- Source: ds_proxy.go:230-234
- Any authenticated user overrides backend datasource credentials via X-DS-Authorization header
- Pre-traced evidence: director function reads header and sets Authorization, no stripping in pipeline
- Severity estimate: HIGH

### H-00b: Public Dashboard DS_ACCESS_DIRECT Credential Exposure (Probe Teams 02+03)
- Source: frontendsettings.go:541-577
- Unauthenticated public dashboard viewers receive decrypted BasicAuth credentials for direct-mode datasources
- Severity estimate: HIGH (CVE-2026-27877 residual)

### H-00c: CVE-2026-27877 Bypass via Template Variable Datasource UIDs (Probe Team 03)
- Source: ds_lookup.go:129, frontendsettings.go:851-853
- Template variable of type "datasource" with direct-mode DS UID bypasses the fix filter
- Severity estimate: HIGH

### H-00d: directUrl Exposed via simplejson Map Reference (Probe Team 02)
- Source: frontendsettings.go:538,596
- Internal Prometheus URL leaked to public dashboard viewers via shared map reference
- Severity estimate: MEDIUM

### H-00e: OAuthPassThru + SSRF Token Theft Chain (Probe Team 02)
- Source: ds_proxy.go:266-275
- Org admin creates datasource pointing to attacker URL with oauthPassThru=true, steals OAuth tokens
- Severity estimate: HIGH

### H-00f: ListPublicDashboards Token Enumeration (Probe Team 03)
- Source: publicdashboards/api/api.go:82,113
- Any authenticated Viewer can list all org public dashboard access tokens
- Severity estimate: MEDIUM

### H-00g: Tag Annotation Org-Wide Scope (Probe Team 03)
- Source: publicdashboards/service/query.go:61-65
- Tag-based annotations in public dashboards query org-wide, exposing private dashboard annotations
- Severity estimate: MEDIUM

---

## Round 1 -- Ideation

### [IDEATOR] Hypothesis Generation -- 2026-04-11T10:05:00Z

Based on pre-seeded probes and SAST findings F-002, F-004, F-013, F-014, F-018, F-022, the following 7 hypotheses are prioritized for this chamber (Data Exposure & Credential Leak). Two lower-priority hypotheses (H-00h hidden query execution, H-00i roleAuthorizer watch verb) are deferred to their respective chambers as they cross cluster boundaries.

**H-01: X-DS-Authorization Header Injection** (from H-00a)
- Attack: Authenticated user with datasources:query sends `X-DS-Authorization: Bearer <attacker-token>` to `/api/datasources/proxy/uid/<uid>/*`. The director function at ds_proxy.go:230-234 reads this header and overwrites the stored datasource Authorization header.
- Impact: Cross-tenant data access at the backend datasource level in multi-tenant environments (shared Prometheus/Loki).

**H-02: Public Dashboard DS_ACCESS_DIRECT Credential Exposure** (from H-00b, SAST F-002)
- Attack: Unauthenticated user accesses public dashboard with direct-mode datasource. `GET /api/frontend/settings` returns decrypted BasicAuth password and plaintext InfluxDB passwords.
- Impact: Unauthenticated credential disclosure; direct access to production datasources.

**H-03: CVE-2026-27877 Bypass via Template Variable Datasource UIDs** (from H-00c)
- Attack: Dashboard editor adds a datasource-type template variable with `current.value` = UID of a direct-mode datasource. Public dashboard filter is bypassed because `ByRef` fallback returns the ref even when the empty lookup map has no entries.
- Impact: Extends H-02 to datasources not directly queried by dashboard panels.

**H-04: directUrl Exposure in Public Dashboard Context** (from H-00d)
- Attack: Unauthenticated public dashboard viewer receives internal Prometheus URL in `jsonData.directUrl` field because `ds.JsonData.Set("directUrl", ds.URL)` modifies the same map returned by `MustMap()`.
- Impact: Information disclosure of internal network topology.

**H-05: OAuthPassThru Token Theft via Malicious Datasource** (from H-00e)
- Attack: Org admin creates datasource with `url: "https://attacker.example.com"` and `oauthPassThru: true`. OAuth tokens of all querying users are forwarded to attacker server.
- Impact: OAuth access token and ID token theft; account takeover in external systems.

**H-06: ListPublicDashboards Access Token Enumeration** (from H-00f)
- Attack: Authenticated Viewer calls `GET /api/dashboards/public-dashboards`. Route is gated by `middleware.ReqSignedIn` only (no RBAC). Response includes `accessToken` field for all org public dashboards.
- Impact: Enables H-02 exploitation chain -- Viewer enumerates tokens, then uses them to access credential-leaking public dashboards.

**H-07: Tag Annotation Org-Wide Scope in Public Dashboards** (from H-00g)
- Attack: Unauthenticated visitor to public dashboard with tag-based annotations. `DashboardID=0` and `DashboardUID=""` cause query to return annotations from ALL org dashboards matching tags.
- Impact: Cross-dashboard information disclosure of operational annotations.

---

## Round 2 -- Tracing

### [TRACER] Evidence Trace -- 2026-04-11T10:15:00Z

#### H-01: X-DS-Authorization Header Injection

**Path**: `pkg/api/pluginproxy/ds_proxy.go`
1. Authenticated request hits `/api/datasources/proxy/uid/<uid>/*`
2. `proxyDatasourceRequest` at line ~91 calls `NewReverseProxy` → `wrapDirector` → `director`
3. `director` at line 220-228: if `ds.BasicAuth`, sets `Authorization` header from stored credentials
4. Lines 230-234: reads `X-DS-Authorization` from the INBOUND request, deletes it, then OVERWRITES `Authorization`:
   ```go
   dsAuth := req.Header.Get("X-DS-Authorization")
   if len(dsAuth) > 0 {
       req.Header.Del("X-DS-Authorization")
       req.Header.Set("Authorization", dsAuth)
   }
   ```
5. Checked `GetAuthHTTPHeaders` at `contexthandler.go:220-244` -- strips `Authorization`, `X-Grafana-Device-Id`, JWT header, proxy headers. Does NOT strip `X-DS-Authorization`.
6. No other middleware strips `X-DS-Authorization` from inbound requests.

**Verdict: REACHABLE** -- confirmed. Attacker-controlled header directly overwrites datasource credentials on the outbound request.

#### H-02: Public Dashboard DS_ACCESS_DIRECT Credential Exposure

**Path**: `pkg/api/frontendsettings.go`
1. `IsPublicDashboardView()` check at line 476 correctly filters datasource selection
2. Lines 541-577: Inside `for _, ds := range orgDataSources` loop (which includes public-dashboard-filtered DSes)
3. `if ds.Access == DS_ACCESS_DIRECT` at line 541 -- NO `!c.IsPublicDashboardView()` guard
4. Line 543: `DecryptedBasicAuthPassword` called, base64-encoded into `dsDTO.BasicAuth`
5. Lines 557-576: For InfluxDB types, `DecryptedPassword` returns PLAINTEXT password into `dsDTO.Password`
6. These fields are serialized directly into the JSON response returned to the unauthenticated caller

**Verdict: REACHABLE** -- confirmed. Decrypted credentials returned to unauthenticated callers for any direct-mode datasource used by a public dashboard.

#### H-03: CVE-2026-27877 Bypass via Template Variable Datasource UIDs

**Path**: `pkg/services/store/kind/dashboard/ds_lookup.go`
1. `publicDashFilterUsedDataSources` calls `ReadDashboard` which parses template variables
2. `getDsRefsByTemplateVariableValue` extracts UIDs from template variable `current.value`
3. `DsLookup.ByRef` at line 129: when UID not found in the empty `byUID` map, returns `ref` (the original ref) as fallback
4. This adds the template-variable-referenced DS UID to the `usedUIDs` set
5. The direct-mode DS passes the filter and its credentials are included per H-02

**Verdict: REACHABLE** -- confirmed. The empty lookup fallback defeats the CVE-2026-27877 fix.

#### H-04: directUrl Exposure in Public Dashboard Context

**Path**: `pkg/api/frontendsettings.go`
1. Line 538: `dsDTO.JSONData = ds.JsonData.MustMap()` -- returns REFERENCE to underlying map (simplejson behavior)
2. Line 594-596: `ds.JsonData.Set("directUrl", ds.URL)` -- modifies the SAME underlying map via simplejson's `.data` pointer
3. Since `dsDTO.JSONData` was set from `MustMap()` which returns the same backing map, `directUrl` appears in the DTO
4. No `IsPublicDashboardView()` guard around the `directUrl` assignment
5. Internal URL like `http://prometheus.internal:9090` returned to unauthenticated viewer

**Verdict: REACHABLE** -- confirmed. Shared map reference causes internal URL leakage.

#### H-05: OAuthPassThru Token Theft

**Path**: `pkg/api/pluginproxy/ds_proxy.go`
1. Line 266: `IsOAuthPassThruEnabled(proxy.ds)` checks `jsonData.oauthPassThru` (admin-controlled per DS)
2. Line 267: `GetCurrentOAuthToken(req.Context(), proxy.ctx.SignedInUser, proxy.ctx.UserToken)` retrieves the QUERYING user's OAuth token
3. Line 268: Sets `Authorization: Bearer <token>` on the OUTBOUND request to `ds.URL`
4. Lines 270-273: Also forwards `X-ID-Token` (OIDC identity token)
5. `OSSDataSourceRequestValidator.Validate` at `pkg/services/validations/oss.go:11` is a NO-OP (returns nil)
6. `checkWhiteList` at line 402: `DataProxyWhiteList` is empty by default (`setting.go:1925`)
7. `datasource.ValidateURL` only checks URL format, not destination IP

**Verdict: REACHABLE** -- confirmed. Requires org admin to create/modify datasource. OAuth tokens forwarded to attacker-controlled URL.

#### H-06: ListPublicDashboards Access Token Enumeration

**Path**: `pkg/services/publicdashboards/api/api.go`
1. Line 82: Route `GET /api/dashboards/public-dashboards` gated by `middleware.ReqSignedIn` only
2. No `accesscontrol.EvalPermission()` wrapper (compare with GetPublicDashboard at line 85 which has scope check)
3. Handler at line 113 calls `FindAllWithPagination` which queries: `SELECT uid, access_token, dashboard_uid, is_enabled FROM dashboard_public WHERE org_id = ?`
4. `PublicDashboardListResponse` struct at models.go:116-118: `AccessToken string \`json:"accessToken"\`` -- explicitly serialized
5. Any Viewer in the org gets ALL access tokens

**Verdict: REACHABLE** -- confirmed. Missing RBAC check; access tokens exposed to all org members.

#### H-07: Tag Annotation Org-Wide Scope

**Path**: `pkg/services/publicdashboards/service/query.go`
1. Lines 61-64: For tag-type annotations, sets `DashboardID = 0` and `DashboardUID = ""`
2. Line 64: `Tags` from the annotation config are set on the query
3. Line 68: `AnnotationsRepo.Find(svcCtx, annoQuery)` with service identity (org-level access)
4. With `DashboardID=0`, the annotation repository returns matches from ALL dashboards in the org
5. Annotation text, tags, timestamps, and panel IDs returned to unauthenticated viewers

**Verdict: REACHABLE** -- confirmed. Tag annotations intentionally remove dashboard scope, but this behavior is exposed to unauthenticated users.

---

## Round 3 -- Challenge

### [ADVOCATE] Defense Briefs -- 2026-04-11T10:30:00Z

#### H-01 Defense Brief: X-DS-Authorization Header Injection

**Layer 1 - Authentication**: Requires authenticated user with `datasources:query` permission. NOT unauthenticated.
**Layer 2 - Authorization/RBAC**: The user must have `datasources:query` permission to reach the proxy endpoint at all.
**Layer 3 - Input Validation**: No validation or stripping of `X-DS-Authorization` found anywhere in the request pipeline. Searched: `wrapDirector`, `GetAuthHTTPHeaders`, `AuthHTTPHeaderListFromContext`, all middleware in `pkg/middleware/`. NONE strip this header.
**Layer 4 - Network/Infrastructure**: Could be mitigated by a reverse proxy stripping `X-DS-Authorization`, but this is not a Grafana-level control.
**Layer 5 - Framework Protection**: No framework-level protection found.
**FP Pattern Match**: Not a false positive -- the code explicitly reads and uses the header to override credentials.
**Conclusion**: No blocking protection found. The only requirement is standard authentication with datasources:query (Viewer role by default).

#### H-02 Defense Brief: Public Dashboard DS_ACCESS_DIRECT Credential Exposure

**Layer 1 - Authentication**: No authentication required -- public dashboard access token only.
**Layer 2 - Authorization/RBAC**: `IsPublicDashboardView()` filters datasource LIST but not credential EXTRACTION.
**Layer 3 - Input Validation**: N/A -- no user input drives this; the credentials are unconditionally included.
**Layer 4 - Network/Infrastructure**: DS_ACCESS_DIRECT is a legitimate configuration mode for direct browser-to-datasource communication.
**Layer 5 - Framework Protection**: The CVE-2026-27877 fix (commit `0e5d9e01ef3`) addresses datasource ENUMERATION but not credential SUPPRESSION for remaining datasources.
**FP Pattern Match**: Not a false positive -- residual of partially patched CVE.
**Mitigating Factor**: Requires at least one direct-mode datasource to be used by a public dashboard. Direct mode is less common than proxy mode.
**Conclusion**: No blocking protection for credential extraction in direct-mode public dashboards.

#### H-03 Defense Brief: CVE-2026-27877 Bypass via Template Variables

**Layer 1-5**: Same as H-02 plus:
**Layer 3 - Input Validation**: The `CreateDatasourceLookup` with empty slice was INTENDED to prevent resolution, but `ByRef` fallback at ds_lookup.go:129 defeats this intent. Searched for any secondary validation -- none found.
**Mitigating Factor**: Requires a dashboard editor to add a datasource-type template variable referencing the target DS UID. However, dashboard editors are a standard threat actor.
**Conclusion**: The fix bypass is confirmed. No secondary protection found.

#### H-04 Defense Brief: directUrl Exposure

**Layer 1 - Authentication**: No authentication required for public dashboard viewers.
**Layer 3 - Input Validation**: No guard around `directUrl` assignment for public dashboard context.
**Mitigating Factor**: Exposes URL only (no credentials). Information disclosure of internal infrastructure, not direct data access.
**Conclusion**: No blocking protection found. Impact is limited to internal URL disclosure.

#### H-05 Defense Brief: OAuthPassThru Token Theft

**Layer 2 - Authorization/RBAC**: Requires org admin privilege to create/modify datasource URL and enable `oauthPassThru`.
**Layer 3 - Input Validation**: `datasource.ValidateURL` checks format only. No SSRF protection in OSS.
**Layer 4 - Network/Infrastructure**: `DataProxyWhiteList` exists but is empty by default. Enterprise `DataSourceRequestValidator` may add validation.
**Mitigating Factor**: Org admin is already a high-privilege role. This finding requires admin to be the attacker. In multi-tenant SaaS deployments (Grafana Cloud), org admins DO represent a meaningful threat actor.
**Conclusion**: Blocked by admin requirement in single-tenant. Valid in multi-tenant where org admin is a lower-trust role.

#### H-06 Defense Brief: ListPublicDashboards Token Enumeration

**Layer 1 - Authentication**: Requires authenticated org member.
**Layer 2 - Authorization/RBAC**: Only `middleware.ReqSignedIn` -- no RBAC check found. Searched all middleware attachments for this route. Confirmed missing.
**Layer 5 - Framework Protection**: Other public dashboard endpoints (Get, Create, Update, Delete) all have `EvalPermission` with scope. List is the exception.
**Mitigating Factor**: Access tokens alone don't grant data access unless combined with H-02/H-03 or the token viewer simply uses the public dashboard as intended. However, tokens enable circumventing per-dashboard RBAC.
**Conclusion**: Missing RBAC is confirmed. Severity depends on chain with H-02/H-03.

#### H-07 Defense Brief: Tag Annotation Org-Wide Scope

**Layer 2 - Authorization/RBAC**: Annotations are queried with service identity, not user identity.
**Layer 3 - Input Validation**: Tag-type annotations intentionally have org-wide scope (by design in the codebase comment: `DashboardID = 0` for tags). The design assumes authenticated context where org-level annotation access is acceptable.
**Mitigating Factor**: Requires: (1) public dashboards feature enabled, (2) annotations enabled on the public dashboard, (3) tag-type annotation configured, (4) other dashboards in the org using matching tags with sensitive annotation text.
**Conclusion**: No blocking protection found. The design assumption (authenticated context) is violated by public dashboard exposure.

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-04-11T10:45:00Z

**Prosecution summary**: Any authenticated user with `datasources:query` permission can inject arbitrary Authorization headers into outbound datasource proxy requests via the `X-DS-Authorization` header. The header is not stripped from inbound requests anywhere in the pipeline. This enables cross-tenant data access in shared backend datasource deployments.

**Defense summary**: Requires authenticated user with datasources:query permission (Viewer role by default). No blocking protection found after exhaustive search of all middleware layers.

**Pre-FP Gate**:
1. Attacker control verified: YES -- header value directly from HTTP request
2. Framework protection searched: YES -- all 5 layers checked, none block
3. Trust boundary crossing: YES -- user identity boundary overridden at datasource level
4. Normal attacker position: YES -- Viewer role is the lowest authenticated role
5. Ships to production: YES -- ds_proxy.go is core production code

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Confirmed reachable code path where any Viewer can override backend datasource credentials via X-DS-Authorization header; no protection found after 5-layer defense search. Enables cross-tenant data access in multi-tenant backend deployments.

**Finding draft written to**: archon/findings-draft/p8-001-xds-auth-header-injection.md
**Registry updated**: AP-001 X-DS-Authorization Header Injection

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-04-11T10:46:00Z

**Prosecution summary**: Unauthenticated public dashboard viewers receive decrypted BasicAuth credentials and plaintext InfluxDB passwords for direct-mode datasources. The credential extraction block at frontendsettings.go:541-577 has no `IsPublicDashboardView()` guard.

**Defense summary**: Requires direct-mode datasource configuration (less common). No blocking protection found for credential suppression. CVE-2026-27877 fix addressed enumeration but not credential extraction.

**Pre-FP Gate**:
1. Attacker control: YES -- unauthenticated access via public dashboard token
2. Framework protection: YES -- 5 layers searched, CVE fix is incomplete
3. Trust boundary: YES -- unauthenticated internet to internal credentials
4. Attacker position: YES -- unauthenticated
5. Production code: YES

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Unauthenticated credential disclosure via residual gap in CVE-2026-27877 patch. Decrypted passwords returned in JSON to any public dashboard visitor with a direct-mode datasource. Advocate confirmed no blocking protection.

**Finding draft written to**: archon/findings-draft/p8-002-pubdash-credential-exposure.md
**Registry updated**: AP-002 Public Dashboard Credential Leak

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-04-11T10:47:00Z

**Prosecution summary**: CVE-2026-27877 fix bypassed via template variable datasource references. `ByRef` fallback at ds_lookup.go:129 returns the original ref when UID not found in empty lookup map, adding non-queried datasource UIDs to the filtered set and exposing their credentials per H-02.

**Defense summary**: Requires dashboard editor to add template variable. No secondary validation found against the fallback behavior.

**Pre-FP Gate**:
1. Attacker control: YES -- dashboard editor controls template variable definitions
2. Framework protection: YES -- the fix itself is the protection, and it is bypassed
3. Trust boundary: YES -- extends unauthenticated credential disclosure to non-queried datasources
4. Attacker position: YES -- editor role (standard threat actor)
5. Production code: YES

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Confirmed bypass of CVE-2026-27877 fix via template variable datasource UID fallback behavior. Extends H-02 credential exposure to arbitrary direct-mode datasources not used in panel queries.

**Finding draft written to**: archon/findings-draft/p8-003-cve-2026-27877-bypass.md
**Registry updated**: AP-002 (appended instance)

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-04-11T10:48:00Z

**Prosecution summary**: Internal Prometheus URL exposed to unauthenticated public dashboard viewers via `directUrl` field. The `ds.JsonData.Set("directUrl", ds.URL)` at line 596 modifies the same map backing `dsDTO.JSONData` due to simplejson reference semantics.

**Defense summary**: Information disclosure only -- no credentials, no direct data access. Internal URL reveals network topology.

**Pre-FP Gate**:
1. Attacker control: YES -- unauthenticated access
2. Framework protection: YES -- no guard found
3. Trust boundary: YES -- internal infrastructure URL to internet
4. Attacker position: YES -- unauthenticated
5. Production code: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Confirmed internal URL disclosure to unauthenticated viewers via shared simplejson map reference. No credential exposure but reveals internal network topology. Advocate found no blocking protection.

**Finding draft written to**: archon/findings-draft/p8-004-directurl-public-exposure.md
**Registry updated**: AP-002 (appended instance)

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-04-11T10:49:00Z

**Prosecution summary**: Org admin can create datasource with attacker-controlled URL and oauthPassThru=true, causing all querying users' OAuth tokens (access + ID) to be forwarded to attacker. OSS has no SSRF protection (validator is no-op, whitelist empty by default).

**Defense summary**: Requires org admin privilege to create/modify datasource. In single-tenant deployments, org admin is already a trusted role. In multi-tenant/SaaS (Grafana Cloud), org admin is a lower-trust role where this attack is meaningful.

**Pre-FP Gate**:
1. Attacker control: YES -- admin controls DS URL and oauthPassThru setting
2. Framework protection: YES -- OSS validator is no-op, whitelist empty
3. Trust boundary: YES -- user OAuth tokens forwarded to attacker-controlled server
4. Attacker position: PARTIAL -- requires admin role (elevated privilege)
5. Production code: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Requires org admin privilege (significant precondition), but in multi-tenant deployments org admins are a real threat actor. OAuth token exfiltration is a meaningful impact. Downgraded from HIGH due to admin requirement.

**Finding draft written to**: archon/findings-draft/p8-005-oauthpassthru-token-theft.md
**Registry updated**: AP-003 OAuthPassThru Token Forwarding

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-04-11T10:50:00Z

**Prosecution summary**: Any authenticated Viewer can enumerate all public dashboard access tokens in their org via `GET /api/dashboards/public-dashboards`. Route lacks RBAC check. Combined with H-02/H-03, this creates a credential disclosure chain.

**Defense summary**: Access tokens alone enable viewing public dashboards (which is their intended purpose). However, missing RBAC means any org member can discover ALL public dashboards including those they shouldn't know about.

**Pre-FP Gate**:
1. Attacker control: YES -- authenticated request
2. Framework protection: YES -- RBAC missing on this specific route (confirmed)
3. Trust boundary: YES -- Viewer accesses admin-controlled public dashboard tokens
4. Attacker position: YES -- Viewer role
5. Production code: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Missing RBAC on ListPublicDashboards exposes all org access tokens to any authenticated member. Standalone impact is information disclosure; chain impact with H-02 enables credential theft.

**Finding draft written to**: archon/findings-draft/p8-006-pubdash-token-enum.md
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-04-11T10:51:00Z

**Prosecution summary**: Tag-based annotations in public dashboards query org-wide (DashboardID=0, DashboardUID=""), returning annotations from ALL org dashboards matching tags. Annotation text may contain sensitive operational data.

**Defense summary**: Requires specific configuration (annotations enabled, tag-type annotations, matching tags with sensitive text). The org-wide scope for tag annotations is by design, but the design assumed authenticated context.

**Pre-FP Gate**:
1. Attacker control: YES -- unauthenticated access
2. Framework protection: YES -- no protection against org-wide scope for tags
3. Trust boundary: YES -- private dashboard annotations to unauthenticated viewer
4. Attacker position: YES -- unauthenticated
5. Production code: YES

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Org-wide annotation scope exposed to unauthenticated public dashboard viewers. Design assumption violation -- tag annotations were designed for authenticated context but are now accessible without auth.

**Finding draft written to**: archon/findings-draft/p8-007-tag-annotation-scope.md
**Registry updated**: no new pattern

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 X-DS-Authorization Injection | VALID | HIGH | p8-001-xds-auth-header-injection.md |
| H-02 Public Dashboard Credential Exposure | VALID | HIGH | p8-002-pubdash-credential-exposure.md |
| H-03 CVE-2026-27877 Bypass | VALID | HIGH | p8-003-cve-2026-27877-bypass.md |
| H-04 directUrl Public Exposure | VALID | MEDIUM | p8-004-directurl-public-exposure.md |
| H-05 OAuthPassThru Token Theft | VALID | MEDIUM | p8-005-oauthpassthru-token-theft.md |
| H-06 Public Dashboard Token Enumeration | VALID | MEDIUM | p8-006-pubdash-token-enum.md |
| H-07 Tag Annotation Org-Wide Scope | VALID | MEDIUM | p8-007-tag-annotation-scope.md |

Findings written: 7
Patterns added to registry: 3
Variant candidates: 0

Chamber closed: 2026-04-11T11:00:00Z
