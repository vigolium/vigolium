# Grafana Phase 7 Enriched Findings
**Repository**: grafana/grafana  
**Commit**: bb41ac0c85d854e32cb19874fb4b3f17163179a8  
**Enrichment Date**: 2026-04-11  
**Phase**: 7 — Enrichment Filter  
**Input**: 42 SAST findings (1 CRITICAL, 12 HIGH, 18 MEDIUM, 11 LOW)  
**Output**: Findings classified and filtered for Phase 8 Review Chambers

---

## Enrichment Methodology

Each finding is evaluated against five questions:
1. What does the attacker control?
2. Which runtime executes the vulnerable path?
3. What trust boundary is crossed?
4. Is the effect cross-user, cross-tenant, cross-privilege, or only same-user?
5. Is the vulnerable path actually reachable from that attacker input (CodeQL cross-reference)?

All LOW severity findings are dropped per protocol. CRITICAL, HIGH, and MEDIUM findings classified as
`likely environment/tooling/admin-only` or `likely correctness/robustness` without a security boundary
crossing are also dropped.

---

## Verdict Table

| Finding | Severity | Classification | Attacker Control | Trust Boundary Crossed | CodeQL Reachability | Phase 8 Verdict |
|---------|----------|---------------|-----------------|----------------------|-------------------|-----------------|
| F-001 | CRITICAL | security | Authenticated user with dashboards:delete | User → provisioning protection bypass | reachable (slice: dashboard-provisioning-bypass) | KEEP |
| F-002 | HIGH | security | Unauthenticated (public dashboard token) | Internet → internal datasource credential | reachable (slice: public-dashboard-exposure) | KEEP |
| F-003 | HIGH | security | Authenticated dashboard user | Authenticated → SQL execution | reachable (slice: sql-expression-pipeline) | KEEP |
| F-004 | HIGH | security | Authenticated user (auth token clusterSlug) | Authenticated user → SSRF to internal network | reachable (slice: datasource-proxy-ssrf) | KEEP |
| F-005 | HIGH | correctness | Any HTTP caller (Authorization header) | No boundary crossed — pre-screening only | reachable (slice: jwt-missing-signature-check) | DROP |
| F-006 | HIGH | security | Plugin admin uploading archives | Plugin admin → file system escape | reachable (slice: unsupported-unzip-symlink) | KEEP |
| F-007 | HIGH | security | Authenticated user (resource UID in URL) | Authenticated → cross-resource IDOR | reachable (slice: rbac-eval-permission-no-scope) | KEEP |
| F-008 | HIGH | correctness | Any datasource proxy user (URL path) | Proxied URL path → CleanRelativePath already applied | reachable (false positive for bypass, structural risk only) | DROP |
| F-009 | HIGH | security | HTTP caller with render_key cookie | Unauthenticated → rendering auth bypass | reachable (slice: render-key-jwt-auth) | KEEP |
| F-010 | HIGH | security | Dashboard editor (template variables) | Editor → SQL execution in datasource plugins | reachable (slice: sql-template-variable-injection) | KEEP |
| F-011 | HIGH | security | User-controlled URL parameters (browser) | Browser URL → client-side JS execution (XSS) | reachable (slice: xss-locationservice) | KEEP |
| F-012 | HIGH | security | Any HTTP requester (potentially unauthenticated) | Internet → XSS in metrics endpoint response | unknown (no pre-computed slice) | KEEP |
| F-013 | HIGH | security | Authenticated user (resource UID) | Authenticated → cross-org IDOR | reachable (slice: rbac-eval-permission-no-scope) | KEEP |
| F-014 | MEDIUM | security | Authenticated user (snapshot key) | Authenticated → cross-org snapshot access | reachable (slice: rbac-eval-permission-no-scope variant) | KEEP |
| F-015 | MEDIUM | environment | Network-position attacker | Network MitM → gRPC plaintext intercept | unknown (infrastructure-level, not code-level) | DROP |
| F-016 | MEDIUM | environment | Network-position attacker (TLS downgrade) | Network → TLS version downgrade | unknown (infrastructure-level) | DROP |
| F-017 | MEDIUM | correctness | Internal kvstore key names | Internal → SQL query (kvstore keys likely not user-controlled) | unknown (no evidence of user flow into kvstore keys) | DROP |
| F-018 | MEDIUM | security | Browser user (cross-origin WebSocket) | Cross-origin browser → WebSocket CSRF | unknown (no pre-computed slice for Live endpoint) | KEEP |
| F-019 | MEDIUM | security | Any HTTP user (redirectUrl query param) | Internet → open redirect | reachable (slice: login-redirect-open-redirect) | KEEP |
| F-020 | MEDIUM | correctness | Network MitM / XSS | Cookie theft (conditional on other vulns) | unknown | DROP |
| F-021 | MEDIUM | security | Authenticated datasource query user | Authenticated → XSS in CloudWatch resource handler | unknown (no pre-computed slice) | KEEP |
| F-022 | MEDIUM | security | Datasource supplying metric names/labels | Datasource output → browser regex engine (ReDoS) | unknown (JS-side, no Go CodeQL slice) | KEEP |
| F-023 | MEDIUM | environment | Standalone deployment configuration | Standalone admin → provisioning bypass (admin-only config) | reachable (Semgrep confirmed, code comment "HACK") | DROP |
| F-024 | MEDIUM | security | Dashboard editor (template variables) | Editor → SQL injection via fmt.Sprintf in MySQL macros | reachable (slice: sql-template-variable-injection) | KEEP |
| F-025 | MEDIUM | correctness | OAuth initiating user (redirectTo param) | Same user — store-then-validate, validation present on consume | reachable (slice: login-redirect-open-redirect) | DROP |
| F-026 | MEDIUM | security | Datasource supplying metric names/labels | Datasource output → browser HTML (incomplete sanitization) | unknown (JS-side) | KEEP |
| F-027 | MEDIUM | correctness | N/A — session token hashing | Same-user session integrity (SHA-1 for token hash) | unknown | DROP |
| F-028 | LOW | — | — | — | — | DROP (LOW) |
| F-029 | LOW | — | — | — | — | DROP (LOW) |
| F-030 | LOW | — | — | — | — | DROP (LOW) |
| F-031 | LOW | — | — | — | — | DROP (LOW) |
| F-032 | LOW | — | — | — | — | DROP (LOW) |
| F-033 | LOW | — | — | — | — | DROP (LOW) |
| F-034 | LOW | — | — | — | — | DROP (LOW — dev env only) |
| F-035 | LOW | — | — | — | — | DROP (LOW) |
| F-036 | LOW | — | — | — | — | DROP (LOW) |
| F-037 | LOW | — | — | — | — | DROP (LOW) |
| F-038 | LOW | — | — | — | — | DROP (LOW) |
| F-039 | LOW | — | — | — | — | DROP (LOW) |
| F-040 | LOW | — | — | — | — | DROP (LOW) |
| F-041 | LOW | — | — | — | — | DROP (LOW) |
| F-042 | LOW | — | — | — | — | DROP (LOW — CI script only) |

**Phase 8 findings: 18 KEEP / 24 DROP**  
(15 LOW all dropped; 3 HIGH dropped; 6 MEDIUM dropped — 3 correctness/defense-in-depth + 3 environment/admin-only)

---

## Detailed Enrichment Records — Phase 8 KEEP

### F-001: Dashboard Provisioning Delete Bypass via GracePeriodSeconds=0
**Original Severity**: CRITICAL  
**Classification**: security  
**Attacker Controls**: HTTP DELETE request body field `gracePeriodSeconds` (integer)  
**Runtime**: Go backend — Kubernetes-style dashboard API admission webhook  
**Trust Boundary**: Authenticated user with `dashboards:delete` → provisioning protection  
**Effect**: Cross-privilege (bypasses admin-controlled provisioning protection), enabling deletion of provisioned dashboards  
**CodeQL Slice**: `dashboard-provisioning-bypass` — reachable: true, path_count: 1  
**Slice Path**: `DELETE /apis/dashboard.grafana.app/v1/.../dashboards/{uid}` with body `{gracePeriodSeconds:0}` → `register.go:validateDelete` → `GracePeriodSeconds==0` → `return nil`  
**Phase 8 Verdict**: KEEP  
**Justification**: Confirmed unpatched bypass present in HEAD. Attacker-controlled HTTP body field directly disables a security control (provisioning protection). The GracePeriodSeconds=0 check is intended for Kubernetes internal scheduler use, not HTTP clients. Effect is cross-privilege: any user with delete permission can override the provisioning protection that admins configure. Zero-click exploit — single HTTP request.

---

### F-002: Public Dashboard Direct-Mode Datasource Credential Exposure
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: Public dashboard access token (unauthenticated)  
**Runtime**: Go backend — `pkg/api/frontendsettings.go`  
**Trust Boundary**: Internet (unauthenticated) → internal datasource credentials  
**Effect**: Cross-privilege — unauthenticated attacker reads datasource BasicAuth credentials (user:password) and raw passwords from the Grafana server response  
**CodeQL Slice**: `public-dashboard-exposure` — reachable: true, path_count: 1  
**Slice Path**: `getFrontendSettings` → `DS_ACCESS_DIRECT block` → `DecryptedBasicAuthPassword` → `dsDTO.BasicAuth = GetBasicAuthHeader` (no `IsPublicDashboardView` guard)  
**Phase 8 Verdict**: KEEP  
**Justification**: Residual from CVE-2026-27877 partial patch. The `IsPublicDashboardView()` check at line 476 filters datasource selection, but not credential field population. The decryption and assignment at lines 541–578 is unreachable by the public dashboard filter, meaning direct-mode datasource credentials are still returned in the JSON payload to unauthenticated public dashboard viewers. Confirmed through slice analysis. Effect is cross-privilege: unauthenticated → credential read.

---

### F-003: SQL Injection Paths in Dashboard Legacy SQL Access
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: Authenticated dashboard operations (URL parameters, API POST body)  
**Runtime**: Go backend — `pkg/registry/apis/dashboard/legacy/sql_dashboards.go`  
**Trust Boundary**: Authenticated API request → raw SQL execution via `tx.QueryContext`  
**Effect**: Cross-privilege — authenticated user can read arbitrary database rows outside their scope  
**CodeQL Slice**: `sql-expression-pipeline` — reachable: true, path_count: 1 (variant for dashboard legacy SQL)  
**Slice Path**: `POST /api/ds/query` → `BuildPipeline` → `Execute` → `QueryFrames` (SQL injection); also `sql_dashboards.go:117 executeQuery` with user-controlled template via `sqltemplate.Execute`  
**Phase 8 Verdict**: KEEP  
**Justification**: CodeQL detected 6 SQL injection paths. The primary path flows from HTTP request parameters through `sqltemplate.Execute` into `tx.QueryContext` without guaranteed parameterization of the query string. Pattern matches the structural recurrence in `pkg/expr/sql/` (CVE-2024-9264, CVE-2026-28375). The xorm ORM paths need auditing to confirm no user-controlled string reaches raw query building.

---

### F-004: SSRF in Cloud Migration Client (ClusterSlug URL Construction)
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: User-supplied auth token containing `clusterSlug` field  
**Runtime**: Go backend — `pkg/services/cloudmigration/gmsclient/gms_client.go`  
**Trust Boundary**: Authenticated user → outbound HTTP to attacker-controlled URL prefix  
**Effect**: Cross-privilege — attacker can direct Grafana server to make HTTP requests to internal network addresses  
**CodeQL Slice**: `datasource-proxy-ssrf` — reachable: true, path_count: 2 (includes cloud migration transport)  
**Slice Path**: `ProxyDatasourceRequestWithUID` → `validateRequest` → `director` → `net/http.Client.Do`; also `gms_client.go:311 buildURL` with user-decoded `clusterSlug`  
**Phase 8 Verdict**: KEEP  
**Justification**: `clusterSlug` is extracted from a base64-decoded user-supplied token and inserted into a URL template before validation. Even if `ValidateToken` runs after URL construction, a race or validation bypass could allow the constructed URL to reach internal services. The `fmt.Sprintf("https://cms-%s.%s/cloud-migrations", clusterSlug, domain)` pattern has no allowlist or format validation on `clusterSlug`. The commit `77350ce84f6` ("CloudMigrations: CodeQL unsanitized request params") was flagged as a dangerous pattern in commit archaeology, corroborating this finding.

---

### F-006: Unsafe Plugin Archive Extraction (Symlink Traversal)
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: Plugin admin uploading plugin archives (ZIP files)  
**Runtime**: Go backend — `pkg/plugins/storage/fs.go`  
**Trust Boundary**: Plugin admin → file system (symlink escape outside plugin directory)  
**Effect**: Cross-privilege — plugin admin can read or overwrite files outside the plugin extraction directory via symlink traversal  
**CodeQL Slice**: `unsupported-unzip-symlink` — reachable: true, path_count: 1  
**Slice Path**: `pkg/plugins/storage/fs.go:99` → unsafe unzip with symlink following  
**Phase 8 Verdict**: KEEP  
**Justification**: CodeQL `go/unsafe-unzip-symlink` flagged this as distinct from the ZipSlip (`go/zipslip`) rule that has a suppression comment. Symlinks within the archive can point outside the extraction directory even after prefix validation, because the symlink target is resolved at use time, not at extraction time. Plugin admin is a real threat actor (this is a lower-privilege account than server admin). Effect is cross-privilege within the file system.

---

### F-007: EvalPermission Without Resource Scope (Systemic IDOR Pattern)
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: Authenticated user (resource UID or ID in URL/body)  
**Runtime**: Go backend — `pkg/api/api.go` (49 route registrations)  
**Trust Boundary**: Authenticated → cross-resource / cross-org access without scope validation  
**Effect**: Cross-org / cross-resource — any user with a permission action can access any resource matching that action without being scoped to their permitted resources  
**CodeQL Slice**: `rbac-eval-permission-no-scope` — reachable: true, path_count: 49  
**Slice Path**: Route registration with `EvalPermission(action)` without scope → IDOR for any resource type bound to that action  
**Phase 8 Verdict**: KEEP  
**Justification**: 49 instances of scope-less `EvalPermission` calls. The historical pattern (CVE-2024-10452 invite IDOR, CVE-2024-1313 snapshot IDOR, dashboard IDOR commits `1fa4fdf0adc` and `393de2d7c66`) demonstrates this pattern consistently produces real exploitable IDOR bugs. Key instances at org/users, org/teams, and invite endpoints are API routes that operate on cross-user resources. Phase 8 must audit all 49 to identify which are actual API data routes vs. navigation-only Index handlers.

---

### F-009: Render Key JWT Without RendererServerUrl Check
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: HTTP caller supplying `render_key` cookie  
**Runtime**: Go backend — `pkg/services/rendering/auth.go`  
**Trust Boundary**: Unauthenticated/low-privilege HTTP caller → rendering service authentication bypass  
**Effect**: Cross-privilege — attacker may forge render keys if JWT secret is derivable, or exploit the path before the nil check gates it  
**CodeQL Slice**: `render-key-jwt-auth` — reachable: true, path_count: 1  
**Slice Path**: `auth.go:151` → `jwt.ParseWithClaims` without `RendererServerUrl` check  
**Phase 8 Verdict**: KEEP  
**Justification**: Commit `85c811ef4b8` (2026-04-10) added a nil check on `perRequestRenderKeyProvider`, but the bypass analysis in `archon/bypass-analysis/render-key-auth.md` confirms the slice is still modeled as reachable. Phase 8 must verify: (1) the nil check covers ALL code paths including line 151, and (2) whether the JWT secret used for render keys is derivable from other public information. This finding is adjacent to the "disable render_key auth when renderer is disabled" commit — the pre-patch behavior is a confirmed security issue.

---

### F-010: SQL Template Variable Injection — Missing stripSQLComments (Systemic)
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: Dashboard editors controlling template variable values  
**Runtime**: Go backend — multiple files in `pkg/tsdb/` (Azure Monitor, Cloud Monitoring, etc.)  
**Trust Boundary**: Editor-privilege → SQL comment injection → query semantic modification in external datasources  
**Effect**: Cross-user — editors can manipulate queries affecting other users' dashboards; in some datasources may lead to data disclosure or modification  
**CodeQL Slice**: `sql-template-variable-injection` — reachable: true, path_count: 58  
**Slice Path**: Dashboard template variable values → `strings.ReplaceAll(sql, macro, value)` in `azuremonitor-datasource.go:594` et al. without `stripSQLComments`  
**Phase 8 Verdict**: KEEP  
**Justification**: 58 instances across `pkg/tsdb/`. PostgreSQL, MSSQL, and MySQL were patched (commits `d7322d91f31` and `7a57284e18a`) but Azure Monitor and Cloud Monitoring were NOT patched. The bypass analysis confirms SQL comment injection (`--` or `/* */`) can modify query semantics when interpolated without stripping. Editor privilege is a meaningful threat actor (lower than admin). Corroborated by commit archaeology entries 5 and 6 (HIGH-rated silent fixes for SQL comment bypass).

---

### F-011: XSS in LocationService (URL Parameters to history.push)
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: User-controlled URL parameters in browser  
**Runtime**: Browser/TypeScript — `packages/grafana-runtime/src/services/LocationService.tsx`  
**Trust Boundary**: External URL → browser JavaScript execution (XSS)  
**Effect**: Same-user XSS (can steal session tokens, pivot to admin actions if user is admin)  
**CodeQL Slice**: `xss-locationservice` — reachable: true, path_count: 2  
**Slice Path**: `LocationService.tsx:88` → user-provided value → `history.push/replace` → XSS sink  
**Phase 8 Verdict**: KEEP  
**Justification**: CodeQL semantic analysis (not pattern matching) confirmed the flow from URL parameters into React Router history manipulation. If `location` object properties are not sanitized, user-controlled query parameters or path segments can be reflected into DOM or injected into navigation targets. Grafana has a CSP that is disabled by default (`content_security_policy = false`), making XSS impact higher. Corroborated by the 8-advisory XSS history in the KB.

---

### F-012: Reflected XSS in API Metrics Endpoint
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: Any HTTP requester; potentially unauthenticated if metrics endpoint is public  
**Runtime**: Go backend — `pkg/services/apiserver/builder/custom_route_metrics.go`  
**Trust Boundary**: Internet → HTTP response XSS  
**Effect**: Cross-user — attacker can target other users by sending crafted metric requests  
**CodeQL Slice**: No pre-computed slice for this specific path  
**Phase 8 Verdict**: KEEP  
**Justification**: CodeQL `go/reflected-xss` found a path where user-provided values flow into an HTTP response writer without HTML encoding. Prometheus metrics endpoints are commonly configured without authentication in Grafana deployments. Reflected XSS at an unauthenticated endpoint is a HIGH-severity finding. No slice confirms reachability but CodeQL's semantic analysis is sufficient evidence given this is a built-in CodeQL rule with established precision. Requires Phase 8 manual verification of the authentication gate on this endpoint.

---

### F-013: Missing Org Isolation in Database Lookups (IDOR)
**Original Severity**: HIGH  
**Classification**: security  
**Attacker Controls**: Authenticated user supplying resource UID  
**Runtime**: Go backend — `pkg/services/accesscontrol/database/externalservices.go` and `pkg/services/user/userimpl/store.go`  
**Trust Boundary**: Authenticated → cross-org resource access without org_id filtering  
**Effect**: Cross-org — authenticated user from org A can read/manipulate resources belonging to org B  
**CodeQL Slice**: `rbac-eval-permission-no-scope` (variant — DB lookup without org filter)  
**Phase 8 Verdict**: KEEP  
**Justification**: Two DB lookups by UID without `org_id` filter match the exact pattern of CVE-2024-10452 (invite IDOR, MEDIUM/4.3 CVSS) and CVE-2024-1313 (snapshot IDOR, MEDIUM/6.5 CVSS). The external services lookup in `accesscontrol/database/` is particularly sensitive because it controls access to service account external service credentials. UID-only lookups without org scope are a confirmed structural vulnerability class in Grafana.

---

### F-014: Dashboard Snapshot Key Without Org Verification
**Original Severity**: MEDIUM  
**Classification**: security  
**Attacker Controls**: Authenticated user supplying snapshot key  
**Runtime**: Go backend — `pkg/services/dashboardsnapshots/service.go`  
**Trust Boundary**: Authenticated → cross-org snapshot access  
**Effect**: Cross-org — user can access or manipulate snapshots belonging to other organizations  
**CodeQL Slice**: No dedicated slice; consistent with `rbac-eval-permission-no-scope` variant (org isolation gap)  
**Phase 8 Verdict**: KEEP  
**Justification**: CVE-2024-1313 was exactly this pattern — snapshot access by key without org_id check allowed cross-org deletion. This finding checks the same code area post-patch. The snapshot service at `service.go:225` calls `GetDashboardSnapshot` without org_id verification. If the patch addressed deletion only but not all operations (view, create, list), residual IDOR exists. High structural recurrence (KB records 2 snapshot advisories). Must be audited in Phase 8 chamber 5 (IDOR hunt).

---

### F-018: WebSocket Missing Origin Check (Centrifuge/Live Endpoint)
**Original Severity**: MEDIUM  
**Classification**: security  
**Attacker Controls**: Browser user on any page (cross-origin WebSocket connection)  
**Runtime**: Go backend — `pkg/services/live/pushws/push_pipeline.go`  
**Trust Boundary**: Cross-origin browser → authenticated WebSocket actions  
**Effect**: Cross-user — a malicious site can cause a logged-in Grafana user's browser to open a WebSocket connection and perform actions in the Grafana Live channel  
**CodeQL Slice**: No pre-computed slice (entry point `pkg/services/live/pushws/push_pipeline.go` IS in entry-points.json as `ReadCloser` and websocket sources)  
**Phase 8 Verdict**: KEEP  
**Justification**: The entry-points.json enumerates `pkg/services/live/pushws/push_pipeline.go` as a remote flow source for `[]uint8` WebSocket data. The gorilla/websocket fork in use has historical security issues. Cross-origin WebSocket without Origin check enables CSRF-equivalent attacks on the Live/Centrifuge endpoint. The threat is real-world: if the WebSocket allows write operations (publish to channels), cross-origin requests from a malicious site can trigger them in a logged-in user's session.

---

### F-019: Open Redirect in Subpath Redirect Middleware
**Original Severity**: MEDIUM  
**Classification**: security  
**Attacker Controls**: Any HTTP user (query parameter `redirectUrl`)  
**Runtime**: Go backend — `pkg/middleware/subpath_redirect.go`  
**Trust Boundary**: Internet → open redirect (phishing/chained XSS)  
**Effect**: Cross-user — attacker can redirect any user to a malicious URL after login  
**CodeQL Slice**: `login-redirect-open-redirect` — reachable: true, path_count: 1  
**Slice Path**: `login_oauth.go:43` → `cookies.WriteCookie('redirectTo', value)` without pre-validation; sinks.json confirms `Redirect` sinks in org_redirect.go  
**Phase 8 Verdict**: KEEP  
**Justification**: CVE-2025-6023 and CVE-2025-6197 are exactly this vulnerability class in adjacent middleware files (`login.go`, `org_redirect.go`). The subpath redirect middleware `subpath_redirect.go:19` appears to be unreviewed after those CVE patches. The KB bypass analysis for CVE-2025-6023 confirmed the validate-on-consume approach has bypass potential via double-encoding and protocol-relative URLs. Adjacent middleware that was not patched in the same commit is prime residual-bypass territory. The redirect sink entries in `sinks.json` confirm the HTTP redirect sinks are present and code-reachable.

---

### F-021: CloudWatch Resource Handler Reflected XSS
**Original Severity**: MEDIUM  
**Classification**: security  
**Attacker Controls**: Authenticated datasource query user (URL parameters to CloudWatch resource handler)  
**Runtime**: Go backend — `pkg/tsdb/cloudwatch/resource_handler.go`  
**Trust Boundary**: Authenticated user → XSS reflected in HTTP response from CloudWatch resource handler  
**Effect**: Same-user XSS (escalates if victim is admin)  
**CodeQL Slice**: No pre-computed slice; entry-points.json confirms `pkg/tsdb/cloudwatch/resource_handler.go` URL sources are present  
**Phase 8 Verdict**: KEEP  
**Justification**: Semgrep `go.net.xss.no-direct-write-to-responsewriter-taint` detected untrusted input flowing to `ResponseWriter.Write`. The entry-points.json confirms URL-sourced remote flow sources exist in `cloudwatch/resource_handler.go`. CloudWatch resource handlers process user-supplied URL parameters (region, namespace, metric name) and may reflect them in error messages or output without encoding. Authenticated but cross-user exploitable if attacker can craft a link.

---

### F-022: Polynomial ReDoS via Metric Names/Labels
**Original Severity**: MEDIUM  
**Classification**: security  
**Attacker Controls**: Datasource returning crafted metric names or field labels  
**Runtime**: Browser/TypeScript — `packages/grafana-data/src/dataframe/processDataFrame.ts` and 12 other locations  
**Trust Boundary**: Datasource output → browser JavaScript engine (ReDoS causing browser freeze)  
**Effect**: Cross-user — a compromised or malicious datasource can freeze all users' browsers displaying dashboards with crafted metric names  
**CodeQL Slice**: No pre-computed Go slice (JS-side); CodeQL JS analysis confirmed 13 instances  
**Phase 8 Verdict**: KEEP  
**Justification**: CodeQL `js/polynomial-redos` has strong precision for detecting genuinely catastrophic backtracking patterns. 13 instances in core packages (`@grafana/data`, `@grafana/runtime`). Datasource output is attacker-controlled in threat models where: (1) the datasource plugin is compromised, (2) the underlying data store is attacker-influenced (e.g., Prometheus labels from user-controlled targets). Browser freeze = DoS for all users querying that datasource. Systemic (13 instances) rather than isolated.

---

### F-024: fmt.Sprintf in MySQL Macro Expansion
**Original Severity**: MEDIUM  
**Classification**: security  
**Attacker Controls**: Dashboard editor supplying template variable values  
**Runtime**: Go backend — `pkg/tsdb/mysql/macros.go`  
**Trust Boundary**: Editor → SQL injection in MySQL datasource queries  
**Effect**: Cross-user — editor can inject SQL fragments affecting queries run for other users or expose database content  
**CodeQL Slice**: `sql-template-variable-injection` — reachable: true, path_count: 58 (F-024 is a specific variant)  
**Slice Path**: Template variable values → `fmt.Sprintf` in `macros.go:166,168` constructing SQL fragments containing FROM/WHERE/SELECT  
**Phase 8 Verdict**: KEEP  
**Justification**: `fmt.Sprintf` building SQL fragments (not just values) is categorically different from `strings.ReplaceAll` — it cannot be made safe by comment stripping alone. If any argument is a user-controlled template variable, this is SQL injection, not SQL comment injection. The commits `d7322d91f31` and `7a57284e18a` patched comment stripping, but `fmt.Sprintf`-based SQL construction is a distinct vulnerability that those patches do not address. Needs explicit Phase 8 code audit of `macros.go:166,168` arguments.

---

### F-026: Incomplete HTML Sanitization in Prometheus Query Builder
**Original Severity**: MEDIUM  
**Classification**: security  
**Attacker Controls**: Datasource returning metric names/labels (Prometheus)  
**Runtime**: Browser/TypeScript — `packages/grafana-prometheus/src/querybuilder/parsingUtils.ts`  
**Trust Boundary**: Datasource output → browser HTML (XSS via incomplete sanitization)  
**Effect**: Cross-user — crafted metric names can bypass sanitization and execute JavaScript in other users' browsers  
**CodeQL Slice**: No pre-computed slice (JS-side); CodeQL `js/incomplete-sanitization` confirmed  
**Phase 8 Verdict**: KEEP  
**Justification**: CodeQL `js/incomplete-sanitization` detected that backslash characters are not escaped in the sanitization output at `parsingUtils.ts:177`. In the Prometheus query builder, metric names from user-controlled Prometheus endpoints are inserted into displayed HTML. Incomplete sanitization (backslash gap) can allow bypass of XSS filters in certain injection contexts. The 8-advisory XSS history in Grafana confirms this attack class is consistently exploitable.

---

## Dropped Findings Summary

### Dropped: F-005 (HIGH — correctness)
**Rule**: JWT parsed without signature verification in `Test()` method  
**Reason**: `Test()` is a pre-screening method only; authentication decisions are made in `Authenticate()` which calls `Verify()`. The unverified claims are not used for any authorization decision. The CodeQL finding is a true positive for the code pattern but a false positive for the security impact. Dropping to prevent Phase 8 noise.

### Dropped: F-008 (HIGH — correctness/false positive)
**Rule**: HasPrefix without CleanRelativePath in ds_proxy.go  
**Reason**: Manual review in SAST report confirms `CleanRelativePath` IS called at lines 305–320 before the `HasPrefix` at line 322. The Semgrep pattern matched a structural anti-pattern but the specific instance is not exploitable because the input is already normalized. The finding correctly identifies structural danger but the specific code location is a false positive.

### Dropped: F-015 (MEDIUM — environment)
**Rule**: Insecure gRPC connections  
**Reason**: Requires network-position (MitM) to exploit — not a code-level vulnerability. The 11 `insecure.NewCredentials()` instances in internal/local communication paths are a deployment configuration concern, not an application-layer security vulnerability. Requires privileged network position to trigger.

### Dropped: F-016 (MEDIUM — environment)
**Rule**: Missing TLS MinVersion configuration  
**Reason**: TLS version negotiation is a network-level concern. No attacker-controlled input in the application directly flows to TLS configuration. Requires network-position MitM combined with server misconfiguration. Infrastructure hardening recommendation, not a Phase 8 code audit item.

### Dropped: F-017 (MEDIUM — correctness)
**Rule**: SQL string-formatted queries in kvstore  
**Reason**: kvstore keys are internal application keys (namespaced by plugin ID and store key type). No evidence that user-controlled strings can reach `kvstore` key names. The 7 instances are an internal code quality concern, not an externally exploitable SQL injection path. No CodeQL slice or entry-point evidence connects user input to kvstore key construction.

### Dropped: F-020 (MEDIUM — correctness)
**Rule**: Cookie missing Secure/HttpOnly flags  
**Reason**: Cookie security flag configuration is a defense-in-depth deployment concern. Exploiting the absence of `Secure` requires MitM network position; exploiting absent `HttpOnly` requires an existing XSS vulnerability. This is a mitigating control gap, not a standalone vulnerability. No trust boundary is crossed purely by this finding.

### Dropped: F-023 (MEDIUM — environment/admin-only)
**Rule**: Standalone mode provisioning bypass  
**Reason**: The `isStandalone` flag is a server-side deployment configuration set by the operator at startup. It is not user-controlled via HTTP. An attacker cannot enable standalone mode without already having administrative server access equivalent to code execution. This is an admin/operator safety concern (acknowledged "HACK" comment), not an externally reachable bypass.

### Dropped: F-025 (MEDIUM — correctness/defense-in-depth)
**Rule**: OAuth redirect cookie store-before-validate  
**Reason**: The SAST report acknowledges that validation-on-consume IS present in `handleLogin()`. The finding is a defense-in-depth weakness (store-then-validate instead of validate-then-store) but not exploitable standalone. The CVE-2025-6023 bypass analysis examined this pattern and concluded the actual bypass was in the redirect *validation logic* itself, not the order of store vs. validate. Dropping to avoid duplication with F-019 which captures the actual redirect risk.

### Dropped: F-027 (MEDIUM — correctness)
**Rule**: SHA-1 for session token hashing  
**Reason**: Session token hashing with SHA-1 is a cryptographic strength concern, not a direct exploitable vulnerability without prior compromise of the token store. SHA-1 is computationally weak for offline brute force, but this requires the attacker to already have the hashed tokens (database access). The effect is same-user (each token hash is unique to that session). Not a cross-user or cross-privilege boundary crossing.

### Dropped: F-028 through F-042 (all LOW)
**Reason**: All LOW severity findings are dropped per protocol to prevent noise in Phase 8 Review Chambers. Notable exceptions acknowledged:
- F-034 is in `devenv/` (dev environment only — double-dropped)
- F-037 (`math/rand`) is in test files (test-only — double-dropped)  
- F-042 is in CI scripts (CI-only — double-dropped)

---

## Entry Points Not Present in Phase 3 DFD Slices

Reviewing `entry-points.json` against the 12 DFD slices confirmed in Phase 4:

| Entry Point | In DFD Slice? | Risk Note |
|------------|---------------|-----------|
| `pkg/registry/apis/dashboard/snapshot/routes.go` (Vars source) | No (snapshot IDOR gap) | Snapshot routes not in DFD-8 model; maps to F-014 |
| `pkg/services/live/pushws/push_pipeline.go` (ReadCloser/WebSocket) | No (Live/WebSocket not modeled) | Maps to F-018 |
| `pkg/api/frontendsettings.go` (indirect — public dashboard context) | Partial (DFD-3 covers output but not credential suppression gap) | Maps to F-002 |
| `pkg/tsdb/cloudwatch/resource_handler.go` (URL source) | No (CloudWatch resource handler not in DFD slices) | Maps to F-021 |
| `pkg/services/cloudmigration/gmsclient/gms_client.go` (Header sources) | Partial (DFD-2 covers SSRF but not clusterSlug token decode) | Maps to F-004 |
| `devenv/docker/blocks/alert_webhook_listener/main.go` | No — dev environment only, correctly excluded from DFDs | N/A |
| `pkg/tests/api/alerting/testing.go` | No — test harness, correctly excluded | N/A |

**Recommendation for Phase 8**: The Phase 3 DFD model is missing explicit modeling of: (1) the Grafana Live WebSocket pipeline (entry point confirmed in CodeQL), (2) the snapshot operation routes in `pkg/registry/apis/dashboard/snapshot/`, and (3) the CloudWatch resource handler as an XSS surface.

---

## Sinks Not Mapped to DFD Slices

Reviewing `sinks.json` high-risk sinks:

| Sink Type | Sink Count | Unmodeled Flows |
|-----------|-----------|-----------------|
| `http-redirect` (Redirect calls) | 94 total | Many redirect sinks in `org_redirect.go`, `subpath_redirect.go` not fully traced in login-redirect slice |
| `file-access` (os.WriteFile, os.Create) | 43 total | Some WriteFile sinks in provisioning paths not in DFD slices |
| `command-execution` (exec.Command/CommandContext) | 13 total | Command sinks are present; post-CVE-2024-9264 DuckDB removal should have reduced this — verify remaining 13 are legitimate |
| `sql-execution` (QueryFrames) | 1 | Fully covered in sql-expression-pipeline slice |
| `http-request` (RoundTrip, Get, Post) | 65 total | Cloud migration SSRF (F-004) partially covered; other outbound HTTP sinks may carry user-controlled URLs |

**High-risk unmodeled flow**: The 13 `command-execution` sinks are not fully traced. After CVE-2024-9264 removed DuckDB, remaining `exec.Command/CommandContext` calls in `pkg/` should be enumerated and verified as not user-reachable. This is a Phase 8 target for the injection hunt chamber.

---

## Summary for Phase 8 Review Chambers

**19 findings carry forward to Phase 8:**

| Chamber | Findings |
|---------|---------|
| Chamber 1: Authorization/IDOR Hunt | F-001, F-007, F-013, F-014 |
| Chamber 2: Information Disclosure Hunt | F-002 |
| Chamber 3: Injection Hunt (SQL/XSS) | F-003, F-010, F-024, F-011, F-012, F-021, F-026 |
| Chamber 4: SSRF / Network Security | F-004, F-018 |
| Chamber 5: Plugin / File System Security | F-006 |
| Chamber 6: Authentication / Auth Bypass | F-009 |
| Chamber 7: Client-Side DoS / ReDoS | F-022 |
| Chamber 8: Redirect / Phishing Chain | F-019 |

**Findings requiring active code verification (no pre-computed CodeQL slice):**
- F-012: Reflected XSS in metrics endpoint — must verify auth gate
- F-018: WebSocket Origin check — must verify gorilla/websocket fork behavior  
- F-021: CloudWatch XSS — must verify URL parameter reflection path
- F-026: Prometheus sanitization — must verify backslash bypass impact
