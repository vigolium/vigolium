# Phase 2: Security Patch Analysis — Bypass Potential Assessment (EXPANDED)

**Audit ID:** 2026-03-21T00:00:00.000Z
**Generated:** 2026-03-21
**Purpose:** Structured list of security patches for Phase 2 bypass analysis — expanded to include 2024 CVEs

---

## Executive Summary for Phase 2

This document lists all identified security patches for Phase 2 bypass analysis.

Scope: All CVEs where the fix is in the Grafana main repository OR where reachability from attacker input is credible. Plugin-only and separate-repo fixes are noted. 

Priority tiers:
- **Tier 1** — Prior audit confirmed findings with residual bypass risk (in-tree fixes)
- **Tier 2** — New 2025–2026 CVEs patched in-tree
- **Tier 3** — 2024 CVEs patched in-tree (new since expanded Phase 1)
- **Tier 4** — Dependency CVEs; reachability from attacker input credible

---

## Tier 1: Prior Confirmed Findings — Residual Risk

### PATCH-T1-01: CVE-2026-21721 + CVE-2025-3260 — Dashboard Permission Scope Binding
**Severity:** HIGH (8.1 / 8.3)
**Component:** `pkg/api/api.go` (routes), `pkg/services/accesscontrol/`
**Patch Commits:** `1fa4fdf0adc` (T1-01a), `5a62f35f5b6` (T1-01b)
**Fix Type:** Added `dashUIDScope`/`dashIDScope` to GET/POST `/permissions` routes and version endpoints

**What the patch does:**
- CVE-2026-21721: Scoped `/uid/:uid/permissions` GET and POST routes to specific dashboard UID
- CVE-2025-3260: Same fix for `/uid/:uid/versions`, `/uid/:uid/restore` and `/id/:dashboardId/` variants

**Bypass hypotheses:**
1. Are there additional dashboard sub-routes that still lack scope binding? (`/uid/:uid/access`, export routes, etc.)
2. Does `ac.EvalPermission(action, scope)` verify ownership correctly when the scope UID is attacker-controlled?
3. Can the scope be bypassed by encoding the UID (e.g., `%2f..%2f`)?
4. Is the fix applied to the deprecated `/id/:dashboardId` path consistently?
5. Can a user with folder-level permissions access dashboard permissions below that folder?

**Phase 2 tasks:**
- Enumerate all `/api/dashboards/uid/:uid/*` sub-routes in `pkg/api/api.go`
- Verify each route has scope passed to `authorize()`
- Test with a user that has `dashboards:permissions:write` on dashboard A attempting to modify dashboard B
- Check if folder admin scope transitively includes dashboard permission management

---

### PATCH-T1-02: CVE-2026-21722 — Public Dashboard Timerange Bypass
**Severity:** MEDIUM (5.3)
**Component:** `pkg/api/annotations.go`, public dashboard annotation handler
**Patch Commits:** `e97fa5f587c` (main), multiple backport commits (release branches)
**PR:** #117854

**What the patch does:**
- Forces annotation queries to use the dashboard's locked timerange when `timeSelectionEnabled = false`
- Was previously passing client-supplied `from`/`to` parameters directly to annotation query

**Bypass hypotheses:**
1. Does the fix apply to ALL annotation query paths (both REST API and WebSocket streaming)?
2. Can `timeSelectionEnabled` flag be overridden via URL parameters?
3. Is there a separate authenticated annotation endpoint (`/api/annotations`) that still accepts arbitrary timeranges for the same public dashboard data?
4. Are there annotation query types (alert state history, etc.) that bypass the timerange check?
5. Does the fix handle relative time expressions (e.g., `now-6h`) correctly vs. absolute timestamps?

---

### PATCH-T1-03: CVE-2025-3454 — Datasource Proxy Double-Slash
**Severity:** MEDIUM (5.0)
**Component:** `pkg/services/datasourceproxy/`, route matching
**Patch:** Multiple security releases; URL path normalized before route permission checking

**Bypass hypotheses:**
1. Are %2F encoded slashes handled the same as literal slashes after normalization?
2. Does the route matching normalize `..` sequences?
3. Are backslash (`\`) separators rejected?
4. Does the fix apply to all datasource proxy entry points (uid-based and id-based)?
5. Are non-Prometheus datasource type backends (Loki, Tempo) also covered?

---

## Tier 2: 2025–2026 CVEs Patched In-Tree

### PATCH-T2-01: CVE-2026-21720 — Unauthenticated Avatar Cache DoS
**Severity:** HIGH (7.5)
**Component:** `pkg/api/avatar/avatar.go`
**Patch Commit:** `86c2e52464f`
**PR:** #116891

**What the patch does:**
- Avatar endpoint now requires authentication (`reqSignedIn` middleware)
- Removed the goroutine queue that could be exhausted
- Added request timeout

**Bypass hypotheses:**
1. Is authentication required consistently across all avatar URL patterns (`/avatar/:hash`, `/avatar/`)?
2. Can the auth check be bypassed using an anonymous/guest session (`[auth.anonymous]` enabled)?
3. Are there alternative URLs that serve avatar content without the auth requirement?
4. Does the timeout prevent amplification attacks from authenticated users?
5. Can multiple authenticated but low-privilege users cooperate to exhaust the new timeout-bounded pool?

---

### PATCH-T2-02: CVE-2026-21727 — Cross-Tenant Legacy Correlation
**Severity:** LOW (3.3)
**Component:** `pkg/services/correlations/database.go`
**Patch Commit:** `e702db6096e`
**PR:** #116877

**What the patch does:**
- Removed `(correlation.org_id = 0 OR dss.org_id = correlation.org_id)` fallback
- Now requires strict equality: `dss.org_id = correlation.org_id`

**Bypass hypotheses:**
1. Are there still database rows with `org_id = 0` from before the fix accessible via other API paths?
2. Is there a migration that removes legacy `org_id = 0` rows?
3. Are there other correlation query functions (besides `getCorrelation`, `getCorrelationsBySourceUID`) that still use the old condition?
4. Can `deleteCorrelation` be called cross-tenant for legacy rows?

---

### PATCH-T2-03: CVE-2025-6023 — XSS in Scripted Dashboards
**Severity:** HIGH (7.6)
**Component:** Frontend scripted dashboard rendering
**Patch Commits:** Multiple security releases (12.0.2+security-01, 11.6.3+security-01)
**Commit:** 4669b586e98 (#108330)

**What the patch does:**
- Sanitizes user-controlled content in scripted dashboard rendering paths
- Validates redirect URLs in org switching flow

**Bypass hypotheses:**
1. Are all HTML rendering contexts covered by the sanitization?
2. Can SVG-based XSS bypass the sanitization?
3. Are there legacy scripted dashboard execution paths that were not patched?
4. Does the sanitizer handle attribute-based injection (event handlers)?
5. Can the open redirect be exploited with a `data:` or `javascript:` URI scheme?

---

### PATCH-T2-04: CVE-2025-41117 — XSS in TraceView
**Severity:** MEDIUM (6.8)
**Component:** `public/app/features/explore/` — TraceView component
**Patch Commit:** `8dfa6446942`
**PR:** #117853

**What the patch does:**
- Added HTML sanitization to TraceView stack trace rendering
- Uses DOMPurify via `dangerouslySetInnerHTML`

**Bypass hypotheses:**
1. Is DOMPurify configured with correct options for trace data context?
2. Are there other `dangerouslySetInnerHTML` usages in TraceView that were not sanitized?
3. Can trace attribute names or values inject into non-innerHTML contexts?
4. Are there SVG/math namespace bypasses against the specific DOMPurify version in use?

---

### PATCH-T2-05: CVE-2025-3580 — Admin User Deletion Escalation
**Severity:** MEDIUM (5.5)
**Component:** `pkg/api/` — DELETE /api/org/users/:userId
**Patch Commit:** `5963be6f317`
**PR:** #105976

**What the patch does:**
- Adds check preventing org admin from deleting a server admin account

**Bypass hypotheses:**
1. Does the check verify server admin role at time of deletion (not cached value)?
2. Can the check be bypassed by first demoting server admin via a separate concurrent request (race condition)?
3. Are there batch removal endpoints that bypass the individual check?
4. Does the fix cover both `/api/org/users/` and `/api/orgs/:orgId/users/:userId`?
5. Can the server admin be removed by other means (e.g., SCIM sync that removes org membership)?

---

### PATCH-T2-06: CVE-2025-11539 — Image Renderer RCE
**Severity:** CRITICAL (9.9)
**Component:** grafana-image-renderer plugin (separate repo)
**Patch Version:** 4.0.17+
**Note:** Fix is in separate renderer repo, not in grafana/grafana main repo

**What the patch does:**
- Added filePath validation to `/render/csv` endpoint
- Restricts file writes to allowed directories

**Bypass hypotheses:**
1. Does the filePath validation handle all path traversal encodings (%2E%2E, ../, ..\)?
2. Are symlinks resolved before validation (TOCTOU between check and write)?
3. Are there alternative file write endpoints beyond `/render/csv`?
4. If the validator uses a prefix check, can it be bypassed with `/allowed/../../etc/`?
5. Can the prior auth bypass (H2 — default JWT token `-`) be chained with this?

---

### PATCH-T2-07: CVE-2025-3415 — DingDing Integration Info Disclosure
**Severity:** MEDIUM (4.3)
**Component:** `pkg/services/ngalert/` alerting contact points
**Fix:** Multiple security releases; contact point secrets now redacted from Viewer responses
**Commit context:** f2b9830fdaa (#104386) — Alerting: Improve secret fields handling in contact points

**What the patch does:**
- Redacts DingDing API key from contact point API responses for non-admin users

**Bypass hypotheses:**
1. Does the redaction apply to all contact point retrieval endpoints (REST + k8s API)?
2. Are there debug or test-receiver endpoints that still return unredacted secrets?
3. Does the fix cover all alerting integration types beyond DingDing (e.g., VictorOps, Slack, PagerDuty)?
4. Can a Viewer user access secrets via alerting state history or notification logs?
5. Is there a way to trigger a notification test that echoes back the secret in an error response?

---

### PATCH-T2-08: CVE-2025-41115 — SCIM Privilege Escalation (Enterprise)
**Severity:** CRITICAL (10.0)
**Component:** SCIM provisioning endpoint (Enterprise only)
**Patch:** >=12.3.0, >=12.2.1, >=12.1.3, >=12.0.6
**Note:** Requires SCIM feature + user sync enabled in enterprise

**What the patch does:**
- Validates that numeric externalId cannot override internal user identifiers during SCIM provisioning
- Prevents user impersonation via externally-controlled SCIM provisioning requests

**Bypass hypotheses:**
1. Does the fix validate type of externalId or just reject numeric values? Can hex strings that parse as numbers bypass it?
2. Is the fix applied to both CREATE and UPDATE SCIM operations?
3. Can a SCIM client with valid credentials but wrong org target another org's users?
4. Are there SCIM group sync operations that bypass the externalId validation?
5. Does the fix handle externalId collision on update vs. create differently?

---

## Tier 3: 2024 CVEs Patched In-Tree (New in Expanded Phase 1)

### PATCH-T3-01: CVE-2024-9264 — SQL Expressions RCE (CRITICAL 9.4)
**Component:** `pkg/expr/` — SQL Expressions feature
**Patch PRs:** #94942 (main), #94955 (v11.3.x), #94959 (v11.2.x)
**Patch Commit (present in repo):** 5221584143a (v11.3.x backport)

**What the patch does:**
- Completely removed duckdb dependency and disabled SQL Expressions feature
- Feature was gated behind `experimentalFeatureEnabled` flag; entire code path removed

**Bypass hypotheses:**
1. Has SQL Expressions been re-enabled in any form on the main branch? (check if `sqlExpressions` feature flag exists and is enabled)
2. Are there other duckdb/external process invocations in the codebase that could serve as alternative RCE paths?
3. Does the current development branch (13.0.0-pre) re-introduce SQL Expressions with different sandboxing?
4. Are there similar features (e.g., user-controlled queries passed to external binaries) in other datasource backends?
5. Can the `expr-lang/expr` expression evaluator be abused to execute system commands via reflection or unsafe operations?

**Phase 2 tasks:**
- Search codebase for `duckdb`, `sqlExpressions`, `SQL Expressions` to verify complete removal
- Review current `pkg/expr/` for any user-controlled external process invocations
- Check `go.mod` for any duckdb transitive dependencies remaining

---

### PATCH-T3-02: CVE-2024-8118 — Alerting Permission Bypass (MEDIUM 5.1)
**Component:** `pkg/services/ngalert/api/authorization.go`
**Patch Commit:** c2799b4901d (#93940)

**What the patch does:**
- Changed POST external rule groups endpoint permission from `ExternalAlertRuleWrite` to `AlertRuleWrite`
- Single-line fix: `ac.EvalPermission(ac.ActionAlertingRuleCreate)` instead of wrong action

**Bypass hypotheses:**
1. Are there other alerting API endpoints that have similar permission action mismatches?
2. Can `ExternalAlertRuleWrite` permission still be abused to perform unintended operations on internal alert rules?
3. Is the fix consistently applied to both REST API and k8s API-based alerting endpoints?
4. Are there alerting endpoints that use `OR`-chained permissions where either permission is sufficient?
5. Does the permission model correctly differentiate between internal and external Alertmanager rule management?

**Phase 2 tasks:**
- Audit `pkg/services/ngalert/api/authorization.go` for all endpoint permission assignments
- Map each endpoint's required action to its intended privilege level
- Cross-reference with new provisioning API changes in latest commits (#120552)

---

### PATCH-T3-03: CVE-2024-1313 — Snapshot Deletion Auth Bypass (MEDIUM 6.5)
**Component:** `pkg/api/snapshot.go` (or equivalent), DELETE /api/snapshots/:key
**Patch:** >=9.5.18, >=10.0.13, >=10.1.9, >=10.2.6, >=10.3.5

**What the patch does:**
- Verifies caller is in the same organization as snapshot owner before allowing deletion
- Previously, view key alone was sufficient to delete — org membership not checked

**Bypass hypotheses:**
1. Is there a K8s API path for snapshot deletion (see recent commits: `Snapshots: Add permissions validation to K8s API #120229`) that had the same auth bypass?
2. Does the fix cover the `deleteExternalSnapshot` path (for externally hosted snapshots)?
3. Can snapshot view key be brute-forced if it is not cryptographically random?
4. Is the fix applied to the `snapshotPublicModeEnabled` flow where org checks may differ?
5. The recent commit 5c89af649b2 ("Snapshots: Add permissions validation to K8s API") suggests the K8s migration may have re-introduced this class of bug.

**Phase 2 tasks:**
- Review `5c89af649b2` and `c196ecd521b` (Snapshots: Add dashboard validation to k8s api) for auth model correctness
- Compare permission enforcement between legacy REST and new K8s API snapshot endpoints

---

### PATCH-T3-04: CVE-2024-1442 — Datasource Wildcard UID Privilege Escalation (MEDIUM 6.0)
**Component:** `pkg/services/datasources/` — datasource creation/update
**Patch:** >=9.5.7, >=10.3.4

**What the patch does:**
- Rejects datasource UID of `*` (wildcard) during creation and update
- Wildcard UID previously granted access to all datasources in the org

**Bypass hypotheses:**
1. Does the validation reject ALL wildcard-like values or only literal `*`? (e.g., `%2A`, `%*`, glob patterns)
2. Is the UID validation applied at both REST API and k8s API datasource endpoints?
3. Are there other special UID values (e.g., empty string, reserved names) that could provide elevated access?
4. Does the fix apply to datasource update (PATCH) operations, not just creation (POST)?
5. With the new unified storage / app platform, are datasource UIDs validated in the k8s admission layer?

---

### PATCH-T3-05: CVE-2024-9476 — Cloud Migration Cross-Org Access (MEDIUM 5.1)
**Component:** `pkg/services/cloudmigration/` — Cloud Migration Assistant
**Patch:** >=11.3.0+sec, >=11.2.3+sec

**What the patch does:**
- Scoped Cloud Migration Assistant resource access to caller's organization
- Prevented cross-organization resource access during migration export

**Bypass hypotheses:**
1. Are there residual Cloud Migration API endpoints that still lack org-scoping?
2. Is the fix applied to both the export and import phases of migration?
3. Can the SSRF chain (H4 in prior audit) be combined with this bypass to exfiltrate data from other orgs?
4. With the GMS (Grafana Migration Service) integration, are API calls to GMS properly scoped to the user's org?
5. Does the migration snapshot decryption path check that the snapshot belongs to the caller's org?

---

### PATCH-T3-06: CVE-2024-6322 — Plugin Datasource ReqActions Bypass (MEDIUM 4.4)
**Component:** `pkg/plugins/` — plugin data source access control
**Patch:** see advisory

**What the patch does:**
- Fixed ReqActions validation to scope checks to the individual datasource rather than any datasource
- Previously: having query access to any datasource bypassed ReqActions on protected datasource

**Bypass hypotheses:**
1. Are there other plugin manifest fields (`ReqRole`, `ReqOrgRole`) with similar scoping bugs?
2. Does the fix apply to all plugin types (datasource, panel, app) or only datasource plugins?
3. Can a plugin with permissive ReqActions be installed to then access protected plugins?
4. Is the fix applied to the new app platform plugin routes (`/api/plugins/...` vs `/apis/...`)?
5. Does the k8s-style plugin registration in `apps/` use the same access control infrastructure?

---

## Tier 4: Dependency CVEs — Reachability Analysis Required

### PATCH-T4-01: CVE-2024-45337 — golang.org/x/crypto SSH Auth Bypass (CRITICAL 9.1)
**Package:** `golang.org/x/crypto` — SSH implementation
**Patch Commit:** 0a390cc069f (#97823) — bumped to v0.31.0
**Current Status:** Patched in current branch

**Reachability questions:**
1. Does Grafana use `golang.org/x/crypto/ssh` with `ServerConfig.PublicKeyCallback` anywhere?
2. Which datasource backends (PostgreSQL, MySQL, SSH tunnel?) use SSH key-based auth via x/crypto?
3. Is the SSH tunnel feature in datasource configuration exposed to low-privilege users?
4. Can an attacker authenticate with one SSH key but cause authorization decisions to be made about a different key?

**Bypass hypotheses:**
1. Even with the updated x/crypto, does Grafana's SSH usage correctly check the key that was actually used for auth?
2. Are there SSH connection pools that might reuse a connection authenticated with key A for a user that should use key B?

---

### PATCH-T4-02: CVE-2024-45338 — golang.org/x/net HTML DoS (HIGH 5.3–8.7)
**Package:** `golang.org/x/net/html`
**Patch Commit:** 5a2344ed0ca (#98340) — bumped to v0.33.0
**Current Status:** Patched in current branch

**Reachability questions:**
1. Does Grafana parse user-supplied HTML using `golang.org/x/net/html` in any API path?
2. Are dashboard panel titles, markdown content, or annotation text parsed via this library?
3. Can an unauthenticated user trigger HTML parsing (e.g., via public dashboard)?

---

### PATCH-T4-03: CVE-2025-30204 — golang-jwt DoS (HIGH 7.5)
**Package:** `github.com/golang-jwt/jwt/v4`
**Patch Commits:** e862fb3cd78 (#102715), b2605ed2926 (#102727)
**Current go.mod:** v4.5.2 (patched)

**Reachability questions:**
1. Does Grafana call `jwt.ParseUnverified` on attacker-controlled Authorization headers?
2. Is there a code path where a malformed JWT with many periods reaches `ParseUnverified` before rejection?
3. Which auth flows use golang-jwt/jwt (renderer JWT, ext JWT, gRPC storage JWT)?

**Bypass hypotheses:**
1. Even with DoS patched, does `ParseUnverified` expose any path where claims are used before signature verification?
2. Is the v5 variant (`github.com/golang-jwt/jwt/v5`) also present in go.mod and also vulnerable?

---

### PATCH-T4-04: CVE-2025-29786 — expr-lang/expr DoS (HIGH 7.5)
**Package:** `github.com/expr-lang/expr`
**Patch Commit:** fef74521e98 (#102533) — bumped to v1.17.0
**Current Status:** Patched

**Reachability questions:**
1. Does Grafana pass user-controlled expressions to `expr.Compile()` or `expr.Eval()` without length limits?
2. What features use expr-lang? (alerting rule expressions, transformations, panel queries?)
3. Can a low-privilege user trigger expr evaluation via dashboard panel configuration?

---

### PATCH-T4-05: CVE-2025-48371 — OpenFGA Auth Bypass
**Package:** `github.com/openfga/openfga`
**Patch Commits:** c4c4faff1ee (#106064) and backports
**Current go.mod:** v1.11.3 (patched, well past v1.8.13 fix)

**Reachability questions:**
1. Is OpenFGA used for authorization decisions in production Grafana Enterprise?
2. Can the bypass conditions (contextual tuples + public access + userset) be triggered by a low-privilege API call?
3. Does the Grafana OpenFGA usage involve ListObjects or Check calls with contextual tuples?

---

### PATCH-T4-06: GO-2026-4602 — os.Root FileInfo Sandbox Escape (via nanogit)
**Package:** `github.com/grafana/nanogit` (uses Go stdlib)
**Patch Commit:** 4bc3b94077e (#120290)
**Current go.mod:** nanogit v0.13.0 (uses Go 1.25.8, patched)

**Reachability questions:**
1. Does Grafana provisioning via nanogit call `os.Root` operations on user-controlled paths?
2. Can a crafted git repository with special file names trigger the sandbox escape?
3. Is nanogit used for any user-facing provisioning feature accessible to non-admins?

---

## Cumulative Patch Analysis Priorities

| Priority | CVE | In Repo | Bypass Complexity | Impact If Bypassed |
|----------|-----|---------|-------------------|-------------------|
| P1 | CVE-2026-21721 + CVE-2025-3260 | Yes | LOW — related sub-routes likely missing scope | HIGH — any authed user with generic perm targets any dashboard |
| P2 | CVE-2024-9264 (SQL Expressions RCE) | Yes | LOW — verify feature truly removed from 13.0 branch | CRITICAL — RCE from VIEWER |
| P3 | CVE-2026-21722 (Public dashboard timerange) | Yes | MEDIUM — alternate code path | MEDIUM — data leakage on public dashboards |
| P4 | CVE-2026-21720 (Avatar DoS) | Yes | LOW — anonymous mode bypass | HIGH — unauthenticated DoS |
| P5 | CVE-2024-8118 (Alerting permission) | Yes | MEDIUM — other endpoints may have same error | MEDIUM — creates/modifies alert rules without permission |
| P6 | CVE-2025-3454 (Proxy double-slash) | Yes | MEDIUM — other encoding variants | MEDIUM — unauthorized datasource endpoint access |
| P7 | CVE-2024-1313 (Snapshot deletion) | Yes | MEDIUM — K8s API path may lack same fix | MEDIUM — cross-org snapshot deletion |
| P8 | CVE-2025-11539 (Image Renderer RCE) | Separate repo | MEDIUM — path encoding variants | CRITICAL — RCE |
| P9 | CVE-2025-6023 (Scripted dashboard XSS) | Yes | MEDIUM — sanitizer bypass payloads | HIGH — XSS steals session |
| P10 | CVE-2026-21727 (Cross-tenant correlation) | Yes | LOW — legacy rows may persist | LOW-MEDIUM — cross-tenant data exposure |
| P11 | CVE-2024-45337 (SSH auth bypass) | Dep | HIGH — needs SSH usage in grafana | CRITICAL — auth bypass |
| P12 | CVE-2025-30204 (JWT DoS) | Dep | MEDIUM — ParseUnverified call sites | HIGH — DoS in auth path |
| P13 | CVE-2024-9476 (Cloud Migration) | Yes | MEDIUM — related to H4 from prior audit | MEDIUM — cross-org data access |
| P14 | CVE-2025-41115 (SCIM privilege escalation) | Enterprise | LOW — numeric externalId is direct | CRITICAL — full admin takeover |
| P15 | CVE-2025-3415 (DingDing info disclosure) | Yes | MEDIUM — other integration types | MEDIUM — secret exposure |

