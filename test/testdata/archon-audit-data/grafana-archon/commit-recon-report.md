# Commit Archaeology Report

**Repository**: grafana/grafana (https://github.com/grafana/grafana)
**Commit range**: 3 years ago..bb41ac0c85d854e32cb19874fb4b3f17163179a8
**Branches searched**: main (HEAD), all remote branches (via --all)
**Languages detected**: Go (5735 files), TypeScript (4229 files), JavaScript (127 files)
**Project security vocabulary discovered**:
- `PROJECT_VOCAB_VALIDATORS`: `ValidateHostHeader`, `ValidatePath`, `ValidateRelativePath`, `CleanRelativePath`, `ValidateScope`, `ValidateUID`, `ValidateURL`, `ValidatePassword`, `validateAssetsID`, `writeSanitized`, `addEscapeCharactersToString`
- `PROJECT_VOCAB_AUTH`: `AccessControl`, `AccessClient`, `Authorizer`, `AccessChecker`, `authorize`, `isAdmin`, `isAuthenticated`, `requireAuth`
- `PROJECT_VOCAB_CONFIG`: `csrf`, `allowlist`, `cspHeader`, `throttling`, `cspReportOnlyHeader`
**Scan date**: 2026-04-11T15:05:19Z
**Total commits in repo**: 68,050 (26,050 in last 3 years)

---

## Summary Statistics

| Category | Commits Found | HIGH | MEDIUM | LOW |
|----------|--------------|------|--------|-----|
| 1. Dangerous Pattern Introduction | 4 | 1 | 2 | 1 |
| 2. Security Control Weakening | 4 | 2 | 2 | 0 |
| 3. Silent Security Fixes | 12 | 6 | 5 | 1 |
| 4. Reverted Security Fixes | 1 | 1 | 0 | 0 |
| 5. Secret Archaeology | 1 | 0 | 1 | 0 |
| 6. CI/CD Pipeline Weakening | 1 | 0 | 1 | 0 |
| 7. Suspicious Patterns | 1 | 0 | 0 | 1 |
| **Total (deduplicated)** | **24** | **10** | **11** | **3** |

Note: Advisory-hunter SHAs already recorded (`8dfa6446942`, `ea71201ddc6`, `86c2e52464f`) are excluded from this report.

---

## Priority Commits (top 30, ordered by risk)

| # | SHA | Category | Risk | Author | Date | Description | Recommended Phase |
|---|-----|----------|------|--------|------|-------------|-------------------|
| 1 | `1fa4fdf0adc` | 3 | HIGH | mihai-turdean | 2026-01-07 | patch(security): Fix dashboard permission vulnerability — IDOR via missing scope on permission endpoints | Phase 2 (undisclosed-fix), Phase 5 |
| 2 | `393de2d7c66` | 3 | HIGH | jguer | 2026-01-02 | patch(security): add missing scope check on dashboards — scope missing for UID route | Phase 2 (undisclosed-fix), Phase 5 |
| 3 | `85c811ef4b8` | 3 | HIGH | mariell.hoversholm | 2026-04-10 | fix: disable render_key auth when renderer is disabled — any valid HMAC key accepted when no renderer configured | Phase 2 (undisclosed-fix), Phase 5 |
| 4 | `dc9ac13e84a` | 3 | HIGH | nic.westvold | 2026-03-23 | fix: harden query history authorization — fail-open to fail-closed + cross-user data leakage in Mode5 | Phase 2 (undisclosed-fix), Phase 5 |
| 5 | `d7322d91f31` | 3 | HIGH | adamyeats | 2026-04-08 | SQL: strip comments with quote-aware state machine in PostgreSQL and MSSQL — regex-based stripping bypassed via quoted strings | Phase 2 (undisclosed-fix), Phase 5 |
| 6 | `7a57284e18a` | 3 | HIGH | karthik-idikuda | 2026-04-02 | MySQL: Preserve # inside quoted strings in SQL comment stripping — naive regex truncated JSON path queries | Phase 2 (undisclosed-fix), Phase 5 |
| 7 | `07d136f66c5` | 3 | HIGH | andres.martinez | 2025-03-31 | Sanitize paths before evaluating access to route — path traversal via // in proxy path | Phase 2 (undisclosed-fix), Phase 5 |
| 8 | `a8b373144f6` | 2 | HIGH | ajhack93 | 2026-04-01 | fix batch requests bypass Grafana's credential proxy — Azure Monitor batch API used wrong auth audience/client | Phase 2 (undisclosed-fix), Phase 5 |
| 9 | `0fc29cbaae0` | 2 | HIGH | mariell.hoversholm | 2025-08-19 | Rendering: Remove SVG sanitization — entire SVG sanitizer service removed, `SanitizeSVG` capability dropped | Phase 5 |
| 10 | `7d62590d000` | 3 | HIGH | william.wernert | 2026-04-07 | Expressions: Add memory limit for math expression binary operations — OOM DoS via cartesian explosion | Phase 2 (undisclosed-fix), Phase 5 |
| 11 | `329327952e9` | 3 | MEDIUM | yuriy.tseretyan | 2026-03-17 | Alerting: Add protected fields authorization check to provisioning API — users could modify protected contact point fields | Phase 2 (undisclosed-fix), Phase 5 |
| 12 | `c30a9e2003a` | 3 | MEDIUM | yuriy.tseretyan | 2026-03-25 | Alerting: Protect /api/v2/status endpoint with dedicated permission — endpoint previously accessible to any notification reader | Phase 2 (undisclosed-fix) |
| 13 | `9e399e0b19a` | 3 | MEDIUM | mariell.hoversholm | 2026-01-14 | Data Source: Proxy fallback routes must match all inputs — empty proxy path bypassed route access check | Phase 2 (undisclosed-fix), Phase 5 |
| 14 | `7b366ebd007` | 3 | MEDIUM | rafael.paulovic | 2026-03-25 | Dashboard: fail closed on non-404 ReadResponse.Error — 403/5xx treated as "not found" allowed bypassing provisioning protection | Phase 2 (undisclosed-fix) |
| 15 | `2e51ce6e4e8` | 3 | MEDIUM | gamab | 2026-04-08 | Annotations: fix permission check using subresource — RBAC action mapping incorrect for annotation subresources | Phase 2 (undisclosed-fix), Phase 5 |
| 16 | `07b7c08939c` | 3 | MEDIUM | rodrigopk | 2026-04-10 | Alerting: Fix missing permission check for routing preview — routing preview accessible without permissions | Phase 2 (undisclosed-fix) |
| 17 | `77350ce84f6` | 1 | MEDIUM | macabu | 2025-02-21 | CloudMigrations: Address CodeQL issue on unsanitized request params — URL injection via unvalidated ClusterSlug | Phase 2 (undisclosed-fix), Phase 5 |
| 18 | `053ee5cb1f4` | 1 | MEDIUM | academo | 2025-03-19 | Frontend Sandbox: Use DOMPurify to sanitize innerHTML — plugins could set onerror/onload handlers via innerHTML | Phase 2 (undisclosed-fix) |
| 19 | `561156c4da9` | 1 | MEDIUM | Ret2Me | 2025-03-03 | Auth: Add TlsSkipVerify parameter to JWT Auth — new config option enabling TLS certificate bypass for JWT key fetching | Phase 5 |
| 20 | `04f39457cf9` | 3 | MEDIUM | marcus.andersson | 2024-06-24 | Chore: Remove sensitive information from presigned URLs prior to logging — auth_token leaked into log files | Phase 2 (undisclosed-fix) |
| 21 | `b20b2cb7962` | 3 | LOW | jev.forsberg | 2026-04-07 | Fix XSS in SearchableList — dangerouslySetInnerHTML replaced with safe React node rendering | Phase 5 |
| 22 | `246a55e9e71` | 4 | HIGH | rodrigopk | 2026-04-07 | Revert "Alerting: Managed routes access control UI" — access control UI for notification policies rolled back | Phase 5 |
| 23 | `e775bda9ca5` | 6 | MEDIUM | kminehart | 2026-03-24 | CI: fix codeql-analysis missing permission — workflow had global write instead of job-scoped permission | Phase 3 (KB) |
| 24 | `beb47f4176d` | 3 | LOW | jguer | 2026-04-10 | Use SHA-256 for Gravatar email hashes — MD5 replaced for privacy (not crypto security) | record only |

---

## Category 1: Dangerous Pattern Introduction

### [77350ce84f6] CloudMigrations: Unsanitized request params (CodeQL)
- **Commit**: `77350ce84f68611da904f321399f1bc231f6cea7`
- **Author**: Matheus Macabu <macabu@users.noreply.github.com>
- **Date**: 2025-02-21
- **Files**: `pkg/services/cloudmigration/gmsclient/gms_client.go`
- **Pattern**: `fmt.Sprintf("%s/api/v1/validate-key", c.buildBasePath(cm.ClusterSlug))` — `ClusterSlug` was interpolated directly into URLs without sanitization, allowing path injection
- **Discovery source**: Generic baseline (CodeQL mention + unsanitized params pattern)
- **Risk**: MEDIUM
- **FP assessment**: Fixed by replacing `buildBasePath` with `buildURL` that parses and validates URLs. CodeQL flagged this, meaning it was a real injection path before the fix.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: cloud migration client URL construction)

### [053ee5cb1f4] Frontend Sandbox: innerHTML missing DOMPurify
- **Commit**: `053ee5cb1f4e335b90e12f033e5e5f15b6a579fa`
- **Author**: Esteban Beltran <academo@users.noreply.github.com>
- **Date**: 2025-03-19
- **Files**: `public/app/features/plugins/sandbox/distortion_map.ts`
- **Pattern**: Plugin sandbox was distorting `innerHTML` setter but not sanitizing on events like `onerror`/`onload`/`onsuccess`/`onbeforeunload`, allowing XSS via those attributes
- **Discovery source**: Generic baseline (innerHTML + DOMPurify pattern)
- **Risk**: MEDIUM
- **FP assessment**: Production plugin sandbox code. Before the fix, plugins running in the sandbox could set `innerHTML` to content with event handler attributes without sanitization.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

### [561156c4da9] Auth: TlsSkipVerify parameter for JWT Auth
- **Commit**: `561156c4da99701bd95914c807a74af427e83ade`
- **Author**: Filip "Ret2Me" Poplewski <37419029+Ret2Me@users.noreply.github.com>
- **Date**: 2025-03-03
- **Files**: `pkg/services/auth/jwt/key_sets.go`, `conf/defaults.ini`, `pkg/setting/setting_jwt.go`
- **Pattern**: `InsecureSkipVerify: s.Cfg.JWTAuth.TlsSkipVerify` — new configuration option that allows disabling TLS certificate verification for JWT key fetching
- **Discovery source**: Generic baseline (InsecureSkipVerify pattern)
- **Risk**: MEDIUM (low by default, but introduces dangerous capability)
- **FP assessment**: Not a false positive. The feature adds ability for administrators to bypass TLS certificate verification in JWT auth flows — a security downgrade if misconfigured. Default is `false`.
- **Downstream**: Phase 5 (deep-probe: JWT auth key fetching)

### [b20b2cb7962] Fix XSS in SearchableList
- **Commit**: `b20b2cb7962b4cf9ee0cbf24a28aed1042e7791e`
- **Author**: Jev Forsberg <jev.forsberg@grafana.com>
- **Date**: 2026-04-07
- **Files**: `public/app/core/components/SearchableList/SearchableList.tsx`
- **Pattern**: `dangerouslySetInnerHTML` replaced with safe `HighlightedLabel` component
- **Discovery source**: Generic baseline (dangerouslySetInnerHTML pattern)
- **Risk**: LOW
- **FP assessment**: Commit message explicitly says "Fix XSS" — the previous implementation used `dangerouslySetInnerHTML` to render highlighted search matches, which would have allowed XSS if the search query contained HTML.
- **Downstream**: Phase 5

---

## Category 2: Security Control Weakening

### [0fc29cbaae0] Rendering: Remove SVG Sanitization
- **Commit**: `0fc29cbaae095dc6f87bb69d768544866567ea8c`
- **Author**: Mariell Hoversholm <mariell.hoversholm@grafana.com>
- **Date**: 2025-08-19
- **Files**: `pkg/services/rendering/interface.go`, `pkg/services/rendering/capabilities.go`, `pkg/server/wire_gen.go`, `pkg/server/wire.go`, `pkg/registry/backgroundsvcs/background_services.go`
- **Pattern**: Entire `sanitizer.ProvideService` wire dependency removed. `SanitizeSVGRequest`, `SanitizeSVGResponse`, `sanitizeFunc`, `SanitizeSVG()` method removed from `Service` interface. `SVGSanitization` capability removed.
- **Discovery source**: Generic baseline (SanitizeSVG, sanitizer removal)
- **Risk**: HIGH
- **FP assessment**: The SVG sanitization service was a background service registered at startup. Its removal means Grafana no longer sanitizes SVG content through the rendering service. SVG can contain embedded scripts and XSS vectors. Need to verify if sanitization moved elsewhere or was genuinely dropped.
- **Downstream**: Phase 5 (deep-probe: SVG upload/rendering path, what sanitizes SVGs now?)

### [a8b373144f6] Fix: Batch requests bypass Grafana's credential proxy
- **Commit**: `a8b373144f6eeb4ecb5fa3820b8873a1c12b2df9`
- **Author**: Andrew Hackmann <ajhack93@gmail.com>
- **Date**: 2026-04-01
- **Files**: `pkg/tsdb/azuremonitor/azuremonitor.go`, `pkg/tsdb/azuremonitor/routes.go`
- **Pattern**: Azure Monitor batch metrics requests (`azureMonitorBatchMetrics`) were using the ARM audience HTTP client instead of a dedicated `metrics.monitor.azure.com` audience client, causing credentials to be sent to the wrong audience or bypass the proxy credential check.
- **Discovery source**: Generic baseline (credential proxy bypass term)
- **Risk**: HIGH
- **FP assessment**: Commit message explicitly states "fix batch requests bypass Grafana's credential proxy". Before fix, batch calls used the ARM-scoped client for a different Azure service domain, potentially sending tokens scoped for ARM to a different endpoint.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: Azure Monitor data source batch endpoint)

### [246a55e9e71] Revert "Alerting: Managed routes access control UI"
- **Commit**: `246a55e9e712d624bc7c7a8c0f64a2704969ee1f`
- **Author**: Rodrigo Vasconcelos de Barros <rodrigopk@gmail.com>
- **Date**: 2026-04-07
- **Files**: Alerting notification policy UI components
- **Pattern**: Access control UI for alerting managed routes (`ActionAlertingManagedRoutes*`) rolled back — reverts commit `ef1ab9b5572` which added K8s-annotation-based access control (canWrite, canDelete, canAdmin) for notification policies
- **Discovery source**: Category 4 revert analysis
- **Risk**: HIGH (in terms of missing security control, but may be intentional temporary rollback)
- **FP assessment**: The original commit `ef1ab9b5572` added access control for alerting managed routes. The revert removes that access control, leaving managed notification route administration unprotected by per-resource annotations. This is a genuine security control regression.
- **Downstream**: Phase 5 (verify current state of managed route authorization)

### [92e6ba2c2de] fix user_auth updates
- **Commit**: `92e6ba2c2de13898983abff0cd22beca4dc9a850`
- **Author**: Mihai Doarna <mihai.doarna@grafana.com>
- **Date**: 2026-03-10
- **Files**: `pkg/services/login/authinfoimpl/store.go`
- **Pattern**: SQL WHERE clause logic inverted — previously `UserUID != ""` took priority, now `UserId > 0` takes priority. The `upd > 1` duplicate cleanup check now only runs when `UserId > 0`.
- **Discovery source**: Project vocab discovery (auth store, user_auth)
- **Risk**: MEDIUM
- **FP assessment**: The logic inversion could affect how OAuth token updates are applied. If a user record has both `UserId` and `UserUID`, the behavior changes. The `upd > 1` check being skipped for UID-based updates means duplicate `user_auth` entries are no longer cleaned up in that path.
- **Downstream**: Phase 5 (deep-probe: auth token update race conditions)

---

## Category 3: Silent Security Fixes

### [1fa4fdf0adc] patch(security): Fix dashboard permission vulnerability
- **Commit**: `1fa4fdf0adcb67eeccd91abfdd045b0e8e15484b`
- **Author**: Mihai Turdean <6640685+mihai-turdean@users.noreply.github.com>
- **Date**: 2026-01-07
- **Files**: `pkg/api/api.go`
- **Pattern**: `authorize(ac.EvalPermission(dashboards.ActionDashboardsPermissionsRead, dashUIDScope))` — scope added to permission check that previously lacked it
- **Discovery source**: Generic baseline (authorize + missing scope) + security patch prefix
- **Risk**: HIGH
- **Confidence**: HIGH (3/3 signals: production auth code, vague commit for what is actually an IDOR fix, security-critical path)
- **FP assessment**: The commit title "Fix dashboard permission vulnerability" is unambiguous. Without scope binding, any user with global `dashboards.permissions:read` action could enumerate permissions of any dashboard — IDOR vulnerability. Backported to multiple release branches. No CVE/GHSA reference found.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: `/api/dashboards/uid/:uid/permissions`, `/api/dashboards/id/:dashboardId/permissions`)

### [393de2d7c66] patch(security): add missing scope check on dashboards
- **Commit**: `393de2d7c66be26f25af38f29a14141f2e5be5e3`
- **Author**: Jo Garnier <git@jguer.space>
- **Date**: 2026-01-02
- **Files**: `pkg/api/api.go`
- **Pattern**: Same as `1fa4fdf0adc` — scope added to UID route dashboard permission authorization
- **Discovery source**: Security patch prefix
- **Risk**: HIGH
- **Confidence**: HIGH (all 3 signals)
- **FP assessment**: Companion commit to `1fa4fdf0adc`. Multiple security patch variants (`0f182e66b0f`, `3cde34e12f8`, `8c8bd0d731b`, `393de2d7c66`) exist for different release branches, then publicly backported to release branches with the message "Add missing scope check on dashboards".
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

### [85c811ef4b8] fix: disable render_key auth when renderer is disabled
- **Commit**: `85c811ef4b8a541a4e3688d7eef88eec7166224a`
- **Author**: Mariell Hoversholm <mariell.hoversholm@grafana.com>
- **Date**: 2026-04-10
- **Files**: `pkg/services/rendering/auth.go`, `pkg/services/rendering/auth_test.go`
- **Pattern**: `if rs.perRequestRenderKeyProvider == nil { return nil, false }` — early return added when renderer is not configured
- **Discovery source**: Generic baseline (authentication bypass pattern) + project vocab
- **Risk**: HIGH
- **Confidence**: HIGH (3/3 signals: production auth code, message says "fix" without security terminology, rendering auth path)
- **FP assessment**: Commit message explains: "we just permit any key that is correctly signed, which could lead to dashboard reads we never fail on startup for if the key is default." — authenticated rendering could be triggered with the default HMAC secret even without a renderer configured. Backported to release-13.0.0 and release-13.0.1.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: `/render/*` authenticated endpoints)

### [dc9ac13e84a] fix: harden query history authorization and search response accuracy
- **Commit**: `dc9ac13e84a1d023e2e1395fad294f401b6bcfb4`
- **Author**: Nic Westvold <nic.westvold@grafana.com>
- **Date**: 2026-03-23
- **Files**: `pkg/registry/apis/queryhistory/`, `pkg/registry/apps/queryhistory/register.go`, `pkg/services/queryhistory/`
- **Pattern**: `NamespaceScopedStorageAuthorizerProvider` added to filter list/get results by `created-by` label in Mode5; authorizer changed to deny on transient storage errors instead of failing open
- **Discovery source**: Project vocab (authorizer, fail-open/fail-closed)
- **Risk**: HIGH
- **Confidence**: HIGH (3/3 signals: production auth code, commit says "harden" without CVE, query history auth path)
- **FP assessment**: Commit message explicitly says "preventing cross-user data leakage in Mode5 list/get" and "deny on transient storage errors instead of failing open." These are two separate security issues: information disclosure and fail-open to fail-closed.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: query history list/get API in Mode5)

### [d7322d91f31] SQL: strip comments with quote-aware state machine in PostgreSQL and MSSQL
- **Commit**: `d7322d91f318e641e431558b8024864722c62856`
- **Author**: Adam Yeats <16296989+adamyeats@users.noreply.github.com>
- **Date**: 2026-04-08
- **Files**: `pkg/tsdb/grafana-postgresql-datasource/macros.go`, `pkg/tsdb/mssql/sqleng/macros.go`
- **Pattern**: Replaced regex-based SQL comment stripping (`reBlockComment`, `reLineComment`) with a character-by-character state machine that respects single-quoted strings, double-quoted identifiers, and dollar-quoted strings
- **Discovery source**: Generic baseline (SQL comment stripping / SELECT pattern)
- **Risk**: HIGH
- **Confidence**: HIGH (3/3 signals: SQL datasource production code, "SQL: strip comments" message with no CVE, SQL macro processing path)
- **FP assessment**: The old regex `/\*.*?\*/` and `--[^\n]*` would strip comments inside quoted strings, potentially truncating valid SQL. More critically, a malicious user could craft SQL with comment-like sequences inside strings to bypass the comment filter and inject SQL content. Backported to multiple release branches.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: PostgreSQL and MSSQL macros)

### [7a57284e18a] MySQL: Preserve # inside quoted strings in SQL comment stripping
- **Commit**: `7a57284e18ace584c828c99576a8e7e51d36e7be`
- **Author**: Karthik Idikuda <74087332+karthik-idikuda@users.noreply.github.com>
- **Date**: 2026-04-02
- **Files**: `pkg/tsdb/mysql/macros.go`, `pkg/tsdb/mysql/macros_test.go`
- **Pattern**: Replaced `#[^\n]*` regex with character-by-character state machine that tracks quoted string context
- **Discovery source**: Generic baseline (SQL + regex strip pattern)
- **Risk**: HIGH
- **Confidence**: HIGH (3/3 signals: MySQL datasource production code, benign-sounding "Preserve #" message, SQL macro path)
- **FP assessment**: The commit message explains: "The stripSQLComments function used a naive regex that stripped everything after # even when it appeared inside single-quoted, double-quoted, or backtick-quoted SQL strings." This could cause SQL injection if a template variable contained `#` inside a quoted value that was then incorrectly truncated, altering query structure.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: MySQL datasource template variable interpolation)

### [07d136f66c5] Sanitize paths before evaluating access to route
- **Commit**: `07d136f66c59a7597c00cc0e2133001f15c5f9d6`
- **Author**: Andres Martinez Gotor <andres.martinez@grafana.com>
- **Date**: 2025-03-31
- **Files**: `pkg/api/pluginproxy/ds_proxy.go`
- **Pattern**: `util.CleanRelativePath(proxy.proxyPath)` applied before prefix check — previously `strings.HasPrefix(proxy.proxyPath, route.Path)` without normalization
- **Discovery source**: Generic baseline (path sanitization pattern)
- **Risk**: HIGH
- **Confidence**: HIGH (3/3 signals: datasource proxy production code, vague "Sanitize paths" message, data source proxy path)
- **FP assessment**: Test added explicitly demonstrates `//api//admin` bypasses old check. The security patch file name (`357-202503311017.patch`) confirms internal security tracking. Backported to many release branches (5+).
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: data source proxy route access control)

### [7d62590d000] Expressions: Add memory limit for math expression binary operations
- **Commit**: `7d62590d00088e691d8b5a8ba9f613cf285da736`
- **Author**: William Wernert <william.wernert@grafana.com>
- **Date**: 2026-04-07
- **Files**: `pkg/services/expr/`, `conf/defaults.ini`
- **Pattern**: `WithMemoryLimit(limit int64)` option added; pre-execution cartesian explosion estimate prevents OOM
- **Discovery source**: Generic baseline (memory limit pattern)
- **Risk**: HIGH
- **Confidence**: HIGH (3/3 signals: expression evaluation engine production code, "Add memory limit" message without DoS/security terms, expression evaluation path)
- **FP assessment**: Commit message: "Prevent OOM kills from cartesian explosions when label sets diverge in binary operations like $A || $B." This is a DoS vulnerability where a malicious query could cause Grafana to exhaust memory and crash. Default limit 1 GiB.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (attack surface: math expressions in alerting/query evaluation)

### [329327952e9] Alerting: Add protected fields authorization check to provisioning API
- **Commit**: `329327952e9bc785fddfbd3b1f1e70d64aa42778`
- **Author**: Yuri Tseretyan <yuriy.tseretyan@grafana.com>
- **Date**: 2026-03-17
- **Files**: `pkg/services/ngalert/api/api_provisioning.go`, `pkg/services/ngalert/provisioning/contactpoints.go`
- **Pattern**: `ProtectedFieldsAuthz` interface and `HasUpdateProtected`/`AuthorizeUpdateProtected` methods added to contact point update path
- **Discovery source**: Project vocab (authorization, permission enforcement)
- **Risk**: MEDIUM
- **Confidence**: MEDIUM (2/3 signals: alerting provisioning production code, message mentions "authorization check" but includes "protected fields" context)
- **FP assessment**: Users with provisioning API write access could previously modify contact point "protected fields" (likely sensitive notification settings like Slack tokens, PagerDuty keys) without the access control check that the UI enforces. Backported to multiple release branches.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

### [c30a9e2003a] Alerting: Protect /api/v2/status endpoint with dedicated permission
- **Commit**: `c30a9e2003af41bc11b7286f1e7800ee30523b81`
- **Author**: Yuri Tseretyan <yuriy.tseretyan@grafana.com>
- **Date**: 2026-03-25
- **Files**: `pkg/services/accesscontrol/models.go`, alerting API route configuration
- **Pattern**: New `ActionAlertingNotificationSystemStatus` permission required for `GET /api/alertmanager/grafana/api/v2/status`
- **Discovery source**: Project vocab (permission enforcement, dedicated permission)
- **Risk**: MEDIUM
- **Confidence**: MEDIUM (2/3 signals: production alerting auth code, "Protect" + "dedicated permission" in message)
- **FP assessment**: The endpoint previously used the broad `alert.notifications:read` permission which doesn't restrict by resource scope. Granted to any notification reader rather than requiring admin-level access to system status.
- **Downstream**: Phase 2 (undisclosed-fix)

### [9e399e0b19a] Data Source: Proxy fallback routes must match all inputs
- **Commit**: `9e399e0b19a713c665baa7e06bcfb5af16774ebb`
- **Author**: Mariell Hoversholm <mariell.hoversholm@grafana.com>
- **Date**: 2026-01-14
- **Files**: `pkg/api/pluginproxy/ds_proxy.go`
- **Pattern**: Special case for `"."` path added — empty proxy path was being normalized to `"."` by `CleanRelativePath`, then matching any route prefix
- **Discovery source**: Project vocab (CleanRelativePath, route access)
- **Risk**: MEDIUM
- **Confidence**: HIGH (3/3 signals: datasource proxy production code, vague "must match all inputs" message, proxy route validation path)
- **FP assessment**: References issue #116273. When `proxyPath` was empty and `CleanRelativePath` returned `"."`, the prefix check `strings.HasPrefix(".", "")` would always succeed, bypassing route access restrictions. Backported to 5 release branches.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

### [7b366ebd007] Dashboard: fail closed on non-404 ReadResponse.Error
- **Commit**: `7b366ebd0071f2a55b032468130fc23869e56c75`
- **Author**: Rafael Paulovic <rafael.paulovic@grafana.com>
- **Date**: 2026-03-25
- **Files**: `pkg/registry/apis/dashboard/register.go`
- **Pattern**: Delete hook changed: only 404 errors allowed as "not found" — 403/5xx now explicitly return error (fail closed)
- **Discovery source**: Generic baseline (fail-open/fail-closed pattern)
- **Risk**: MEDIUM
- **Confidence**: HIGH (3/3 signals: dashboard delete hook production code, vague message about "non-404 error", dashboard provisioning path)
- **FP assessment**: Commit message: "Previously these were treated as 'not found' and allowed deletion, bypassing provisioning protection." A 403 from storage would be silently treated as "not found", allowing deletion of a provisioned dashboard that should be protected.
- **Downstream**: Phase 2 (undisclosed-fix)

### [2e51ce6e4e8] Annotations: fix permission check using subresource
- **Commit**: `2e51ce6e4e88891cde1f0f7586cd11bf7439afc1`
- **Author**: Gabriel MABILLE <gamab@users.noreply.github.com>
- **Date**: 2026-04-08
- **Files**: `pkg/services/authz/rbac/mapper.go`
- **Pattern**: Virtual annotations resource removed from RBAC action mapper; subresource authorization path corrected
- **Discovery source**: Project vocab (permission check, RBAC)
- **Risk**: MEDIUM
- **Confidence**: MEDIUM (2/3 signals: production auth code, message says "fix permission check")
- **FP assessment**: RBAC action mapping for annotation subresources was incorrect, potentially allowing or denying access incorrectly to annotation-related operations.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

### [07b7c08939c] Alerting: Fix missing permission check for routing preview
- **Commit**: `07b7c08939c82868188cd99f32b16dac7f384567`
- **Author**: Rodrigo Vasconcelos de Barros <rodrigopk@gmail.com>
- **Date**: 2026-04-10
- **Files**: `public/app/features/alerting/unified/components/notificaton-preview/NotificationPreview.tsx`
- **Pattern**: Permission check added to routing preview UI component
- **Discovery source**: Generic baseline (missing permission check)
- **Risk**: MEDIUM
- **Confidence**: MEDIUM (2/3 signals: production alerting code, "Fix missing permission check" explicit)
- **FP assessment**: The alerting routing preview endpoint was accessible without permission checks. This is a frontend-only check but reveals the underlying API endpoint likely needs review too.
- **Downstream**: Phase 2 (undisclosed-fix)

### [04f39457cf9] Chore: Remove sensitive information from presigned URLs prior to logging
- **Commit**: `04f39457cf944af7afccc1d1684639ea9f2ac184`
- **Author**: Marcus Andersson <marcus.andersson@grafana.com>
- **Date**: 2024-06-24
- **Files**: `pkg/api/pluginproxy/ds_proxy.go`, `pkg/middleware/loggermw/logger.go`, `pkg/util/uri_sanitize.go`
- **Pattern**: `SanitizeURI()` applied to `proxy.ctx.Req.RequestURI` and `r.Referer()` before logging — previously `auth_token` query parameter was logged in plaintext
- **Discovery source**: Generic baseline (presigned URL + sensitive info pattern)
- **Risk**: MEDIUM
- **Confidence**: MEDIUM (2/3 signals: production middleware code, "Chore" prefix disguises security fix)
- **FP assessment**: `auth_token` was a sensitive query string parameter logged by the middleware. Pre-fix, any request with `?auth_token=...` would write the token to logs. New `SanitizeURI` utility strips the parameter.
- **Downstream**: Phase 2 (undisclosed-fix)

### [beb47f4176d] Use SHA-256 for Gravatar email hashes
- **Commit**: `beb47f4176d40b7f4fa5f0768fb79ab9f58ba779`
- **Author**: Jo Garnier <git@jguer.space>
- **Date**: 2026-04-10
- **Files**: `pkg/api/avatar/avatar.go`, `pkg/api/dtos/models.go`
- **Pattern**: MD5 replaced with SHA-256 for Gravatar email hash
- **Discovery source**: Generic baseline (MD5 hash pattern)
- **Risk**: LOW
- **FP assessment**: This follows Gravatar's own API update. Reduces email re-identification risk via rainbow tables on MD5 hashes in the avatar URL, but not a traditional security vulnerability.
- **Downstream**: record only

---

## Category 4: Reverted Security Fixes

### [246a55e9e71] Revert "Alerting: Managed routes access control UI"
- **Commit**: `246a55e9e712d624bc7c7a8c0f64a2704969ee1f`
- **Author**: Rodrigo Vasconcelos de Barros <rodrigopk@gmail.com>
- **Date**: 2026-04-07
- **Original commit**: `ef1ab9b55721d1f05068ed3483d506fce60229bf` (2026-04-02)
- **Files**: Alerting notification policy UI components (`NotificationPreview.tsx`, `PoliciesList.tsx`, `Policy.tsx`)
- **Pattern**: Reverted commit that wired K8s access-control annotations (`grafana.com/access/canWrite`, `canDelete`, `canAdmin`) to notification policy UI controls
- **Risk**: HIGH
- **FP assessment**: The original commit added `ActionAlertingManagedRoutes*` access control actions. The revert removes those controls from the UI. The commit was reverted 5 days after being merged — no replacement was immediately committed. Policy administration is now gated only at the API level (if at all), not the UI.
- **Downstream**: Phase 5 (verify if API-level controls still exist after UI revert)

---

## Category 5: Secret Archaeology

### No real-credential commits found
AWS key pattern matches were all in Yarn lockfile binaries (not real credentials). The `github-with-inline-secrets.json.tmpl` file deleted in `85a00bb6c86` was a test template using Go template variables (`{{ .SecureTokenCreate }}`), not real credentials.

The presigned URL logging fix `04f39457cf9` (Category 3) is the closest finding — `auth_token` parameters were being written to logs, but no actual credentials were found committed to the repository.

---

## Category 6: CI/CD Pipeline Weakening

### [e775bda9ca5] CI: fix codeql-analysis missing permission
- **Commit**: `e775bda9ca5d3bb7234d7f373ccd37b9a185f72b`
- **Author**: Kevin Minehart Tenorio <5140827+kminehart@users.noreply.github.com>
- **Date**: 2026-03-24
- **Files**: `.github/workflows/codeql-analysis.yml`
- **Pattern**: Moved `security-events: write` from top-level `permissions` to job-scoped permissions within the upload step
- **Discovery source**: CI/CD pattern search (security-events permission)
- **Risk**: MEDIUM
- **FP assessment**: The original workflow had `permissions: security-events: write` at the top level, granting all jobs in the workflow write access to security events. The fix scopes it correctly to only the upload step. This is a positive security improvement (the pre-fix state was the weakness), but the pre-fix state could allow a compromised action in the workflow to write arbitrary SARIF to code scanning.
- **Downstream**: Phase 3 (KB: supply-chain risk note)

---

## Category 7: Suspicious Commit Patterns

### [0ad10c481e4] Deps(remove-me): Update authlib for testing
- **Commit**: `0ad10c481e434fa2f6f8fb22541683dc501d09b2`
- **Author**: Matheus Macabu <macabu.matheus@gmail.com>
- **Date**: 2026-04-07
- **Files**: Multiple `go.mod`/`go.sum` files across apps
- **Pattern**: Commit message `Deps(remove-me): Update authlib for change but remove me, just to test` — test commit on security-critical library (authlib) left in main branch history
- **Discovery source**: Category 7 pattern analysis
- **Risk**: LOW
- **FP assessment**: This appears to be a development test commit for updating the authlib dependency that was accidentally left in the commit history. The authlib package handles authentication. While this specific commit appears harmless (just go.mod changes), it demonstrates insufficient commit hygiene on security-critical dependency changes.
- **Downstream**: record only

---

## HIGH-Risk Commit Feed for Phase 2 (patch-bypass-checker)

The following commits should be fed to `patch-bypass-checker` agents as `type: undisclosed-fix`:

| Priority | SHA | Type | Component | Description |
|----------|-----|------|-----------|-------------|
| 1 | `1fa4fdf0adcb67eeccd91abfdd045b0e8e15484b` | undisclosed-fix | dashboard permissions API | IDOR: missing scope check on dashboard permissions routes |
| 2 | `393de2d7c66be26f25af38f29a14141f2e5be5e3` | undisclosed-fix | dashboard permissions API | IDOR: missing scope check on dashboard permissions routes (UID path) |
| 3 | `85c811ef4b8a541a4e3688d7eef88eec7166224a` | undisclosed-fix | rendering auth | render_key accepted without renderer configured |
| 4 | `dc9ac13e84a1d023e2e1395fad294f401b6bcfb4` | undisclosed-fix | query history | fail-open + cross-user data leakage in Mode5 |
| 5 | `d7322d91f318e641e431558b8024864722c62856` | undisclosed-fix | PostgreSQL/MSSQL macros | SQL comment injection via quoted-string bypass |
| 6 | `7a57284e18ace584c828c99576a8e7e51d36e7be` | undisclosed-fix | MySQL macros | SQL comment injection via quoted-string bypass |
| 7 | `07d136f66c59a7597c00cc0e2133001f15c5f9d6` | undisclosed-fix | datasource proxy | path traversal via unnormalized proxy path |
| 8 | `a8b373144f6eeb4ecb5fa3820b8873a1c12b2df9` | undisclosed-fix | Azure Monitor datasource | batch requests use wrong credential audience |
| 9 | `7d62590d00088e691d8b5a8ba9f613cf285da736` | undisclosed-fix | math expressions engine | OOM DoS via cartesian label explosion |
| 10 | `329327952e9bc785fddfbd3b1f1e70d64aa42778` | undisclosed-fix | alerting provisioning API | protected contact point fields modifiable via provisioning |
| 11 | `9e399e0b19a713c665baa7e06bcfb5af16774ebb` | undisclosed-fix | datasource proxy | empty path bypasses route access control |
| 12 | `7b366ebd0071f2a55b032468130fc23869e56c75` | undisclosed-fix | dashboard delete hook | 403/5xx treated as 404, bypassing provisioning protection |

---

## Phase 5 Attack Surface Hints (from HIGH-risk commit paths)

- `pkg/api/api.go` — dashboard permission routes (IDOR scope binding)
- `pkg/services/rendering/auth.go` — render key validation when renderer not configured
- `pkg/registry/apis/queryhistory/` — query history list/get Mode5 namespace scoping
- `pkg/tsdb/grafana-postgresql-datasource/macros.go` — PostgreSQL comment stripping in template macros
- `pkg/tsdb/mssql/sqleng/macros.go` — MSSQL comment stripping in template macros
- `pkg/tsdb/mysql/macros.go` — MySQL hash-comment stripping in template macros
- `pkg/api/pluginproxy/ds_proxy.go` — datasource proxy path normalization and route matching
- `pkg/tsdb/azuremonitor/` — Azure Monitor batch endpoint credential audience selection
- `pkg/services/expr/` — math expression binary operation memory limits
- `pkg/services/ngalert/provisioning/contactpoints.go` — alerting contact point protected field authorization
- `pkg/services/store/sanitizer/` — SVG sanitization service (removed, verify alternative)
- `public/app/features/plugins/sandbox/distortion_map.ts` — plugin sandbox innerHTML distortion

