# Grafana Phase 4 - CodeQL Flow Paths (All Severities)

**Generated:** 2026-03-20  
**CodeQL Version:** 2.25.0  
**Database:** security/codeql-artifacts/db/ (1,035,634 lines, Go)  
**Suites Run:** go-security-extended.qls, go-security-experimental.qls

---

## Critical / High Severity Flow Paths

### FLOW-001: Public Dashboard Annotation Timerange Bypass (CVE-2026-21722)
**CWE:** CWE-284 (Improper Access Control)  
**Severity:** CRITICAL  
**File:** `pkg/services/publicdashboards/api/query.go:96-97` -> `pkg/services/annotations/annotationsimpl/xorm_store.go:389`

**Source:** `c.QueryInt64("from")` / `c.QueryInt64("to")` (anonymous HTTP request)  
**Sink:** `sql.WriteString(AND a.epoch <= ? AND a.epoch_end >= ?)` — omitted when From=0 AND To=0

**Flow:**
```
GET /api/public/dashboards/:token/annotations?from=0&to=0
  -> GetPublicAnnotations handler (no auth, accessToken only)
  -> AnnotationsQueryDTO{From: c.QueryInt64("from"), To: c.QueryInt64("to")}
  -> FindAnnotations(ctx, reqDTO, accessToken)
  -> xorm_store.Get: if query.From > 0 && query.To > 0 { /* omitted */ }
  -> Returns ALL annotations for org (no time filter)
```

---

### FLOW-002: Datasource Proxy Parser Differential (CVE-2025-3454 residual)
**CWE:** CWE-22 (Path Traversal)  
**Severity:** HIGH  
**File:** `pkg/api/pluginproxy/ds_proxy.go:212`

**Source:** `proxy.proxyPath` (extracted from URL, route-matched on encoded form)  
**Sink:** `req.URL.Path = url.PathUnescape(req.URL.RawPath)` — decoded AFTER route matching

**Flow:**
```
ANY /api/datasources/proxy/uid/:uid/%2Fetc%2Fpasswd
  -> extractProxyPath: path stripped of /api/datasources/proxy/uid/UID/
  -> CleanRelativePath: normalizes double-slash but NOT %2F
  -> route matching on encoded path ("%2F" != "/")
  -> director(): url.PathUnescape -> "/etc/passwd"
  -> Backend receives /etc/passwd instead of matched route path
```

---

### FLOW-003: http.ServeFile Without Path Confinement (DFD-2)
**CWE:** CWE-22 (Path Traversal)  
**Severity:** HIGH  
**File:** `pkg/api/render.go:122`

**Source:** `result.FilePath` from `getNewFilePath()` (currently safe - random 20-char)  
**Sink:** `http.ServeFile(c.Resp, c.Req, result.FilePath)` — no runtime confinement assertion

**Flow:**
```
GET /render/*
  -> getNewFilePath() -> filepath.Abs(filepath.Join(folder, random.ext))
  -> writeResponseToFile -> os.Create(filePath) [nolint:gosec]
  -> http.ServeFile(c.Resp, c.Req, result.FilePath)  [no strings.HasPrefix check]
```
**Note:** Currently safe because filePath derives from random string. Defense-in-depth missing.

---

### FLOW-004: Plugin Zip Extraction Symlink Traversal (DFD-4)
**CWE:** CWE-22 (Path Traversal)  
**Severity:** HIGH  
**File:** `pkg/plugins/storage/fs.go:99`  
**CodeQL Rule:** `go/unsafe-unzip-symlink`

**Source:** `zf.Name` (archive header from zip file)  
**Sink:** `os.Symlink(symlinkPath, filePath)`

**Flow:**
```
Plugin install: ZIP file extraction
  -> extractPackage() iterates zf entries
  -> ZipSlip check: filepath.HasPrefix passes
  -> isSymlink(zf) -> extractSymlink(installDir, zf, dstPath)
  -> symlink target read from archive contents
  -> isSymlinkRelativeTo check (may not cover all traversal variants)
  -> os.Symlink(symlinkPath, filePath)
```

---

### FLOW-005: SQL Injection in Dashboard Legacy API (New Finding)
**CWE:** CWE-89 (SQL Injection)  
**Severity:** HIGH  
**File:** `pkg/registry/apis/dashboard/legacy/sql_dashboards.go:151`  
**CodeQL Rule:** `go/sql-injection`

**Source:** `pkg/registry/apis/provisioning/request.go:23` (user-provided value)  
**Sink:** SQL query in sql_dashboards.go

**Flow:**
```
POST /apis/dashboard.grafana.app/* (provisioning API)
  -> pkg/registry/apis/provisioning/request.go:23 (user input binding)
  -> pkg/registry/apis/dashboard/legacy/sql_dashboards.go:151 (SQL query)
```

---

### FLOW-006: SQL Injection in Unified Storage DB (New Finding)
**CWE:** CWE-89 (SQL Injection)  
**Severity:** HIGH  
**File:** `pkg/storage/unified/sql/db/dbimpl/db.go:36,63`  
**CodeQL Rule:** `go/sql-injection`

**Source:** `pkg/registry/apis/dashboard/search.go:387` (user-provided search params)  
**Sink:** SQL query in db.go

---

### FLOW-007: JWT Parsed Without Signature Verification (CFD-1)
**CWE:** CWE-347 (Missing Cryptographic Signature Verification)  
**Severity:** HIGH  
**File:** `pkg/services/authn/clients/ext_jwt.go:346`  
**CodeQL Rule:** `go/missing-jwt-signature-check`

**Source:** Bearer token from HTTP Authorization header  
**Sink:** `parsedToken.UnsafeClaimsWithoutVerification(&claims)`

**Note:** This is inside `verifyRFC9068TokenWithoutVerification()` which appears to be a pre-validation helper (checking token format before full verification). Requires triage to confirm whether this is intentional.

---

### FLOW-008: SSRF in Cloud Migration Client (New Finding)
**CWE:** CWE-918 (SSRF)  
**Severity:** HIGH  
**File:** `pkg/services/cloudmigration/gmsclient/gms_client.go:63,266`  
**CodeQL Rule:** `go/ssrf` / `go/request-forgery`

**Source:** User-provided migration target URL  
**Sink:** HTTP request to user-controlled URL

---

### FLOW-009: CSRF Header Bypass via User-Controlled Values (CFD-2)
**CWE:** CWE-352 (CSRF)  
**Severity:** HIGH  
**File:** `pkg/middleware/csrf/csrf.go:122,135`  
**CodeQL Rule:** `go/user-controlled-bypass`

**Source:** `r.Header.Get(customCsrfHeader)` (user-controlled) compared to `r.Header.Get("Origin")` (also user-controlled)  
**Sink:** `trustedOrigin = true` bypass

**Note:** Only exploitable when `csrf_additional_headers` is configured (non-default).

---

### FLOW-010: X-DS-Authorization Header Injection (DFD-1)
**CWE:** CWE-116 (Header Injection)  
**Severity:** HIGH  
**File:** `pkg/api/pluginproxy/ds_proxy.go:230-233`

**Source:** `r.Header.Get("X-DS-Authorization")` (user-controlled HTTP header)  
**Sink:** `req.Header.Set("Authorization", dsAuth)` forwarded to backend datasource

---

## Medium Severity Findings

### FLOW-011: Path Injection in Static File Server (DFD-4)
**CWE:** CWE-22  
**Severity:** MEDIUM  
**Files:** `pkg/api/static/static.go:143,177`  
**CodeQL Rule:** `go/path-injection`

---

### FLOW-012: Reflected XSS in Response Writer (TB9)
**CWE:** CWE-79  
**Severity:** MEDIUM  
**Files:** `pkg/web/response_writer.go:100`, `pkg/services/apiserver/builder/custom_route_metrics.go:55`  
**CodeQL Rule:** `go/reflected-xss`

---

### FLOW-013: Datasource TOCTOU - Stale ReadOnly Check (DFD-5)
**CWE:** CWE-362  
**Severity:** MEDIUM  
**File:** `pkg/api/datasources.go:306` (Semgrep: `grafana-readwrite-check-outside-transaction`)

---

### FLOW-014: TLS InsecureSkipVerify in Production Code
**CWE:** CWE-295  
**Severity:** MEDIUM  
**Files:** `pkg/storage/unified/resource/tenant_watcher.go:102`, `pkg/storage/unified/resource/client.go:145`

---

### FLOW-015: String-Formatted SQL Queries in xorm Dialect
**CWE:** CWE-89  
**Severity:** MEDIUM  
**Files:** `pkg/util/xorm/dialect_postgres.go:972,1073,1114`, `pkg/util/xorm/dialect_sqlite3.go:254`  
**Note:** Semgrep finding; xorm dialect functions are typically internal/schema-level, not user-data bearing. Requires triage.

---

### FLOW-016: MarkdownCell noSanitize Controlled by Field Data
**CWE:** CWE-79  
**Severity:** MEDIUM  
**File:** `packages/grafana-ui/src/components/Table/TableNG/Cells/MarkdownCell.tsx:23`  
**Semgrep Rule:** `grafana-renderMarkdown-disableSanitizeHtml-variable`

---

---

## Audit 2026-03-21 -- New High-Priority Flow Paths

### FLOW-017: SQL Expression INTO OUTFILE File Write (CVE-2024-9264)
**CWE:** CWE-73 (External Control of File Name or Path)
**Severity:** HIGH
**Files:** `pkg/expr/sql/parser_allow.go:113`, `pkg/expr/sql/db.go:71,82`
**Tool:** Semgrep custom + CodeQL custom (SqlExpressionIntoOutfileFileWrite.ql)

**Source:** User-controlled SQL expression in POST /api/ds/query body
**Sink:** go-mysql-server file write via INTO OUTFILE

**Flow:**
```
POST /api/ds/query {type: sql, expression: "SELECT 1 INTO OUTFILE '/etc/passwd2'"}
  -> Feature flag sqlExpressions=true gate
  -> AllowQuery(name, query): *sqlparser.Into ALLOWED (parser_allow.go:113)
  -> mysql.NewContext(ctx, WithSession(session)) [NO WithDisableFileWrites]
  -> sqle.New(analyzer, &sqle.Config{IsReadOnly: true})
  -> engine.Query(mCtx, query)
  -> plan.Into.IsReadOnly() -> child SELECT.IsReadOnly() -> true [BYPASS]
  -> go-mysql-server writes to filesystem
```

**SAST IDs:** SAST-001, SAST-002

---

### FLOW-018: Avatar Anonymous Auth Bypass DoS (CVE-2026-21720)
**CWE:** CWE-306 (Missing Authentication for Critical Function)
**Severity:** HIGH
**File:** `pkg/api/api.go:605`, `pkg/middleware/auth.go:216`
**Tool:** Semgrep custom + CodeQL custom (AvatarReqSignedInAnonymousBypass.ql)

**Source:** Unauthenticated GET /avatar/:hash with arbitrary hash
**Sink:** Outbound HTTP to Gravatar per unique hash

**Flow:**
```
GET /avatar/<unique_hash> (unauthenticated, anonymous enabled)
  -> reqSignedIn middleware
  -> AllowAnonymous=true (from [auth.anonymous] enabled=true)
  -> requireLogin = !AllowAnonymous || false || false = false
  -> Handler executes without authentication
  -> AvatarCacheServer.Handler: LRU miss for unique hash
  -> http.Get(https://secure.gravatar.com/avatar/<hash>)
  -> Goroutine per unique hash; 2000 concurrent = resource exhaustion
```

**SAST ID:** SAST-003

---

### FLOW-019: K8s Snapshot Delete Cross-Org (CVE-2024-1313 K8s path)
**CWE:** CWE-284 (Improper Access Control)
**Severity:** HIGH
**File:** `pkg/registry/apis/dashboard/snapshot/routes.go:257-275`
**Tool:** Semgrep custom + CodeQL custom (SnapshotK8sApiMissingOrgCheck.ql)

**Source:** Authenticated DELETE with cross-org deleteKey
**Sink:** dashboardsnapshots.DeleteWithKey without org check

**Flow:**
```
DELETE /apis/dashboard.grafana.app/.../snapshots/delete/:deleteKey
  -> identity.GetRequester(ctx) [authenticated, any org]
  -> RBAC: ActionSnapshotsDelete [passes]
  -> vars[deleteKey] from URL path
  -> dashboardsnapshots.DeleteWithKey(ctx, key, service)
  -> DB: DELETE FROM dashboard_snapshot WHERE delete_key=? [no org_id filter]
  -> Snapshot from any org deleted
```

**SAST ID:** SAST-004

---

### FLOW-020: CancelSnapshot Cross-Org via Missing OrgID (CVE-2024-9476)
**CWE:** CWE-284 (Improper Access Control)
**Severity:** HIGH
**Files:** `pkg/services/cloudmigration/cloudmigration.go:33`, `pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go:228`
**Tool:** Semgrep custom + CodeQL custom (CloudMigrationCancelSnapshotMissingOrgId.ql)

**Source:** Admin POST to cancel snapshot with cross-org session_uid/snapshot_uid
**Sink:** SQL UPDATE without org_id WHERE constraint

**Flow:**
```
POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/cancel
  -> CancelSnapshot(ctx, sessionUid, snapshotUid) [no orgID parameter]
  -> s.cancelFunc() + s.updateSnapshotWithRetries
  -> s.store.UpdateSnapshot(ctx, UpdateSnapshotCmd{UID, SessionID, Status: Canceled})
  -> SQL: UPDATE cloud_migration_snapshot SET status=? WHERE session_uid=? AND uid=?
  -> [NO org_id in WHERE] Snapshot from any org updated
```

**SAST ID:** SAST-005, SAST-017

---

## Summary Statistics (Combined Audit 2026-03-20 + 2026-03-21)

| Severity | Count |
|----------|-------|
| HIGH | 13 (9 original + 4 new) |
| MEDIUM | 10 |
| LOW | 4 |
| **Total Unique Flows** | **23** |

| Tool | Suite | Findings |
|------|-------|----------|
| CodeQL | go-security-extended | 379 raw; 13 high-signal unique flows |
| CodeQL | go-security-experimental | 420 raw; adds CORS, allocation overflow |
| CodeQL | custom-queries-5 | 8 findings (5 high-priority targets confirmed) |
| Semgrep | custom rules (Go) | 4 confirmed high-priority findings |
| Semgrep | gosec | 1 finding (TLS MinVersion) |
| Semgrep | github-actions | 0 findings (89 workflows clean) |
| Semgrep Pro | golang/security-audit/trailofbits | 0 findings on targeted paths |
