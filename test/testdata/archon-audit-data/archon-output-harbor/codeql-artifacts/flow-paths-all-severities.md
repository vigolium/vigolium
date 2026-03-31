# Harbor Phase 4 CodeQL + Semgrep Flow Paths

**Generated:** 2026-03-27
**Tools:** CodeQL 2.25.0, Semgrep Pro 1.156.0

---

## Critical / High Severity Flows

### Flow 1: Open Redirect via Auth-Proxy postURI (SAST-001)

**Tool:** CodeQL `go/unvalidated-url-redirection`
**Severity:** HIGH
**Location:** `src/core/controllers/authproxy_redirect.go:77`

```
Source: apc.Ctx.Request.URL.Query().Get(postURIKey)  [user-controlled query param]
  └── uri variable assignment
       └── apc.Ctx.Redirect(http.StatusMovedPermanently, uri)  [SINK: unvalidated redirect]
```

No call to `utils.IsLocalPath()` or equivalent validation before redirect. Contrast with `OIDCController.RedirectLogin()` which correctly validates via `utils.IsLocalPath()`.

---

### Flow 2: SSRF via Webhook Job Address (SAST-002)

**Tool:** Semgrep `harbor-ssrf-job-http-client`
**Severity:** HIGH
**Location:** `src/jobservice/job/impl/notification/webhook_job.go:103-120`

```
Source: params["address"].(string)  [from job parameters map, originating from DB webhook policy]
  └── address variable
       └── http.NewRequest(http.MethodPost, address, body)
            └── wj.client.Do(req)  [SINK: outbound HTTP to user-controlled URL]
```

Path from UI to sink:
```
POST /api/v2.0/projects/{id}/webhook/policies
  → NotificationController.CreatePolicy()
    → DB: INSERT notification_policy (event_types, target={address, skip_cert_verify})
      → Artifact push event fires
        → Notification manager creates JobService task
          → Redis job queue
            → JobService WebhookJob.execute()
              → http.NewRequest(POST, address, payload)  ← SSRF
```

No private IP filtering, no scheme restriction, no DNS pinning.

---

### Flow 3: fmt.Sprintf SQL Flows (SAST-003)

**Tool:** CodeQL `harbor/raw-sql-fmt-sprintf` (44 confirmed flows)
**Severity:** HIGH (pattern risk), MEDIUM (current exploitability)

**Highest-risk examples:**

```go
// src/pkg/artifactrash/dao/dao.go:89
sql := fmt.Sprintf(`SELECT aft.* FROM artifact_trash ... WHERE ... aft.creation_time <= TO_TIMESTAMP('%f')`,
    float64(cutOff.UnixNano())/float64((time.Second)))
// cutOff = time.Time from function parameter — currently not user-controlled
// but pattern is identical to injection-vulnerable code
```

```go
// src/pkg/securityhub/dao/security.go:135
sqlStr = fmt.Sprintf(" and %v = ?", col)
// col comes from filterMap key lookup — currently allowlisted, but fragile
```

---

## Medium Severity Flows

### Flow 4: Decompression Bomb in CNAI Parser (SAST-004)

**Tool:** Semgrep `harbor-decompression-bomb-tar`
**Location:** `src/controller/artifact/processor/cnai/parser/util.go:45`

```
Source: OCI layer content from artifact push
  └── tar.NewReader(gzReader)
       └── tr.Next()  [iterates tar entries]
            └── io.Copy(&buf, tr)  [SINK: no LimitReader, unbounded copy]
```

---

### Flow 5: Reflected XSS in JobService API Handler (SAST-007)

**Tool:** Semgrep `go.net.xss.no-direct-write-to-responsewriter-taint`
**Location:** `src/jobservice/api/handler.go:367`

User-controlled value written directly to `http.ResponseWriter` without HTML encoding. Jobservice API requires shared secret authentication, limiting exposure.

---

## Low Severity / Informational

| ID | Location | Finding | Tool |
|----|----------|---------|------|
| SAST-005 | Multiple (12 files) | TLS MinVersion not set | Semgrep |
| SAST-006 | Multiple (7 files) | math/rand in security components | Semgrep |
| SAST-008 | 3 middleware files | filepath.Clean misuse | Semgrep |
| SAST-009 | registry/proxy.go:40 | ReverseProxy Director drops headers | Semgrep |
| SAST-010 | lib/pprof.go:41 | pprof exposed on non-TLS server | Semgrep |
| SAST-011 | retention.go:144 | GetRentenitionMetadata no auth check | CodeQL |
| SAST-012 | webhook_job.go:91 | skip_cert_verify user-controlled | Manual |

---

## DFD/CFD Slice Coverage

| Slice | Covered | Tool Used | Findings |
|-------|---------|-----------|---------|
| DFD-1: API query -> SQL | Yes | CodeQL custom (44 flows) | SAST-003 |
| DFD-2: Webhook SSRF | Yes | Semgrep custom + manual | SAST-002, SAST-012 |
| DFD-3: OIDC callback | Partial | Manual analysis | Open redirect in onboard flow |
| DFD-4: V2 token auth | Not directly (go-swagger generated code not in DB) | - | - |
| CFD-1: Auth proxy redirect | Yes | CodeQL builtin | SAST-001 |
| Manifest push / CNAI | Yes | Semgrep | SAST-004 |
