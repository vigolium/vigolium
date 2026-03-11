# New Extension Utilities — Planning

Exploration of the `vigolium.*` JavaScript extension API surface to identify high-impact utility functions to add, with focus on multi-request handling and auth session scenarios.

## Current API Surface

The existing API covers:

- **`vigolium.http`** — Basic requests (`get`, `post`, `request`, `send`, `buildRequest`), sessions (`session`, `login`), batch (`batch`, `replay`), flow orchestration (`sequence`)
- **`vigolium.parse`** — URL, request, response, headers, cookies, query, JSON, form, HTML parsing
- **`vigolium.utils`** — Encoding/hashing, string ops, file I/O, shell exec, anomaly detection, diff/similarity, token extraction, URL/path utilities
- **`vigolium.scan`** — Module listing, scope control, finding creation, scan orchestration
- **`vigolium.ingest`** — URL/curl/raw/OpenAPI/Postman ingestion
- **`vigolium.source`** — Source code file access with path-traversal protection
- **`vigolium.agent`** — LLM integration (complete, ask, chat, high-level helpers, subprocess)
- **`vigolium.db`** — Records/findings query, annotation, anomaly comparison
- **`vigolium.oast`** — Out-of-band testing payload generation and polling
- **`vigolium.payloads`** — Built-in wordlists (xss, sqli, ssti, ssrf, lfi, path_traversal, xxe, cmdi, open_redirect, crlf)
- **`vigolium.log`** — Structured logging (info, warn, error, debug)
- **`vigolium.config`** — Runtime configuration variables
- **`vigolium.record`** — Current record context in scan callbacks (uuid, annotate, addRiskScore, addRemarks)

## Recommended New Utilities

### 1. `utils.jwtDecode` / `utils.jwtEncode` / `utils.jwtExpired` — JWT Decode/Forge

Massive gap for auth testing. No way to inspect or manipulate JWTs today.

```typescript
// Decode without verification
utils.jwtDecode(token: string): { header: object, payload: object, signature: string } | null

// Forge with modifications (for privilege escalation testing)
utils.jwtEncode(payload: object, opts?: { algorithm?: string, secret?: string }): string

// Check expiry
utils.jwtExpired(token: string): boolean
```

**Why:** Almost every modern API uses JWTs. Extensions testing IDOR, privilege escalation, or role-based access need to decode tokens to understand claims, modify `sub`/`role` fields, and test with altered tokens. Currently requires `utils.base64Decode` + manual JSON parsing + no way to re-encode.

---

### 2. `HttpSession` Interceptors — Auto Token Refresh

```typescript
interface HttpSession {
  // Run callback before every request (auto-refresh, logging)
  onRequest(fn: (req: RequestInfo) => RequestInfo | void): void

  // Run callback after every response (token rotation, error handling)
  onResponse(fn: (resp: HttpResponse, req: RequestInfo) => void): void

  // Auto-refresh when 401 detected
  setAutoRefresh(opts: {
    trigger: number,           // status code (401)
    refresh: () => string,     // function that returns new token
    header: string,            // "Authorization"
    maxRetries?: number        // default 1
  }): void
}
```

**Why:** Real-world APIs rotate tokens mid-scan. Today, if a token expires during a batch/sequence, everything after that point fails silently. The `onResponse` interceptor + `setAutoRefresh` would handle this transparently.

---

### 3. `http.authTest(sessions, records)` — IDOR/BOLA Helper

```typescript
http.authTest(opts: {
  sessions: HttpSession[],      // e.g., [adminSession, userSession, unauthSession]
  records: string[] | DBRecord[], // UUIDs or records to test
  method?: "replay" | "swap",   // replay=same request different auth, swap=cross-user resources
}): AuthTestResult[]

// Result per record
interface AuthTestResult {
  record_uuid: string,
  url: string,
  results: {
    session_label: string,
    status: number,
    body_similarity: number,    // vs original response
    accessible: boolean,        // heuristic: same status + high similarity = accessible
  }[],
  vulnerability: "idor" | "bola" | "none",
  confidence: number
}
```

**Why:** This is the #1 use case for "I have multiple requests and need auth sessions." Testing access control requires replaying the same requests across different privilege levels and comparing responses. Today you'd write 50+ lines of boilerplate with `http.batch` + `utils.similarity` + manual comparison. This collapses it to one call.

---

### 4. `utils.multipart(fields)` — Multipart Form Builder

```typescript
utils.multipart(fields: MultipartField[]): { body: string, contentType: string }

interface MultipartField {
  name: string
  value?: string
  filename?: string        // triggers file upload mode
  contentType?: string     // default: application/octet-stream for files
  data?: string            // raw bytes for file content
}
```

**Why:** File upload testing (unrestricted file upload, path traversal via filename, XXE via SVG/DOCX) is impossible today without manually constructing multipart boundaries. `http.buildRequest` doesn't handle this.

---

### 5. `db.records.grouped()` — Group by Path Template

```typescript
db.records.grouped(opts?: {
  hostname?: string,
  min_group_size?: number,   // default 2
  methods?: string[],
}): RecordGroup[]

interface RecordGroup {
  template: string,          // e.g., "/api/users/*/profile"
  method: string,
  records: DBRecord[],
  param_values: string[][],  // extracted dynamic segments per record
}
```

**Why:** When you have hundreds of ingested records, the first step is usually grouping by path template to find parameterized endpoints (IDOR candidates). Today you'd query all records, call `utils.pathToTemplate()` on each, and group manually. This is a very common pattern that should be a single call.

---

### 6. `http.sequence` Enhancements — Conditional Steps

The existing `http.sequence` is good but lacks conditionals:

```typescript
interface SequenceStep {
  // ... existing fields ...

  // Skip this step if condition is false
  condition?: string          // e.g., "{{token}} != ''" or "{{prev_status}} == 200"

  // On failure, run alternative step
  fallback?: SequenceStep

  // Repeat this step N times (for polling)
  repeat?: { times: number, delay_ms?: number, until?: string }
}
```

**Why:** Real auth flows have branches: "if MFA is enabled, submit OTP; otherwise proceed." Polling patterns (wait for async operation) are also common. Without conditionals, users fall back to raw JS loops, losing the declarative benefits of `http.sequence`.

---

## Priority Ranking

| # | Feature | Impact | Effort | Rationale |
|---|---------|--------|--------|-----------|
| 1 | `http.authTest` | Very High | Medium | Directly solves the "multiple requests + auth" problem |
| 2 | `utils.jwt*` | Very High | Low | Tiny implementation, massive auth testing unlock |
| 3 | `utils.multipart` | High | Low | Small utility, enables entire class of upload vulns |
| 4 | `db.records.grouped` | High | Low | Common boilerplate elimination |
| 5 | Session interceptors | High | Medium | Prevents silent failures during long scans |
| 6 | Sequence conditionals | Medium | Medium | Nice-to-have, can workaround with raw JS |
