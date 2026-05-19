---
name: audit-auth
description: Audit authentication and session-management code for common issues — weak JWT config, session fixation, password-handling flaws, insecure cookies, broken OAuth flows, and missing auth checks on routes. Use when the user asks to review auth code or when source-aware scanning targets login/session/token handling.
license: MIT
allowed-tools:
  - read_file
  - grep
  - glob
  - bash
  - report_finding
---

# Authentication & Session Code Audit

You are auditing authentication and session-management code. Your goal is
to identify concrete, reproducible vulnerabilities — not style nits. Each
issue you raise must map to a CWE and a specific file + line range, and
must be persisted via the `report_finding` tool.

## Scope — what to look for

Work through these in order; some targets will be irrelevant (skip and
say so in your final summary rather than fabricating findings):

### 1. JWT / token handling
- `alg=none` accepted by the verifier (CWE-327)
- Secret reused for HMAC and RSA (key confusion, CWE-347)
- Hard-coded secrets or secrets pulled from non-secret sources
- Missing `iss`, `aud`, `exp` validation (CWE-345)
- Tokens logged at INFO level (CWE-532)

### 2. Session management
- Session IDs derived from user input or predictable sources (CWE-330)
- No session rotation on privilege change (CWE-384 session fixation)
- Cookies missing `HttpOnly`, `Secure`, or `SameSite` (CWE-1004)
- Long or unbounded session lifetime

### 3. Password handling
- Plaintext storage or fast hashes (MD5/SHA1/SHA256 without KDF) (CWE-916)
- Passwords in URL query strings, logs, or error messages
- Timing-unsafe comparison of password hashes (CWE-208)
- No rate limiting on login (CWE-307)

### 4. OAuth / OIDC
- Missing `state` / PKCE (CWE-352 CSRF on auth flow)
- Open redirect on callback (CWE-601)
- `redirect_uri` not validated against allowlist
- Token exposure via referer or fragment-in-GET

### 5. Route-level auth
- Handlers that forget to call the auth middleware
- Role checks on client-supplied fields (e.g., trusting `req.body.role`)
- IDOR: authorization based on URL param without ownership check (CWE-639)

## Recommended workflow

1. **Inventory**: use `glob` to find auth-related files. Typical patterns:
   - `**/auth/**`, `**/session*`, `**/login*`, `**/oauth*`, `**/middleware*`, `**/jwt*`
2. **Read the entry points**: login handler, session middleware, token verifier.
3. **Grep for red flags**:
   - `alg.*none`, `jwt.Parse[^A-Z]` (missing key func)
   - `md5|sha1` in a hashing context
   - `bcrypt\.CompareHashAndPassword` — good; absence of it near a login handler — suspicious
   - `httpOnly\s*:\s*false`, `secure\s*:\s*false`
   - `res.redirect.*req\.` (open redirect pattern)
4. **For each concrete finding**, call `report_finding` with:
   - `severity`: critical | high | medium | low
   - `title`: short, specific (e.g., "JWT verifier accepts alg=none")
   - `cwe_id`: CWE-xxx
   - `source_file`: relative path
   - `description`: 1-3 sentences of what + why
   - `remediation`: 1-2 sentences of fix

## Output expectations

- At least one line of summary per file audited (even if clean).
- Every finding persisted via `report_finding` — do NOT just enumerate
  in your final text message.
- If you run out of context (very large codebase), audit the most
  critical paths first: JWT verification, session creation, login handler.
  Skip admin panels and internal tools unless explicitly in scope.
- Do NOT flag speculative issues ("this could theoretically be…") — only
  concrete code paths with file + line.
