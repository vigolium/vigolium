# p4-f07: CORS Allows file:// Origin — Full Unauthenticated API Access from Local HTML

**Severity**: HIGH
**CWE**: CWE-942 (Overly Permissive Cross-domain Policy), CWE-306 (Missing Authentication)
**DFD Slice**: DFD-2, CFD-1
**CVE**: CVE-2025-63389 (auth bypass pattern), CVE-2024-28224 (DNS rebinding)

## Location

- `envconfig/config.go:86-109`: `AllowedOrigins()` — always includes `file://*`
- `server/routes.go:1664`: `corsConfig.AllowOrigins = envconfig.AllowedOrigins()`
- `server/routes.go:1668-1671`: single CORS config applied to ALL routes

## Description

`AllowedOrigins()` unconditionally includes `file://*` in the allowed origins list. This cannot be removed by setting `OLLAMA_ORIGINS` (which only adds origins). All API routes share a single CORS config — there is no route-group separation between destructive and read-only endpoints.

A malicious HTML file opened locally (`file:///tmp/evil.html`) can:
1. `DELETE /api/delete` — delete any model (no auth)
2. `POST /api/pull` — pull attacker-controlled model (enabling supply-chain RCE via ENTRYPOINT)
3. `POST /api/create` — create model from attacker-specified blobs
4. `POST /api/push` — exfiltrate model data
5. `POST /api/chat` — exfiltrate inference results

Both CORS check and `allowedHostsMiddleware` pass: `file://` origin is allowed, and Host is `localhost:11434` (loopback).

`OLLAMA_ORIGINS` only extends the default list — no operator can restrict `file://*`.

## Exploit Conditions

- Victim has Ollama running (default: localhost:11434)
- Victim opens a malicious HTML file in browser (email attachment, downloaded file)
- No other interaction required

## Evidence

- `envconfig/config.go:97` — `"file://*"` in always-included defaults
- `envconfig/config.go:86-109` — no mechanism to remove defaults
- `server/routes.go:1681-1698` — DELETE, pull, create, push all on same CORS config

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security

**Attacker Control**: The attacker delivers a malicious HTML file (email attachment, downloaded document, browser-based drive-by landing). The victim opens it locally. The file's JavaScript makes cross-origin requests to `http://localhost:11434`. The CORS `file://*` origin bypass is the entry point.

**Runtime**: Ollama HTTP server (`ollama serve`) on the victim's local machine. The browser acts as the attacker's HTTP client, making credentialed requests to the local API.

**Trust Boundary Crossed**: Browser same-origin policy boundary is the trust boundary; `file://*` in CORS allow-list collapses it. The boundary between "local file" (untrusted content) and "local API" (trusted operations) is eliminated.

**Effect**: The impact is cross-operation but same-user: any model management operation accessible to the user running Ollama can be performed without consent. Combined with p4-f01 (ENTRYPOINT RCE), a `POST /api/pull` of a malicious model followed by `ollama run` gives full RCE. The CORS bypass itself does not execute code, but enables the model-management API to be weaponized.

**CodeQL Reachability**: Confirmed on main branch. `envconfig/config.go:102` contains `"file://*"` hardcoded in the `AllowedOrigins()` return value (verified via grep). `server/routes.go:1664` applies it to all routes. The gin middleware chain at lines 1668-1671 confirms `allowedHostsMiddleware` and CORS both apply to the gin router, but NOT to `registry.Local` (see p4-f08). The `file://` origin + `localhost:11434` Host combination passes both checks.

**KB Cross-Reference**: Phase 6 bypass analysis (cluster: cors-access-control) confirms this as bypassable. The prior route-group separation (commit f84cc993) was reverted. `OLLAMA_ORIGINS` cannot remove defaults (confirmed in code). No mitigation is available to operators in current default configuration.

**Exploit Prerequisites**:
- Ollama must be running and listening (always true for users actively using Ollama)
- Victim must open a local HTML file — social engineering required (email attachment, downloaded installer, malicious PDF with embedded HTML link, etc.)
- No browser extensions, plugins, or special configuration needed

**Verdict**: KEEP — HIGH security finding. The `file://*` origin in the CORS allow-list is a clear and present attack surface. Fix: either (a) remove `file://*` from defaults and require explicit opt-in via `OLLAMA_ORIGINS`, or (b) re-implement route-group separation so destructive endpoints (delete, push, create, pull) require a non-file origin, or (c) add a per-request CSRF token for state-changing operations.
