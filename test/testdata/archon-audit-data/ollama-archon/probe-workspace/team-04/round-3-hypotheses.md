# Round 3 Hypotheses — causal-verifier-04
# Method: Causal Counterfactual / Intervention Analysis

## Causal-01: Counterfactual Test — Does removing file://* from AllowedOrigins block PH-01/PH-02?

**From**: CROSS-01 (PH-02 + PH-11), CROSS-03 (PH-02 + PH-16)
**Intervention**: Remove `"file://*"` from `AllowedOrigins()` hardcoded defaults
**Counterfactual question**: Would this block the file:// cross-origin attack?

**Analysis**:
- For gin-routed paths (rc==nil): YES — removing file://* from corsConfig.AllowOrigins would cause gin-cors to reject the preflight → browser blocks the request. BUT: the `AllowedOrigins()` function unconditionally appends file://* (lines 100-106). There is no code path to remove it.
- For registry.Local paths (rc!=nil): NO — registry.Local emits NO CORS headers regardless. The fix is orthogonal; CORS removal from AllowedOrigins has no effect on the registry.Local bypass.
- **Conclusion**: The file:// CORS entry in AllowedOrigins IS the problem for gin-routed endpoints, but registry.Local has a SEPARATE, parallel vulnerability that persists even if AllowedOrigins is fixed.

**Causal verdict**: Two independent vulnerabilities. Fixing AllowedOrigins does not fix registry.Local bypass. Both must be addressed independently.

**PH-CX1 (new)**: The registry.Local bypass for /api/delete and /api/pull is causally INDEPENDENT of the CORS configuration. Even if an administrator deploys Ollama with an empty OLLAMA_ORIGINS, or even if the gin-cors middleware is disabled entirely, registry.Local.ServeHTTP will still process these endpoints without any access control. The vuln is in the architecture of the registry.Local wrapper, not in CORS config.

**Code evidence**:
- `server/routes.go:1727-1736` — registry.Local wraps gin as Fallback; /api/delete and /api/pull are intercepted FIRST
- `server/internal/registry/server.go:109-129` — NO CORS, NO host, NO auth checks
- Fragility: Stable — architectural; not a config issue

**Severity**: CRITICAL
**Validation**: CONFIRMED

---

## Causal-02: Counterfactual Test — Does Content-Type enforcement block PH-11 (simple-request bypass)?

**From**: CROSS-01 (PH-11 + PH-02)
**Intervention**: Add Content-Type validation to `decodeUserJSON`
**Counterfactual question**: Would checking `Content-Type: application/json` block the simple-request attack?

**Analysis**:
- `server/internal/registry/server.go:377-399` — `decodeUserJSON` uses `json.NewDecoder(r.Body).Decode(&v)`. Zero Content-Type check.
- If attacker sends `Content-Type: text/plain` with JSON body `{"model":"attacker.com/evil"}`, `json.Decode` succeeds because JSON parsing is content-agnostic.
- `Content-Type: text/plain` makes the request a **simple request** per CORS spec → no preflight → browser sends without CORS check.
- Even with `mode:'no-cors'`, a POST with text/plain body is sent.
- **Counterfactual**: If Content-Type were enforced, the request would need `Content-Type: application/json`, making it non-simple, triggering preflight. Preflight against registry.Local returns 405 → browser blocks.
- **BUT**: The preflight option goes to registry.Local.serveHTTP which checks URL path. For `/api/pull` with OPTIONS method, the switch falls through to `s.Fallback` (gin). Gin's CORS middleware would handle OPTIONS and, if file://* matches, return CORS approval. Then the actual POST would go to registry.Local (no CORS headers in response) → browser blocks response reading but SERVER EXECUTES the request.

**Refined analysis**: Adding Content-Type enforcement to decodeUserJSON would reduce the attack surface by requiring application/json (non-simple) → preflight → preflight hits gin (via Fallback) and gets CORS headers from gin-cors (since file://* is allowed) → preflight succeeds → POST sent with application/json → hits registry.Local → no Content-Type check... wait, this is a loop.

**Correct reasoning**: 
1. Preflight (OPTIONS /api/pull) → registry.Local → default branch → Fallback (gin) → gin-cors handles OPTIONS → emits ACAO:file:// → preflight succeeds
2. Actual POST → registry.Local → handlePull → executes
3. Response has NO CORS headers → browser blocks JS from reading response
4. But SERVER HAS ALREADY EXECUTED the pull

The server-side execution happens regardless. Browser blocking the response is meaningless for fire-and-forget pulls.

**Causal verdict**: Content-Type enforcement would NOT prevent the attack for fire-and-forget operations (pull, delete). The only fix is proper access control in registry.Local itself.

**PH-CX2 (new)**: Preflight for `/api/pull` in the rc!=nil configuration flows through registry.Local → gin (via Fallback) → gin-cors returns CORS approval. This means the preflight SUCCEEDS for cross-origin JSON POST requests to `/api/pull` (file:// origin → CORS passes on preflight). The subsequent POST executes in registry.Local with no protection. Browser cannot read the response, but server has already pulled the model.

**Severity**: CRITICAL
**Validation**: CONFIRMED (tracing preflight OPTIONS flow through registry.Local Fallback to gin-cors)

---

## Causal-03: Counterfactual Test — Does isExperimental gate block ENTRYPOINT on parth/agents branch?

**From**: PH-06 (round-1), CROSS-01
**Intervention**: Check whether adding `if !isExperimental { return }` before runEntrypoint() call would require --experimental flag
**Counterfactual question**: Is the isExperimental flag the intended gate?

**Analysis** (parth/agents branch):
- Line 748: `isExperimental, _ = cmd.Flags().GetBool("experimental")`
- Line 535-536 (approx): `if opts.Entrypoint != "" { return runEntrypoint(opts) }` — executes BEFORE isExperimental is used at line 779
- Line 779: `if isExperimental { return xcmd.GenerateInteractive(...) }`

The placement strongly suggests that `runEntrypoint` was intended to run regardless of `--experimental`, OR it was an oversight that the entrypoint check precedes the experimental gate. Either way, the behavior is: ENTRYPOINT executes without any flag.

**Causal verdict**: The experimental flag check at line 779 is NOT causally connected to entrypoint execution at line 535. They are sequential, independent branches. Entrypoint fires first.

**PH-CX3 (new, confirmed)**: On parth/agents branch, `ollama run <model-with-entrypoint>` executes the entrypoint command UNCONDITIONALLY — no experimental flag, no user confirmation, no capability check. This is a zero-interaction RCE from a pulled model.

**Severity**: CRITICAL
**Validation**: CONFIRMED (logical analysis of code structure confirmed by KB)

---

## Causal-04: Counterfactual Test — Does the digest mismatch check in CreateBlobHandler prevent GGUF injection (PH-14)?

**From**: CROSS-04 (PH-14 + PH-02)
**Intervention**: Assume attacker cannot pre-compute matching SHA-256 (collision resistance)
**Counterfactual question**: Does the digest check at line 1544 block PH-14?

**Analysis**:
- `server/routes.go:1544` — `if layer.Digest != c.Param("digest") → 400 bad request`
- `manifest.NewLayer(c.Request.Body, "")` hashes the actual bytes
- The attacker provides malicious GGUF bytes AND the URL contains the pre-computed SHA-256 of those exact bytes
- SHA-256 collision resistance holds — attacker cannot create two different byte sequences with the same hash
- **BUT**: The attacker can create a VALID SHA-256 of their malicious GGUF. They compute `sha256(malicious_gguf)` → `<hash>`. They POST to `/api/blobs/sha256-<hash>` with the exact malicious GGUF bytes. Hash matches → `layer.Digest == c.Param("digest")` → accepted.
- The check does NOT prevent PH-14; it only prevents accidental corruption. A deliberate attacker computes the correct hash.

**Causal verdict**: The digest check is not a security control against deliberate injection; it's a data integrity check. PH-14 is fully valid.

**PH-CX4 (confirmed)**: A cross-origin request from file:// can inject any GGUF content into the local blob store by pre-computing its SHA-256 and using it as the URL parameter. The digest check passes because the attacker's hash IS correct for their malicious payload.

**Severity**: HIGH (requires attacker-crafted GGUF + cross-origin write access + subsequent model creation)
**Validation**: CONFIRMED

---

## Causal-05: Null Origin Analysis — Does Chrome/Firefox Send null for file:// Pages?

**From**: PH-05 (round-1)
**Intervention**: Trace browser Origin header behavior for file:// pages
**Counterfactual question**: Do browsers send `Origin: null` or `Origin: file:///path` for cross-origin requests from file:// pages?

**Analysis** (based on browser security model):
- **Chrome**: For cross-origin requests from `file://` pages, Chrome sends `Origin: null` (not `file:///path/to/file.html`)
- **Firefox**: Same — sends `Origin: null`
- **Safari**: Similar behavior

The gin-contrib/cors library (v1.7.2) with `AllowWildcard=true` processes origins by checking if the origin matches any pattern in `AllowOrigins`. The pattern `file://*` uses wildcard matching. In gin-contrib/cors, wildcard matching typically checks if the pattern is a suffix/prefix match or a glob match.

**Critical**: `file://*` would NOT match `null`. The literal string `null` does not start with `file://`.

**HOWEVER**: gin-contrib/cors v1.7.2 has a known behavior: if `AllowAllOrigins = false` and the origin is `null`, some versions treat it as opaque and may return `Access-Control-Allow-Origin: null`. Need to check the exact library behavior.

**Alternative attack path that doesn't depend on null origin**:
- `tauri://*` — Tauri app context; Origin is `tauri://localhost`
- `app://*` — Electron app context; Origin is `app://some-name`
- `vscode-webview://*` — VS Code webview
- If victim has ANY of these applications running with embedded webviews that can be manipulated, the attack works without the null origin issue

**PH-CX5 (new)**: Cross-origin attacks via `app://*` (Electron) or `vscode-webview://*` (VS Code extensions) in the CORS allowlist. A malicious VS Code extension running in a webview has `Origin: vscode-webview://<id>` which matches `vscode-webview://*` in AllowedOrigins. VS Code extensions are a common software supply-chain vector. A compromised VS Code extension could interact with the local Ollama API using CORS-permitted cross-origin requests — including model deletion, pull, and chat access.

**Severity**: HIGH (vscode-webview attack vector is plausible; VS Code extensions have broad installation base)
**Validation**: VALIDATED (structural — vscode-webview://* is in hardcoded AllowedOrigins; VS Code extension attack surface is well-known)

---

## Causal-06: Counterfactual — Does allowedHostsMiddleware IsPrivate() bypass require server on 0.0.0.0?

**From**: PH-10 (round-2), CROSS-02
**Intervention**: Server bound ONLY to 127.0.0.1 (default)
**Counterfactual question**: Is the IsPrivate() bypass exploitable when server listens only on loopback?

**Analysis**:
- When server binds to `127.0.0.1:11434` (default): `addr.Addr().IsLoopback()` = true → line 1607 does NOT skip middleware (it skips when NOT loopback)
- Middleware runs: incoming request with `Host: 192.168.1.100:11434` → `netip.ParseAddr("192.168.1.100").IsPrivate()` = true → `c.Next()` at line 1618
- BUT: The request physically arrived on `127.0.0.1:11434`. A request with `Host: 192.168.1.100` but routed to `127.0.0.1:11434` requires the DNS rebind to point `192.168.1.100`'s IP resolution to `127.0.0.1`.

**DNS rebinding to private IP is more complex**:
- Standard DNS rebinding rebinds `attacker.com` → `127.0.0.1` (loopback)
- To exploit IsPrivate(), attacker must rebind to victim's own LAN IP `192.168.1.100`
- `192.168.1.100:11434` must be accessible from the browser
- This works if victim's machine has `192.168.1.100` assigned and EITHER:
  a. Server also listens on that IP (OLLAMA_HOST=0.0.0.0 or =192.168.1.100) — but then middleware is skipped at line 1607 anyway
  b. Server listens on 127.0.0.1 only — then TCP connection to 192.168.1.100:11434 fails

**Causal verdict**: The IsPrivate() bypass requires either: (a) server listening on 0.0.0.0 (then middleware is already skipped — the IsPrivate check is irrelevant), or (b) OS IP stack forwarding that routes external IPs to loopback (unusual). In the standard default configuration (bind 127.0.0.1), IsPrivate() bypass doesn't add attack surface beyond what's already there.

**Revised severity**: MEDIUM → LOW for default config; HIGH for 0.0.0.0 binding (but middleware is already bypassed there)

**PH-CX6 (clarifying)**: The IsPrivate() allowance in allowedHostsMiddleware creates attack surface primarily in non-default configurations where the server is bound to a specific LAN IP. In that case, DNS rebinding to that LAN IP succeeds AND passes the IsPrivate() check. For default (loopback-only) configurations, this is not exploitable via standard DNS rebinding.

**Severity**: MEDIUM (non-default config dependency)
**Validation**: VALIDATED (conditional on deployment config)
