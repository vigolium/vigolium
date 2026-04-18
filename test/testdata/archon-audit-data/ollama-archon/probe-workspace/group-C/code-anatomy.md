# Code Anatomy: Group C — HTTP Handlers / Middleware / Auth

## File Inventory

| File | Lines | Role |
|------|-------|------|
| server/routes.go | ~2400 | Route registration, all HTTP handlers, allowedHostsMiddleware, signinURL |
| server/create.go | ~800 | CreateHandler, model creation pipeline |
| server/cloud_proxy.go | 569 | Cloud proxy: middleware, signing, URL forwarding, decompression |
| server/auth.go | 101 | Registry challenge construction, getAuthorizationToken, token fetch |
| middleware/openai.go | ~700 | OpenAI compat response writers, ChatMiddleware, ResponsesMiddleware, etc. |
| middleware/anthropic.go | ~500 | Anthropic compat writers, WebSearchAnthropicWriter |
| openai/openai.go | ~600 | OpenAI request/response transformation types and functions |
| openai/responses.go | ~400 | Responses API types and transformations |

## Key Functions and Data Flows

### allowedHostsMiddleware (routes.go:1608)
- Input: `net.Addr` (listener address)
- Logic: If listener is non-loopback → skip entirely (`c.Next()`). Else: parse Host header IP; allow if loopback/private/unspecified/local-interface. Fall through to `allowedHost` for string-based matching.
- `allowedHost` (routes.go:1581): accepts `""`, `"localhost"`, OS hostname, `*.localhost`, `*.local`, `*.internal` — pure string suffix match, no DNS resolution.

### cloudPassthroughMiddleware (cloud_proxy.go:72)
- Input: POST body from any `/v1/*` request
- zstd branch: `http.MaxBytesReader(20MB)` applied
- non-zstd branch: `readRequestBody` → `io.ReadAll` with NO size limit
- Extracts `model` field from JSON; calls `parseAndValidateModelRef`
- If cloud model: calls `proxyCloudRequestWithPath` then `c.Abort()`
- If not cloud: `c.Next()` to pass to OpenAI middleware

### proxyCloudRequestWithPath (cloud_proxy.go:179)
- Builds target URL: `baseURL + path + c.Request.URL.RawQuery` (verbatim query passthrough)
- Copies request headers (hop-by-hop filtered)
- Signs with `signCloudProxyRequest` → skips signing if hostname != `cloudProxySigningHost`
- Streams response body back with `copyProxyResponseBody`
- No response size limit on the cloud response body

### webExperimentalProxyHandler (routes.go:1966)
- Calls `readRequestBody` → `io.ReadAll` with NO size limit
- Checks body not empty
- Calls `proxyCloudRequestWithPath` directly (no model validation, no local auth check)

### WhoamiHandler (routes.go:1981)
- Hardcoded to `https://ollama.com`
- On unsigned-in user: calls `signinURL()` which calls `auth.GetPublicKey()` → emits base64 public key in response body
- No caller authentication; any reachable client gets the public key

### getAuthorizationToken (auth.go:53)
- Builds redirect URL from `registryChallenge.Realm` (attacker-controlled)
- Host equality check: `redirectURL.Host != originalHost` — stops cross-host token sends
- Does NOT enforce HTTPS scheme on redirect
- Calls `makeRequest` with the constructed URL

### registry.Local.serveHTTP (internal/registry/server.go:114)
- When `OLLAMA_EXPERIMENT=client2`: dispatches `/api/delete` and `/api/pull` directly, bypassing the gin handler chain entirely — `allowedHostsMiddleware` not called

### ChatMiddleware / ResponsesMiddleware (middleware/openai.go)
- `ChatMiddleware`: `c.ShouldBindJSON` (gin's JSON decoder, uses `json.NewDecoder` — NOT bounded)
- `ResponsesMiddleware`: zstd branch bounded at 20MB; non-zstd `c.ShouldBindJSON` unbounded
- Replaces `c.Request.Body` with re-encoded Ollama format before passing to handler

### PullHandler (routes.go:914)
- `req.Insecure` forwarded as `regOpts.Insecure` — allows HTTP pull
- Model name host component is NOT validated against any allowlist before manifest fetch
- Manifest fetch URL = `https://<attacker-host>/v2/...`

## Critical Sinks

| Sink | Reachable From | Unbounded Input? |
|------|---------------|-----------------|
| `io.ReadAll(r.Body)` in `readRequestBody` | All non-zstd POST bodies on `/v1/*`, `/api/experimental/*` | YES — no size limit |
| `json.Unmarshal(body, ...)` in `extractModelField` | All `/v1/*` POSTs | Bounded by body read (itself unbounded) |
| outbound HTTP to `targetURL` in `proxyCloudRequestWithPath` | All cloud-proxied paths | Body forwarded in-memory |
| outbound HTTP to `redirectURL` in `getAuthorizationToken` | Registry auth challenge | Attacker-controlled URL (host-checked only) |
| outbound HTTP to `https://<model-host>/v2/...` in `PullHandler` | Any unauthenticated POST /api/pull | Attacker-controlled host |
| `c.Request.URL.RawQuery` → outbound cloud request | All `/v1/*` cloud paths | Verbatim query injection |
| public key disclosure in `WhoamiHandler`/`SignoutHandler` | Unauthenticated POST | Device fingerprint leak |
