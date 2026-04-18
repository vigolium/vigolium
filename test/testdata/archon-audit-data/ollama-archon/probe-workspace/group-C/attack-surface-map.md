# Attack Surface Map: Group C — HTTP Handlers / Middleware / Auth

## Entry Points

- `server/routes.go:1707` — `WebSearchExperimentalHandler` — unauthenticated POST; raw body forwarded to cloud proxy via `readRequestBody` (unbounded `io.ReadAll`)
- `server/routes.go:1708` — `WebFetchExperimentalHandler` — unauthenticated POST; same pattern
- `server/routes.go:1696` — `WhoamiHandler` — unauthenticated POST; emits `signin_url` containing public key
- `server/routes.go:1698` — `SignoutHandler` — unauthenticated POST; emits public key, calls ollama.com
- `server/routes.go:1689` — `PullHandler` — unauthenticated POST; model name contains attacker-controlled registry host
- `server/routes.go:1703` — `CreateHandler` — unauthenticated POST; `r.From` is attacker-controlled model ref / remote host
- `server/routes.go:1704` — `CreateBlobHandler` — unauthenticated POST `/api/blobs/:digest`; body streamed to disk
- `server/routes.go:1705` — `HeadBlobHandler` — unauthenticated HEAD `/api/blobs/:digest`
- `server/routes.go:1720` — `/v1/chat/completions` — POST; `cloudPassthroughMiddleware` runs before `ChatMiddleware`
- `server/routes.go:1721` — `/v1/completions` — POST; same middleware stack
- `server/routes.go:1725` — `/v1/responses` — POST; `ResponsesMiddleware` reads zstd, maxDecompressedBodySize=20MB enforced only if Content-Encoding=zstd
- `server/routes.go:1733` — `/v1/messages` — POST (Anthropic); `cloudPassthroughMiddleware` can short-circuit `AnthropicMessagesMiddleware`
- `server/routes.go:1735-1744` — `registry.Local.ServeHTTP` (client2) — wraps gin; dispatches `/api/delete` and `/api/pull` before gin middleware chain runs
- `server/cloud_proxy.go:72` — `cloudPassthroughMiddleware` — reads entire request body via `readRequestBody` (unbounded `io.ReadAll`) for any POST to `/v1/*`
- `server/auth.go:53` — `getAuthorizationToken` — outbound request to attacker-supplied `Realm` (registry challenge); no scheme allowlist
- `middleware/openai.go:408` — `ChatMiddleware` — reads full JSON body via `c.ShouldBindJSON`
- `middleware/openai.go:509` — `ResponsesMiddleware` — reads zstd body with 20MB cap, then JSON body unboundedly if not zstd

## Trust Boundary Crossings

- **Unauthenticated-to-privileged**: `/api/experimental/web_search`, `/api/experimental/web_fetch`, `/api/me`, `/api/signout` are mounted with no auth middleware; any caller reaching the bind address can invoke them.
- **Client-supplied host in registry challenge**: `server/auth.go:28-50` — `registryChallenge.URL()` builds a redirect URL from the `Realm` field, which is attacker-controlled data from a registry 401 response. A host-equality check exists (`redirectURL.Host != originalHost`) but only compares the *pre-query-parsing* URL host, and the check does not enforce HTTPS scheme.
- **Client2 dispatch pre-middleware**: `server/internal/registry/server.go:117-121` — when `OLLAMA_EXPERIMENT=client2`, `/api/pull` and `/api/delete` are dispatched before the gin router, meaning `allowedHostsMiddleware` and CORS are not applied.
- **cloudPassthroughMiddleware body buffering**: `server/cloud_proxy.go:96` — calls `readRequestBody` which calls `io.ReadAll(r.Body)` with no size limit when the `Content-Encoding` is NOT `zstd`. The 20MB cap only applies to zstd-decoded bodies.
- **webExperimentalProxyHandler body buffering**: `server/routes.go:1967` — calls `readRequestBody` which calls `io.ReadAll` with no size limit.
- **RawQuery forwarded to cloud**: `server/cloud_proxy.go:193-194` — `c.Request.URL.RawQuery` is passed verbatim to the outgoing request to ollama.com.

## Auth / AuthZ Decision Points

- `server/routes.go:1608-1644` — `allowedHostsMiddleware` — decides whether a request's Host header is trusted; skipped entirely when listener is non-loopback (`!addr.Addr().IsLoopback()`)
- `server/routes.go:1581-1606` — `allowedHost` — accepts empty host, `localhost`, OS hostname, or any suffix `.localhost`/`.local`/`.internal`
- `server/auth.go:59-62` — realm host vs original host comparison in `getAuthorizationToken` — sole auth gate before outbound token request
- `server/cloud_proxy.go:360-373` — `signCloudProxyRequest` — skips signing if target host does not match `cloudProxySigningHost`; no verification that non-signing paths are safe
- `server/routes.go:271` — `slices.Contains(envconfig.Remotes(), remoteURL.Hostname())` — remote model host allowlist (applies to generate/chat with RemoteHost model config, NOT to pull)
- `server/cloud_proxy.go:384-429` — `resolveCloudProxyBaseURL` — validates `OLLAMA_CLOUD_BASE_URL` override; non-loopback in release mode rejected

## Validation / Sanitization Functions

- `server/model_resolver.go:36` — `parseAndValidateModelRef` — validates model name, identifies `:cloud`/`:local` suffixes; does NOT validate the host component for pull
- `server/model_resolver.go:57` — `parseNormalizePullModelRef` — normalizes cloud tag for pull; same host-validation gap
- `manifest/paths.go:40-61` — `BlobsPath` — regex `^sha256[:-][0-9a-fA-F]{64}$`; used by `HeadBlobHandler` and `CreateBlobHandler`, NOT used by `pullWithTransfer` tensor path
- `server/cloud_proxy.go:384` — `resolveCloudProxyBaseURL` — validates cloud proxy URL override at startup
- `server/routes.go:1625-1629` — `netip.ParseAddr` + `IsLoopback()|IsPrivate()|IsUnspecified()|isLocalIP` — IP-based Host header checks (overly permissive)

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| TCP/IP | `allowedHostsMiddleware` | Host header identifies legitimate caller | NO | `OLLAMA_HOST=0.0.0.0`: middleware short-circuits entirely (G1). `client2` experiment: `/api/pull`, `/api/delete` dispatched before gin (G6). |
| `allowedHostsMiddleware` | gin router | Host is validated loopback/trusted | NO | Non-loopback bind bypasses validation completely. `.localhost`/`.local`/`.internal` suffix accepted without zone check (G3). |
| gin router | `cloudPassthroughMiddleware` | Request body is size-bounded | NO | Non-zstd bodies: `io.ReadAll` with no limit. Only zstd branch has 20MB cap. |
| `cloudPassthroughMiddleware` | `proxyCloudRequestWithPath` | Model is a `:cloud` ref; local model is passed to next handler | YES (for cloud detection) | `webExperimentalProxyHandler` bypasses model check entirely; forwards raw body with no model validation. |
| `proxyCloudRequestWithPath` | ollama.com | Target URL is always ollama.com | YES (validated at startup) | `cloudProxySignRequest` skips signing for non-`ollama.com` hosts (but base URL is startup-validated). |
| gin router | `ChatMiddleware`/`AnthropicMessagesMiddleware` | Body is properly formed OpenAI/Anthropic JSON | NO | `cloudPassthroughMiddleware` may abort before middleware runs (cloud path), bypassing OpenAI-to-Ollama translation. |
| Middleware | `ChatHandler`/`GenerateHandler` | Caller is authenticated if using remote model | NO | No local auth enforced; remote model auth delegated to downstream ollama.com challenge. |
| `registry challenge (Realm)` | outbound token fetch | Realm host matches registry host | FRAGILE | Scheme not enforced to HTTPS; `redirectURL.Host` comparison may be bypassed if attacker controls Realm with port mismatch. |
| `WhoamiHandler` | ollama.com response | TLS to ollama.com is trust anchor | YES (TLS) | No per-response signature verification; DNS/MITM on ollama.com breaks. |
| `web_search`/`web_fetch` | cloud proxy | Caller is authorized local user | NO | No auth required; any caller that bypasses `allowedHostsMiddleware` can use local signing key to proxy queries. |

## Trust Chain Gaps

1. **Non-loopback bind eliminates all Host validation** (`OLLAMA_HOST=0.0.0.0`): `allowedHostsMiddleware` at `routes.go:1615` short-circuits unconditionally, restoring pre-CVE-2024-28224 attack surface. Any LAN-adjacent browser can DNS-rebind and reach all API endpoints.

2. **`.localhost`/`.local`/`.internal` suffix match accepts squatted domains**: `allowedHost` at `routes.go:1592-1603` is a raw `strings.HasSuffix`, not an IP-resolution check. Attacker with a public DNS entry pointing `evil.localhost` to victim's LAN IP satisfies this check.

3. **`client2` experiment dispatches `/api/pull` and `/api/delete` before gin middleware**: `registry/server.go:117-121` — `allowedHostsMiddleware`, CORS, and any future auth middleware are all skipped for these two endpoints when `OLLAMA_EXPERIMENT=client2`.

4. **`readRequestBody` has no size limit for non-zstd bodies**: `cloud_proxy.go:294` and `routes.go:1967` — `io.ReadAll(r.Body)` without `http.MaxBytesReader` wrapping. A POST to `/api/experimental/web_search`, `/api/experimental/web_fetch`, or any `/v1/*` endpoint with a multi-gigabyte non-zstd body will be fully buffered into RAM before any processing.

5. **`/api/experimental/web_search` and `/api/experimental/web_fetch` require no local auth**: These endpoints at `routes.go:1707-1708` proxy any body to ollama.com using the local user's signing key. An attacker who bypasses `allowedHostsMiddleware` (via gaps 1-3) can perform arbitrary web search/fetch queries billed to the victim's ollama.com account.

6. **Registry `Realm` host matching does not enforce HTTPS scheme**: `server/auth.go:59-62` — `redirectURL.Host != originalHost` only compares hosts. An attacker controlling a 401 response with `Realm=http://registry.example.com/token` can redirect token exchange to HTTP.

7. **`/api/pull` host is not allowlisted**: `routes.go` and `images.go` — `POST /api/pull {"name":"169.254.169.254/library/x:latest"}` issues an outbound HTTPS request to IMDS. `envconfig.Remotes()` allowlist only applies to generate/chat with embedded RemoteHost, not to manifest fetches.

8. **RawQuery forwarded verbatim to cloud**: `cloud_proxy.go:193-194` — query parameters from the inbound request are copied unmodified to the outbound ollama.com request, potentially injecting unintended parameters.
