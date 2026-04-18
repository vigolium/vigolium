# 39982a95 — Cloud auth proxy revert (and its re-revert)

**Patch under analysis:** `39982a95` Revert "Reapply 'don't require pulling stubs for cloud models'" (#14606)
**Cluster ID:** `cloud-stub-flap` (8207e55e -> 97d2f05a -> 799e51d4 -> 39982a95 -> 4eab60c1)
**Type:** reverted-fix / control-weakening (subsequently re-reverted)
**Tag:** `[undisclosed]`

## Patch summary
Commit `39982a95` deleted 2843 lines that introduced `cloud_proxy.go`,
`model_resolver.go`, `internal/modelref/modelref.go`, plus the 988-line
`routes_cloud_test.go`. The deleted code provided:
- `cloudPassthroughMiddleware` / `cloudModelPathPassthroughMiddleware` to
  intercept `/v1/*` calls and proxy `:cloud` model traffic to ollama.com.
- `parseAndValidateModelRef` / `parseNormalizePullModelRef` model source
  validation.
- `writeCloudUnauthorized` 401-with-signin-url helper.
- `signCloudProxyRequest` ed25519 request signing for outgoing cloud calls.

## Bypass verdict
**relocated** — `39982a95` was itself reverted three days later by
`4eab60c1` ("Reapply ... again"), so the deleted code is back in HEAD
57653b8e. The series is a four-step revert flap, not a long-lived
weakening. **However**, the re-applied code carries pre-existing security
gaps that the patch ping-pong did not address.

## Evidence — current state in HEAD 57653b8e

### Cloud proxy code is present and active
- `server/cloud_proxy.go` (568 lines) exists and exports `cloudPassthroughMiddleware`,
  `cloudModelPathPassthroughMiddleware`, `proxyCloudRequestWithPath`,
  `signCloudProxyRequest`, `writeCloudUnauthorized`.
- `server/model_resolver.go` (81 lines) exists with `parseAndValidateModelRef`
  and `parseNormalizePullModelRef`.
- `internal/modelref/modelref.go` (115 lines) exists.
- `server/routes.go:1720-1733` — all `/v1/*` routes wrap
  `cloudPassthroughMiddleware`; `/v1/models/:model` wraps
  `cloudModelPathPassthroughMiddleware`.
- `server/routes.go:210, 690, 871, 931, 1065, 1127, 2118` and
  `server/create.go:113` actively call `parseAndValidateModelRef` /
  `parseNormalizePullModelRef`.

### `/api/me` (WhoamiHandler) — `server/routes.go:1981-2010`
- Hardcoded to `https://ollama.com` (no SSRF), uses `http.DefaultClient`
  (TLS verification on).
- **Trust anchor weakness:** the JSON `UserResponse` returned by ollama.com
  is consumed without signature verification. The local server only
  trusts TLS PKI; if an attacker controls DNS or terminates TLS for
  ollama.com on the client's network they can spoof identity. There is
  no per-response ed25519 verification using the registry's well-known key.
  This is a long-standing design choice (not introduced or worsened by
  the revert/re-revert).

### `/api/experimental/web_search` and `/api/experimental/web_fetch` — `server/routes.go:1707-1708, 1958-1979`
- Both call `webExperimentalProxyHandler` which forwards the request body
  to `proxyCloudRequestWithPath(c, body, "/api/web_search", ...)` against
  `cloudProxyBaseURL` (default `https://ollama.com:443`).
- The outgoing request is signed via `signCloudProxyRequest`
  (`cloud_proxy.go:360`) which only signs when the host matches
  `cloudProxySigningHost` (default `ollama.com`).
- **Origin validation gap:** the handler does not require local-client
  authentication. Any attacker who can reach the bind address (e.g. via
  the localhost-allowlist bypass tracked separately) can use the local
  server as an unauthenticated proxy to ollama.com's web search and web
  fetch endpoints. The ollama.com side will rate-limit per signed key,
  but the local user's signing key is implicitly used to authenticate
  arbitrary attacker queries — query-content exfiltration and signing-key
  reuse risk.

### `cloudProxyBaseURL` override (`OLLAMA_CLOUD_BASE_URL`) — `cloud_proxy.go:384-429`
- `resolveCloudProxyBaseURL` enforces:
  - non-loopback hosts blocked in `gin.ReleaseMode`
  - non-loopback hosts must use `https`
  - userinfo, query, fragment, and non-root path rejected
- Sound — the override cannot be used to redirect cloud traffic to an
  attacker host in release builds.

### Pull SSRF surface (this is the most actionable finding)
The revert/re-revert did NOT touch `PullHandler`, but the cloud-proxy
discussion is the right context to surface this. `/api/pull` accepts a
fully-qualified model name `host/namespace/model:tag`. The host is parsed
by `model.ParseName` (`types/model/name.go:140`), validated only by
`isValidPart` (`name.go:344-372`), which permits any string of
alphanumerics + `_`, `-`, `.`, `:` up to 350 chars.
- `pullModelManifest` (`server/images.go:853-858`) builds the URL via
  `n.BaseURL().JoinPath("v2", ...)` — i.e. `https://<user-host>/v2/...`.
- `BaseURL` (`types/model/name.go:317-322`) sets `Scheme = n.ProtocolScheme`
  (defaults to `https` only when `n.Host == defaultHost`; otherwise the
  scheme is empty until the request goes out, where Go's `url.URL` with
  empty Scheme + Host = `<host>` may be coerced).
- **No host allowlist** for pull. `POST /api/pull
  {"name":"169.254.169.254/library/x:latest"}` will issue an outbound
  request to AWS/GCP IMDS. Response data ends up in error messages
  ("pull model manifest: ...") visible to the requester.
- The `RemoteHost` allowlist via `envconfig.Remotes()` at
  `server/routes.go:271, 2193` only governs `/api/generate` and
  `/api/chat` invocation against a manifest that already specifies a
  `RemoteHost` — it does NOT cover `/api/pull` registry lookups. Two
  different allowlists, only one wired up.
- `Insecure: req.Insecure` (`server/routes.go:953, 1002`) lets the
  caller force HTTP. Combined with the missing host allowlist, the
  pull path is a fully-controllable outbound HTTP client. This is the
  CVE-2024-39722-class blast radius that the cloud auth deletion would
  have widened, but it is independently exploitable today.

### TLS / `OLLAMA_INSECURE_REGISTRY`
- No env-controlled InsecureSkipVerify. The only path to disabling TLS
  verification is the `https+insecure://` scheme on a registry name
  (`server/internal/client/ollama/registry.go:969-984`), which is a
  per-pull caller-controlled opt-in. Not weakened by this revert.
- `regOpts.Insecure` toggles HTTP-vs-HTTPS but only for `n.ProtocolScheme
  == "http"`. Still relies on caller intent.

### `parseAndValidateModelRef` enforcement
- Re-applied verbatim by `4eab60c1` and called from every model-name
  surface in routes.go and create.go (see grep table above). Not
  re-located or stripped.

### Cluster behavior
The revert sequence `8207e55e` (introduce) -> `97d2f05a` (revert) ->
`799e51d4` (reapply) -> `39982a95` (revert) -> `4eab60c1` (reapply
again) shows leadership churn around UX behavior ("don't require
pulling stubs for cloud models"), not security intent. The deleted
code is currently restored, so `39982a95` is a non-issue in HEAD —
**but** the underlying cloud auth model that the code implements
(unauthenticated /api/me, unauthenticated /api/experimental/* proxy,
unallowlisted /api/pull host) carries the same SSRF / unauthenticated-
proxy surface in either state. The flap merely demonstrates that the
maintainers are willing to disable significant cloud-side validation
on short notice; future similar reverts could land without review.

## Recommended follow-ups
1. Track `/api/pull` host allowlist as a separate finding — independent
   of the revert. Should reuse `envconfig.Remotes()` (which already
   defaults to `ollama.com`) at the manifest-fetch step.
2. Track `/api/experimental/web_search` and `/api/experimental/web_fetch`
   as missing local auth — depends on whether ollama exposes the bind
   address beyond loopback (CVE-2024-28224 territory; covered by
   `allowedHostsMiddleware`).
3. Track `/api/me` / `Whoami` response trust as a design weakness — the
   server should verify the response signature, not rely on TLS to
   ollama.com alone.
4. Flag the revert flap pattern in the audit notes — four reverts in
   eight days on a security-sensitive code path is a process signal.

## Files of interest (absolute paths)
- `/Users/bytedance/Desktop/demo/ollama/server/cloud_proxy.go`
- `/Users/bytedance/Desktop/demo/ollama/server/model_resolver.go`
- `/Users/bytedance/Desktop/demo/ollama/internal/modelref/modelref.go`
- `/Users/bytedance/Desktop/demo/ollama/server/routes.go` (lines 1696-1733, 1958-2010, 271, 914-970)
- `/Users/bytedance/Desktop/demo/ollama/server/create.go` (lines 100-140, 285-328)
- `/Users/bytedance/Desktop/demo/ollama/server/images.go` (lines 596-708, 853-875, 951-993)
- `/Users/bytedance/Desktop/demo/ollama/types/model/name.go` (lines 140-176, 317-322, 333-372)
- `/Users/bytedance/Desktop/demo/ollama/envconfig/config.go` (lines 166-175)
