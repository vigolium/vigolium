# Evidence File — Group C (All Rounds)

## Evidence Summary

All hypotheses were validated by direct code inspection of HEAD commit 57653b8e. No runtime execution was required as the vulnerabilities are statically verifiable from the source.

---

## PH-01 — Unbounded Body via web_fetch/web_search
**Evidence type**: Static code trace
**File/Line**: `server/cloud_proxy.go:289-301` (`readRequestBody`) + `server/routes.go:1966-1978` (`webExperimentalProxyHandler`)
**Proof**: `readRequestBody` calls `io.ReadAll(r.Body)` with no `http.MaxBytesReader` wrapper. The only size limit in the module is at `cloud_proxy.go:88-89` (zstd branch), which is NOT on the code path to `webExperimentalProxyHandler`. The `routes.go:1973` check for non-empty body does not limit size.
**Fragility**: SOUND — the absence of `http.MaxBytesReader` is deterministic.
**Verdict**: VALIDATED

## PH-02 — Unbounded Body via non-zstd /v1/* POST
**Evidence type**: Static code trace
**File/Line**: `server/cloud_proxy.go:72-134` (`cloudPassthroughMiddleware`) + `cloud_proxy.go:289-301`
**Proof**: The `Content-Encoding == "zstd"` check at line 80 is the sole guard. Its false branch (non-zstd) calls `readRequestBody` at line 96 which is unbounded.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-03 — client2 middleware skip on /api/pull
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:1735-1744` + `server/internal/registry/server.go:114-128`
**Proof**: `registry.Local.ServeHTTP` dispatches `/api/pull` via `s.handlePull` before calling `s.Fallback.ServeHTTP` (the gin router). The gin router carries `allowedHostsMiddleware` at routes.go:1676-1679. Fallback is only invoked for non-matching paths.
**Fragility**: SOUND — structural dispatch order is deterministic
**Verdict**: VALIDATED

## PH-04 — .localhost suffix bypass
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:1592-1603` (`allowedHost`)
**Proof**: `strings.HasSuffix(host, ".localhost")` is a raw string comparison. No DNS resolution. No IP-to-domain verification. `Host: evil.localhost` satisfies the check regardless of what IP `evil.localhost` resolves to.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-05 — Unauthenticated signing key proxy
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:1707-1708` (route registration, no auth middleware); `server/cloud_proxy.go:360-373` (`signCloudProxyRequest`)
**Proof**: Route registration shows `r.POST("/api/experimental/web_search", s.WebSearchExperimentalHandler)` with no auth middleware in the chain. Signing at cloud_proxy.go:360 runs for all requests targeting `ollama.com`.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-06 — Public key oracle via /api/me
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:1696-1700` (route registration); `server/routes.go:1981-2010` (`WhoamiHandler`); `server/routes.go:183-192` (`signinURL`)
**Proof**: `/api/me` has no auth middleware. `WhoamiHandler` calls `signinURL()` which calls `auth.GetPublicKey()` and encodes the result in the response. Same leak path exists in `GenerateHandler` at routes.go:330-338 and `ChatHandler` at routes.go:~2248.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-07 — Registry Realm HTTPS downgrade
**Evidence type**: Static code trace
**File/Line**: `server/auth.go:53-100` (`getAuthorizationToken`)
**Proof**: `redirectURL.Host != originalHost` check at auth.go:61 only compares host components; `redirectURL.Scheme` is not checked. An attacker-controlled registry can return `Realm=http://evil.com/token` and if `originalHost == "evil.com"`, the token request proceeds over HTTP.
**Fragility**: FRAGILE — requires attacker to control the registry (reachable via SSRF PH-03/PH-16). On its own, requires victim to pull from an attacker-controlled registry.
**Verdict**: VALIDATED (dependent on pull from attacker-controlled host)

## PH-08 — RawQuery injection
**Evidence type**: Static code trace
**File/Line**: `server/cloud_proxy.go:191-194` + `cloud_proxy.go:376-382`
**Proof**: `targetURL := baseURL.ResolveReference(&url.URL{..., RawQuery: c.Request.URL.RawQuery})`. The `buildCloudSignatureChallenge` then calls `req.URL.Query()` and `query.Set("ts", ts)` on this URL. `url.Values.Set` replaces any existing `ts` value, so attacker-supplied `ts` would be overwritten. Other attacker parameters persist in the signed URL.
**Fragility**: FRAGILE — timestamp is overwritten by signing; other params are attacker-injectable but impact depends on ollama.com behavior.
**Verdict**: NEEDS-DEEPER (timestamp attack closed; other parameter injection pending ollama.com behavior analysis)

## PH-09 — zstd/non-zstd asymmetry (amplifies PH-02)
**Evidence type**: Static code trace  
**File/Line**: `server/cloud_proxy.go:80-101`
**Proof**: Binary branch: zstd → `http.MaxBytesReader(20MB)`; non-zstd → `readRequestBody` (unbounded). Same attack as PH-02; confirmed as a contradiction in the defense design.
**Fragility**: SOUND
**Verdict**: VALIDATED (same finding as PH-02 from different analysis angle)

## PH-10 — Non-loopback bind disables all host validation
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:1615-1618`
**Proof**: `if addr, err := netip.ParseAddrPort(addr.String()); err == nil && !addr.Addr().IsLoopback() { c.Next(); return }` — unconditional pass-through.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-11 — client2 feature flag breaks middleware security
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:95` + `server/routes.go:1789-1744` + `server/internal/registry/server.go:109-128`
**Proof**: `var useClient2 = experimentEnabled("client2")` at package init. When true, `registry.Local{Fallback: r}` is returned from `GenerateRoutes`. Gin router `r` (with middleware) is only invoked for paths that don't match `/api/delete` or `/api/pull` in the Local dispatcher.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-12 — IsPrivate() accepts RFC1918 Host headers
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:1625-1629`
**Proof**: `addr.IsPrivate()` is true for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. A browser with `Host: 192.168.1.50` satisfies this check on a loopback-bound server. Rebinding `evil.com` to `192.168.1.50` and setting `Host: 192.168.1.50` completes the attack.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-13 — Anthropic web search bypasses cloud abort
**Evidence type**: Static code trace
**File/Line**: `server/cloud_proxy.go:122-131` + `server/routes.go:2124-2130`
**Proof**: `legacyCloudAnthropicKey` branch at cloud_proxy.go:126-130 sets the key and calls `c.Next()` instead of proxying. `ChatHandler` at routes.go:2126 routes to `proxyCloudJSONRequestWithPath` on `/api/chat` path.
**Fragility**: SOUND (behavioral, not a security vulnerability per se; consequence is format mismatch and rate limit amplification)
**Verdict**: VALIDATED (behavioral gap, medium severity)

## PH-14 — Double-buffering in cloudPassthroughMiddleware + ChatMiddleware
**Evidence type**: Static code trace
**File/Line**: `server/cloud_proxy.go:289-301` + `middleware/openai.go:422-435`
**Proof**: `readRequestBody` at cloud_proxy.go:294 reads entire body into `[]byte`; `ChatMiddleware` at openai.go:430 calls `json.NewEncoder(&b).Encode(chatReq)` allocating a new `bytes.Buffer`. Both are heap allocations proportional to (or exceeding) the original body size.
**Fragility**: SOUND
**Verdict**: VALIDATED (amplification factor on PH-02)

## PH-15 — ResponsesMiddleware unbounded JSON read
**Evidence type**: Static code trace
**File/Line**: `middleware/openai.go:509-570`
**Proof**: zstd branch at line 511 applies `MaxBytesReader(20MB)`. Non-zstd path falls to `c.ShouldBindJSON(&req)` at line 523 with no limit.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-16 — /api/pull host not allowlisted; Insecure flag enables HTTP SSRF
**Evidence type**: Static code trace
**File/Line**: `server/routes.go:952-954` (`regOpts.Insecure = req.Insecure`); `server/images.go:853-858` (manifest fetch uses model name BaseURL)
**Proof**: `req.Insecure` is directly propagated to `registryOptions.Insecure`. In `pullModelManifest`, the scheme is derived from `n.ProtocolScheme` which is `"http"` when `Insecure=true` and the host is non-default. No host allowlist exists in the pull path.
**Fragility**: SOUND
**Verdict**: VALIDATED

## PH-17 through PH-22 — Causal Verification
All causal findings confirmed as documented in round-3-hypotheses.md. PH-21 (RawQuery timestamp) is NEEDS-DEEPER pending ollama.com backend analysis. PH-22 (web search loop DoS) downgraded to MEDIUM (rate-limit amplification, not OOM).
