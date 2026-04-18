# Bypass Analysis: CVE-2025-51471 — Cross-Domain Auth Token Exposure

**Patch commit**: 7601f0e9  
**Cluster ID**: server-auth-cross-origin  

## Patch Summary

The vulnerability allowed a malicious registry to return a `WWW-Authenticate` header with a `realm` URL pointing to an attacker-controlled host. The client would then send its signed authentication token to that host.

The fix adds a host comparison in `getAuthorizationToken()`: `redirectURL.Host != originalHost`. The `originalHost` is derived from `base.Host` (the model name's parsed host) at each call site in `server/images.go` and `server/upload.go`.

## Bypass Verdict: **sound**

## Analysis

### 1. Alternate Entry Points
All four call sites for `getAuthorizationToken` in the `server/` package now pass `originalHost`:
- `pullWithTransfer` (images.go:738) — passes `base.Host`
- `pushWithTransfer` (images.go:814) — passes `base.Host`
- `makeRequestWithRetry` (images.go:889) — passes `requestURL.Host`
- `uploadPart` (upload.go:284) — passes `requestURL.Host`

There is a separate `getAuthorizationToken` in `api/client.go`, but it is an entirely different function that signs a locally-constructed challenge string (method + path + timestamp). It never processes a realm URL from a remote server, so it is not vulnerable to the same class of attack.

### 2. Config-Gated Checks
The host check is unconditional — no environment variable, config flag, or `regOpts` field can disable it.

### 3. HTTP Redirect / Scheme Changes
The `registryOptions.Insecure` flag can change the scheme from HTTPS to HTTP, but this does not affect `base.Host` (which is scheme-independent). The host comparison is unaffected by scheme changes.

Go's `net/http` client follows redirects by default, but the 401 challenge is parsed from the *first* response's headers. The `requestURL.Host` used in `makeRequestWithRetry` is the original URL, not the redirected URL. An HTTP redirect before the 401 would change the response source but the comparison anchor stays at the original host — this is correct behavior since the token should only go to the intended host.

### 4. Parser Differentials / URL Manipulation
The comparison uses Go's `url.URL.Host` on both sides. Go's URL parser:
- Strips userinfo (`user@host` puts `user` in `User`, not `Host`)
- Preserves port in `Host` field when explicitly specified
- Does not perform IDN/punycode normalization

Since both sides come from `url.URL.Host`, the comparison is apples-to-apples. An attacker cannot inject a userinfo component to confuse the host matching.

### 5. Missing Normalization
**Port normalization**: If the original request is to `registry.example.com` (no port) but the realm URL is `https://registry.example.com:443/token`, Go's `url.Parse` will produce `Host = "registry.example.com:443"` which would NOT match `"registry.example.com"`. This is a **false positive** (legitimate auth blocked), not a bypass. It would fail closed, which is the safe direction.

**Case normalization**: Go's `url.Parse` lowercases the scheme but preserves host case. A realm of `https://Registry.Example.Com/token` would produce `Host = "Registry.Example.Com"` which might not match `registry.example.com`. Again, this fails closed.

No bypass vector was identified through normalization gaps.

### 6. Sibling/Related Paths
The `transfer` package receives the `getToken` closure and uses it for auth challenges. Since the closure captures `base.Host` at creation time, all auth within the transfer flow is covered.
