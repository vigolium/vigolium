Phase: 10
Sequence: 002
Slug: oidc-ping-ssrf
Verdict: VALID
Rationale: PingOIDC passes a system-admin-supplied URL directly to gooidc.NewProvider which makes an outbound HTTP GET to fetch the OIDC discovery document; no IP filtering is applied, enabling SSRF to cloud metadata and internal services.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-029-scanner-ssrf.md
Origin-Pattern: AP-022

## Summary

The `PingOIDC` handler at `POST /api/v2.0/system/oidc/ping` accepts a user-supplied OIDC endpoint URL and calls `oidcpkg.TestEndpoint(conn)` → `gooidc.NewProvider(ctx, conn.URL)`. The go-oidc library immediately issues an outbound HTTP GET to `{url}/.well-known/openid-configuration` to fetch the OIDC discovery document. There is no IP filtering, no `ValidateHTTPURL` call, and no allowlist check applied to the URL before the outbound request. The `verify_cert: false` option additionally enables TLS bypass.

Unlike scanner and registry ping endpoints, PingOIDC appends a fixed path suffix (`/.well-known/openid-configuration`), limiting the attacker to error-based oracle (similar to PingScanner's fixed `/api/v1/metadata` suffix). However, the fixed suffix is predictable and any server responding to that path will trigger further requests.

## Location

- `src/server/v2.0/handler/oidc.go:37-51` — `PingOIDC` accepts URL, passes to `TestEndpoint`
- `src/pkg/oidc/helper.go:505-512` — `TestEndpoint` calls `gooidc.NewProvider(ctx, conn.URL)`
- `src/pkg/oidc/helper.go:86-104` — `providerHelper.create()` uses same pattern for stored OIDC config

## Attacker Control

- System admin controls the `url` field via `POST /api/v2.0/system/oidc/ping`
- URL is passed directly to `gooidc.NewProvider` with no IP filtering
- `verify_cert: false` disables TLS certificate verification
- Fixed path suffix `/.well-known/openid-configuration` appended — error-based oracle only

## Trust Boundary Crossed

- TB-8: Core API container to any HTTP-reachable host on the internal network
- System admin privilege escalates to internal network HTTP probing

## Impact

- Internal service discovery via error-based oracle
- Cloud metadata probing via `http://169.254.169.254/.well-known/openid-configuration`
- TLS bypass via `verify_cert: false` enables targeting internal HTTPS services
- If a metadata service or internal HTTP server happens to serve the discovery path, full SSRF response disclosure

## Evidence

- `oidc.go:41-43`: `oidcpkg.TestEndpoint(oidcpkg.Conn{URL: params.Endpoint.URL, VerifyCert: params.Endpoint.VerifyCert})` — no URL sanitization before call
- `helper.go:509-511`: `gooidc.NewProvider(ctx, conn.URL)` — HTTP request made immediately
- No `ValidateHTTPURL` call in the PingOIDC code path (unlike PingRegistry and PingScanner which at least call scheme validation)
- Pattern matches AP-022: user-controlled URL as sole input to HTTP client call

## Reproduction Steps

1. Authenticate as system administrator
2. Send: `POST /api/v2.0/system/oidc/ping` with body:
   `{"url": "http://169.254.169.254", "verify_cert": false}`
3. Observe: go-oidc attempts GET to `http://169.254.169.254/.well-known/openid-configuration`
4. Response timing/error message reveals open vs. closed vs. filtered port status
5. Iterate across internal IPs to discover services responding on port 80/443
