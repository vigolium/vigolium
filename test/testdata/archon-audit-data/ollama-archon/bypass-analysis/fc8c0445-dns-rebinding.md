# CVE-2024-28224 — DNS Rebinding Fix Bypass Analysis

**Patch commit:** fc8c0445
**Cluster ID:** dns-rebinding-host-check

## Patch Summary

The fix adds `allowedHostsMiddleware` to the gin router's middleware chain. When the server is bound to a loopback address, the middleware validates the `Host` header against an allowlist (localhost, local TLDs, loopback/private IPs, machine hostname). Requests with disallowed Host headers are rejected with 403, preventing DNS rebinding attacks where a malicious page's JS sends requests with an attacker-controlled Host header to the local Ollama API.

## Bypass Verdict: bypassable

## Evidence

### Vector 1: Alternate entry points bypass middleware (registry.Local wrapper)

**Severity: HIGH**

In `server/routes.go:1727-1736`, when a registry client (`rc`) is non-nil, `GenerateRoutes` wraps the gin router inside a `registry.Local` struct as its `Fallback` handler. The `registry.Local.ServeHTTP` (at `server/internal/registry/server.go:109`) directly handles two routes **before** falling back to gin:

- `/api/delete` (line 118-119) -> `s.handleDelete`
- `/api/pull` (line 120-121) -> `s.handlePull`

These requests are handled by `registry.Local` directly and **never reach the gin middleware chain**, meaning `allowedHostsMiddleware` does not execute. A DNS rebinding attack can invoke `/api/delete` to delete models and `/api/pull` to pull arbitrary models from a registry, both without Host header validation.

The `/api/pull` bypass is particularly dangerous as it allows an attacker to pull attacker-controlled models onto the victim's machine via DNS rebinding.

### Vector 2: Non-loopback binding disables all checks (by design, but risky)

**Severity: LOW (informational)**

At line 1607, if the server is bound to a non-loopback address (e.g., `OLLAMA_HOST=0.0.0.0`), the middleware skips all checks and allows any Host header. This is by design (the server is intentionally exposed), but users setting `OLLAMA_HOST=0.0.0.0` for LAN access may not realize this disables DNS rebinding protection entirely.

### Vector 3: Host header normalization is adequate

The current code (evolved from the original patch) now includes `strings.ToLower(host)` in `allowedHost` (line 1574) and properly strips ports via `net.SplitHostPort`. No bypass via case or port variations.

### Vector 4: All gin-routed paths are covered

The middleware is applied at the router level via `r.Use()`, so all routes registered on the gin router (including `/v1/*` OpenAI compat, `/v1/messages` Anthropic compat) are covered. No route-specific gaps within gin.

### Vector 5: addr == nil bypass

At line 1602, if `addr` is nil, the middleware allows all requests. In `Serve()` at line 1790 (where `s` is constructed), `addr` is set from `ln.Addr()`, so this should not be nil in production. However, in test code (`Server{}` with zero value), `addr` is nil, meaning tests do not exercise the middleware.

## Summary

The primary bypass is the `registry.Local` wrapper intercepting `/api/delete` and `/api/pull` before they reach gin's middleware chain. This is a real, exploitable bypass of the DNS rebinding protection for these two endpoints when the registry client is enabled.
