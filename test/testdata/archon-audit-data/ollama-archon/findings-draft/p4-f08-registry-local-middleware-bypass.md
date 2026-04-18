# p4-f08: registry.Local Intercepts /api/delete and /api/pull Before gin Middleware

**Severity**: HIGH
**CWE**: CWE-284 (Improper Access Control)
**DFD Slice**: CFD-1
**CVE**: CVE-2024-28224 bypass (DNS rebinding protection bypass)

## Location

- `server/internal/registry/server.go:114-128`: `serveHTTP()` intercepts before fallback
- `server/routes.go:1727-1736`: `registry.Local` wraps gin router as Fallback

## Description

When a registry client (`rc`) is non-nil, `GenerateRoutes` wraps the gin router inside `registry.Local` as its `Fallback` handler. `registry.Local.ServeHTTP` directly handles `/api/delete` and `/api/pull` BEFORE falling through to gin:

```go
func (s *Local) serveHTTP(rec *statusCodeRecorder, r *http.Request) {
    switch r.URL.Path {
    case "/api/delete":
        return false, s.handleDelete(rec, r)  // gin middleware never runs
    case "/api/pull":
        return false, s.handlePull(rec, r)    // gin middleware never runs
    default:
        if s.Fallback != nil {
            s.Fallback.ServeHTTP(rec, r)  // gin (with middleware) only for other routes
```

`allowedHostsMiddleware` (DNS rebinding protection) is applied only to gin routes. `/api/delete` and `/api/pull` bypass it entirely when the registry client is active.

## Impact

- DNS rebinding attack can invoke `/api/delete` to delete all models
- DNS rebinding attack can invoke `/api/pull` to pull attacker-controlled models (enables ENTRYPOINT RCE)
- Both endpoints bypass the CORS + Host header validation chain

## Evidence

- `server/internal/registry/server.go:118-121` — direct route handling before fallback
- `server/routes.go:1727-1736` — gin router wrapped as Fallback
- `server/routes.go:1668-1671` — middleware only in gin chain

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security

**Attacker Control**: DNS rebinding attacker controls the DNS response for a hostname they own. When a victim's browser visits the attacker's page, the attacker changes the DNS record to resolve to `127.0.0.1`. Subsequent XHR requests from the browser use the attacker's hostname as `Host`, which resolves to `127.0.0.1:11434`. The `allowedHostsMiddleware` would normally reject this (`attacker.com` is not a recognized local host), but `registry.Local` intercepts before that middleware runs.

**Runtime**: `ollama serve` — the `registry.Local` wrapper is an `http.Handler` inserted at the outermost layer of the HTTP stack, before the gin engine.

**Trust Boundary Crossed**: Network-to-localhost trust boundary enforced by `allowedHostsMiddleware`. The bypass eliminates DNS rebinding protection for exactly the two highest-impact endpoints: model deletion and model pull.

**Effect**: Cross-user (any user whose browser the attacker can reach). An attacker with a malicious website can delete all models and/or pull attacker-controlled models on any victim who visits the page while Ollama is running. Combined with p4-f01 (ENTRYPOINT RCE on the `parth/agents` branch), `POST /api/pull` of a malicious model is a pre-requisite for the supply-chain RCE.

**CodeQL Reachability**: Confirmed on main branch. `server/routes.go:1729-1736` shows `registry.Local{..., Fallback: r}` where `r` is the gin engine. `server/internal/registry/server.go:114-129` shows the switch statement that intercepts `/api/delete` and `/api/pull` without calling `Fallback`. The gin middleware (including `allowedHostsMiddleware`) is attached to `r`, not to `registry.Local`. The bypass is structural.

**Condition for Activation**: The `rc != nil` branch at `server/routes.go:1727` determines whether `registry.Local` is used. If the new registry client is disabled or nil, gin handles all routes with middleware intact. The vulnerability is only active when the new registry backend is enabled — which is the direction of current development.

**KB Cross-Reference**: CVE-2024-28224 (GHSA-5jx5-hqx5-2vrj) — DNS rebinding — full API access — was patched via `allowedHostsMiddleware`. This finding is a bypass of that patch, specifically for the two routes handled by `registry.Local`. The original fix is rendered ineffective for these routes.

**Exploit Prerequisites**:
- Victim has Ollama running with the new registry client enabled (`rc != nil`)
- Attacker controls a domain and can perform DNS rebinding (standard browser security research technique)
- Victim's browser visits the attacker's page while Ollama is running

**Verdict**: KEEP — HIGH security finding. This is a patch bypass for a known CVE (CVE-2024-28224). Fix: move `allowedHostsMiddleware` (and CORS middleware) to the `registry.Local.ServeHTTP` level, before route dispatch, so all routes are protected regardless of which handler processes them. Alternatively, inline the host validation directly in `handleDelete` and `handlePull`.
