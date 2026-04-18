Phase: 8
Sequence: 062
Slug: client2-experiment-bypasses-middleware
Verdict: VALID
Rationale: `server/internal/registry/server.go:109-128` dispatches `/api/pull` and `/api/delete` directly in its outer `ServeHTTP` when `OLLAMA_EXPERIMENT=client2` is set — skipping gin entirely, so `allowedHostsMiddleware`, cors, and every other middleware never runs on those routes; Advocate confirms the flag is documented-off but undocumented as security-relevant. Distinct from p8-008 (which covers unbounded body on the same path) because this is the host-header / auth-middleware bypass, not the body-size issue.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: check-5-ambiguous (gated by non-default experiment flag)
Debate: archon/chamber-workspace/chamber-04/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Deterministic test at archon/real-env-evidence/p8-062/middleware_bypass_review_test.go shows GET /api/pull and GET /api/delete on a Local{Fallback: ginRouterWithHostCheck} are served entirely within Local.serveHTTP (status 405 from handlePull/handleDelete method guard) with the gin-registered host-check middleware never invoked, while the control GET /api/tags returns 403 via the same middleware.
Severity-Final: MEDIUM
PoC-Status: executed

## Summary

When `OLLAMA_EXPERIMENT=client2` is set:

```go
// server/routes.go:92-96
useClient2 = experimentEnabled("client2")

// server/routes.go:1735-1744
if useClient2 {
    return &registry.Local{Fallback: r}, err
}
```

The HTTP handler returned is `*registry.Local` — NOT the gin router. `(*Local).ServeHTTP` at `server/internal/registry/server.go:109-128` is then the outermost HTTP handler:

```go
func (s *Local) serveHTTP(rec ResponseRecorder, r *http.Request) (bool, error) {
    switch r.URL.Path {
    case "/api/delete":
        return false, s.handleDelete(rec, r)
    case "/api/pull":
        return false, s.handlePull(rec, r)
    default:
        s.Fallback.ServeHTTP(rec, r)
        return true, nil
    }
}
```

`/api/delete` and `/api/pull` are dispatched directly without ever entering gin. The `allowedHostsMiddleware` (DNS-rebinding filter), the CORS middleware, and every future security middleware are registered on the gin router `r`, which is only reached via the `default` branch. Thus the two highest-risk endpoints (the ones that trigger outbound HTTP and model deletion) run with zero middleware protection.

p8-008 (AP-041) already documented the body-size angle of the same bypass. This finding captures the orthogonal-but-equally-serious angle: **host allowlist and cors are also bypassed** for `/api/pull` under `client2`. An attacker reaching loopback (via DNS rebinding against `.localhost` per p8-061, or via `OLLAMA_HOST=0.0.0.0` per p8-060) can submit `POST /api/pull {"name":"169.254.169.254/x:y","insecure":true}` with no host-header check — SSRF to IMDS without even the suffix filter.

## Location

- `server/routes.go:92-96` — `useClient2` initialization from env
- `server/routes.go:1735-1744` — handler swap when flag set
- `server/internal/registry/server.go:109-128` — outer dispatch bypassing gin
- `server/internal/registry/server.go:118-121` — `handlePull` invocation without middleware

## Attacker Control

Any network-reachable attacker (dependent on bind + rebinding primitives). The victim must have exported `OLLAMA_EXPERIMENT=client2`.

## Trust Boundary Crossed

B10 (network) → host. Additionally, structural: middleware contract broken.

## Impact

- `/api/pull` SSRF reach (link-local IMDS, private networks, arbitrary hosts per finding p8-002) WITHOUT the Host-header filter that normally provides DNS-rebinding defense on loopback bind.
- `/api/delete` exposed to DNS-rebinding-driven model wipeout.
- Compounding with p8-063 (readRequestBody unbounded), p8-060 (0.0.0.0 bind), and p8-002/p8-003 (body OOM sinks) into a full remote-DoS + SSRF primitive on default `OLLAMA_EXPERIMENT=client2` users.

## Evidence

Tracer confirmed: client2 dispatch is OUTER; `Fallback: r` (the gin router with middleware) only runs for non-matched paths. `entry-points.json` and `sinks.json` flag `server/internal/registry/server.go` as an independent handler surface.

Advocate: only protection is the opt-in flag. Docs do NOT describe `client2` as a security-relevant flag — the name "experiment" implies "may be unstable" rather than "disables security middleware".

Adversarial reproduction (archon/real-env-evidence/p8-062/):
- TestPullBypassesAllowedHosts: GET /api/pull with hostile Host header -> 405 from Local.handlePull; host-check middleware never invoked.
- TestDeleteBypassesAllowedHosts: GET /api/delete with hostile Host -> 405 from Local.handleDelete; middleware never invoked.
- TestTagsDoesNotBypass (control): GET /api/tags with hostile Host -> 403 from host-check middleware; confirms middleware is wired.

## Reproduction Steps

1. Run Ollama: `OLLAMA_HOST=0.0.0.0 OLLAMA_EXPERIMENT=client2 ollama serve`.
2. From the LAN (or drive-by): `curl http://ollama-host:11434/api/pull -d '{"name":"169.254.169.254/test:latest","insecure":true}' -H 'Host: anything'`.
3. Response leaks IMDS body (via the fmt.Errorf reflection path in `server/images.go:921-927`); `allowedHostsMiddleware` never fired because gin was bypassed.

Remediation: bring the `allowedHostsMiddleware` / auth / CORS middleware into the `Local` dispatcher (either by delegating to gin for ALL paths and only intercepting AFTER middleware, or by duplicating the middleware into the outer handler). Document `OLLAMA_EXPERIMENT=client2` as security-relevant in `docs/faq.mdx`.
