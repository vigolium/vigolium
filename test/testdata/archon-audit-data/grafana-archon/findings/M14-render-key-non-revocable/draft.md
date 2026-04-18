Phase: 8
Sequence: 044
Slug: render-key-non-revocable
Verdict: VALID
Rationale: JWT render keys cannot be revoked before expiry (auth.go:141 "do nothing"), enabling persistent Admin-level access if a key is leaked, though the nil check at auth.go:34 prevents exploitation when renderer is not configured.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-3-ambiguous
Debate: archon/chamber-workspace/chamber-3/debate.md

## Summary

JWT-based render keys in Grafana cannot be revoked once issued. The `jwtRenderKeyProvider.afterRequest()` at `pkg/services/rendering/auth.go:141-143` is an empty function with the comment "do nothing - the JWT will just expire." A leaked render key remains valid for its full JWT lifetime, granting the bearer the ability to authenticate as the rendering service with the OrgRole specified in the key (potentially Admin). The render authentication client is registered at priority 10, meaning it takes precedence over session-based authentication at priority 60.

## Location

- `pkg/services/rendering/auth.go:141-143` — empty `afterRequest()` (no revocation)
- `pkg/services/rendering/auth.go:145-161` — `validate()` function
- `pkg/services/rendering/auth.go:33-37` — `GetRenderUser()` with nil check (mitigation)
- `pkg/services/authn/clients/render.go:36-67` — `Render.Authenticate()` identity creation

## Attacker Control

The attacker must obtain a valid JWT render key through a separate vulnerability or exposure:
- Log file exposure (reverse proxy access logs)
- XSS attack capturing the render key cookie
- Network sniffing (if communication is not encrypted)

## Trust Boundary Crossed

Leaked render key -> persistent Admin-level authentication. The trust boundary is the assumption that render keys are short-lived and constrained to the rendering service process.

## Impact

- Persistent Admin-level access for the full JWT lifetime
- Priority 10 authentication shadows any existing user session
- No revocation mechanism — key remains valid until expiry
- Attacker can access all admin functionality in the org associated with the render key

## Evidence

```go
// pkg/services/rendering/auth.go:141-143
func (j *jwtRenderKeyProvider) afterRequest(_ context.Context, _ AuthOpts, _ string) {
    // do nothing - the JWT will just expire
}

// pkg/services/rendering/auth.go:33-37 (mitigation)
func (rs *RenderingService) GetRenderUser(ctx context.Context, key string) (*RenderUser, bool) {
    if rs.perRequestRenderKeyProvider == nil {
        // Rendering is not configured. Just reject the token.
        return nil, false
    }
    // ...
}
```

## Reproduction Steps

1. Configure Grafana with a rendering service (image renderer plugin)
2. Trigger a dashboard rendering operation (e.g., scheduled report or alert screenshot)
3. Capture the render key JWT from the render_key cookie or request logs
4. After the rendering operation completes, replay the render key:
   `curl -b "renderKey=<captured-jwt>" http://grafana:3000/api/org`
5. Observe: request is authenticated as the rendering service with Admin role
6. Verify: the render key remains valid until JWT expiry, with no revocation
