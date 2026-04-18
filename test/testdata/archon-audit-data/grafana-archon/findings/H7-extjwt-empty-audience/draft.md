Phase: 8
Sequence: 041
Slug: extjwt-empty-audience
Verdict: VALID
Rationale: ID token audience check intentionally omitted (ext_jwt.go:58 comment), enabling cross-service identity spoofing with TypeRenderService escalation to Admin in shared-JWKS deployments, despite namespace cross-check mitigation.
Severity-Original: HIGH
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-3/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: The missing audience validation on ID tokens is verified in code (go-jose skips check when AnyAudience is empty), and the render-service-to-Admin escalation path is confirmed at ext_jwt.go:184-190, but exploitation requires non-default shared-JWKS deployment with an existing valid access-policy token.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

The ExtendedJWT authentication client at `pkg/services/authn/clients/ext_jwt.go:58-60` creates an ID token verifier with an empty `AllowedAudiences` configuration, explicitly skipping audience validation. In deployments where multiple services share a JWKS endpoint, an ID token issued for another service can be presented to Grafana. Combined with the TypeRenderService subject handling at lines 184-190, an attacker with a cross-service token can obtain Admin role in Grafana's default org without an active rendering service.

## Location

- `pkg/services/authn/clients/ext_jwt.go:58-60` — ID token verifier with empty AllowedAudiences
- `pkg/services/authn/clients/ext_jwt.go:147-150` — TypeRenderService accepted as valid identity type
- `pkg/services/authn/clients/ext_jwt.go:184-190` — TypeRenderService grants Admin role

## Attacker Control

The attacker must possess a valid JWT signed by the configured JWKS key with:
- `sub=render:<anything>` (TypeRenderService subject)
- Correct namespace claim matching the Grafana instance
- Valid access token for the same namespace

In shared-JWKS deployments, tokens issued for other services in the same namespace satisfy these requirements.

## Trust Boundary Crossed

Cross-service authentication -> Grafana Admin role. A token intended for Service-B is accepted by Service-A (Grafana) because audience is not validated on ID tokens.

## Impact

Privilege escalation to Admin role in Grafana's default organization. This grants full administrative access including:
- Dashboard and datasource management
- User and organization administration
- Access to stored datasource credentials
- Alerting rule modification

## Evidence

```go
// pkg/services/authn/clients/ext_jwt.go:58-60
// For ID tokens, we explicitly do not validate audience, hence an empty AllowedAudiences
// Namespace claim will be checked
idTokenVerifier := authlib.NewIDTokenVerifier(authlib.VerifierConfig{}, keys)

// pkg/services/authn/clients/ext_jwt.go:184-190
if t == claims.TypeRenderService {
    // RenderService always has Admin role (based on render.go logic)
    identity.OrgRoles = map[int64]org.RoleType{
        s.cfg.DefaultOrgID(): org.RoleAdmin,
    }
    identity.ClientParams.FetchSyncedUser = false
}
```

## Reproduction Steps

1. Configure Grafana with `ExtJWTAuth.Enabled=true` pointing to a shared JWKS endpoint
2. Obtain a valid JWT from another service in the same namespace with `sub=render:1`
3. Send request with `X-Access-Token: <valid-access-token>` and `X-Grafana-Id: <id-token-with-render-subject>`
4. Observe: identity is created with Admin role in the default org
5. Verify: the rendering service is not required to be running for this escalation
