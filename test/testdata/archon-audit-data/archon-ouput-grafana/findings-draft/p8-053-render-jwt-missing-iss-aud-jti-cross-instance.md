Phase: 10
Sequence: 053
Slug: render-jwt-missing-iss-aud-jti-cross-instance
Verdict: VALID
Rationale: The jwtRenderKeyProvider builds JWT claims with only an ExpiresAt field and no iss, aud, jti, or nbf claims; in multi-instance Grafana deployments where renderAuthJWT is enabled, a JWT minted by one instance (or forged by an attacker against any instance using the default key) is accepted by all other instances without any binding to the originating instance, enabling cross-instance authentication bypass.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-041-renderer-jwt-forgery-admin-takeover.md
Origin-Pattern: AP-041

## Summary

The `jwtRenderKeyProvider.buildJWTClaims()` method in `pkg/services/rendering/auth.go:149-160` generates JWT tokens with only a `RenderUser` struct (OrgID, UserID, OrgRole) and an `ExpiresAt` claim. No standard JWT security claims are set:

- **`iss` (Issuer)**: Not set — no binding to the specific Grafana instance that minted the token
- **`aud` (Audience)**: Not set — no binding to any specific endpoint or service
- **`jti` (JWT ID)**: Not set — no per-token uniqueness, enabling replay across instances and services
- **`nbf` (Not Before)**: Not set — token is valid from issuance with no minimum age requirement

In high-availability and multi-instance Grafana deployments (multiple Grafana instances sharing the same `renderer_token` configuration), a render JWT minted by one Grafana instance is fully valid for authentication against any other Grafana instance with the same `renderer_token`. This is the intended behavior for JWT-based stateless authentication, but it creates a critical cross-instance attack path:

When ANY instance uses the default `renderer_token = "-"`, a JWT forged against one instance (or crafted by an attacker with knowledge of the default key) authenticates against ALL instances in the cluster without any instance-level binding, because:
1. No `iss` claim binds the token to an originating instance
2. No `aud` claim restricts which endpoints/instances may accept the token
3. The signing key is shared globally (same `renderer_token` config applies to all instances)
4. No JTI means the same forged token can be replayed against multiple instances simultaneously

This is a structural variant because the absence of these claims is a distinct vulnerability from the default-key issue: even with a non-default `renderer_token` in a multi-tenant environment where multiple customers share infrastructure, one customer's JWT can authenticate against another customer's Grafana instance if they accidentally use the same token value.

## Location

- **Primary**: `pkg/services/rendering/auth.go:149-160` — `buildJWTClaims` sets only `ExpiresAt`, no `iss`, `aud`, `jti`, `nbf`
- **Primary**: `pkg/services/rendering/auth.go:56-68` — `getRenderUserFromJWT` validates only `jwt.WithValidMethods` and expiry; no issuer/audience check
- **Secondary**: `pkg/setting/setting.go:2070` — shared `renderer_token` configuration applies to all instances in a cluster
- **Secondary**: `pkg/services/authn/clients/render.go:73-78` — `Test()` fires on all endpoints without instance-scoping

## Attacker Control

**Scenario — Multi-instance Grafana cluster:**
- Two or more Grafana instances (HA deployment) share the same `renderer_token = "-"` (default)
- Attacker has access to one instance's render flow (e.g., via M13: X-Auth-Token bypass, or by being an authenticated user who triggers a render)
- Attacker captures a JWT from instance A's render URL or forges one using the default key
- Attacker presents the JWT as `Cookie: renderKey=<jwt>` to instance B's API endpoints
- Since JWT has no `iss` or `aud` binding to instance A, instance B accepts it as valid

**Attacker-controlled fields in the JWT:**
- `OrgID`: any value → cross-org access
- `OrgRole`: "Admin" → Admin identity
- No per-instance restriction

## Trust Boundary Crossed

Instance A's render authorization domain → Instance B's HTTP API trust boundary. In a multi-instance cluster, the absence of instance-binding claims in the JWT allows authentication to cross from one instance's context into another, defeating the expected isolation between cluster members.

## Impact

- Cross-instance authentication bypass in HA/multi-instance Grafana deployments
- All instances sharing the same `renderer_token` (including non-default custom tokens that happen to be identical) are affected simultaneously
- An attacker who has obtained or forged one render JWT can authenticate against ALL instances in the cluster for the JWT's TTL duration
- Combined with the default `renderer_token = "-"`: a single forged JWT authenticates against ALL default-configured Grafana instances in any deployment (not just multi-instance; truly global across all deployments using the default)
- In managed/SaaS Grafana deployments where multiple customer tenants share backend infrastructure with the same renderer_token, cross-tenant authentication may be possible

## Evidence

1. `auth.go:149-160`: `buildJWTClaims` returns `renderJWT{RenderUser: ..., RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: ...}}` — only `ExpiresAt` set
2. `auth.go:56-68`: `getRenderUserFromJWT` uses only `jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()})` — no audience, issuer, or JTI validation options
3. The `golang-jwt/jwt` library does NOT enforce `iss` or `aud` by default without explicit `jwt.WithIssuedAt()`, `jwt.WithAudience()`, `jwt.WithIssuer()` options
4. `rendering.go:116`: `authToken: []byte(cfg.RendererAuthToken)` — the same key is used across all instances in a cluster sharing the same configuration
5. Compare: `ext_jwt.go` (ExtendedJWT client) uses `authlib.NewAccessTokenVerifier` with `AllowedAudiences` — demonstrates that audience validation IS available and used in other Grafana JWT paths but not in the renderer JWT path

## Reproduction Steps

1. Deploy two Grafana instances (A and B) with `renderAuthJWT` enabled and `renderer_token = "-"` (default or same custom value)
2. On instance A, forge a render JWT:
   ```go
   token := jwt.NewWithClaims(jwt.SigningMethodHS512, &renderJWT{
       RenderUser: &RenderUser{OrgID: 1, UserID: 0, OrgRole: "Admin"},
       RegisteredClaims: jwt.RegisteredClaims{
           ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
       },
   })
   signedToken, _ := token.SignedString([]byte("-"))
   ```
3. Use the forged JWT against instance B (different host/pod):
   ```
   curl -H "Cookie: renderKey=<signedToken>" http://instanceB:3000/api/admin/settings
   ```
4. Expected: Admin settings returned from instance B — JWT from instance A (or forged) accepted

Note: The same JWT also works against instance A. The issue is that there is no instance-binding mechanism at all.
