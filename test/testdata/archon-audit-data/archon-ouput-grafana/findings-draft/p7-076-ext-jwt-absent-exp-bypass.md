Phase: 9
Sequence: 076
Slug: ext-jwt-absent-exp-bypass
Verdict: VALID
Rationale: The ext_jwt.go client delegates claim validation to authlib's VerifierBase.Verify(), which calls go-jose's Claims.Validate() with Time=now but without requiring exp presence; an access token or ID token issued without an exp claim will have Expiry=nil and pass go-jose's nil-guard check, granting permanent authentication.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-003-jwt-missing-exp-enforcement.md
Origin-Pattern: AP-003

## Summary

The Extended JWT authentication client at `pkg/services/authn/clients/ext_jwt.go` delegates all JWT verification to `authlib.NewAccessTokenVerifier` and `authlib.NewIDTokenVerifier`. Both ultimately call `authlib.VerifierBase.Verify()` at `github.com/grafana/authlib@.../authn/verifier.go:88-123`. This function calls `claims.Validate(jwt.Expected{AnyAudience: ..., Time: time.Now()})` using go-jose's `Claims.Validate()`. Per go-jose's `ValidateWithLeeway` at line 116: `if c.Expiry != nil && validationTime.Add(-leeway).After(c.Expiry.Time())` — expiry is only checked when `c.Expiry != nil`. If a token is issued without an `exp` claim, go-jose decodes it into a typed `jwt.Claims` struct where `Expiry` remains `nil`, and the expiry check is skipped unconditionally.

This is the same root-cause nil-guard bypass as AP-003, but manifesting through a different code path: authlib's VerifierBase rather than Grafana's own `validateClaims()`. The ext_jwt path is used for internal Grafana service-to-service authentication (Grafana Cloud control plane to Grafana instance) via `X-Access-Token` and `X-Grafana-Id` HTTP headers. The signing keys are held by Grafana Cloud's key infrastructure, so external exploitation requires access to Grafana Cloud's signing infrastructure. Within a compromised Grafana Cloud context, permanently-valid access tokens without `exp` could be issued.

## Location

- **Entry point**: `pkg/services/authn/clients/ext_jwt.go:87` -- `s.accessTokenVerifier.Verify(ctx, jwtToken)`
- **Verifier**: `github.com/grafana/authlib@.../authn/verifier.go:88-123` -- `VerifierBase.Verify()`
- **Validation call**: `github.com/grafana/authlib@.../authn/verifier.go:115-120` -- `claims.Validate(jwt.Expected{Time: time.Now()})`
- **Library nil guard**: `github.com/go-jose/go-jose/v4@v4.1.3/jwt/validation.go:116` -- `if c.Expiry != nil && ...`
- **HTTP entry**: `X-Access-Token` header (ExtJWTAuthenticationHeaderName) processed by `ext_jwt.go:363-368`
- **ID token entry**: `X-Grafana-Id` header (ExtJWTAuthorizationHeaderName) processed by `ext_jwt.go:371-376`
- **Config gate**: `pkg/setting/setting_jwt.go:51` -- `auth.extended_jwt.enabled` (disabled by default)

## Attacker Control

The ext_jwt path accepts tokens from the `X-Access-Token` HTTP header. Tokens must be signed with the private key corresponding to the JWKS served at `cfg.ExtJWTAuth.JWKSUrl`. The `AllowedAudiences` is hardcoded to `["grafana"]` for Grafana deployments.

Two scenarios:
1. **Compromised Grafana Cloud signing key**: An attacker with access to Grafana Cloud's access token signing infrastructure could issue access tokens without `exp`. These tokens would be accepted indefinitely by any Grafana instance with `auth.extended_jwt` enabled.
2. **Self-hosted ext_jwt deployment**: In a self-hosted Grafana deployment where an operator configures their own `jwks_url` pointing to their own JWKS endpoint and generates access tokens, a token issued without `exp` would be accepted permanently by `VerifierBase.Verify()`.

## Trust Boundary Crossed

TB2 -- Authentication Gate (extended JWT service-to-service path). The ext_jwt mechanism is designed for short-lived service authentication between Grafana Cloud components. Absent exp enforcement means a compromised or malformed access token without expiry grants permanent service-level authentication until the signing key is rotated.

## Impact

- **Permanent service authentication**: An ext_jwt access token without `exp` is valid indefinitely, granting full service-level permissions encoded in the token's `permissions` claim
- **Service account persistence**: The `authenticateAsService()` path at `ext_jwt.go:195-245` uses the access token's permissions directly; a permanent access token becomes a non-expiring service credential
- **Same root cause, different path**: The authlib `VerifierBase` uses go-jose's `Claims.Validate()` directly — the same nil-Expiry bypass as AP-003, but in the third-party library wrapper rather than Grafana's own validation code
- **Wider blast radius**: Ext_jwt tokens can authenticate as service identities with arbitrary permissions (including `fixed:*` admin roles), not just user-level access

## Evidence

```go
// pkg/services/authn/clients/ext_jwt.go:87-90
// ext_jwt Authenticate -- delegates verification to authlib
accessTokenClaims, err := s.accessTokenVerifier.Verify(ctx, jwtToken)
if err != nil {
    return nil, errExtJWTInvalid.Errorf("failed to verify access token: %w", err)
}
```

```go
// github.com/grafana/authlib@v0.0.0-20260316143530-e1d123886039/authn/verifier.go:108-122
// VerifierBase.Verify -- decodes into typed struct, then calls Validate with Time=now
claims := Claims[T]{token: token}
if err := parsed.Claims(jwk, &claims.Claims, &claims.Rest); err != nil {
    return nil, err
}
// When "exp" is absent: claims.Claims.Expiry remains nil after Claims() decoding

if err := claims.Validate(jwt.Expected{
    AnyAudience: jwt.Audience(v.cfg.AllowedAudiences),
    Time:        time.Now(),
}); err != nil {
    return nil, mapErr(err)
}
// go-jose ValidateWithLeeway:
// if c.Expiry != nil && validationTime.Add(-leeway).After(c.Expiry.Time()) { return ErrExpired }
// Expiry == nil => condition is false => no expiry error => token accepted permanently
```

```go
// Hardcoded audience for Grafana ext_jwt (pkg/setting/setting_jwt.go:10,54)
const extJWTAccessTokenExpectAudience = "grafana"
jwtSettings.Audiences = []string{extJWTAccessTokenExpectAudience}
```

An access token payload `{"sub":"accesspolicy:svc-id","namespace":"*","permissions":["fixed:dashboards.admin:read"],"aud":"grafana"}` signed with the Grafana Cloud private ECDSA key and WITHOUT an `exp` claim would be accepted indefinitely.

## Reproduction Steps

1. Configure Grafana with `auth.extended_jwt.enabled = true` and `jwks_url` pointing to a controlled JWKS endpoint
2. Generate an EC P-256 key pair; serve the public key at the JWKS endpoint
3. Issue an access token (typ: `at+jwt`) signed with the private key, WITHOUT an `exp` claim:
   ```json
   {
     "sub": "accesspolicy:my-service",
     "namespace": "*",
     "permissions": ["fixed:dashboards.admin:read"],
     "aud": "grafana"
   }
   ```
4. Send a request to any authenticated Grafana endpoint with `X-Access-Token: <token>`
5. Observe that the request is authenticated successfully
6. Wait any amount of time and repeat -- the token is accepted indefinitely

## Comparison with Origin Finding AP-003 (p7-003)

| Dimension | p7-003 (auth.jwt service) | p7-076 (ext_jwt / authlib) |
|-----------|--------------------------|---------------------------|
| Library | go-jose/v4 (direct) | authlib wrapper -> go-jose/v4 |
| Validation path | Grafana's validateClaims() | authlib VerifierBase.Verify() |
| Nil guard location | validation.go:86-95 (explicit case) | verifier.go:115 -> go-jose:116 |
| Token source | Operator-configured HMAC/RSA key | Grafana Cloud JWKS or self-hosted |
| Config gate | auth.jwt.enabled | auth.extended_jwt.enabled |
| Severity modifier | Key possession required | Grafana Cloud infra compromise |
| Both use go-jose | Yes (same underlying library call) | Yes (same nil-Expiry behavior) |
