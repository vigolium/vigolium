Phase: 9
Sequence: 075
Slug: renderer-jwt-absent-exp-bypass
Verdict: VALID
Rationale: The rendering service's getRenderUserFromJWT() uses golang-jwt/v4 ParseWithClaims which calls VerifyExpiresAt with required=false, meaning tokens without an exp claim are unconditionally accepted as valid; combined with AP-041's default signing key of "-", an attacker can craft a permanently-valid renderer JWT.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-003-jwt-missing-exp-enforcement.md
Origin-Pattern: AP-003

## Summary

The rendering service's `getRenderUserFromJWT()` function at `pkg/services/rendering/auth.go:56-68` uses the `golang-jwt/jwt/v4` library's `ParseWithClaims()` to validate renderer authentication JWTs. This is a structurally distinct JWT validation path from AP-003's `pkg/services/auth/jwt/` path, using a different JWT library with the same root cause. The `golang-jwt/v4` `RegisteredClaims.Valid()` method calls `VerifyExpiresAt(now, false)` — with `required = false`. Per the library source at `verifyExp()`: when `c.ExpiresAt == nil` (absent exp), it returns `!required = true`, so the token passes expiry validation unconditionally. A renderer JWT crafted without an `exp` claim is accepted as permanently valid by `ParseWithClaims`. This is compounded by the AP-041 finding: `RendererAuthToken` defaults to `"-"`, meaning any attacker who knows this default (or has read the Grafana documentation) can sign a permanent renderer JWT without needing to compromise any credentials.

The renderer JWT path is gated behind the `FlagRenderAuthJWT` feature flag and is used to authenticate the image renderer service to Grafana's `GetRenderUser` endpoint. A valid renderer JWT grants a `RenderUser` identity (with arbitrary OrgID, UserID, OrgRole) that Grafana uses to serve rendered images.

## Location

- **Primary**: `pkg/services/rendering/auth.go:56-68` -- `getRenderUserFromJWT()` using `jwt.ParseWithClaims` without requiring exp
- **Library behavior**: `golang-jwt/jwt/v4@v4.5.2/claims.go:57` -- `VerifyExpiresAt(now, false)` called with `required=false`
- **Library source**: `golang-jwt/jwt/v4@v4.5.2/claims.go:243-247` -- `verifyExp`: returns `!required` when `exp == nil`
- **Default key**: `pkg/setting/setting.go:2070` -- `RendererAuthToken` defaults to `"-"` (AP-041)
- **Feature flag gate**: `pkg/services/rendering/auth.go:41` -- `FlagRenderAuthJWT` must be enabled
- **JWT producer**: `pkg/services/rendering/auth.go:144-160` -- `jwtRenderKeyProvider.buildJWTClaims()` always sets `ExpiresAt` when Grafana issues tokens; the gap is on the consumer side

## Attacker Control

The render key (JWT string) is accepted as the render authentication token. In the `FlagRenderAuthJWT` code path:
1. Grafana's renderer client produces JWTs (setting `ExpiresAt` correctly)
2. The JWT is passed from the renderer process back to Grafana via the render key mechanism
3. Any actor who can present a correctly-signed JWT string to `GetRenderUser` (directly or via the rendering HTTP path) with a crafted payload can authenticate as any `RenderUser` identity

Two attacker paths:
- **Default key path** (chained with AP-041): If the operator has not changed `RendererAuthToken` from the default `"-"`, the attacker knows the HMAC-SHA512 signing key and can craft any renderer JWT, including one without `exp`, that is permanently valid
- **Key-knowledge path**: An attacker who has extracted the `RendererAuthToken` (via config file read, environment variable exposure, or another vulnerability) can craft a permanent renderer JWT

## Trust Boundary Crossed

TB2 -- Authentication Gate (renderer authentication sub-path). The rendering JWT mechanism is intended to provide short-lived, expiring credentials for the renderer service. Accepting tokens without `exp` means a crafted or leaked renderer JWT grants permanent access as any Grafana user identity (arbitrary OrgID, UserID, OrgRole including Admin).

## Impact

- **Identity impersonation**: A permanent renderer JWT with `{"org_id": 1, "user_id": 1, "org_role": "Admin"}` grants admin-level rendering access indefinitely
- **Compounded by AP-041**: The default `RendererAuthToken = "-"` means an unauthenticated attacker who knows Grafana defaults can forge both the identity AND the token without any credential theft
- **Feature-flagged surface**: The impact is limited to deployments where `FlagRenderAuthJWT` is enabled, but this flag is on a path toward becoming default behavior
- **Different library, same root cause**: Uses `golang-jwt/v4` instead of go-jose; the root cause (absent exp treated as no restriction) is identical to AP-003 but independently manifested in a different JWT library's design

## Evidence

```go
// pkg/services/rendering/auth.go:56-68
// getRenderUserFromJWT -- ParseWithClaims with no exp requirement
func (rs *RenderingService) getRenderUserFromJWT(key string) *RenderUser {
    claims := new(renderJWT)
    tkn, err := jwt.ParseWithClaims(key, claims, func(_ *jwt.Token) (any, error) {
        return []byte(rs.Cfg.RendererAuthToken), nil
    }, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

    if err != nil || !tkn.Valid {
        rs.log.Error("Could not get render user from JWT", "err", err)
        return nil
    }
    return claims.RenderUser
}
```

```go
// golang-jwt/jwt/v4@v4.5.2/claims.go:47-78
// RegisteredClaims.Valid() -- called by ParseWithClaims internally
func (c RegisteredClaims) Valid() error {
    // ...
    if !c.VerifyExpiresAt(now, false) { // required = false
        // only fails if ExpiresAt is non-nil AND expired
    }
    // ...
}

// golang-jwt/jwt/v4@v4.5.2/claims.go:243-247
func verifyExp(exp *time.Time, now time.Time, required bool) bool {
    if exp == nil {
        return !required // returns true when required=false, even if exp is absent
    }
    return now.Before(*exp)
}
```

```go
// renderJWT struct embeds RegisteredClaims -- which uses VerifyExpiresAt with required=false
type renderJWT struct {
    RenderUser *RenderUser
    jwt.RegisteredClaims  // ExpiresAt field is *NumericDate (pointer, nil when absent)
}
```

A JWT payload `{"org_id":1,"user_id":1,"org_role":"Admin"}` signed with `"-"` (default key) using HS512 and WITHOUT an `exp` field is accepted as permanently valid.

## Reproduction Steps

1. Confirm `FlagRenderAuthJWT` is enabled (feature flag configuration)
2. Identify the `RendererAuthToken` (defaults to `"-"` in Grafana config)
3. Craft a renderer JWT without an `exp` claim:
   ```json
   Header: {"alg":"HS512","typ":"JWT"}
   Payload: {"org_id":1,"user_id":1,"org_role":"Admin"}
   ```
   Signed with HS512 using the key value of `RendererAuthToken` (default: `"-"`)
4. Present this token to Grafana's render user lookup path (the key string passed to `GetRenderUser`)
5. Observe that `getRenderUserFromJWT` returns a valid `RenderUser` with Admin role for org 1
6. Wait any amount of time and repeat -- token remains valid indefinitely

## Comparison with Origin Finding AP-003 (p7-003)

| Dimension | p7-003 (auth.jwt service) | p7-075 (renderer JWT) |
|-----------|--------------------------|----------------------|
| Library | go-jose/v4 | golang-jwt/v4 |
| Mechanism | switch-case absent key + nil Expiry | VerifyExpiresAt(required=false) |
| Scope | JWT auth user authentication | Renderer service authentication |
| Feature gate | auth.jwt enabled | FlagRenderAuthJWT enabled |
| Key strength | Operator-configured | Defaults to "-" (AP-041) |
| Attacker needs | Signing key | Default key (no rotation needed) |
| Severity amplifier | Second-order (token leak) | AP-041 default key chains directly |
