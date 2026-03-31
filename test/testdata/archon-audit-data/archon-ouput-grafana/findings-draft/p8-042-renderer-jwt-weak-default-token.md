---
id: p8-042
title: Renderer JWT Authentication Uses Weak Default Signing Key "-"
severity: MEDIUM
status: VALID
verdict: VALID
cluster: Data Isolation & Rendering
---

Phase: 8
Sequence: 042
Slug: renderer-jwt-weak-default-token
Verdict: VALID
Rationale: The renderer authentication token defaults to the single character "-" (setting.go:2070), which is used as HMAC-SHA512 signing key for JWT-based render key authentication. When the renderAuthJWT feature flag is enabled without changing the default token, any attacker who can reach the renderer endpoint can forge JWTs to impersonate any user. Requires two non-default conditions (feature flag + unchanged default), making this a misconfiguration-dependent vulnerability.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: check-4-ambiguous
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

Grafana's image rendering service supports JWT-based authentication via the `renderAuthJWT` feature flag. When this flag is enabled, render keys are generated as JWTs signed with HMAC-SHA512 using the `renderer_token` configuration value. The default value for `renderer_token` is `"-"` (a single ASCII hyphen character), which is a trivially known key. An attacker who can reach the Grafana server's renderer authentication endpoints can forge JWTs signed with this default key to impersonate any user with any org role.

## Affected Code

### Default Token Value
- **File**: `pkg/setting/setting.go:2070`
```go
cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")
```

### JWT Signing with Default Token
- **File**: `pkg/services/rendering/auth.go:144-146`
```go
func (j *jwtRenderKeyProvider) get(_ context.Context, opts AuthOpts) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS512, j.buildJWTClaims(opts))
    return token.SignedString(j.authToken)  // j.authToken = []byte("-")
}
```

### JWT Verification with Default Token
- **File**: `pkg/services/rendering/auth.go:56-65`
```go
func (rs *RenderingService) getRenderUserFromJWT(key string) *RenderUser {
    claims := new(renderJWT)
    tkn, err := jwt.ParseWithClaims(key, claims, func(_ *jwt.Token) (any, error) {
        return []byte(rs.Cfg.RendererAuthToken), nil  // []byte("-")
    }, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))
```

### Feature Flag Gate
- **File**: `pkg/services/rendering/auth.go:41`
```go
if looksLikeJWT(key) && rs.features.IsEnabled(ctx, featuremgmt.FlagRenderAuthJWT) {
```

## Attack Path

1. Attacker identifies a Grafana instance with `renderAuthJWT` feature flag enabled
2. Attacker knows the default `renderer_token` is `"-"` (publicly visible in source code)
3. Attacker crafts a JWT with:
   - Header: `{"alg": "HS512", "typ": "JWT"}`
   - Payload: `{"RenderUser": {"org_id": 1, "user_id": 1, "org_role": "Admin"}, "exp": <future_timestamp>}`
   - Signed with HMAC-SHA512 using key `"-"`
4. Attacker sends this JWT as the render key to Grafana's `GetRenderUser` endpoint
5. `looksLikeJWT` returns true (JWT starts with "eyJ")
6. `getRenderUserFromJWT` verifies the signature with `[]byte("-")` -- passes
7. Attacker is authenticated as Admin user for rendering operations

## Evidence

### Default Token Configuration
```go
// pkg/setting/setting.go:2070
cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")
```

### Token Used as HMAC Key
```go
// pkg/services/rendering/auth.go:116
authToken: []byte(cfg.RendererAuthToken),  // []byte("-") = single byte key
```

### JWT Claims Include Identity
```go
// pkg/services/rendering/auth.go:149-159
func (j *jwtRenderKeyProvider) buildJWTClaims(opts AuthOpts) renderJWT {
    return renderJWT{
        RenderUser: &RenderUser{
            OrgID:   opts.OrgID,
            UserID:  opts.UserID,
            OrgRole: string(opts.OrgRole),
        },
    }
}
```

## Reproduction Steps

1. Enable the `renderAuthJWT` feature flag in Grafana configuration
2. Do NOT change the `renderer_token` from its default value
3. Craft a JWT with the structure shown in the attack path, signed with HMAC-SHA512 using key `"-"`
4. Use this JWT as the render key in a request to Grafana's rendering endpoint
5. Verify that the JWT is accepted and the forged identity is used

**Defense context from Advocate**: This requires two non-default conditions: (1) the renderAuthJWT feature flag must be enabled, and (2) the renderer_token must be left at its default. These are contradictory deployment practices -- enabling JWT auth should prompt token configuration. The renderer endpoint is typically internal-only.

## Severity Justification

- **MEDIUM** severity based on:
  - Requires two non-default conditions (feature flag + unchanged default)
  - Single-byte signing key is trivially known from public source code
  - Impact if exploitable: full authentication bypass for renderer endpoints
  - Downgraded from HIGH because exploitation requires specific misconfiguration
  - The renderer endpoint is typically internal, reducing attack surface
