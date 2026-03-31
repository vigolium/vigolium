Phase: 7
Sequence: 001
Slug: oidc-missing-claim-validation
Verdict: VALID
Rationale: validateIDTokenSignatureWithURLs() verifies cryptographic signature but omits exp/iss/aud claim validation, violating OIDC Core 1.0 Section 3.1.3.7. The OAuth authorization code flow provides strong transport-level protection against direct exploitation, but the missing validation is a defense-in-depth gap exploitable if the IdP is compromised, the token response is intercepted, or cross-audience tokens are issued.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-1/debate.md

## Summary

The OIDC ID token signature validation function `validateIDTokenSignatureWithURLs()` in `social_base.go` verifies the cryptographic signature of ID tokens using JWKS but does not validate the `exp` (expiration), `iss` (issuer), or `aud` (audience) claims. After signature verification succeeds at line 429, the function immediately marshals and returns the raw claims at lines 438-442 without any temporal or identity claim checks. This violates OpenID Connect Core 1.0 Section 3.1.3.7 which requires validation of these claims. The AzureAD connector correctly validates audience (azuread_oauth.go:432-434), but Generic OAuth, GitLab, Okta, and Google connectors do not.

## Location

- **Primary**: `pkg/login/social/connectors/social_base.go:385-449` -- `validateIDTokenSignatureWithURLs()` function
- **Callers without post-facto validation**:
  - `pkg/login/social/connectors/generic_oauth.go:442` (via `validateIDTokenSignature()`)
  - `pkg/login/social/connectors/gitlab_oauth.go:295`
  - `pkg/login/social/connectors/okta_oauth.go:135`
  - `pkg/login/social/connectors/google_oauth.go:265`
- **Caller WITH post-facto validation**: `pkg/login/social/connectors/azuread_oauth.go:432-434` (validates audience)

## Attacker Control

The ID token is obtained from the IdP's token endpoint during the OAuth authorization code exchange (oauth.go:165). In the standard flow, the attacker does not control the ID token content. However:
- If the IdP is compromised or misconfigured, it may return expired or cross-audience tokens
- If the token response is intercepted (logging middleware, CDN, proxy inspection), the ID token can be extracted
- If multiple applications share the same IdP JWKS, a token issued for application A could be accepted by Grafana if it is somehow presented in the token exchange response

## Trust Boundary Crossed

TB2 -- Authentication Gate. Expired tokens with valid signatures allow authentication after the intended session lifetime. Cross-audience tokens bypass IdP-level application access controls.

## Impact

- **Expired token acceptance**: A user whose account was revoked at the IdP but whose old token has a valid signature could re-authenticate if the IdP returns a stale token
- **Cross-audience confusion**: A token issued for a different client_id (different application) would be accepted, bypassing IdP-enforced application-level access controls
- **Issuer confusion**: Tokens from a different IdP using the same JWKS URL format could be accepted

## Evidence

```go
// social_base.go:428-442 -- after signature verification, returns immediately
var claims map[string]any
if err := parsedToken.Claims(key, &claims); err == nil {
    // Successfully verified, cache the keyset if we got it from URL
    if expiry != 0 {
        if err := s.cacheJWKS(ctx, cacheKey, keyset, expiry); err != nil {
            s.log.Warn("Failed to cache key set", "err", err)
        }
    }
    rawJSON, err := json.Marshal(claims)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal verified claims: %w", err)
    }
    return rawJSON, nil  // NO exp/iss/aud validation before return
}
```

## Reproduction Steps

1. Configure Grafana with Generic OAuth, `validate_id_token=true`, and `jwk_set_url` pointing to a test IdP
2. Obtain a valid ID token from the test IdP with a past `exp` value
3. Ensure the signing key is still in the IdP's JWKS
4. Trigger an OAuth callback where the IdP returns this expired token in the token exchange response
5. Observe that Grafana accepts the expired token and creates a session

Note: Direct injection of the ID token is not possible through the standard OAuth callback flow. The token exchange is server-to-server HTTPS. Testing requires controlling the IdP's token endpoint response.
