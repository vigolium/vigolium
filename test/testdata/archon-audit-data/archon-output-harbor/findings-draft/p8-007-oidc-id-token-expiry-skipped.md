Phase: 8
Sequence: 007
Slug: oidc-id-token-expiry-skipped
Verdict: VALID
Rationale: Confirmed RFC 7519 / OIDC Core spec compliance gap. Limited practical impact because actual authentication relies on refresh token validity at the OIDC provider.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

## Summary

Harbor's `parseIDToken` function at `helper.go:214` uses `SkipExpiryCheck: true` when parsing ID tokens for claim extraction. This function is called by `UserInfoFromIDToken` (used in the OIDC CLI auth path) to extract groups, admin status, and other claims from stored ID tokens. While the actual authentication relies on the OIDC provider's refresh token validation, the expired ID token's claims (potentially stale group memberships or admin status) are accepted without expiry checking, violating OIDC Core 1.0 Section 3.1.3.7 Step 9 and RFC 7519 Section 4.1.4.

## Location

- `src/pkg/oidc/helper.go:214-217` -- `parseIDToken` with `SkipExpiryCheck: true`
- `src/pkg/oidc/helper.go:362-371` -- `UserInfoFromIDToken` calls `parseIDToken`
- `src/pkg/oidc/helper.go:282-313` -- `UserInfoFromToken` uses `UserInfoFromIDToken` for claim extraction

## Attacker Control

Limited. The attacker needs a previously valid (signature-valid) ID token. The token's claims are from the original legitimate issuance, not attacker-crafted. The risk is stale claims (e.g., group membership revoked at the OIDC provider but still present in the stored ID token).

## Trust Boundary Crossed

Expired OIDC credentials -> Valid claim extraction. Token lifetime controls are bypassed for claim extraction.

## Impact

- Stale group memberships and admin status from expired ID tokens used in authorization decisions
- Token lifetime controls defined by the OIDC provider are not respected
- If a user's admin group membership is revoked at the OIDC provider, Harbor may continue granting admin access based on the stale ID token until the stored token is replaced

## Evidence

```go
// src/pkg/oidc/helper.go:214-217
func parseIDToken(ctx context.Context, rawIDToken string) (*gooidc.IDToken, error) {
    conf := &gooidc.Config{SkipClientIDCheck: true, SkipExpiryCheck: true}
    return verifyTokenWithConfig(ctx, rawIDToken, conf)
}
```

## Reproduction Steps

1. Authenticate via OIDC CLI to store a token in Harbor's DB
2. Wait for the ID token to expire (typically 5-60 minutes)
3. At the OIDC provider, revoke the user's admin group membership
4. Re-authenticate via OIDC CLI (triggers token refresh + claim extraction from stored ID token)
5. Observe that if the refreshed token does not include a new ID token, the stale claims from the expired ID token are used
6. Recommended fix: Remove `SkipExpiryCheck: true` or re-extract claims from a freshly issued ID token after refresh
