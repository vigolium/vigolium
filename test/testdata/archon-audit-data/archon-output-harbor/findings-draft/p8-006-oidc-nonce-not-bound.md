Phase: 8
Sequence: 006
Slug: oidc-nonce-not-bound
Verdict: VALID
Rationale: Missing nonce is a confirmed OIDC Core 1.0 Section 3.1.2.1 spec compliance gap verified across RedirectLogin, AuthCodeURL, and VerifyToken. Authorization code flow limits practical exploitability.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

## Summary

Harbor's OIDC authentication flow does not generate, store, or validate a `nonce` parameter as required by OIDC Core 1.0 Section 3.1.2.1 and Section 3.1.3.7 Step 11. The `RedirectLogin` function generates state and PKCE but no nonce. The `AuthCodeURL` call adds no nonce option. The `VerifyToken` call provides no nonce to the go-oidc verifier, causing nonce validation to be silently skipped. This is a spec compliance gap that theoretically enables ID token replay attacks, though the authorization code flow significantly limits practical exploitability.

## Location

- `src/core/controllers/oidc.go:68-104` -- `RedirectLogin` generates state and PKCE, no nonce
- `src/pkg/oidc/helper.go:164-188` -- `AuthCodeURL` adds state/PKCE options, no nonce
- `src/core/controllers/oidc.go:146` -- `oidc.VerifyToken` called with no nonce to check
- `src/pkg/oidc/helper.go:220-241` -- `verifyTokenWithConfig` creates config without Nonce field

## Attacker Control

Exploitation requires obtaining a valid ID token for a target user AND the ability to inject it into a callback response. In authorization code flow, the ID token is obtained server-to-server, making injection very difficult without MITM to the OIDC provider.

## Trust Boundary Crossed

OIDC provider token endpoint -> Harbor ID token validation. The missing nonce means Harbor cannot distinguish fresh tokens from replayed ones, though the authorization code flow provides compensating protection.

## Impact

- OIDC Core 1.0 spec non-compliance
- Theoretical ID token replay enabling session fixation/account takeover
- Practical exploitation requires elevated position (MITM to OIDC provider in auth code flow)
- State parameter provides partial compensating protection against CSRF

## Evidence

```go
// src/core/controllers/oidc.go:68-97
func (oc *OIDCController) RedirectLogin() {
    state := utils.GenerateRandomString()   // state generated
    pkceCode, err := pkce.Generate()        // PKCE generated
    // NO nonce generated or stored
    url, err := oidc.AuthCodeURL(oc.Context(), state, pkceCode)
    oc.SetSession(pkceCodeKey, string(pkceCode))
    oc.SetSession(stateKey, state)           // state stored, nonce NOT stored
}

// src/core/controllers/oidc.go:146
_, err = oidc.VerifyToken(ctx, token.RawIDToken)
// VerifyToken calls go-oidc verifier with no Nonce option -- nonce check silently skipped
```

## Reproduction Steps

1. Confirm Harbor OIDC configuration
2. Inspect `RedirectLogin` -- verify no nonce generation
3. Inspect `AuthCodeURL` -- verify no nonce in auth URL options
4. Inspect `VerifyToken` -> `verifyTokenWithConfig` -- verify Config has no Nonce field
5. Recommended fix: Generate nonce in RedirectLogin, store in session, add as AuthCodeURL option, and set in verifier Config.Nonce for validation
