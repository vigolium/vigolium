Phase: 8
Sequence: 010
Slug: oidc-pkce-silent-downgrade
Verdict: VALID
Rationale: Confirmed silent PKCE downgrade via Go type assertion failure producing empty string. State parameter and provider-side PKCE enforcement provide partial mitigations.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

## Summary

When the PKCE code verifier stored in the Redis session is absent or corrupted (due to session expiry, sticky-session failure, or Redis key deletion), Harbor's OIDC callback silently proceeds without PKCE verification. At `oidc.go:133`, the Go type assertion `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)` produces an empty string on failure (no error checked). At `helper.go:203-206`, `len(pkceCode) == 0` causes the PKCE verifier to be omitted from the token exchange. The authorization code is exchanged without `code_verifier`, downgrading PKCE protection silently.

## Location

- `src/core/controllers/oidc.go:133` -- `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)` silent type assertion
- `src/pkg/oidc/helper.go:203-206` -- PKCE verifier skipped when length is zero
- `src/core/controllers/oidc.go:92-96` -- PKCE code stored in session during RedirectLogin

## Attacker Control

Natural: Session expiry between RedirectLogin and Callback causes PKCE key absence. Adversarial: Redis write access (see p8-003) to delete the `oidc_pkce_code` session key.

## Trust Boundary Crossed

Authorization code -> Token exchange without PKCE binding. The code can be exchanged by any party who intercepts it (assuming the OIDC provider does not enforce PKCE server-side).

## Impact

- PKCE protection silently disabled without user or operator awareness
- Authorization code interception attacks become viable against permissive OIDC providers
- State parameter still provides CSRF protection but cannot bind the code to the client (PKCE's role)
- Many OIDC providers enforce PKCE server-side, making this a login failure rather than security bypass for those providers

## Evidence

```go
// src/core/controllers/oidc.go:133
pkceCode, _ := oc.GetSession(pkceCodeKey).(string)
// Go type assertion failure -> pkceCode = "" (zero value), no error

// src/pkg/oidc/helper.go:203-206
if len(pkceCode) > 0 {
    opts = append(opts, pkceCode.Verifier())
}
// len("") == 0 -> verifier NOT added -> exchange without code_verifier
```

## Reproduction Steps

1. Configure Harbor with OIDC auth
2. Start OIDC login flow (RedirectLogin stores PKCE code in Redis session)
3. Delete the `oidc_pkce_code` key from the Redis session (or wait for session expiry)
4. Complete the OIDC callback
5. Observe that the token exchange request does not include `code_verifier` parameter
6. If OIDC provider is permissive, authentication succeeds without PKCE verification
7. Recommended fix: Change to `pkceCode, ok := ...; if !ok { return error }` to make PKCE mandatory
