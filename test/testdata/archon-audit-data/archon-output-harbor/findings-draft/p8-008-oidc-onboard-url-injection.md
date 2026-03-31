Phase: 8
Sequence: 008
Slug: oidc-onboard-url-injection
Verdict: VALID
Rationale: Confirmed missing URL encoding with open redirect potential at the onboard step. Narrow attack scenario (new OIDC user + controlled IdP) limits practical impact.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

## Summary

In the OIDC callback handler, when a new user requires onboarding (auto-onboard disabled), the OIDC-provider-supplied username is interpolated into a redirect URL without URL encoding. At `oidc.go:203`, `fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr)` allows a username containing characters like `&`, `=`, `?`, or `#` to inject additional query parameters or override the `redirect_url` parameter. This enables an open redirect after the onboarding step.

## Location

- `src/core/controllers/oidc.go:203` -- unencoded username interpolation in redirect URL
- `src/core/controllers/oidc.go:176` -- only spaces replaced (`strings.Replace(username, " ", "_", -1)`)

## Attacker Control

The attacker controls the OIDC provider's username claim. A malicious provider or a provider where usernames are user-controlled can supply a username containing URL metacharacters (e.g., `user&redirect_url=https://evil.com`).

## Trust Boundary Crossed

OIDC provider username claim -> Harbor onboard redirect URL. The injected parameters affect the Angular SPA's onboarding page behavior.

## Impact

- Open redirect after onboarding to attacker-controlled URL
- Potential session theft if the Angular SPA processes the redirect without validation
- Parameter injection may override other query parameters used by the onboarding page
- Limited to first-time OIDC users with auto-onboard disabled

## Evidence

```go
// src/core/controllers/oidc.go:175-203
username := info.Username
username = strings.Replace(username, " ", "_", -1)  // only spaces replaced
// ...
oc.Controller.Redirect(
    fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr),
    http.StatusFound,
)
// username is NOT url.QueryEscape()'d
```

## Reproduction Steps

1. Configure Harbor with OIDC auth mode, auto-onboard disabled
2. At the OIDC provider, create a user with username: `testuser&redirect_url=https://evil.com`
3. Have this user authenticate via Harbor OIDC login for the first time
4. Observe the redirect URL: `/oidc-onboard?username=testuser&redirect_url=https://evil.com&redirect_url=<legitimate>`
5. The first `redirect_url` parameter (attacker-controlled) may override the second in the Angular SPA
6. Recommended fix: Use `url.QueryEscape(username)` and `url.QueryEscape(redirectURLStr)` in the Sprintf call
