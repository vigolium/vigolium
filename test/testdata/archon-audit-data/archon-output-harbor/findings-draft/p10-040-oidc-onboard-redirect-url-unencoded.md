Phase: 10
Sequence: 040
Slug: oidc-onboard-redirect-url-unencoded
Verdict: VALID
Rationale: The redirect_url parameter in the oidc-onboard redirect URL is not URL-encoded, allowing a redirect_url value containing URL metacharacters (?, &, #) to inject additional query parameters or fragment identifiers into the Angular onboarding page URL.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-008-oidc-onboard-url-injection.md
Origin-Pattern: AP-030

## Summary

In `src/core/controllers/oidc.go:203`, both the `username` and the `redirect_url` parameters are interpolated without URL encoding into the onboard redirect URL:

```go
oc.Controller.Redirect(
    fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr),
    http.StatusFound,
)
```

The confirmed finding p8-008 documents the `username` injection vector. This variant documents the separate `redirect_url=%s` injection: `redirectURLStr` is the session-stored redirect URL (validated only by `IsLocalPath`, which allows `/path?key=val` and `/path#fragment`). A redirect URL containing `?` or `#` injects extra query parameters or a fragment into the onboard URL that the Angular SPA receives. An attacker who can influence the initial `redirect_url` query parameter to `IsLocalPath`-valid values containing metacharacters can manipulate the onboarding page's behavior.

## Location

- `src/core/controllers/oidc.go:203` -- `redirectURLStr` interpolated without `url.QueryEscape`
- `src/core/controllers/oidc.go:81-87` -- `redirectURL` accepted from query param, validated only by `IsLocalPath`
- `src/core/controllers/oidc.go:87` -- stored raw (not normalized) into session

## Attacker Control

1. Attacker crafts OIDC login link: `https://harbor.example.com/c/oidc/login?redirect_url=/dashboard%3Fevil%3Dinjected`
2. `IsLocalPath` passes (`/dashboard?evil=injected` starts with `/` and not `//`)
3. Value stored raw in session: `/dashboard?evil=injected`
4. New user completes OIDC auth, auto-onboard is disabled
5. Redirect issued to: `/oidc-onboard?username=newuser&redirect_url=/dashboard?evil=injected`
6. Angular SPA receives two `redirect_url` parameters, or a `redirect_url` with an injected query string fragment that alters onboarding page state

## Trust Boundary Crossed

- OIDC provider to Harbor onboarding Angular SPA
- Attacker-controlled URL metacharacters break parameter boundary in frontend redirect

## Impact

- Query parameter injection into Angular SPA onboarding page URL
- May override legitimate Angular route parameters depending on SPA routing logic
- Potential for open redirect if the SPA trusts the first `redirect_url` occurrence over the second
- Distinct from p8-008 (username injection): targets the redirect_url parameter rather than username

## Evidence

```go
// src/core/controllers/oidc.go:203
oc.Controller.Redirect(
    fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr),
    http.StatusFound,
)
// redirectURLStr: retrieved from session at oidc.go:166:
//   redirectURLStr, _ = oc.GetSession(redirectURLKey).(string)
// IsLocalPath("/dashboard?evil=injected") == true (starts with /, not //)
// url.QueryEscape NOT applied to redirectURLStr
```

## Reproduction Steps

1. Configure Harbor with OIDC auth mode, auto-onboard disabled
2. Craft URL: `https://harbor.example.com/c/oidc/login?redirect_url=/dashboard%3Fevil%3Dinjected%26second%3Dparam`
3. Have a first-time OIDC user authenticate via this link
4. Observe the onboard redirect: `/oidc-onboard?username=user&redirect_url=/dashboard?evil=injected&second=param`
5. The Angular SPA router receives `redirect_url=/dashboard` with extra injected params
6. Recommended fix: apply `url.QueryEscape(redirectURLStr)` in the fmt.Sprintf call
