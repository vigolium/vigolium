Phase: 8
Sequence: 030
Slug: oidc-open-redirect-backslash
Verdict: VALID
Rationale: IsLocalPath check in OIDC flow is bypassed by /\evil.com (passes starts-with-/ and not-starts-with-// checks); modern browsers normalize backslash to forward slash per WHATWG URL spec, creating protocol-relative redirect to attacker site. Redirect URL stored in session and not re-validated on callback.
Severity-Original: HIGH
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: IsLocalPath bypass with /\evil.com confirmed at code level; complete attack chain verified through every layer (input, validation, session, redirect, HTTP header); browser backslash normalization is WHATWG-specified behavior; no blocking protection found at any layer.
Severity-Final: HIGH
PoC-Status: theoretical

## Summary

Harbor's OIDC login flow validates redirect URLs via `IsLocalPath()` which checks that the path starts with `/` but not `//`. The value `/\evil.com` passes both checks but modern browsers (per WHATWG URL spec) normalize `\` to `/` in the Location header, making `/\evil.com` equivalent to `//evil.com` -- a protocol-relative redirect to `evil.com`. The redirect URL is stored in the session at login time and NOT re-validated when used in the OIDC callback redirect, creating a TOCTOU gap.

## Location

- `src/common/utils/utils.go:308-311` -- `IsLocalPath` checks `HasPrefix("/") && !HasPrefix("//")` only
- `src/core/controllers/oidc.go:81-86` -- `RedirectLogin` validates and stores redirect URL in session
- `src/core/controllers/oidc.go:230-233` -- Callback retrieves redirect URL from session, uses directly in `Redirect()` without re-validation

## Attacker Control

- Unauthenticated attacker crafts OIDC login URL with `redirect_url=/\evil.com`
- Redirect URL passes IsLocalPath validation and is stored in session
- After OIDC authentication, victim is redirected to attacker-controlled site

## Trust Boundary Crossed

- TB-1: Internet to Core API (Harbor auth flow) to attacker site
- User's post-authentication redirect hijacked to external attacker domain

## Impact

- Post-authentication phishing: user redirected to fake Harbor login page
- Credential harvesting: user re-enters credentials thinking session expired
- Session token theft: attacker site can harvest session cookies if SameSite is not strict
- Distinct from P7-001 (authproxy open redirect): different flow, different bypass technique

## Evidence

- Tracer confirmed PARTIAL: IsLocalPath bypass confirmed, browser behavior per WHATWG spec
- utils.go:308-311: `/\evil.com` passes both prefix checks
- oidc.go:230-233: no re-validation on callback redirect
- WHATWG URL spec: backslash treated as forward slash in path component
- Bypass analysis bypass-b6c083d73: IsLocalPath backslash bypass identified

## Cold Verification Evidence

- `IsLocalPath("/\\evil.com")` returns `true` -- confirmed via standalone Go test
- `http.Redirect` produces `Location: /\evil.com` header -- confirmed via httptest
- Go's `hexEscapeNonASCII` does NOT encode backslash (ASCII 0x5C) -- confirmed via Go stdlib source
- Go's `path.Clean` does NOT normalize backslash -- confirmed via test
- No `proxy_redirect` directive in nginx config -- verified
- No re-validation between session retrieval (oidc.go:124) and redirect (oidc.go:233) -- verified
- Evidence files: `security/real-env-evidence/oidc-open-redirect-backslash/`

## Reproduction Steps

1. Craft URL: `https://harbor.example.com/c/oidc/login?redirect_url=/\evil.com`
2. User clicks link, is redirected to OIDC provider for authentication
3. After successful OIDC auth, callback redirects to `/\evil.com`
4. Browser normalizes to `//evil.com` (protocol-relative), redirecting to `evil.com`
5. Attacker site presents fake Harbor login page for credential harvesting
