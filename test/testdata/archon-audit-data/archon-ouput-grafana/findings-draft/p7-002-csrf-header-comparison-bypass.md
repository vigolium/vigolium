Phase: 7
Sequence: 002
Slug: csrf-header-comparison-bypass
Verdict: VALID
Rationale: The CSRF middleware at csrf.go:116-126 compares Origin hostname against a user-controlled custom header value, enabling bypass when csrf_additional_headers is configured. Exploitation is blocked in default configuration by empty csrf_additional_headers, SameSite=Lax cookies, and CORS preflight, but the logic flaw is confirmed.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-1/debate.md

## Summary

The CSRF middleware's `check()` function at `csrf.go:71-141` contains a logic flaw in the custom header comparison. When `csrf_additional_headers` is configured (non-default), the middleware iterates over configured header names (line 116), reads the header value from the incoming request (line 117), parses the hostname (line 118), and compares it to the Origin header hostname (line 122). Since both the Origin header and the custom header values are entirely attacker-controlled in a cross-origin request, an attacker can set both to the same hostname, causing `addr.Host == origin` to evaluate to `true` and setting `trustedOrigin = true`. This bypasses the CSRF protection. The comparison should be against the server's own hostname (already available as `netAddr.Host` at line 135), not against a user-supplied header value.

## Location

- **Primary**: `pkg/middleware/csrf/csrf.go:116-126` -- custom header comparison logic
- **Configuration**: `pkg/middleware/csrf/csrf.go:38` -- `csrf_additional_headers` read from config (empty by default)
- **Related**: `pkg/middleware/csrf/csrf.go:104-107` -- empty Origin also skips CSRF (separate but related issue)
- **Cookie config**: `pkg/setting/setting.go:1818` -- SameSite=Lax default

## Attacker Control

The attacker controls both the `Origin` header and the custom header values in a cross-origin request. In the attack scenario:
- `Origin: https://evil.com` (set by browser on cross-origin request)
- Custom header (e.g., `X-Forwarded-Host: evil.com`) (set by attacker in JavaScript)

Both values are parsed for hostname, and the comparison `addr.Host == origin` succeeds.

## Trust Boundary Crossed

TB2 -- Authentication Gate (CSRF protection). The CSRF middleware is designed to prevent cross-site request forgery. This bypass allows an attacker to forge state-mutating requests from a cross-origin context.

## Impact

If exploited (requires non-default configuration), enables:
- Cross-site request forgery on any state-mutating endpoint
- Potential chaining with SAST-007 (X-DS-Authorization header injection to backend datasources)
- Potential chaining with SPEC-GAP-004 (hop-by-hop header forwarding)

## Evidence

```go
// csrf.go:116-126 -- both Origin and custom header are attacker-controlled
trustedOrigin := false
for h := range c.headers {
    customHost := r.Header.Get(h)  // attacker-controlled header value
    addr, err := util.SplitHostPortDefault(customHost, "", "0")
    if err != nil {
        return &errorWithStatus{Underlying: err, HTTPStatus: http.StatusBadRequest}
    }
    if addr.Host == origin {  // compares two attacker-controlled values
        trustedOrigin = true
        break
    }
}
```

```go
// csrf.go:136 -- trustedOrigin=true bypasses the hostname check
hostnameMatches := origin == netAddr.Host
if netAddr.Host == "" || !trustedOrigin && !hostnameMatches {
    return &errorWithStatus{...}
}
```

## Reproduction Steps

1. Configure Grafana with `csrf_additional_headers = X-Forwarded-Host` in the `[security]` section
2. Optionally set `cookie_samesite = none` and `cookie_secure = true` (to allow cross-site cookies)
3. Authenticate to Grafana as a normal user
4. From an attacker-controlled page, send a cross-origin POST request with:
   - `Origin: https://evil.com`
   - `X-Forwarded-Host: evil.com`
5. Observe that the CSRF check passes (trustedOrigin=true at line 123)

Note: In default configuration (empty csrf_additional_headers, SameSite=Lax), this is not exploitable.
