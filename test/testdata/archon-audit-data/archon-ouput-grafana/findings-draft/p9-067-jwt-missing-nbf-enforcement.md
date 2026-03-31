Phase: 9
Sequence: 067
Slug: jwt-missing-nbf-enforcement
Verdict: VALID
Rationale: The JWT auth service's validateClaims() uses the same switch-key-iteration pattern that caused the exp bypass (AP-003/p7-003); the nbf claim also relies on key presence in the map, so tokens without an nbf field have NotBefore=nil and go-jose's Validate() skips the not-before window check entirely.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-001-oidc-missing-claim-validation.md
Origin-Pattern: AP-003

## Summary

The JWT auth service's `validateClaims()` function at `pkg/services/auth/jwt/validation.go:96-105` processes the `nbf` (not-before) claim using the same switch-key-iteration pattern identified in AP-003 for the `exp` claim. When a JWT is presented without an `nbf` claim, the `case "nbf":` branch is never entered, leaving `registeredClaims.NotBefore` as `nil`. The subsequent call to go-jose's `registeredClaims.Validate(expectRegistered)` at line 121 skips the not-before check when `NotBefore` is nil (verified in go-jose library source: `if c.NotBefore != nil && !validationTime.Add(leeway).After(c.NotBefore.Time()) { return ErrNotValidYet }`). This means a JWT token with no `nbf` claim and a valid signature is accepted regardless of when it was issued or intended to become valid.

While RFC 7519 Section 4.1.5 makes `nbf` optional, a security-conscious implementation should either enforce `nbf` when present (which Grafana does correctly for present values) or provide a configuration option to require it. The structural gap is that absent `nbf` is treated as "no restriction" rather than as a policy decision that operators should be able to configure.

## Location

- **Primary**: `pkg/services/auth/jwt/validation.go:96-105` -- `nbf` case in the `validateClaims()` switch
- **Root function**: `pkg/services/auth/jwt/validation.go:55-136` -- `validateClaims()` full function
- **Library nil guard**: `go-jose/v4/jwt/validation.go` -- `if c.NotBefore != nil` guard skips check when field is nil

## Attacker Control

Same preconditions as AP-003 (p7-003):
- JWT auth must be explicitly enabled (`auth.jwt` section in Grafana config; disabled by default)
- Attacker must possess a JWT signed with the configured key (HMAC shared secret or RSA/ECDSA private key)
- The JWT omits the `nbf` claim (many JWT libraries allow this; RFC 7519 makes it optional)
- The attacker wants to use a token before a specific time window (e.g., a pre-issued token that should not be valid until a future date)

Practical scenario: An operator pre-issues JWT tokens for scheduled service account access (e.g., "this token is for use during maintenance window X"). Without enforced `nbf`, a token issued with a future intended start date but no `nbf` claim is immediately usable.

## Trust Boundary Crossed

TB2 -- Authentication Gate. A JWT token intended to be valid only after a future date is accepted immediately if the `nbf` claim is absent, because `NotBefore=nil` causes go-jose's not-before validation to be skipped.

## Impact

- **Pre-activation token acceptance**: A JWT intended to be valid from a future date (but without an explicit `nbf` claim) is accepted immediately upon creation. This is lower severity than the `exp` bypass in p7-003 because the primary temporal control for JWTs is expiration (exp), not not-before (nbf).
- **Defense-in-depth gap**: The same structural pattern (switch-key-iteration) that causes the exp bypass also silently ignores the nbf claim when absent. Both gaps coexist in the same code path.
- **Consistent structural failure**: The fix for AP-003 (adding mandatory exp when absent) should be applied symmetrically to nbf, otherwise the fix will be incomplete.

## Evidence

```go
// pkg/services/auth/jwt/validation.go:96-105
// nbf case -- same absent-key bypass as exp at lines 86-95
case "nbf":
    if value == nil {
        continue
    }
    if floatValue, ok := value.(float64); ok {
        out := jwt.NumericDate(floatValue)
        registeredClaims.NotBefore = &out
    } else {
        return fmt.Errorf("%q claim has invalid type %T, number expected", key, value)
    }
// When "nbf" key is ABSENT from the claims map: this case is never entered.
// registeredClaims.NotBefore stays nil.
```

```go
// pkg/services/auth/jwt/validation.go:119-121
// go-jose Validate() is called with Time=now but NotBefore=nil
expectRegistered := s.expectRegistered
expectRegistered.Time = time.Now()
if err := registeredClaims.Validate(expectRegistered); err != nil {
    return err
}
```

```go
// go-jose/v4/jwt/validation.go (library source)
// The nil guard means missing nbf passes validation unconditionally
if c.NotBefore != nil && !validationTime.Add(leeway).After(c.NotBefore.Time()) {
    return ErrNotValidYet
}
```

Contrast with the exp claim behavior (AP-003/p7-003) at lines 86-95 of the same file -- identical structural pattern.

## Reproduction Steps

1. Enable JWT auth in Grafana: `[auth.jwt] enabled = true`, configure HMAC key or RSA key
2. Issue a JWT signed with the configured key that omits the `nbf` claim entirely (set only `iss`, `sub`, `exp` for a far-future expiry)
3. Present this JWT in the `Authorization: Bearer` header to any Grafana endpoint requiring auth
4. Observe that Grafana accepts the token: `validateClaims()` never enters the `case "nbf":` branch, `NotBefore` is nil, and go-jose skips the not-before check
5. Optionally: issue the same token WITH a future `nbf` date to confirm that present-nbf IS correctly enforced (regression check)

## Comparison with Origin Finding AP-003 (p7-003)

| Dimension | p7-003 (exp absent) | p9-067 (nbf absent) |
|-----------|---------------------|---------------------|
| RFC claim | exp -- OPTIONAL per RFC 7519 | nbf -- OPTIONAL per RFC 7519 |
| Security impact | Permanent tokens (no expiry) | Pre-window token usage |
| Severity | MEDIUM | MEDIUM (lower practical impact) |
| Root cause | switch-key-iteration, absent key skips case | Identical root cause |
| go-jose nil guard | Expiry nil guard at validation.go:116 | NotBefore nil guard (same file) |
| Fix scope | Require exp or reject absent-exp | Same pattern; same fix approach |

Both AP-003 and this variant share the same root cause code pattern and require the same structural fix: either reject tokens that omit the claim, or add a configuration option to enforce it.
