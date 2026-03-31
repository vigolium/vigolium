Phase: 7
Sequence: 003
Slug: jwt-missing-exp-enforcement
Verdict: VALID
Rationale: The JWT auth service's validateClaims() skips expiry enforcement when the "exp" key is absent from the token claims map, accepting tokens as permanently valid. While JWT auth is opt-in and key possession is required, this creates a defense-in-depth gap where leaked tokens without exp become permanent credentials.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-1/debate.md

## Summary

The JWT auth service's `validateClaims()` function at `validation.go:55-117` iterates over the claims map keys using a switch statement. The `exp` case at line 86 is only reached when the "exp" key exists in the claims map. If a JWT is crafted without an "exp" field (the key entirely absent from the JSON payload), `registeredClaims.Expiry` remains its zero value (nil pointer). At line 121, `registeredClaims.Validate(expectRegistered)` calls go-jose v4's Validate function, which only enforces expiry when `Expiry != nil`. A token without "exp" in its claims is therefore accepted as having no expiration, granting permanent access. Additionally, if "exp" is present with a `null` value, line 87-88 (`if value == nil { continue }`) explicitly skips setting the Expiry field, producing the same result.

## Location

- **Primary**: `pkg/services/auth/jwt/validation.go:86-95` -- `case "exp"` handler in validateClaims()
- **Validation call**: `pkg/services/auth/jwt/validation.go:119-122` -- `registeredClaims.Validate(expectRegistered)`
- **Init**: `pkg/services/auth/jwt/validation.go:12-53` -- `initClaimExpectations()` (does not enforce exp presence)
- **Auth entry**: `pkg/services/auth/jwt/auth.go` -- JWT auth middleware entry point

## Attacker Control

The JWT is provided directly in the `Authorization: Bearer` header (or configured `header_name`). The token must be signed with the configured key (HMAC shared secret or asymmetric key pair). Two attack paths:
1. **Key possession**: Attacker knows the signing key and crafts a token without exp
2. **Token leak**: A legitimately-issued token without exp is leaked from logs, monitoring systems, or error reports and remains valid indefinitely

## Trust Boundary Crossed

TB2 -- Authentication Gate. The JWT authentication mechanism is designed to validate token integrity and temporal validity. Accepting tokens without expiry means a leaked token grants permanent access until the signing key is rotated.

## Impact

- **Permanent credential**: A JWT without `exp` functions as a non-expiring API key
- **Post-compromise persistence**: If a signing key is compromised, the attacker can create permanent tokens that survive credential rotation schedules (unless the key itself is rotated)
- **Token leak amplification**: A leaked token without exp has infinite value to an attacker, compared to a token with a short exp that becomes worthless quickly

## Evidence

```go
// validation.go:86-95 -- exp case only reached when "exp" key exists in claims map
case "exp":
    if value == nil {
        continue  // null exp value: Expiry remains nil
    }
    if floatValue, ok := value.(float64); ok {
        out := jwt.NumericDate(floatValue)
        registeredClaims.Expiry = &out
    } else {
        return fmt.Errorf("%q claim has invalid type %T, number expected", key, value)
    }
```

```go
// validation.go:119-122 -- go-jose Validate only enforces exp when Expiry != nil
expectRegistered := s.expectRegistered
expectRegistered.Time = time.Now()
if err := registeredClaims.Validate(expectRegistered); err != nil {
    return err
}
```

If the "exp" key is entirely absent from the JWT claims JSON, the `case "exp"` branch is never reached, `registeredClaims.Expiry` remains nil, and `Validate()` passes without expiry enforcement.

## Reproduction Steps

1. Enable JWT auth in Grafana configuration: `[auth.jwt]` section with `enabled = true`, `key_file` or `jwk_set_url` configured
2. Generate a JWT WITHOUT an "exp" claim, signed with the configured key:
   ```json
   {"sub": "admin", "iss": "test-issuer"}
   ```
3. Sign with the configured HMAC secret or private key
4. Send a request to any authenticated endpoint with `Authorization: Bearer <token>`
5. Observe the request is authenticated successfully
6. Wait any amount of time and repeat -- the token is accepted indefinitely
