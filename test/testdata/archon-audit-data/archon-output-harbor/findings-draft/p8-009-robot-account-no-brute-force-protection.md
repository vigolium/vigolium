Phase: 8
Sequence: 009
Slug: robot-account-no-brute-force-protection
Verdict: VALID
Rationale: Complete absence of rate limiting for robot accounts despite lockout existing for human accounts. Random secret generation provides practical brute-force resistance.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

## Summary

Harbor's robot account authentication path (`robot.Generate` at `security/robot.go:33-73`) performs no rate limiting, no lockout, and no sleep on authentication failure. This contrasts with the human account path (`basicAuth.Generate` -> `auth.Login`) which has `lock.Lock(username)` and 1.5s sleep on failure. Robot account names follow a predictable `robot$project+name` pattern. Password comparison uses single SHA256 with salt (not bcrypt/argon2). While robot secrets are randomly generated with sufficient entropy, the complete absence of defense-in-depth allows automated attacks without any throttling.

## Location

- `src/server/middleware/security/robot.go:33-73` -- no lockout, no sleep, no rate limiting
- `src/server/middleware/security/robot.go:57` -- `utils.Encrypt(secret, robot.Salt, utils.SHA256)` single SHA256
- `src/core/auth/authenticator.go:151-160` -- human account has `lock.IsLocked` + `lock.Lock` + `time.Sleep`

## Attacker Control

The attacker controls HTTP Basic Auth credentials with a `robot$` prefix username and guessed secret. Robot names are predictable and can be enumerated. Requests can be automated at arbitrary rate.

## Trust Boundary Crossed

External network -> Robot account authentication. Robot accounts are used in CI/CD pipelines for container image operations.

## Impact

- Unlimited online password guessing against robot accounts
- Robot accounts are used in CI/CD pipelines -- compromise enables supply chain attacks
- Single SHA256 hash is fast to compute, no adaptive cost function
- No logging of failed robot auth attempts (log at Errorf level but no security event)
- Contrast with human accounts: human accounts get 5 attempts per 5 minutes with 1.5s sleep; robot accounts have no limit

## Evidence

```go
// src/server/middleware/security/robot.go:33-73 -- NO rate limiting
func (r *robot) Generate(req *http.Request) security.Context {
    name, secret, ok := req.BasicAuth()
    // ... lookup robot by name ...
    if utils.Encrypt(secret, robot.Salt, utils.SHA256) != robot.Secret {
        log.Errorf("failed to authenticate robot account: %s", name)
        return nil  // NO lock.Lock(), NO time.Sleep()
    }
    // ...
}
```

## Reproduction Steps

1. Identify a robot account name (e.g., `robot$myproject+scanner`)
2. Send rapid sequential Basic Auth requests with guessed secrets
3. Observe no rate limiting, no lockout, no delay between failures
4. Compare with human account login: observe 1.5s sleep on each failure and lockout after 5 attempts
5. Recommended fix: Add robot accounts to the existing `UserLock` mechanism or implement per-name rate limiting
