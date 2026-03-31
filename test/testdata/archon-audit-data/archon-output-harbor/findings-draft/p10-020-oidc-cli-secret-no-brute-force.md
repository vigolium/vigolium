Phase: 10
Sequence: 020
Slug: oidc-cli-secret-no-brute-force
Verdict: VALID
Rationale: The OIDC CLI secret authentication path has zero rate limiting or lockout, identical to the confirmed robot account gap (p8-009), allowing unlimited guessing of OIDC CLI secrets.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-009-robot-account-no-brute-force-protection.md
Origin-Pattern: AP-006

## Summary

Harbor's OIDC CLI secret authentication path (`oidc_cli.go:72`) calls `oidc.VerifySecret` which performs a plaintext secret comparison with no rate limiting, no lockout, and no delay on failure. This is structurally identical to the confirmed robot account brute-force gap (p8-009): the human account path via `basicAuth.Generate` -> `auth.Login` has `lock.IsLocked` + `lock.Lock` + `time.Sleep(1.5s)`, but the OIDC CLI path bypasses all of these. OIDC CLI secrets are randomly generated via `utils.GenerateRandomString()` providing good entropy, but the complete absence of throttling removes defense-in-depth and leaves the endpoint unprotected against automated attacks.

## Location

- `src/server/middleware/security/oidc_cli.go:72` -- `oidc.VerifySecret(ctx, username, secret)` called with no preceding lock check
- `src/pkg/oidc/secret.go:86-139` -- `VerifySecret` does a string comparison with no sleep, no lock
- `src/core/auth/authenticator.go:151-160` -- human account path has lock and 1.5s sleep (absent in OIDC CLI path)

## Attacker Control

The attacker controls HTTP Basic Auth credentials with a valid OIDC username and guessed CLI secret. The username can be harvested through the Harbor UI (project members, users endpoint). CLI secrets are managed by users via the Harbor UI profile page and are used in CI/CD Docker login commands.

## Trust Boundary Crossed

External network -> OIDC CLI secret authentication. CLI secrets are used by CI/CD pipelines for artifact registry operations. A compromised CLI secret allows the attacker to push/pull artifacts or trigger replication, potentially enabling supply-chain attacks.

## Impact

- Unlimited online guessing against OIDC user CLI secrets
- No sleep, no lockout, no counter: requests processed at full server throughput
- OIDC CLI secrets are used for container registry operations (docker login) -- compromise enables supply-chain attacks equivalent to robot account compromise
- Contrast: human web login has per-process lockout (5 attempts per 1.5s window), robot accounts have no limit (p8-009), OIDC CLI secrets also have no limit
- The `oidc_cli.valid()` filter restricts paths (only `/v2`, `/service/token`, etc.), but these are exactly the paths used for automated tooling

## Evidence

```go
// src/server/middleware/security/oidc_cli.go:48-82
func (o *oidcCli) Generate(req *http.Request) security.Context {
    username, secret, ok := req.BasicAuth()
    // ... no lock.IsLocked check ...
    info, err := oidc.VerifySecret(ctx, username, secret)
    if err != nil {
        // NO lock.Lock(), NO time.Sleep()
        return nil
    }
    // ...
}

// src/core/auth/authenticator.go:151-160 (human account path -- has protection)
if lock.IsLocked(m.Principal) {
    return nil, nil
}
// ... on failure:
lock.Lock(m.Principal)
time.Sleep(frozenTime)  // 1.5s sleep absent in OIDC CLI path
```

## Reproduction Steps

1. Identify an OIDC user account (via Harbor UI or `/api/v2.0/users`)
2. Have that user generate a CLI secret via the Harbor UI profile page
3. Send rapid sequential Basic Auth requests to `/v2/` with `username:<guess>` at full speed
4. Observe no rate limiting, no lockout, no per-attempt delay
5. Compare with human account login: observe 1.5s sleep on each failure and lockout
6. Recommended fix: Apply the same `UserLock` mechanism used for basic auth to the OIDC CLI secret path
