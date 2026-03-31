Phase: 8
Sequence: 001
Slug: admin-db-auth-brute-force
Verdict: VALID
Rationale: The forced DB auth for admin combined with per-process-only lockout creates a permanently brute-forceable attack surface in HA deployments, confirmed by Tracer evidence of the unconditional IsSuperUser bypass and Advocate finding no distributed lockout mechanism.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: IsSuperUser forces DB auth unconditionally for admin (authenticator.go:142), and UserLock (lock.go) uses only in-memory state with a 1.5s cooldown per failure and no counter-based lockout, providing no distributed brute-force protection in HA deployments.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

Harbor's admin account (userID=1) always authenticates via DB credentials regardless of the configured authentication mode (OIDC, LDAP, etc.). The `IsSuperUser` check at `authenticator.go:142` unconditionally overrides the auth mode to `common.DBAuth` for the admin user. Combined with an in-memory-only lockout mechanism (`UserLock` in `lock.go`) that has no cross-pod synchronization, this enables unlimited brute force attacks against the admin account in multi-instance (HA) deployments.

## Location

- `src/core/auth/authenticator.go:142` -- `IsSuperUser` override forces DB auth
- `src/core/auth/lock.go:22-51` -- `UserLock` uses in-memory `map[string]time.Time`
- `src/server/middleware/security/basic_auth.go` -- entry point via HTTP Basic Auth

## Attacker Control

The attacker controls the HTTP Basic Auth header with the admin username (default: "admin") and password guess. This is fully controllable from the external network via any API endpoint that processes Basic Auth.

## Trust Boundary Crossed

External network -> Harbor Core admin authentication. The IsSuperUser bypass means OIDC/LDAP mode configuration is irrelevant -- the admin account is always DB-authenticated.

## Impact

- Full system admin access via brute-forced DB password
- In multi-instance deployments: attacker distributes requests across N pods, getting N * 5 attempts per 5-minute lockout window per pod
- Organizations that configure OIDC-only mode are not protected -- admin remains brute-forceable
- 1.5s sleep per failed attempt on a single pod limits single-pod rate to ~40 attempts/minute, but across pods this multiplies

## Evidence

```go
// src/core/auth/authenticator.go:142
if authMode == "" || IsSuperUser(ctx, m.Principal) {
    authMode = common.DBAuth
}

// src/core/auth/lock.go:23-30
type UserLock struct {
    d        time.Duration
    failures map[string]time.Time  // in-memory, no Redis sync
    lock     sync.RWMutex
}
```

## Reproduction Steps

1. Deploy Harbor in HA mode with 3+ core pods and OIDC auth mode configured
2. Send HTTP Basic Auth requests with `admin:<guess>` to different core pods (via load balancer)
3. Observe that each pod maintains independent lockout -- 5 failures on pod A do not affect pod B
4. After 5 failures on pod A, route to pod B for 5 more attempts, etc.
5. With 3 pods: 15 attempts per 5-minute window instead of 5
