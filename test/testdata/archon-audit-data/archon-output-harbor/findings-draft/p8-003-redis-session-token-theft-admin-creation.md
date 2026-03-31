Phase: 8
Sequence: 003
Slug: redis-session-token-theft-admin-creation
Verdict: VALID
Rationale: Single precondition (unauthenticated Redis access in default deployment) enables both OIDC refresh token theft and arbitrary admin account creation, with no application-level session integrity protection found.
Severity-Original: HIGH
PoC-Status: theoretical
PoC-Block-Reason: Requires full Harbor deployment with configured OIDC provider (IdP) and default Redis on Docker bridge network. Environment not available for live execution.
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Complete code path traced from unauthenticated Redis (default config) through session injection to admin account creation via Onboard handler, with no integrity check on session data between OIDC Callback and Onboard endpoints.
Severity-Final: HIGH

## Summary

Harbor stores full OIDC tokens (including refresh tokens) unencrypted in Redis sessions. The default deployment uses unauthenticated Redis. An attacker with internal network access to Redis can: (1) read any OIDC user's session to extract refresh tokens for persistent session hijacking, and (2) write crafted session data with `AdminGroupMember: true` then call the OIDC onboard endpoint to create arbitrary system admin accounts. The Onboard handler deserializes session data without re-verifying the OIDC token or checking data integrity.

## Location

- `src/core/controllers/oidc.go:161-168` -- full token stored in Redis session
- `src/core/controllers/oidc.go:376-395` -- Onboard handler trusts session data
- `src/core/session/codec.go:34` -- gobCodec provides no encryption
- Default Redis deployment: unauthenticated on internal Docker network

## Attacker Control

The attacker controls: (1) Redis read access to extract OIDC tokens from any session, (2) Redis write access to inject crafted `oidc_user_info` JSON with admin privileges, (3) the POST request to `/c/oidc/onboard` with the session cookie matching the poisoned session.

## Trust Boundary Crossed

Internal network (Redis) -> OIDC user session tokens AND Harbor admin account creation. A single network position enables both attacks.

## Impact

- **Token theft**: Extract refresh tokens for all OIDC users. Refresh tokens enable silent token renewal until explicit revocation at the OIDC provider.
- **Admin creation**: Create arbitrary Harbor system admin accounts without knowing any credentials. The crafted session contains `AdminGroupMember: true` which propagates through `InjectGroupsToUser`.
- **Persistence**: Refresh tokens provide long-lived access. Admin accounts persist until manually removed.

## Evidence

```go
// Token stored unencrypted -- oidc.go:161-168
tokenBytes, err := json.Marshal(token)  // includes RefreshToken
oc.SetSession(tokenKey, tokenBytes)     // stored in Redis via gob encoding (no encryption)

// Onboard trusts session data -- oidc.go:376-395
userInfoStr, ok := oc.GetSession(userInfoKey).(string)  // from Redis
d := &oidc.UserInfo{}
json.Unmarshal([]byte(userInfoStr), &d)  // no integrity check
userOnboard(ctx, oc, d, username, tb)    // creates user with d.AdminGroupMember
```

## Reproduction Steps

1. Deploy Harbor with OIDC auth mode (default Redis config, no auth)
2. Have a legitimate user authenticate via OIDC
3. From internal network, connect to Redis (default port 6379, no auth)
4. **Token theft**: Read session keys, decode gob values, extract `oidc_token` containing RefreshToken
5. **Admin creation**: Write a new session with `oidc_user_info` = `{"admin_group_member":true,"subject":"attacker","issuer":"https://idp.example.com","username":"attacker"}` and `oidc_token` = valid JSON token bytes
6. Using the session cookie, POST to `/c/oidc/onboard` with `{"username":"attacker"}`
7. Verify admin account created with system admin privileges
