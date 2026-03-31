# Evidence File — auth-chain

Harvested from: round-1, round-2, round-3 hypotheses
Component source paths: src/server/middleware/security/, src/core/controllers/oidc.go, src/pkg/oidc/, src/core/auth/, src/server/middleware/v2auth/, src/pkg/token/, src/controller/robot/

---

## PH-01 / PH-11 / CROSS-01: Admin DB Auth Forced in OIDC Mode + Multi-Instance Lockout Bypass

**Status**: VALIDATED
**Fragility**: SOLID
**Evidence**:

File: `src/core/auth/authenticator.go:142`
```go
if authMode == "" || IsSuperUser(ctx, m.Principal) {
    authMode = common.DBAuth
}
```

File: `src/core/auth/authenticator.go:259-266`
```go
func IsSuperUser(ctx context.Context, username string) bool {
    u, err := user.Mgr.GetByName(ctx, username)
    if err != nil {
        return false
    }
    return u.UserID == 1
}
```

File: `src/core/auth/lock.go:23-51` — `UserLock` uses `map[string]time.Time`, in-memory, no Redis persistence

File: `src/core/auth/authenticator.go:35` — `var lock = NewUserLock(frozenTime)` — package-level, per-process

**Security consequence**: Admin account is permanently available for DB-credential brute force regardless of configured OIDC/LDAP mode. Lockout is bypassable by routing to different pod.

**Severity**: HIGH

---

## PH-02 / PH-12 / CROSS-02: PKCE Silent Bypass via Session Key Absence

**Status**: VALIDATED
**Fragility**: SOLID
**Evidence**:

File: `src/core/controllers/oidc.go:133`
```go
pkceCode, _ := oc.GetSession(pkceCodeKey).(string)
```
The blank identifier `_` discards the type assertion ok flag. When `GetSession(pkceCodeKey)` returns nil (key absent or expired), `nil.(string)` evaluates to `("", false)`. The `_` discards `false`, leaving `pkceCode = ""`.

File: `src/pkg/oidc/helper.go:203-206`
```go
if len(pkceCode) > 0 {
    opts = append(opts, pkceCode.Verifier())
}
```
`len("") == 0` → verifier NOT added to exchange options.

File: `src/core/controllers/oidc.go:92` — PKCE challenge IS sent in auth URL:
```go
if len(pkceCode) > 0 {
    options = append(options, pkceCode.Challenge())
    options = append(options, pkceCode.Method())
}
```

**Gap**: Harbor sends `code_challenge` to provider but silently omits `code_verifier` on exchange when session key is absent. For OIDC providers that don't enforce PKCE server-side (permissive), this is a real bypass.

**Security consequence**: Authorization code can be exchanged without PKCE binding. Combined with unauthenticated Redis (CROSS-02 chain), attacker can delete the PKCE session key to disable PKCE verification.

**Severity**: MEDIUM

---

## PH-03 / CROSS-06: V2 Token Timestamp Check — Bypass at /v2/ and /_catalog

**Status**: VALIDATED (partial)
**Fragility**: SOLID
**Evidence**:

File: `src/server/middleware/security/v2_token.go:84-87`
```go
info := lib.GetArtifactInfo(ctx)
if info.ProjectName == "" {
    return true
}
```

File: `src/core/middlewares/middlewares.go:98-99`
```
artifactinfo.Middleware()  // line 98 - runs first
security.Middleware(...)   // line 99 - runs second
```

File: `src/server/middleware/artifactinfo/artifact_info.go:41-48` — URL patterns: manifest, tag_list, blob_upload, blob, referrers. Does NOT match `/v2/` (base) or `/v2/_catalog`.

**Finding**: For `/v2/` base path: ArtifactInfo produces empty struct → `tokenIssuedAfterProjectCreation` returns true → stale token accepted. The v2auth middleware for login target only checks `IsAuthenticated()`. A stale token authenticates successfully at `/v2/`.

**Severity**: MEDIUM (limited blast radius — `/v2/` and `/_catalog` only)

---

## PH-04 / CROSS-03: OIDC Admin Group Claim Injection

**Status**: VALIDATED
**Fragility**: SOLID
**Evidence**:

File: `src/pkg/oidc/helper.go:394-399`
```go
res.Groups, res.hasGroupClaim = groupsFromClaims(c, setting.GroupsClaim)
if len(setting.AdminGroup) > 0 {
    if slices.Contains(res.Groups, setting.AdminGroup) {
        res.AdminGroupMember = true
    }
}
```
`groupsFromClaims` does NOT call `filterGroup`. Raw groups from OIDC claims.

File: `src/pkg/oidc/helper.go:454-455`
```go
// filterGroup is only called here:
return usergroup.Mgr.Populate(orm.Context(), model.UserGroupsFromName(filterGroup(groupNames, cfg.GroupFilter), common.OIDCGroupType))
```

File: `src/common/security/local/context.go:78`
```go
return s.user.SysAdminFlag || s.user.AdminRoleInAuth
```

File: `src/pkg/oidc/helper.go:491-496`
```go
if gids, err := populateGroups(info.Groups); err != nil {
    // ...
} else {
    user.GroupIDs = gids
}
user.AdminRoleInAuth = info.AdminGroupMember
```

**Attack chain confirmed**: OIDC provider claims `GroupsClaim: harbor-admins` → `groupsFromClaims` returns `["harbor-admins"]` → `slices.Contains(["harbor-admins"], "harbor-admins")` == true → `AdminRoleInAuth = true` → `IsSysAdmin()` returns true → full admin permissions.

**Group filter is NOT applied** before admin check. Even groups that would be filtered from DB population trigger admin role.

**Severity**: HIGH

---

## PH-06: Multi-Instance Lockout Bypass (standalone confirmation)

**Status**: VALIDATED
**Fragility**: SOLID
**Evidence**:

File: `src/core/auth/lock.go:22-51` — In-memory map, `sync.RWMutex`, no external state.

File: `src/core/auth/authenticator.go:35` — `var lock = NewUserLock(frozenTime)` — single package-level instance per process.

No Redis-backed lockout found in any auth-related file. Distributed deployments (Kubernetes) have no shared lockout state.

**Severity**: HIGH

---

## PH-07: OIDC Full Token Stored in Session (Redis)

**Status**: VALIDATED
**Fragility**: CONDITIONAL (depends on Redis auth configuration)
**Evidence**:

File: `src/core/controllers/oidc.go:161-168`
```go
tokenBytes, err := json.Marshal(token)
...
if err := oc.SetSession(tokenKey, tokenBytes); err != nil {
```

`token` is `oidc.Token` which embeds `oauth2.Token` containing `AccessToken`, `RefreshToken`, `TokenType`, `Expiry` plus `RawIDToken`.

**Session storage**: beego's `web.GlobalSessions` stores session data in Redis (default Harbor deployment). No application-level encryption of session values beyond beego's session encoding.

**Redis authentication**: Not a code-level control. Default Harbor `docker-compose.yml` does not set `requirepass` for Redis. Harbor documentation notes Redis auth as optional.

**Severity**: HIGH (in default deployments)

---

## PH-08: Auth Proxy Username Prefix (Partial)

**Status**: NEEDS-DEEPER
**Fragility**: CONDITIONAL
**Evidence**:

File: `src/common/const.go:149`
```go
AuthProxyUserNamePrefix = "tokenreview$"
```

File: `src/server/middleware/security/auth_proxy.go:95-99`
```go
func (a *authProxy) matchAuthProxyUserName(name string) (string, bool) {
    if !strings.HasPrefix(name, common.AuthProxyUserNamePrefix) {
        return "", false
    }
    return strings.Replace(name, common.AuthProxyUserNamePrefix, "", -1), true
}
```

The prefix is `"tokenreview$"` — a dollar sign separator that cannot appear in normal Docker Hub usernames. Username must start with `tokenreview$` to match. After stripping, the username must match the token review result. The binding check at `auth_proxy.go:63` prevents direct username forgery without a valid token review.

**Assessment**: The prefix check provides meaningful separation. The vulnerability is only exploitable if the token review endpoint is misconfigured or attacker-controlled. Downgraded to LOW independent risk.

**Severity**: LOW (MEDIUM only if token review endpoint is attacker-controlled)

---

## PH-09: OIDC Onboard Redirect URL Injection via Username

**Status**: VALIDATED
**Fragility**: CONDITIONAL (requires OIDC provider that allows metacharacters in username claim)
**Evidence**:

File: `src/core/controllers/oidc.go:176`
```go
username = strings.Replace(username, " ", "_", -1)
```
Only spaces are sanitized. No URL encoding.

File: `src/core/controllers/oidc.go:203`
```go
oc.Controller.Redirect(fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr), http.StatusFound)
```

Direct string interpolation. A username containing `&redirect_url=http://evil.com` would inject a second `redirect_url` parameter. Browser query string parsing (first-wins vs. last-wins) varies.

**Note**: `redirectURLStr` was validated with `utils.IsLocalPath` when stored in session during `RedirectLogin`. So the original redirect URL is local. But the injected `redirect_url` parameter is not validated — whether it matters depends on the Angular frontend's handling of duplicate query params.

**Severity**: MEDIUM (URL parameter injection; open redirect depends on frontend behavior)

---

## PH-13: Subject Binding Check Conditional Bypass

**Status**: VALIDATED
**Fragility**: SOLID (code path is real; exploitability requires OIDC provider manipulation)
**Evidence**:

File: `src/pkg/oidc/helper.go:300-312`
```go
if remote != nil && local != nil {
    if remote.Subject != local.Subject {
        return nil, fmt.Errorf("subject mismatch...")
    }
    return mergeUserInfo(remote, local), nil
} else if remote != nil && local == nil {
    return remote, nil
} else if local != nil && remote == nil {
    log.Debugf("Fall back to user data from ID token.")
    return local, nil
}
```

When `remote == nil` (userinfo endpoint failure): binding check never evaluates. Groups, admin status, email all come from local (ID token) without cross-validation.

**Attacker angle**: A compromised OIDC provider that intermittently fails the userinfo endpoint forces fallback to ID token alone. If the ID token was crafted with elevated group claims, those claims are accepted without userinfo cross-validation.

**Severity**: MEDIUM

---

## PH-15 / PH-21: Robot Account No Brute-Force Protection

**Status**: VALIDATED
**Fragility**: SOLID
**Evidence**:

File: `src/server/middleware/security/robot.go:33-73` — No `lock.Lock()` call, no `time.Sleep()`, no lockout mechanism of any kind.

File: `src/server/middleware/security/basic_auth.go:60-81` — By contrast, basic auth delegates to `auth.Login` which has lockout.

File: `src/common/utils/encrypt.go:49-51`
```go
func Encrypt(content string, salt string, encryptAlg string) string {
    return fmt.Sprintf("%x", pbkdf2.Key([]byte(content), []byte(salt), 4096, 16, HashAlg[encryptAlg]))
}
```
PBKDF2-SHA256 with 4096 iterations — provides moderate offline resistance.

**Online brute force**: No lockout means unlimited attempts against robot accounts. Robot names are predictable (format: `robot$projectname+robotname`, visible to project admins via API).

**Severity**: MEDIUM

---

## PH-19 / CROSS-04: OIDC Onboard Trusts Session Without OIDC Re-Verification

**Status**: VALIDATED (HIGH severity chain with Redis)
**Fragility**: CONDITIONAL (requires Redis write access)
**Evidence**:

File: `src/core/controllers/oidc.go:376-404`
```go
userInfoStr, ok := oc.GetSession(userInfoKey).(string)
...
tb, ok := oc.GetSession(tokenKey).([]byte)
...
d := &oidc.UserInfo{}
err := json.Unmarshal([]byte(userInfoStr), &d)
...
if user, onboarded := userOnboard(ctx, oc, d, username, tb); onboarded {
```

No call to `oidc.VerifyToken` or any OIDC provider endpoint in the Onboard flow.

File: `src/pkg/oidc/helper.go:481-496` — `InjectGroupsToUser` applies `AdminGroupMember` to user model from deserialized session data.

**Attack chain**: Redis write → inject `{"admin_group_member":true,...}` at `oidc_user_info` key → trigger `/c/oidc/onboard` → admin account created.

**Severity**: HIGH (with unauthenticated Redis prerequisite)

---

## PH-24: ReversibleDecrypt Base64 Fallback for Legacy Records

**Status**: VALIDATED
**Fragility**: SOLID (code path confirmed; exploitability depends on legacy records in DB)
**Evidence**:

File: `src/common/utils/encrypt.go:82-89`
```go
func ReversibleDecrypt(str, key string) (string, error) {
    if strings.HasPrefix(str, EncryptHeaderV1) {
        str = str[len(EncryptHeaderV1):]
        return decryptAES(str, key)
    }
    // fallback to base64
    return decodeB64(str)
}
```

Any `oidc_user.token` or `oidc_user.secret` stored without `<enc-v1>` prefix is decoded as plain base64 — no encryption key needed.

**Applies to**: OIDC tokens, OIDC secrets stored in `oidc_user` table for accounts created before the `<enc-v1>` encryption format was introduced.

**Severity**: MEDIUM (requires DB read access)

---

## Summary Matrix

| Finding | Severity | Status | Fragility |
|---------|----------|--------|-----------|
| PH-01/PH-11: Admin DBAuth bypass in OIDC mode | HIGH | VALIDATED | SOLID |
| PH-06: Multi-instance lockout bypass | HIGH | VALIDATED | SOLID |
| PH-04/CROSS-03: OIDC admin group injection | HIGH | VALIDATED | SOLID |
| PH-07: OIDC token in Redis session | HIGH | VALIDATED | CONDITIONAL |
| PH-19/CROSS-04: OIDC onboard session trust | HIGH | VALIDATED | CONDITIONAL |
| PH-02/PH-12/CROSS-02: PKCE silent bypass | MEDIUM | VALIDATED | SOLID |
| PH-03/CROSS-06: V2 token timestamp bypass at /v2/ | MEDIUM | VALIDATED | SOLID |
| PH-09: OIDC onboard redirect URL injection | MEDIUM | VALIDATED | CONDITIONAL |
| PH-13: Subject binding check conditional | MEDIUM | VALIDATED | SOLID |
| PH-15/PH-21: Robot no brute-force protection | MEDIUM | VALIDATED | SOLID |
| PH-24: ReversibleDecrypt base64 fallback | MEDIUM | VALIDATED | SOLID |
| PH-05: Robot PBKDF2 hash (weak) | MEDIUM | REVISED (PBKDF2-4096 not plain SHA256) | SOLID |
| PH-08: Auth proxy username prefix | LOW | NEEDS-DEEPER | CONDITIONAL |
| PH-10: Bearer token split parsing | LOW | INVALIDATED | N/A |
| PH-16: idToken dual parse inconsistency | LOW | NEEDS-DEEPER | FRAGILE |
| PH-17: Cross-path bearer confusion | INFORMATIONAL | INVALIDATED | N/A |
| PH-18: Auth proxy web vs CLI path | LOW | NEEDS-DEEPER | FRAGILE |
| PH-20: Provider refresh race | LOW | NEEDS-DEEPER | FRAGILE |
| PH-22: FixEmptySubIss no sig verify | LOW | VALIDATED (needs DB write) | CONDITIONAL |
