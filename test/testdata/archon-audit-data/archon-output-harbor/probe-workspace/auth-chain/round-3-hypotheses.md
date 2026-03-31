# Round 3 Hypotheses — causal-verifier-02

Reasoning model: Causal (counterfactual / intervention analysis)
Source: code-anatomy.md, round-1-hypotheses.md, round-2-hypotheses.md, cross-model-seeds.md
Plus additional code reading for verification.

---

## Causal Verification of Round 1 Validated Findings

### PH-01 / PH-11 (CROSS-01): Admin DB Auth Bypass in OIDC Mode

**Causal chain verified**:
1. `basicAuth.Generate` (basic_auth.go:66) calls `auth.Login`
2. `auth.Login` (authenticator.go:142): `if authMode == "" || IsSuperUser(ctx, m.Principal) { authMode = common.DBAuth }`
3. `IsSuperUser` (authenticator.go:259): queries `user.Mgr.GetByName(ctx, username)` → returns `u.UserID == 1`
4. If true: `authMode = DBAuth` regardless of OIDC configuration
5. `lock` variable (auth/lock.go:35): `var lock = NewUserLock(frozenTime)` — package-level variable, in-memory map, per-process

**Counterfactual test**: Remove `IsSuperUser` check → admin account must authenticate through OIDC provider in OIDC mode. The DB password becomes inactive for `admin` username.

**Confirmed**: `lock.failures` is `map[string]time.Time` in memory. No Redis persistence. Multiple harbor-core pods each have independent lock state. No distributed rate limiting.

**Correction from round-1**: The `lock.Lock(username)` sets a time, and `lock.IsLocked` checks `time.Since(failures[username]) <= d`. When the map key is absent, `time.Since(time.Time{})` is a large duration >> 1.5s, so `IsLocked` returns FALSE for unknown usernames. This is correct behavior. But in multi-instance, after one failure on pod-A, pod-B does not know about it.

**Additional finding**: The `IsSuperUser` DB lookup happens EVERY call to `auth.Login` where the username might be the admin. This is an enumeration oracle: calling `/c/login` with username `admin` and wrong password causes a DB lookup. Timing difference between a username that is userID==1 vs. a username that does not exist in DB reveals whether the username is the system admin.

**Severity**: HIGH — Confirmed

**Finding PH-01-AUGMENT**: `IsSuperUser` is called before authentication for every login attempt with any username. A user calling `auth.Login` with a guessed admin username gets the DB lookup overhead even before the password check. This is a minor timing oracle for admin username discovery.

---

### PH-02 / PH-12 (CROSS-02): PKCE Silent Bypass

**Causal chain verified**:
1. `RedirectLogin` stores `string(pkceCode)` in session at `pkceCodeKey`
2. `Callback` at line 133: `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)`
   - If session key `oidc_pkce_code` is absent: `GetSession` returns nil → `nil.(string)` → `("", false)` → `pkceCode = ""`
   - If session key holds wrong type: same result
3. `helper.go:204`: `if len(pkceCode) > 0 { opts = append(opts, pkceCode.Verifier()) }`
   - `len("") == 0` → verifier NOT added
4. `oauth.Exchange(ctx, code, opts...)` called with empty opts
5. PKCE is silently skipped

**Counterfactual test**: Change the type assertion to check ok flag: `pkceCode, ok := ...; if !ok { return error }` → PKCE becomes mandatory.

**Is PKCE downgrade meaningful?**: YES if the OIDC provider does not enforce PKCE server-side. Per OAuth2 best practices (RFC 9700), PKCE is client-initiated — some providers only enforce it if the client advertises it. If Harbor advertises `code_challenge` in the auth URL (which it does, via `pkceCode.Challenge()` at `oidc.go:92`) but then sends the token exchange WITHOUT `code_verifier`, some providers will:
- Accept: provider does not check code_verifier if not sent (permissive)
- Reject: provider requires code_verifier because challenge was sent (strict)

For permissive providers, PKCE bypass is real. For strict providers, the exchange fails, but this creates a denial of service for legitimate users whose PKCE session key was cleared.

**Severity**: MEDIUM — Confirmed

---

### PH-03 (CROSS-06): V2 Token Timestamp Check Bypass

**Causal chain verified**:
1. `v2_token.go:84`: `info := lib.GetArtifactInfo(ctx)`
2. `v2_token.go:85`: `if info.ProjectName == "" { return true }` — bypass condition
3. For `/v2/` request: `accessList` returns `login` target only; `ArtifactInfo` middleware populates artifact info from URL path
4. Checking `access.go:82-86`: `/v2/` path → `login` target → no repository in accessList
5. `v2auth/auth.go:56`: for `login` target: `if !securityCtx.IsAuthenticated() { return challenge }`

**Key question**: Does `ArtifactInfo` middleware run before the security middleware for `/v2/` requests?
Looking at architecture: `ArtifactInfo` middleware is listed as step 10 in the middleware chain, AFTER security middleware (step 7). Therefore for ALL v2 requests, `ArtifactInfo` has NOT yet been populated when `v2Token.Generate` runs.

**This means**: `tokenIssuedAfterProjectCreation` ALWAYS sees empty `info.ProjectName` during the security context generation phase, and ALWAYS returns true. The timestamp check is NEVER effective in its current position in the middleware chain!

Wait — let me re-read more carefully. The `v2Token.Generate` is called from the `Security` middleware (step 7). `ArtifactInfo` is step 10. So `lib.GetArtifactInfo(ctx)` in `v2Token.Generate` would always return an empty struct.

But looking at `v2auth/auth.go` — this is a SEPARATE middleware applied only to `/v2/*` routes. When is `ArtifactInfo` populated relative to this middleware?

The middleware chain for `/v2/*` routes appears to be: Security middleware → v2auth middleware → ArtifactInfo middleware → handler. So by the time `tokenIssuedAfterProjectCreation` runs in `v2Token.Generate`, `ArtifactInfo` is not yet set.

**Counterfactual**: The timestamp check only works if `ArtifactInfo` is populated before `v2Token.Generate` runs. If `ArtifactInfo` middleware runs before Security middleware, the check is meaningful. But the architecture shows Security runs first.

**Critical finding**: If `ArtifactInfo` is always empty during token generation, then `tokenIssuedAfterProjectCreation` ALWAYS returns true for ALL v2 requests, making the entire timestamp check a dead code path. The fix for bearer token project recreation (commit 89e1c4baa, marked SOUND) may be architecturally inoperative.

**Severity**: HIGH — upgraded from MEDIUM. If confirmed, this completely negates the bearer token project recreation fix.

**Additional note**: The KB marks 89e1c4baa as "SOUND" — this finding, if correct, would change that verdict to BYPASSABLE. Needs route/middleware order confirmation.

---

### PH-04 (CROSS-03): OIDC Admin Group Injection

**Causal chain verified**:
1. `userInfoFromClaims` (helper.go:394): `res.Groups, _ = groupsFromClaims(c, setting.GroupsClaim)` — raw from OIDC claims
2. `helper.go:396`: `if slices.Contains(res.Groups, setting.AdminGroup) { res.AdminGroupMember = true }`
3. `InjectGroupsToUser` (helper.go:480-496): `user.AdminRoleInAuth = info.AdminGroupMember`
4. `local.NewSecurityContext(user)` (local/context.go:78): `return s.user.SysAdminFlag || s.user.AdminRoleInAuth`
5. `s.IsSysAdmin()` returns true → `evaluators.Add(admin.New(s.GetUsername()))` → full system admin permissions

**Is `AdminRoleInAuth` persisted to DB?** — Looking at `InjectGroupsToUser`, it sets `user.AdminRoleInAuth` on the user model object. This is an in-memory modification. The `populateGroupsDB` call below persists group IDs to DB via `user.GroupIDs`. But `AdminRoleInAuth` does not appear to be persisted separately — it's a transient field set on each auth context.

This means admin role is evaluated fresh on every request where OIDC group info is injected. For OIDC CLI requests, `oidcCli.Generate` calls `InjectGroupsToUser` on every request. For web portal sessions, `session.Generate` loads the user from session (Redis) — the session-stored user object may or may not have `AdminRoleInAuth` set.

**Filter bypass confirmed**: `groupsFromClaims` does NOT call `filterGroup`. The filter is only in `populateGroupsDB`. The `AdminGroup` check at line 396 uses the raw group list — groups that would be filtered from DB population still trigger admin role assignment.

**Severity**: HIGH — Confirmed

---

### PH-05: Robot Secret PBKDF2 Correction

**Causal chain corrected**: `utils.Encrypt` is NOT single-round SHA256. Looking at `encrypt.go:49-51`:
```go
func Encrypt(content string, salt string, encryptAlg string) string {
    return fmt.Sprintf("%x", pbkdf2.Key([]byte(content), []byte(salt), 4096, 16, HashAlg[encryptAlg]))
}
```

This is PBKDF2 with 4096 iterations. This is significantly more resistant to brute force than plain SHA256.

**Revised assessment**: Robot secrets use PBKDF2-SHA256 with 4096 iterations and 16 bytes output. While 4096 iterations is low by modern standards (NIST SP 800-63B recommends at least 10,000 for SHA-1, and bcrypt with cost 10 is roughly equivalent to millions of iterations), PBKDF2-4096 is not trivially brute-forceable.

For a strong auto-generated secret (20+ random chars), brute force is not feasible. For weak user-specified secrets, PBKDF2-4096 provides meaningful but not exceptional resistance.

**Severity**: MEDIUM — downgraded from HIGH (PBKDF2 is better than plain SHA256). No lockout is the primary concern.

---

### PH-06: Multi-Instance Lockout Bypass

**Causal chain verified**:
- `lock` is `var lock = NewUserLock(frozenTime)` at package level in `core/auth/authenticator.go`
- `NewUserLock` creates a new `UserLock` struct with an in-memory `map[string]time.Time`
- Each Harbor core process gets its own `lock` instance
- No Redis-backed distributed locking found in the auth package

**Counterfactual**: Adding Redis-backed lockout (e.g., `SET username:lockout NX PX 1500`) would make the lockout effective across all instances.

**Severity**: HIGH — Confirmed

---

### PH-07: OIDC Session Token in Redis

**Causal chain verified**:
- `oc.SetSession(tokenKey, tokenBytes)` — stores JSON-encoded OIDC token in Redis session
- `tokenBytes` includes `access_token`, `refresh_token`, `token_type`, `expiry`, `id_token`
- Session data is stored in Redis under a session key derived from the cookie
- No application-level encryption or HMAC on session values beyond AES session encoding (beego session store uses configurable encoding)

**Is beego Redis session encrypted?** — beego's session provider can encrypt session data if configured. Default configuration may or may not encrypt. The code itself does not add additional encryption.

**Severity**: HIGH — with caveat that exploitation requires unauthenticated Redis access (common in default deployments).

---

### PH-19 (CROSS-04): OIDC Onboard Trusts Session Without Re-Verification

**Causal chain verified**:
1. `OIDCController.Onboard` (oidc.go:360-404)
2. Line 376: `userInfoStr, ok := oc.GetSession(userInfoKey).(string)` — from session
3. Line 382: `tb, ok := oc.GetSession(tokenKey).([]byte)` — from session
4. Line 389: `json.Unmarshal([]byte(userInfoStr), &d)` — deserializes session data into `*oidc.UserInfo`
5. Line 395: `userOnboard(ctx, oc, d, username, tb)` → `ctluser.Ctl.OnboardOIDCUser(ctx, user)` — NO OIDC verification
6. `InjectGroupsToUser(info, user)` at `userOnboard:347` — applies `AdminGroupMember` from deserialized session data

**Counterfactual**: Adding `oidc.VerifyToken(ctx, token.RawIDToken)` in `Onboard` would ensure the token is still valid at onboarding time.

**Critical finding confirmed**: The `AdminGroupMember` field in `oidc.UserInfo` is deserialized from session JSON. If an attacker writes `{"admin_group_member": true, ...}` to the `oidc_user_info` session key in Redis, the onboarded user gets `user.AdminRoleInAuth = true`. Combined with unauthenticated Redis (PH-07), this is a direct path to system admin account creation.

**Severity**: HIGH — Confirmed as HIGH severity chain

---

### PH-22: FixEmptySubIss Called at Startup

**Causal chain verified**:
- `main.go:282`: `_, err = oidc.FixEmptySubIss(orm.Context())` — called at every Harbor core startup
- Not a one-time-only operation — runs on every restart
- If `metaMgr.GetBySubIss(ctx, "", "")` finds records with empty subiss, it decodes token without signature verification

**Counterfactual test**: If the `oidc_user.token` column contains a crafted JWT (written via SQL injection), `FixEmptySubIss` would update `subiss` to attacker-controlled sub+iss values. This could allow: (1) mapping a victim's sub+iss to an attacker's Harbor account; (2) creating a new subiss that collides with another user.

**Severity**: LOW — requires DB write access (SQL injection) as prerequisite. The `FixEmptySubIss` is an amplifier, not a standalone vector.

---

## New Finding from Causal Analysis

### PH-23: ArtifactInfo Context Population Ordering — tokenIssuedAfterProjectCreation Is a Dead Check

**Causal derivation**: During verification of PH-03, analysis of the middleware ordering revealed that `ArtifactInfo` middleware runs AFTER `Security` middleware in Harbor's middleware chain. `v2Token.Generate` is called within `Security` middleware. Therefore `lib.GetArtifactInfo(ctx)` in `tokenIssuedAfterProjectCreation` always returns an empty struct with `ProjectName == ""`.

**Code evidence**:
- `src/core/middlewares/middlewares.go:98-99`: `artifactinfo.Middleware()` at line 98 (BEFORE) `security.Middleware()` at line 99
- `v2_token.go:84`: `info := lib.GetArtifactInfo(ctx)`
- `v2_token.go:85`: `if info.ProjectName == "" { return true }` — early return

**Revised finding**: `artifactinfo` runs BEFORE `security` in the global middleware chain. Therefore `tokenIssuedAfterProjectCreation` DOES have access to artifact info for URL patterns that ArtifactInfo recognizes (manifests, blobs, tag_list, referrers). The bypass at line 85 is only triggered for URLs that ArtifactInfo does NOT recognize: `/v2/` base path (login discovery) and `/v2/_catalog` (catalog).

**The timestamp check IS functional** for the security-critical paths (manifest push/pull, blob upload). PH-03 is partially valid: a stale token can authenticate at `/v2/` (login target, only checks IsAuthenticated), but not for actual content operations.

**Severity**: MEDIUM — downgraded from HIGH. The bypass exists only for base/catalog endpoints with limited security impact.

**Status**: REVISED — PH-03 partial bypass confirmed for `/v2/` and `/_catalog` only.

---

### PH-24: ReversibleDecrypt Fallback to Base64 Enables Cleartext Secret Storage

**New finding from encrypt.go analysis**:
`ReversibleDecrypt` (encrypt.go:82-89) has a fallback: if the string does not start with `<enc-v1>` header, it falls back to base64 decode (`decodeB64`). This means legacy OIDC tokens/secrets stored as plain base64 (without encryption) are accepted.

**Code evidence**:
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

**Implication**: Any `oidc_user.token` or `oidc_user.secret` value stored as plain base64 (legacy format) is trivially readable — base64 decoding is reversible without the AES key. If any OIDC tokens are still stored in legacy format in the DB (from old Harbor versions), they are in plaintext base64.

**Additional implication**: An attacker who gains read access to the `oidc_user` table can determine if records use the legacy format (no `<enc-v1>` prefix) and decode them directly without needing the AES key.

**Severity**: MEDIUM — requires DB read access, but legacy records may still exist in upgraded Harbor deployments.

**Status**: VALIDATED (code is confirmed).
