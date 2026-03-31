# Round 2 Hypotheses — contradiction-reasoner-02

Reasoning model: Contradiction / Assumption-vs-Reality
Source: attack-surface-map.md + code-anatomy.md

---

## PH-11: Contradiction — OIDC Mode Claims Username Is Trusted From Provider, But Admin Bypass Ignores OIDC Entirely

**Contradiction identified**: The security model for OIDC mode states that user identity is controlled entirely by the OIDC provider. The system admin (user ID 1) should authenticate via OIDC. However, `authenticator.go:142-144` explicitly forces DBAuth for any user whose username maps to `userID == 1` in the Harbor DB. This contradicts the OIDC-only authentication promise.

**Assumption broken**: "OIDC auth mode means all authentication goes through the OIDC provider."

**Code evidence**:
- `authenticator.go:142`: `if authMode == "" || IsSuperUser(ctx, m.Principal) { authMode = common.DBAuth }`
- `IsSuperUser` at line 259-267 queries `user.Mgr.GetByName(ctx, username)` and returns `u.UserID == 1`

**Attack scenario**: In an organization that has configured Harbor in OIDC mode and disabled the local admin password (or believes they have), the admin DB password (set during Harbor initialization) is still valid. An attacker who knows the admin username (commonly "admin") can authenticate via Basic Auth on any endpoint processed by `basicAuth.Generate` (all endpoints, since basicAuth has the lowest non-session priority). The OIDC provider is never consulted.

**Additional contradiction**: `IsSuperUser` is called BEFORE the authentication attempt. This function queries the DB for every login attempt where the username matches, leaking timing information about whether a given username corresponds to user ID 1.

**Severity estimate**: HIGH

**Status**: VALIDATED — same underlying mechanism as PH-01 from different analytical direction, confirming the finding. PH-11 is a confirmation of PH-01 from a contradiction perspective.

---

## PH-12: Contradiction — PKCE Is Generated and Stored but Not Verified on Exchange

**Contradiction identified**: The OIDC login flow generates a PKCE code (`pkce.Generate()` at `oidc.go:70`) and stores it in session. This implies PKCE is a security requirement. However, the code exchange at `oidc.go:133` uses `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)` — the blank identifier discards the assertion result. If this returns `""`, PKCE silently becomes optional.

**Assumption broken**: "PKCE is enforced for all OIDC code exchanges in Harbor."

**Code evidence**:
- `oidc.go:70-96`: PKCE code is generated and stored in session
- `oidc.go:133`: `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)` — ok flag discarded
- `helper.go:203-206`: PKCE verifier only appended `if len(pkceCode) > 0`

**This contradicts the security design**: The explicit PKCE implementation (using `go.pinniped.dev/pkg/oidcclient/pkce`) suggests PKCE is intentionally required. The fallback to empty PKCE on session miss means PKCE is a "best-effort" feature, not a hard requirement.

**Trigger conditions**:
1. Session expires between login redirect and callback (long delay)
2. Load balancer routes callback to a different instance than redirect (no shared session without sticky sessions or Redis session store — but Harbor uses Redis sessions, so this should be shared... unless Redis session key expiry is shorter than the OAuth2 flow timeout)
3. Session key type is stored incorrectly (e.g., as `[]byte` instead of `string` by a bug)
4. State fixation attack that manipulates session contents to remove the PKCE key

**Severity estimate**: MEDIUM

**Status**: VALIDATED — complements PH-02.

---

## PH-13: Contradiction — Subject Binding Check Only Fires When Both Sources Are Present

**Contradiction identified**: The subject binding check at `helper.go:301-303` is designed to prevent token substitution attacks (ensuring the user authenticated to Harbor matches the user authenticated to the OIDC provider). However, this check ONLY executes when `remote != nil && local != nil`. When the userinfo endpoint fails (network error, timeout) or returns nil, the code falls back to `local` alone — and the subject binding check is never evaluated.

**Assumption broken**: "Harbor verifies that the OIDC userinfo subject matches the ID token subject."

**Code evidence**:
```go
if remote != nil && local != nil {
    if remote.Subject != local.Subject {
        return nil, fmt.Errorf("subject mismatch...")
    }
    return mergeUserInfo(remote, local), nil
} else if remote != nil && local == nil {
    return remote, nil          // only remote: no binding check needed (single source)
} else if local != nil && remote == nil {
    return local, nil           // ONLY LOCAL: subject binding check SKIPPED
}
```

**Attack scenario**: An attacker controls a flaky OIDC provider that successfully returns an ID token (signed with the provider's key) but makes the userinfo endpoint temporarily unavailable. `userInfoFromRemote` returns an error, `remote` is nil, and `local` is used directly. The ID token contains a crafted `sub` and group claims. Since remote is nil, the binding check never fires.

**Additional finding**: In the `remote only` path (`remote != nil && local == nil`), there is also no binding check. If `parseIDToken` fails but `userInfoFromRemote` succeeds, the subject from userinfo is used without cross-validation. This is arguably correct (single source), but combined with `parseIDToken` using `SkipExpiryCheck: true`, an expired but cached ID token could fail parsing while a fresh userinfo response succeeds.

**Security consequence**: Token substitution attack where a malicious OIDC provider returns correct ID tokens for legitimate users but incorrect/modified userinfo data. When userinfo succeeds and ID token fails (or vice versa), the cross-validation is bypassed.

**Severity estimate**: MEDIUM

**Status**: VALIDATED — the conditional structure is confirmed in helper.go:301-312.

---

## PH-14: Contradiction — Group Filter Regex Protects DB But Not Admin Role Assignment

**Contradiction identified**: The configuration includes a `GroupFilter` regex to control which OIDC groups are populated into the Harbor DB (via `populateGroupsDB`). Administrators may believe this filter prevents unauthorized groups from influencing access control. However, the `AdminGroup` membership check at `helper.go:395-399` operates on the raw, unfiltered group list (`res.Groups` from `groupsFromClaims`), bypassing the `GroupFilter` entirely.

**Assumption broken**: "GroupFilter controls which OIDC groups can affect Harbor access."

**Code evidence**:
- `helper.go:394`: `res.Groups, res.hasGroupClaim = groupsFromClaims(c, setting.GroupsClaim)` — raw groups, no filter
- `helper.go:395-399`: `if slices.Contains(res.Groups, setting.AdminGroup) { res.AdminGroupMember = true }`
- `helper.go:455`: `filterGroup` is only applied in `populateGroupsDB`, which is called later via `InjectGroupsToUser`

**Attack scenario**: An organization configures `GroupFilter = "^harbor-"` to only populate groups named `harbor-*`. They expect that groups not matching this pattern have no effect. However, if `AdminGroup = "harbor-admins"` (matching the filter) AND the OIDC provider returns a group named `harbor-admins` for an unauthorized user, the admin check fires before the filter is applied.

Wait — in this case the filter WOULD pass `harbor-admins`. The more interesting case is: if an admin configures `GroupFilter = "^allowed-"` (strict) and `AdminGroup = "super-admin"` (not matching the filter), they may believe that `super-admin` group membership cannot be asserted. But the admin check at line 396 uses unfiltered groups, so even a user with `super-admin` in their OIDC claims (which would NOT be populated to DB due to filter) would still receive `AdminRoleInAuth = true`.

**Severity estimate**: MEDIUM

**Status**: VALIDATED — the code sequence confirms filter is applied only in populateGroupsDB, not before AdminGroup check.

---

## PH-15: Contradiction — Robot Prefix Check Occurs BEFORE Robot Secret Verification, Enabling Enumeration

**Contradiction identified**: `robot.Generate` first queries the DB for robots matching the trimmed name (`robots[0]`), then compares the secret. The DB query happens before authentication. Combined with the fact that `len(robots) == 0` returns nil immediately (no sleep, no lockout), a timing difference exists between "robot name exists" (proceeds to hash comparison) and "robot name does not exist" (returns nil immediately).

**Assumption broken**: "Robot authentication does not reveal whether a given robot name exists."

**Code evidence**:
- `robot.go:43-53`: DB list query -> if `len(robots) == 0: return nil` (fast)
- `robot.go:57`: `utils.Encrypt(secret, robot.Salt, utils.SHA256)` -> hash comparison (slower by SHA256 computation)
- No constant-time comparison; no lockout; no sleep

**Attack scenario**: Timing-based robot name enumeration. An attacker submitting credentials for non-existent robots gets a faster response than for existing robots (one SHA256 computation difference ~microseconds). More significantly, there is NO lockout for robot accounts. An attacker who correctly guesses a robot name can brute-force the secret with SHA256 verification at maximum rate (no rate limiting, no lockout).

**Severity estimate**: MEDIUM

**Status**: VALIDATED — no lockout for robot accounts confirmed; timing difference exists.

---

## PH-16: Contradiction — idToken Generator Verifies Token Fully, Then Re-Parses With Reduced Checks

**Contradiction identified**: `idToken.Generate` calls `oidc.VerifyToken(ctx, token)` which performs full verification (signature, issuer, audience=ClientID, expiry, nonce). Then it calls `oidc.UserInfoFromIDToken(ctx, &oidc.Token{RawIDToken: token}, *setting)` which calls `parseIDToken` with `SkipClientIDCheck: true, SkipExpiryCheck: true`. The SAME token is parsed twice with different security settings.

**Assumption broken**: "Token verification in idToken.Generate is consistent."

**Code evidence**:
- `idtoken.go:46`: `claims, err := oidc.VerifyToken(ctx, token)` — full verification
- `idtoken.go:61`: `info, err := oidc.UserInfoFromIDToken(...)` -> `parseIDToken` with `SkipExpiryCheck: true`

**What this enables**: At the boundary between `VerifyToken` returning claims and `UserInfoFromIDToken` returning groups, there is a TOCTOU window. In a concurrent environment, if the OIDC provider rotates keys between these two calls, the second parse could succeed with a different key. More critically, if the token contains an embedded claim that drives group extraction (`GroupsClaim` key in `allClaims`), the relaxed parse could extract groups from a token that would have been rejected by the strict parse.

**Practical exploitation**: In normal operation, both parses use the same token string and the same provider JWKS. The risk is architectural: the security guarantee of the first parse is not preserved through the second parse. If the key rotation window is exploitable, a token signed with a compromised key could pass the relaxed check.

**Severity estimate**: LOW (requires key rotation timing exploitation)

**Status**: NEEDS-DEEPER — confirm if nonce from full verification is also checked in the relaxed re-parse.

---

## PH-17: Contradiction — Bearer Token Auth Is Restricted to /v2/* But idToken Is Allowed on /api/* Enabling Cross-Path Auth Confusion

**Contradiction identified**: The `v2Token` generator only fires on `/v2/*` paths (Docker registry protocol). The `idToken` generator fires on `/api/*` and `/service/token`. Both generators accept a `Bearer` token but expect different token types (v2Token expects Harbor-issued RS256 JWT with registry audience; idToken expects OIDC provider-issued ID token).

**Assumption broken**: "Bearer token type is determined by the endpoint path."

**Code evidence**:
- `v2_token.go:46`: `if !strings.HasPrefix(req.URL.Path, "/v2"): return nil`
- `idtoken.go:39`: `if !strings.HasPrefix(req.URL.Path, "/api") && req.URL.Path != "/service/token": return nil`
- Both call `bearerToken(req)` which extracts the same `Authorization: Bearer` header

**Attack scenario**: An attacker who has a valid Harbor-issued registry JWT (for `/v2/*`) cannot use it on `/api/*` because `idToken.Generate` would attempt to verify it as an OIDC ID token via the OIDC provider and fail (wrong issuer, audience). Conversely, an OIDC ID token cannot be used on `/v2/*` because `v2Token.Generate` would attempt RS256 parse with Harbor's key and fail (different issuer).

**However**: What if a user's Harbor-issued JWT (registry token) has the same `sub` claim as their OIDC sub? Could a well-crafted JWT signed with Harbor's RS256 key pass OIDC verification on the `/api/*` path? This would require the OIDC verifier to trust Harbor's key as a valid OIDC provider key — not possible in standard go-oidc.

**Assessment**: This is actually a defense-in-depth feature, not a vulnerability. The path-based routing effectively enforces token type separation. No concrete exploit path identified.

**Severity estimate**: INFORMATIONAL

**Status**: INVALIDATED — no exploitable contradiction.

---

## PH-18: Contradiction — Auth Proxy Only Active on /v2/* But Basic Auth Is Active Everywhere

**Contradiction identified**: `authProxy.Generate` is restricted to `/v2/*` paths (`auth_proxy.go:41`). This means auth proxy authentication only works for Docker CLI operations. For web portal and API operations (`/api/v2.0/*`, `/c/*`), auth proxy users must use the session cookie (after logging in via `/c/login`). The `/c/login` endpoint delegates to `auth.Login` which, in HTTPAuth mode, uses the auth proxy authenticator that makes an outbound POST to the configured proxy endpoint.

**Assumption broken**: "Auth proxy mode handles all authentication consistently."

**The gap**: The web UI login at `/c/login` in HTTPAuth mode calls `auth.Login` -> `authproxy.Auth.Authenticate` -> POST to configured proxy `Endpoint` with username/password. This returns a `session_id` which is used in `tokenReview`. The token review result determines admin status. But the CLI path through `authProxy.Generate` also does a token review via `proxyPwd` (which is a different token). These two paths have different input types (session ID from web login vs. bearer token from CLI) going through the same `authproxy.TokenReview` function.

**Security consequence**: If the token review endpoint accepts both session IDs and bearer tokens interchangeably, there may be session confusion between web and CLI auth paths.

**Severity estimate**: LOW

**Status**: NEEDS-DEEPER — requires examining authproxy.TokenReview implementation to determine if session IDs and bearer tokens are handled identically.

---

## PH-19: Contradiction — OIDC User Onboard Trusts Session-Stored UserInfo Without Re-Verification

**Contradiction identified**: `OIDCController.Onboard` reads user info from session (`GetSession(userInfoKey)`) and token from session (`GetSession(tokenKey)`) to create a Harbor user account. This session data was stored during the `Callback` flow. The `Onboard` endpoint does NOT re-verify the OIDC token or re-check the OIDC provider.

**Assumption broken**: "User onboarding in OIDC mode is tied to a verified OIDC authentication."

**Code evidence**:
- `oidc.go:376-393`: Reads `userInfoKey` and `tokenKey` from session — no re-verification
- `oidc.go:395`: `userOnboard(ctx, oc, d, username, tb)` — creates Harbor user with data from session

**Attack scenario**: If an attacker can manipulate the session (e.g., via Redis injection, or via session fixation before the callback), they can inject arbitrary `userInfoKey` data into the session. When the victim visits `/oidc-onboard` (or the attacker visits it with the manipulated session), a Harbor account is created with the injected username/email/groups.

**The trigger**: The `Onboard` endpoint is accessible after a successful OIDC callback stores state in session. It requires `userInfoKey` to be set in session. If the session is shared (Redis), any process that can write to the session store can inject `userInfoKey`.

**Sanitizers present**: `utils.IsIllegalLength` and `strings.ContainsAny(username, common.IllegalCharsInUsername)` validate the username provided via POST body. But the onboarded username is taken from POST body, not from session — the session-stored username is overridden. The email, subject, issuer, and group data come entirely from the session-stored `userInfoKey`.

**Security consequence**: If Redis is unauthenticated (common Harbor deployment), session injection can create arbitrary OIDC user accounts with arbitrary group memberships and potentially admin status (if injected `AdminGroupMember: true`).

**Severity estimate**: HIGH (combined with unauthenticated Redis)

**Status**: VALIDATED — the onboard endpoint trusts session data without re-verification is confirmed.

---

## PH-20: Contradiction — providerHelper Refreshes Every 3 Seconds Creating Race Window

**Contradiction identified**: `providerHelper.get` in `helper.go:66-84` uses an `atomic.Value` for the OIDC provider instance. The provider is refreshed if `time.Since(p.creationTime) > 3*time.Second`. The update path calls `p.create(ctx)` which stores the new provider via `p.instance.Store(provider)`. Concurrent goroutines may see different provider instances during the 3-second refresh window.

**Assumption broken**: "The OIDC provider key material is consistent during a request."

**Code evidence**:
- `helper.go:68`: `if time.Since(p.creationTime) > 3*time.Second { if err := p.create(ctx)... }`
- `helper.go:81`: `p.create(ctx)` is called WITHOUT the mutex held (mutex is only acquired in the `else` branch for initial creation)
- `helper.go:101`: `p.instance.Store(provider)` — atomic store, but the old instance may still be in use

**The race**: Two goroutines both check `time.Since(p.creationTime) > 3*time.Second` == true at the same time. Both call `p.create(ctx)`. Both store different provider instances. The last write wins. Tokens verified by one provider instance may be invalid under the other. During OIDC provider key rotation, a token signed with the old key may be verified by the new provider instance (which no longer has the old key), causing legitimate users to be rejected.

**More critically (security angle)**: During the 3-second refresh, the provider is replaced WITHOUT a lock. A request currently verifying a token against the OLD provider instance may succeed while the new instance (with rotated keys) would reject the same token. The ATOMIC store means there's no torn read of the provider struct, but there IS a window where verification results are inconsistent.

**This is primarily a availability/reliability concern**, not a direct security vulnerability. An attacker cannot control key rotation timing.

**Severity estimate**: LOW

**Status**: NEEDS-DEEPER — the lack of mutex on refresh (only on initial creation) is a code smell worth flagging for correctness.

---

## PH-21: Contradiction — robot.Generate Does Not Validate Robot Project Access Scope Consistently

**Contradiction identified**: `robot.Generate` authenticates the robot account and creates a security context via `robotCtx.NewSecurityContext(robot)`. The robot model at this point includes `Permissions` (if `WithPermission: true` was set in the `List` query). However, the `v2auth` middleware later checks `securityCtx.Can(ctx, action, resource)`. The robot security context's `Can` method uses the permissions loaded at authentication time.

**The gap**: Robot accounts have `Duration` and `ExpiresAt` fields. The expiry check at `robot.go:66` uses `time.Now().Unix()`. If the robot's `ExpiresAt` value in the DB is updated between the `List` query and the `ExpiresAt` check (TOCTOU), or if the robot is disabled between authentication and the actual registry operation, there's no re-check.

**Code evidence**:
- `robot.go:43-67`: Full authentication including expiry check in a single transaction-less sequence
- `robot.go:43`: `robot_ctl.Ctl.List(ctx, q.New...)` — DB read
- `robot.go:61-68`: Expiry and disabled checks on the read data

**For the specific case of expiry**: If `ExpiresAt` is updated to a past value (robot disabled by admin) while a robot is mid-authentication (between the DB read and the expiry check), the robot proceeds. This is a very narrow TOCTOU window, essentially only relevant in highly concurrent scenarios.

**More relevant finding**: There is NO lockout for robot accounts. Unlike `basicAuth.Generate` which has `lock.Lock(username)` and `time.Sleep(frozenTime)`, `robot.Generate` has no rate limiting at all. An attacker can attempt unlimited robot secret guesses.

**Severity estimate**: MEDIUM (no lockout on robot auth is the primary finding)

**Status**: VALIDATED — no lockout on robot auth confirmed. PH-21 overlaps with PH-15; the primary finding is the unlimited brute-force capability.

---

## PH-22: Contradiction — FixEmptySubIss Decodes JWT Without Signature Verification

**Contradiction identified**: `fix.go:57-76` extracts subject and issuer from a stored ID token by base64-decoding the JWT payload (parts[1]) WITHOUT calling the OIDC verifier. It then uses these values to update the `oidc_user.subiss` field in the DB.

**Assumption broken**: "Subject and issuer values in the oidc_user table come from verified OIDC tokens."

**Code evidence**:
```go
parts := strings.Split(rawIDToken, ".")
data, _ = base64.RawURLEncoding.DecodeString(parts[1])
p := &struct{ Issuer, Subject string }{}
json.Unmarshal(data, p)
metaDao.Update(ctx, &models.OIDCUser{SubIss: p.Subject + p.Issuer}, "subiss")
```

**Attack scenario**: This function is a one-time migration/fix function. If an attacker can write an arbitrary `token` value to an `oidc_user` row (e.g., via SQL injection into the `oidc_user.token` column, or by compromising the AES key), calling `FixEmptySubIss` would cause the `subiss` to be updated to attacker-controlled values. This could allow a different OIDC user's `sub+iss` to be associated with a high-privilege Harbor account.

**Severity estimate**: LOW (requires DB write access or key compromise to exploit, and `FixEmptySubIss` is a one-time fix function)

**Status**: NEEDS-DEEPER — confirm if `FixEmptySubIss` is called at startup unconditionally or only once.
