# Deep Probe Summary: auth-chain

Status: complete
Loops: 2
Total hypotheses: 26 (PH-01 through PH-26, with some numbered cross-model)
Validated: 14
Needs-Deeper: 3
Invalidated: 3
Stop reason: All high-priority entry points covered; remaining uncovered paths are low priority or low severity fragile items.

---

## Validated Hypotheses

### PH-01 / PH-11 / CROSS-01: Admin Account Permanently Bypasses OIDC Mode — DB Brute Force Always Possible

- Reasoning-Model: Pre-Mortem + Contradiction + Causal
- Target: `src/core/auth/authenticator.go:142` — `auth.Login`
- Attack input: HTTP Basic Auth with known admin username (default: "admin") and guessed DB password, sent to any endpoint processed by `basicAuth.Generate` (all paths)
- Code path: `basic_auth.go:66` -> `auth.Login` -> `authenticator.go:142: IsSuperUser(ctx, username) == true` -> `authMode = DBAuth` -> `registry["db"].Authenticate` -> DB password check
- Sanitizers on path: `lock.IsLocked(username)` — in-memory, per-process. Bypassable in multi-instance deployments (PH-06). No distributed lockout.
- Security consequence: Admin account is permanently brute-forceable via DB credentials regardless of OIDC or LDAP auth mode configuration. Organizations that configure OIDC-only mode are not protected.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-06: Multi-Instance Brute Force Lockout Bypass

- Reasoning-Model: Pre-Mortem + Causal
- Target: `src/core/auth/lock.go:22-51` — `UserLock`
- Attack input: Distributed password-guessing requests across multiple Harbor core pods
- Code path: `authenticator.go:151` -> `lock.IsLocked(username)` -> in-memory `map[string]time.Time` per process -> no Redis sync
- Sanitizers on path: None effective in multi-pod deployments
- Security consequence: Effectively unlimited brute force against any account in multi-instance Harbor deployments. Primary enabler for PH-01 chain.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-04 / CROSS-03: OIDC Admin Group Claim Injection — GroupFilter Does Not Protect Admin Role

- Reasoning-Model: Pre-Mortem + Contradiction + Causal
- Target: `src/pkg/oidc/helper.go:395-399` — `userInfoFromClaims`
- Attack input: OIDC provider returns configured `AdminGroup` value in groups claim
- Code path: OIDC callback/CLI auth -> `UserInfoFromToken` -> `userInfoFromClaims` -> `slices.Contains(res.Groups, setting.AdminGroup)` -> `AdminRoleInAuth = true` -> `InjectGroupsToUser` -> `user.AdminRoleInAuth = true` -> `local.NewSecurityContext` -> `IsSysAdmin()` returns true
- Sanitizers on path: `filterGroup` regex — NOT applied before admin check. Only applied to DB population via `populateGroupsDB`. The admin group check at line 396 uses raw, unfiltered groups.
- Security consequence: Compromised or malicious OIDC provider can grant system admin to any user by returning the configured `AdminGroup` in claims. Admin role is refreshed on every OIDC CLI request.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-07: OIDC Full Token (Including Refresh Token) Stored in Unauthenticated Redis Session

- Reasoning-Model: Pre-Mortem
- Target: `src/core/controllers/oidc.go:161-168` — `OIDCController.Callback`
- Attack input: Redis read access (internal network in default deployments)
- Code path: `oc.SetSession(tokenKey, tokenBytes)` -> beego Redis session store -> attacker reads Redis -> extracts `oauth2.Token.RefreshToken` -> calls OIDC provider `/token?grant_type=refresh_token` -> gets new access token -> authenticated as victim
- Sanitizers on path: Session cookie signing/encryption (beego configurable, protects cookie in transit). No application-level encryption of Redis session values.
- Security consequence: Long-lived session hijacking for all OIDC users. Refresh token enables silent token renewal until explicit revocation.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-19 / CROSS-04: OIDC Onboard Trusts Session-Stored User Info Without OIDC Re-Verification

- Reasoning-Model: Contradiction + Causal
- Target: `src/core/controllers/oidc.go:376-404` — `OIDCController.Onboard`
- Attack input: Redis write access -> inject crafted `oidc_user_info` JSON with `admin_group_member: true`
- Code path: Redis write -> manipulate session `oidc_user_info` key -> POST `/c/oidc/onboard` -> `json.Unmarshal(userInfoStr, &d)` -> `userOnboard(ctx, oc, d, username, tb)` -> `InjectGroupsToUser(info, user)` with `AdminGroupMember=true` -> `ctluser.Ctl.OnboardOIDCUser` -> admin Harbor account created
- Sanitizers on path: Username POST body validation (length + chars). Does NOT re-verify OIDC token. No integrity check on session data.
- Security consequence: With unauthenticated Redis access (common default deployment), attacker can create arbitrary Harbor accounts including system admins.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-25: Nginx Does Not Strip `Authorization: Harbor-Secret` Header — External Secret Injection Possible

- Reasoning-Model: Causal (Loop 2)
- Target: `make/photon/prepare/templates/nginx/nginx.http.conf.jinja` — Nginx proxy config
- Attack input: HTTP request with `Authorization: Harbor-Secret <known-secret>` from external network
- Code path: External request -> Nginx (no `proxy_set_header Authorization ""` or equivalent to strip) -> Harbor core -> `secret.Generate` -> `commonsecret.FromRequest(req)` extracts value -> `config.SecretStore.IsValid(sec)` -> if valid: full internal trust context
- Sanitizers on path: `config.SecretStore.IsValid(sec)` — must know the actual secret value. Secret is generated at Harbor startup. If the secret is discovered (log leak, env var exposure), Nginx config does not prevent external injection.
- Security consequence: An external attacker who knows the Harbor internal shared secret can send requests with that secret header, bypassing all other auth and obtaining full internal/system trust. No Nginx-level protection exists.
- Severity estimate: HIGH (conditional on secret knowledge; but there is NO Nginx-level defense-in-depth)
- Evidence file: round-1-evidence.md

### PH-26: LDAP Null Bind — No Empty Password Guard Before User Bind

- Reasoning-Model: Gap Analysis (Loop 2)
- Target: `src/core/auth/ldap/ldap.go:87` — `ldapSession.Bind(dn, m.Password)` + `src/pkg/ldap/ldap.go:190-192` — `Session.Bind`
- Attack input: LDAP authentication request with known username and empty password (`""`)
- Code path: `ldap.Auth.Authenticate` (ldap.go:55) -> `ldapSession.SearchUser(p)` finds DN -> `ldapSession.Bind(dn, "")` -> `s.ldapConn.Bind(dn, "")` -> passes to LDAP server
- Sanitizers on path: `len(strings.TrimSpace(p)) == 0` at line 57 checks username is non-empty. NO check for empty password before `Bind`. `ErrEmptyPassword` is defined but only used in search credential context (`controller.go`), not in user authentication.
- Security consequence: If the LDAP server accepts null bind (many do by default or when misconfigured), an attacker can authenticate as any LDAP user with an empty password. Complete authentication bypass for LDAP mode.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-02 / PH-12 / CROSS-02: PKCE Silently Disabled via Session Key Absence

- Reasoning-Model: Pre-Mortem + Contradiction
- Target: `src/core/controllers/oidc.go:133` — `OIDCController.Callback`
- Attack input: Absent or corrupted `oidc_pkce_code` session key (natural: session expiry, sticky session failure; adversarial: Redis delete)
- Code path: `GetSession(pkceCodeKey).(string)` -> type cast failure produces `""` -> `helper.go:204: len("") == 0` -> PKCE verifier not added -> `oauth.Exchange(ctx, code)` with no `code_verifier`
- Sanitizers on path: State parameter validation — binds callback to login initiation but does not bind code to client (that's PKCE's role)
- Security consequence: Authorization code can be exchanged without PKCE verification for permissive OIDC providers. Combined with Redis manipulation, PKCE can be actively disabled by attacker.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-13: OIDC Subject Binding Check Bypassed When Userinfo Endpoint Fails

- Reasoning-Model: Contradiction
- Target: `src/pkg/oidc/helper.go:300-312` — `UserInfoFromToken`
- Attack input: OIDC provider that successfully issues ID tokens but intermittently fails the userinfo endpoint
- Code path: `userInfoFromRemote` returns error -> `remote = nil` -> `if local != nil && remote == nil { return local, nil }` -> subject binding check (`remote.Subject != local.Subject`) never evaluates
- Sanitizers on path: ID token signature verification via go-oidc verifier. Only bypasses userinfo cross-validation, not ID token signature.
- Security consequence: When userinfo endpoint is unavailable, groups and admin status come from ID token alone without cross-validation. A crafted ID token (from compromised provider) with elevated groups is accepted.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-03: V2 Bearer Token Timestamp Check Bypassed at `/v2/` and `/_catalog` Endpoints

- Reasoning-Model: Pre-Mortem + Causal
- Target: `src/server/middleware/security/v2_token.go:85-87` — `tokenIssuedAfterProjectCreation`
- Attack input: Stale bearer token (issued before project deletion/recreation) sent to `/v2/` base or `/_catalog` endpoints
- Code path: `lib.GetArtifactInfo(ctx).ProjectName == ""` for these paths -> `return true` -> stale token creates authenticated context -> `v2auth` for `login` target only checks `IsAuthenticated()` -> passes
- Sanitizers on path: RS256 signature + audience validation (still enforced). The timestamp check is the only additional gate.
- Security consequence: Stale token with valid signature authenticates at `/v2/` and `/_catalog`. Limited blast radius (discovery and catalog only).
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-09: OIDC Onboard Redirect URL — Username Parameter Injection

- Reasoning-Model: Pre-Mortem
- Target: `src/core/controllers/oidc.go:203` — `OIDCController.Callback`
- Attack input: OIDC username claim containing URL metacharacters (`&`, `?`, `=`)
- Code path: `username = strings.Replace(username, " ", "_", -1)` (spaces only sanitized) -> `fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr)` -> unencoded interpolation -> injected parameters in redirect URL
- Sanitizers on path: `utils.IsLocalPath` on `redirect_url` at login time (not at redirect time). Username chars validated only in `Onboard` handler (not in `Callback` where interpolation happens).
- Security consequence: URL parameter injection via crafted OIDC username. Severity depends on Angular frontend behavior with duplicate query params.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-15 / PH-21: Robot Account — No Brute Force Protection

- Reasoning-Model: Contradiction + Causal
- Target: `src/server/middleware/security/robot.go:33-73` — `robot.Generate`
- Attack input: Rapid sequential basic auth attempts against robot account credentials
- Code path: No `lock.Lock()`, no `time.Sleep()`, no lockout of any kind in `robot.Generate`. Contrast with `basicAuth.Generate` -> `auth.Login` which has `lock.Lock(username)` and 1.5s sleep.
- Sanitizers on path: PBKDF2-SHA256 with 4096 iterations (moderate offline resistance). Robot names are predictable format.
- Security consequence: Unlimited online brute force against robot accounts. Robot accounts are often used in CI/CD pipelines; compromise enables supply chain attacks.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-24: ReversibleDecrypt Base64 Fallback — Legacy OIDC Tokens Stored in Plaintext

- Reasoning-Model: Causal
- Target: `src/common/utils/encrypt.go:82-89` — `ReversibleDecrypt`
- Attack input: DB read access to `oidc_user` table
- Code path: `ReversibleDecrypt(oidcUser.Token, key)` -> if no `<enc-v1>` prefix -> `decodeB64(str)` -> base64 decoded without AES key -> plaintext OIDC token/secret
- Sanitizers on path: Requires DB read access. New records use AES encryption (have `<enc-v1>` prefix).
- Security consequence: In Harbor instances upgraded from old versions, OIDC tokens and CLI secrets for legacy accounts are decodable from DB without the AES key.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

---

## NEEDS-DEEPER

### PH-08: Auth Proxy Username Prefix Security
- Why unresolved: Prefix is `"tokenreview$"` — provides meaningful separation. Exploit requires token review endpoint to be attacker-controlled or misconfigured. Insufficient information about token review endpoint security model.
- Suggested follow-up: Phase 8 should examine `authproxy.TokenReview` implementation and its tolerance for crafted responses.

### PH-16: idToken Generator Dual Parse Inconsistency (Relaxed Second Parse)
- Why unresolved: The dual-parse is architecturally fragile but exploitation requires key rotation timing. Low severity.
- Suggested follow-up: Confirm if `nonce` from first (strict) parse is propagated to second (relaxed) parse path; check if the relaxed parse result is ever used for auth decisions independently.

### PH-22: FixEmptySubIss Decodes JWT Without Signature Verification
- Why unresolved: `FixEmptySubIss` runs at every Harbor core startup (`main.go:282`). Exploitation requires writing crafted token to `oidc_user.token` column (SQL injection prerequisite). Low independent severity.
- Suggested follow-up: Phase 8 should confirm SQL injection paths that reach `oidc_user.token` to determine if this is a meaningful privilege escalation amplifier.

---

## Coverage Summary

| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|------------|:-:|:-:|:-:|
| secret.Generate — internal secret header | PH-25 (loop 2) | NONE | PH-25 |
| oidcCli.Generate — OIDC CLI auth | PH-02, PH-04 | PH-12, PH-13, PH-14 | PH-02, PH-04, PH-13 |
| v2Token.Generate — Bearer JWT | PH-03, PH-10 | PH-17 | PH-03 (revised) |
| idToken.Generate — OIDC ID token on /api | PH-04 | PH-16 | PH-16 (fragile) |
| authProxy.Generate — HTTP Auth Proxy | PH-08 | PH-18 | PH-08 (needs-deeper) |
| robot.Generate — Robot account | PH-05, PH-15 | PH-15, PH-21 | PH-15, PH-21 |
| basicAuth.Generate — Basic auth all paths | PH-01, PH-06 | PH-11 | PH-01, PH-06 |
| session.Generate — Cookie session | PH-07 | PH-19 (via onboard) | PH-07, PH-19 |
| proxyCacheSecret.Generate | NONE | NONE | NONE (internal only) |
| OIDCController.Callback | PH-02, PH-09 | PH-12, PH-19 | PH-02, PH-09 |
| OIDCController.Onboard | PH-09 | PH-19 | PH-19, CROSS-04 |
| OIDCController.RedirectLogin | PH-02, PH-09 | PH-12 | PH-02 |
| auth.Login dispatcher | PH-01, PH-06 | PH-11 | PH-01, PH-06 |
| ldap.Auth.Authenticate | NONE (loop 1) | NONE (loop 1) | PH-26 (loop 2) |
| v2auth.reqChecker.check | PH-03 | PH-17 | PH-03 |
| token.Parse / JWT verification | PH-10 | PH-17 | verified sound |
| oidc.VerifySecret | PH-02, PH-07 | PH-12 | PH-07 |
| Nginx secret header stripping | NONE (loop 1) | NONE (loop 1) | PH-25 (loop 2) |

---

## Priority Recommendations for Phase 8

1. **PH-01/PH-06 (CRITICAL)**: Verify admin account DB password is non-default in production. Add Redis-backed distributed lockout or per-account rate limiting. Remove `IsSuperUser` override of auth mode (admin should authenticate via OIDC like all other users).

2. **PH-26 (HIGH)**: Add empty password check in `ldap.go:Authenticate` before calling `ldapSession.Bind(dn, m.Password)`: `if strings.TrimSpace(m.Password) == "" { return nil, auth.NewErrAuth("empty password") }`.

3. **PH-25 (HIGH)**: Add Nginx directive to strip or replace the `Authorization` header for external requests: `proxy_set_header Authorization ""` for external-facing locations, or verify the shared secret cannot be obtained externally.

4. **PH-04 (HIGH)**: Apply `filterGroup` regex before the `AdminGroup` membership check in `userInfoFromClaims`. Additionally, consider requiring a separate OIDC claim (not derived from group membership) for admin role assignment.

5. **PH-07 + PH-19 (HIGH chain)**: Enable Redis authentication in Harbor deployments. Add application-level HMAC to session data for integrity verification. In `OIDCController.Onboard`, re-verify the OIDC token from session before using it for account creation.

6. **PH-02 (MEDIUM)**: Change type assertion at `oidc.go:133` from `pkceCode, _ := ...` to `pkceCode, ok := ...; if !ok { return error }` to make PKCE mandatory.

7. **PH-09 (MEDIUM)**: URL-encode username and redirectURL in `fmt.Sprintf` at `oidc.go:203`: use `url.QueryEscape(username)`.

8. **PH-15/PH-21 (MEDIUM)**: Add brute force protection for robot account authentication (per-name rate limiting or lockout, or add to the existing `UserLock` mechanism).
