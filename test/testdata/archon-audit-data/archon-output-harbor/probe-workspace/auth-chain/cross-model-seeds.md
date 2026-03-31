# Cross-Model Seeds: auth-chain

Methodology: For each pair of hypotheses across round-1 and round-2, checked for:
1. Same file or function
2. Same trust boundary
3. Attack input from one flows through the other's vulnerable path
4. One hypothesis's "assumption broken" invalidates the other's protection

---

## CROSS-01: Admin Brute Force Bypass Chain (Multi-Instance + Forced DB Auth)

Source-A: PH-01 from backward-reasoner — "Admin Always Uses DB Auth (IsSuperUser forces DBAuth in OIDC mode)"
Source-B: PH-11 from contradiction-reasoner — "OIDC Mode Claims Username Is Trusted From Provider, But Admin Bypass Ignores OIDC Entirely" (confirms PH-01)
Additional: PH-06 from backward-reasoner — "Multi-Instance Lockout Bypass"

Connection: Both PH-01 and PH-11 identify the same code path at `authenticator.go:142`. PH-06 demonstrates that the only defensive mechanism (in-memory lockout) is bypassable in multi-pod deployments. The three findings form a complete exploit chain: (1) OIDC mode does not protect the admin account because DBAuth is forced for user ID 1; (2) the lockout that would otherwise slow brute force is per-instance and bypassable via load balancer routing; (3) the admin account is therefore brute-forceable with no effective rate limiting in multi-instance Harbor deployments.

Combined hypothesis: In Harbor deployments with OIDC auth mode AND multiple core instances, the admin account is brute-forceable against the DB password at the rate of `N_instances * (1/1.5s)` attempts per second. Organizations that believe OIDC mode protects their admin account are exposed.

Test direction for causal-verifier: Confirm (1) `IsSuperUser` is called unconditionally before auth in `auth.Login`; (2) the `lock` variable is per-process (check if it's package-level or singleton); (3) confirm there is no Redis-backed distributed lockout anywhere in the codebase; (4) confirm the admin DB password is set (not empty/disabled) in default Harbor initialization.

---

## CROSS-02: PKCE Bypass Enabling Authorization Code Interception (Session + OIDC Flow)

Source-A: PH-02 from backward-reasoner — "PKCE Silently Disabled via Session Key Type Mismatch"
Source-B: PH-12 from contradiction-reasoner — "PKCE Is Generated and Stored but Not Verified on Exchange" (confirms PH-02)
Connection: Both findings identify the exact same code at `oidc.go:133`. The backward-reasoner identifies the trigger mechanism (session key absent or wrong type). The contradiction-reasoner identifies the design contradiction (PKCE is generated but then made optional). Together they confirm this is a real, triggerable vulnerability.

The connection to PH-07 (OIDC Session Token Leakage via Redis): if an attacker has Redis access (PH-07's attack vector), they could DELETE the `oidc_pkce_code` session key. When the victim returns from the OIDC provider, the PKCE key is absent, `pkceCode` is `""`, and PKCE verification is skipped. The attacker could then use an intercepted authorization code (obtained via, e.g., server log monitoring) without knowing the PKCE verifier.

Combined hypothesis: An attacker with Redis access (unauthenticated Redis deployment) can: (1) Delete the `oidc_pkce_code` session key from a victim's active OAuth2 session; (2) intercept the authorization code (via any code leakage vector — Referer header, server log, network monitoring); (3) exchange the code without PKCE verification because Harbor silently skips PKCE when the session key is absent.

Test direction for causal-verifier: (1) Confirm `oc.GetSession(pkceCodeKey).(string)` with missing key returns `""` in Go; (2) confirm `pkce.Code("").Verifier()` is NOT appended to exchange options when `len("")==0` at `helper.go:204`; (3) verify that no OIDC provider enforces PKCE server-side when Harbor does not send a code_verifier (provider permissiveness matters).

---

## CROSS-03: OIDC Group Claim Admin Injection — Unfiltered Claims Path

Source-A: PH-04 from backward-reasoner — "OIDC Group Claims — Admin Group Injection via Malicious OIDC Provider"
Source-B: PH-14 from contradiction-reasoner — "Group Filter Regex Protects DB But Not Admin Role Assignment"

Connection: Both findings identify the same code location: `helper.go:395-399` (`AdminGroup` membership check uses unfiltered `res.Groups`). PH-04 approaches from the malicious provider angle; PH-14 approaches from the misconfiguration angle. The combined finding is stronger: even with a correct `GroupFilter` regex, the admin group membership check happens on the raw, unfiltered claim list.

The combined attack scenario: An OIDC user is a member of group `harbor-admins` (or whatever the configured `AdminGroup` value is). This group membership comes from the OIDC provider. The admin group check at `helper.go:396` grants `AdminRoleInAuth = true`. Then `InjectGroupsToUser` calls `populateGroupsDB` which applies `filterGroup` — but admin role was already assigned before this filter.

Moreover, the OIDC CLI path through `oidcCli.Generate` refreshes group membership on every request by calling `oidc.InjectGroupsToUser(info, u)`. This means an admin group assignment is re-evaluated on every OIDC CLI request, not just at login. If the OIDC provider suddenly removes a user from the admin group, their `AdminRoleInAuth` is updated on the next CLI request. Conversely, if a provider adds a user to the admin group, admin access is granted immediately on the next CLI request.

Combined hypothesis: (1) OIDC group membership directly controls Harbor system admin status without any additional confirmation step; (2) The `GroupFilter` regex does NOT protect the admin group assignment — only DB population; (3) A compromised or malicious OIDC provider can grant system admin to any user by adding them to the configured `AdminGroup`.

Test direction for causal-verifier: (1) Trace exactly where `AdminRoleInAuth` is consumed in `local.NewSecurityContext` and how it maps to `IsSystemAdmin()` in RBAC decisions; (2) confirm `groupsFromClaims` at `helper.go:394` does NOT call `filterGroup`; (3) check whether `AdminRoleInAuth` persists in DB or is only in-memory per request.

---

## CROSS-04: Redis Session Injection Enabling OIDC Onboard with Arbitrary Identity

Source-A: PH-07 from backward-reasoner — "OIDC Session Token Leakage via Unauthenticated Redis"
Source-B: PH-19 from contradiction-reasoner — "OIDC User Onboard Trusts Session-Stored UserInfo Without Re-Verification"

Connection: PH-07 identifies that session data is stored in unauthenticated Redis. PH-19 identifies that `OIDCController.Onboard` trusts session data for user creation without re-verification. The connection is direct: an attacker with Redis write access can inject arbitrary `oidc_user_info` JSON into a session, then trigger the onboard flow to create a Harbor account with attacker-controlled identity data (subject, issuer, email, groups, admin group membership).

The attack chain:
1. Attacker accesses Redis (unauthenticated default deployment)
2. Attacker creates or finds an active session (or creates a new one — session keys are generated by beego's session manager)
3. Attacker writes `oidc_user_info` key with crafted JSON: `{"iss":"https://provider.com","sub":"victim-sub","name":"admin","email":"admin@example.com","admin_group_member":true,...}`
4. Attacker writes `oidc_token` key with any plausible token bytes (may not even need to be valid if the Onboard endpoint doesn't re-verify it)
5. Attacker triggers `POST /c/oidc/onboard` with the manipulated session cookie (or a cookie for the manipulated session)
6. A Harbor account is created with the attacker-chosen username and admin group membership

Key question for causal-verifier: Does `OIDCController.Onboard` re-verify the token or call any OIDC endpoint? Looking at the code: `userOnboard` at line 395 only calls `ctluser.Ctl.OnboardOIDCUser(ctx, user)` — no OIDC re-verification.

Combined hypothesis: In default Harbor OIDC deployments with unauthenticated Redis, an attacker with internal network access can create arbitrary Harbor accounts (including system admins) by writing crafted session data and triggering the OIDC onboard endpoint.

Test direction for causal-verifier: (1) Confirm `OIDCController.Onboard` does not call `oidc.VerifyToken` or any OIDC endpoint; (2) confirm the `userInfoKey` session value is used directly to create `models.OIDCUser` with `AdminGroupMember` driving admin role; (3) confirm beego session format is predictable enough to allow injection without a known valid session ID.

---

## CROSS-05: Robot No-Lockout + SHA256 — Offline + Online Combined Attack

Source-A: PH-05 from backward-reasoner — "Robot Secret SHA256 Offline Brute Force"
Source-B: PH-15 from contradiction-reasoner — "Robot Auth No Lockout — Enumeration and Online Brute Force"
Additional: PH-21 from contradiction-reasoner — "robot.Generate Does Not Have Lockout"

Connection: PH-05 identifies the weak hash (SHA256 single-round). PH-15 identifies no lockout exists. PH-21 confirms no lockout. Together: robot accounts can be attacked both online (no lockout, direct HTTP guessing) AND offline (if DB is accessible, SHA256 is brute-forceable).

The combined threat model: A robot account can be brute-forced online with no rate limiting at all. Since `robot.Generate` does not call `lock.Lock(name)` or `time.Sleep(frozenTime)`, an attacker can submit rapid-fire password guesses. Robot names are often predictable (`robot$projectname+robotname` format visible in API responses to project admins).

The severity of online brute force depends on secret complexity. `IsValidSec` requires mixed case + digits + length 8-128. `GenerateRandomString()` used for auto-generated secrets is sufficient. But user-set robot secrets (if allowed) might be weaker.

Combined hypothesis: Robot account authentication has no brute force protection (no lockout, no rate limit, no sleep on failure). The SHA256 hash provides no meaningful offline resistance if the DB is accessed. A robot with a predictable or user-chosen weak secret can be compromised online with sustained requests.

Test direction for causal-verifier: (1) Confirm no `lock.Lock` or sleep in `robot.Generate`; (2) check if `robot` API allows user-specified secrets (via `PUT /api/v2.0/robots/{id}` update); (3) verify what `utils.Encrypt` actually implements — is it SHA256 HMAC or plain SHA256?

---

## CROSS-06: V2 Token Timestamp Bypass + Missing ArtifactInfo = Stale Token on Base Endpoint

Source-A: PH-03 from backward-reasoner — "V2 Bearer Token Project Creation Timestamp Check Bypassed"
Source-B: (no direct R2 counterpart, but PH-17 from contradiction-reasoner touches token path routing)

Connection: PH-03 identifies that `tokenIssuedAfterProjectCreation` returns `true` when `ProjectName == ""`. The `accessList` function in `v2auth/access.go:82-86` shows that `/v2/` exactly maps to `login` target — which only checks `IsAuthenticated()`. So a stale token that passes RS256 + audience validation, when sent to `/v2/`, produces an authenticated security context and the v2auth `login` check passes.

The combined finding: A stale bearer token (issued before a project was deleted and recreated) can still authenticate on the `/v2/` discovery endpoint because: (1) `/v2/` produces empty ProjectName; (2) `tokenIssuedAfterProjectCreation` returns true; (3) v2auth only requires `IsAuthenticated()` for the login target.

This may be intentional (the `/v2/` endpoint just confirms the registry is accessible), but the stale token's `claims.Subject` (the username) and `claims.Access` (the repository scopes from when the token was issued) are both embedded in the security context. If subsequent requests reuse this context without re-validation, the stale access claims could be used.

Combined hypothesis: A stale v2 bearer token (post project recreation) authenticates on `/v2/` and creates a security context with stale access claims. If any subsequent registry handler uses the access claims from the context without project-scoped re-validation, the stale claims could enable unauthorized access to the recreated project.

Test direction for causal-verifier: (1) Trace what `v2token.New(ctx, claims.Subject, claims.Access)` does with the `Access` field; (2) check how `v2token.SecurityContext.Can()` uses the `Access` claims vs. doing a DB lookup; (3) confirm whether the KB's "sound" verdict for commit 89e1c4baa (bearer token project recreation fix) is complete or only partial.
