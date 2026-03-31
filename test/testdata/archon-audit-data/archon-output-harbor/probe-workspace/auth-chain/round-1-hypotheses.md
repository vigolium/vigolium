# Round 1 Hypotheses — backward-reasoner-02

Reasoning model: Pre-Mortem (backward from catastrophic outcome)
Source: attack-surface-map.md + code-anatomy.md

---

## PH-01: Auth Mode Bypass — Admin Always Uses DB Auth (Privilege Escalation via Forced DBAuth)

**Reasoning direction**: Working backward from "attacker authenticates as Harbor admin despite OIDC/LDAP-only policy"

**Assumed broken trust**: The `IsSuperUser` check in `authenticator.go:142` forces `DBAuth` for any username that resolves to `userID == 1` regardless of configured auth mode.

**Attack input**: An attacker who knows the admin username (default: "admin") submits basic auth credentials to any Harbor endpoint that processes basic auth (e.g., `GET /v2/` with `Authorization: Basic base64(admin:password)`). The `basicAuth.Generate` calls `auth.Login`. `auth.Login` calls `IsSuperUser(ctx, "admin")` which does a DB lookup. If `userID == 1` is found, `authMode` is overridden to `DBAuth` regardless of whether the system is configured in OIDC-only or LDAP-only mode.

**Code path**: `basic_auth.go:66` -> `authenticator.go:142` -> `IsSuperUser` -> `authenticator.go:144` sets `authMode = DBAuth` -> `registry["db"].Authenticate` -> DB password check

**Why dangerous**: Organizations deploying Harbor in OIDC-only mode believe the local DB admin password is unused. But the admin password is still checked on every `admin` username login attempt. If the admin DB password is weak or default (never changed), brute-force proceeds even in OIDC-only mode. The lockout (`lock.IsLocked`) is in-memory and per-instance.

**Sanitizers on path**: `lock.IsLocked(username)` — 1.5s lockout per instance. Bypassable via multiple core instances (no shared lockout state). No rate limiting in code.

**Security consequence**: Admin account compromise via brute-force on DB credentials even in OIDC-only deployments. Complete system compromise.

**Severity estimate**: HIGH

**Status**: VALIDATED — the code path is confirmed: `authenticator.go:142` explicitly checks `IsSuperUser` and overrides auth mode.

---

## PH-02: PKCE Silently Disabled via Session Key Type Mismatch

**Reasoning direction**: Working backward from "OIDC callback processed without PKCE protection"

**Assumed broken trust**: `OIDCController.Callback` at line 133 performs `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)`. The blank identifier discards the ok flag. If the session key holds a non-string type (or is absent), `pkceCode` is `""`. Then `oidc.ExchangeToken` is called with `pkce.Code("")`. In `helper.go:204`, `if len(pkceCode) > 0` is false, so the PKCE verifier is never appended.

**Attack input**: An attacker who can perform a session fixation attack (or manipulate Redis) to clear or corrupt the `oidc_pkce_code` session key before the callback is processed. Alternatively: in deployments where the session is lost between redirect and callback (e.g., sticky session misconfiguration, load balancer with no session affinity), the PKCE code is absent from session.

**Code path**: `oidc.go:133` -> `pkce.Code("")` -> `helper.go:204: if len(pkceCode) > 0` fails -> `pkceCode.Verifier()` never called -> `oauth.Exchange(ctx, code, opts...)` with no PKCE verifier -> authorization code accepted without PKCE binding

**Why dangerous**: Without PKCE, an authorization code intercepted via the redirect URI (e.g., Referer header leakage, open redirect in post-auth redirect flow) can be exchanged for tokens by an attacker.

**Sanitizers on path**: State parameter validation (`oidc.go:110`) provides some binding. But state alone does not bind the code to the client. PKCE specifically binds the code to the client that initiated the flow.

**Security consequence**: Authorization code interception -> token exchange -> account takeover for any OIDC user whose authorization code is intercepted.

**Severity estimate**: MEDIUM

**Status**: VALIDATED — the silent type cast at `oidc.go:133` is confirmed. The PKCE skip condition at `helper.go:204` is confirmed. The session fixation trigger is realistic in multi-instance deployments.

---

## PH-03: V2 Bearer Token — Project Creation Timestamp Check Bypassed via Missing ArtifactInfo

**Reasoning direction**: Working backward from "stale bearer token reused after project recreation"

**Assumed broken trust**: `tokenIssuedAfterProjectCreation` (v2_token.go:83) returns `true` immediately when `info.ProjectName == ""`. The `ArtifactInfo` is populated by the `ArtifactInfo` middleware which is a separate middleware later in the chain specifically for registry routes. For requests to `/v2/` base path or paths where `ArtifactInfo` cannot extract a project name, the check is completely skipped.

**Attack input**: A bearer token issued before a project was deleted and recreated (with the same name). The attacker sends a request to `/v2/` (base discovery endpoint) or a path where `ArtifactInfo` produces an empty `ProjectName`. The token passes signature and expiry validation, then `tokenIssuedAfterProjectCreation` returns `true` because `ProjectName == ""`.

**Code path**: `v2_token.go:84-87` -> `lib.GetArtifactInfo(ctx).ProjectName == ""` -> `return true` -> security context created with stale claims

**Conditions for exploitation**: The attack is relevant specifically for the `/v2/` base path which returns `login` target in `accessList`. After context creation, the `v2auth` middleware checks `securityCtx.IsAuthenticated()` for `login` target. With a stale but signature-valid token, `IsAuthenticated()` returns true, and the request proceeds.

**Sanitizers on path**: The token must still pass RS256 signature verification and audience validation. The exploit window only arises in the specific case where a project was deleted and recreated during the token lifetime.

**Security consequence**: Stale token grants authenticated status on the `/v2/` base endpoint. May allow cross-project access if subsequent operations do not re-validate project membership.

**Severity estimate**: MEDIUM

**Status**: VALIDATED — the early return on empty ProjectName is confirmed in code. The `/v2/` base path producing `login` target in `accessList` (access.go:82-86) is confirmed.

---

## PH-04: OIDC Group Claims — Admin Group Injection via Malicious OIDC Provider

**Reasoning direction**: Working backward from "attacker gains Harbor system admin via OIDC groups"

**Assumed broken trust**: `userInfoFromClaims` (helper.go:395-399) checks `slices.Contains(res.Groups, setting.AdminGroup)` and sets `AdminRoleInAuth = true`. The `Groups` list is populated from raw OIDC claims. In `mergeUserInfo`, group priority is: remote userinfo > ID token. If the OIDC provider (or its userinfo endpoint) returns the configured `AdminGroup` value in the groups claim, the user is granted system admin.

**Attack input**: An OIDC provider that is misconfigured, compromised, or under attacker control sends a `groups` claim containing the Harbor `AdminGroup` value. The attacker registers as a normal user but the OIDC provider adds them to the admin group.

**Code path**: OIDC callback -> `UserInfoFromToken` -> `mergeUserInfo` -> `remote.hasGroupClaim = true` -> `res.Groups = remote.Groups` -> `userInfoFromClaims(remote, setting)` -> `slices.Contains(groups, AdminGroup) == true` -> `AdminRoleInAuth = true` -> `InjectGroupsToUser` -> `user.AdminRoleInAuth = true` -> `local.NewSecurityContext(user)` -> security context with admin role

**Bypass of intended protection**: There is no separate admin claim separate from group membership. Admin role is purely a function of group membership matching a string value. If the provider response is not verified for group claim integrity beyond signature, the admin group name is the only gate.

**Secondary path (OIDC CLI)**: The same path is taken in `oidcCli.Generate` via `oidc.InjectGroupsToUser(info, u)` on every CLI authentication. Group membership is refreshed from the OIDC token on every request.

**Sanitizers on path**: `filterGroup` (helper.go:459) applies a regex filter to group names before DB population. This filter is a configured regex — it does not specifically protect against admin group injection; it only filters which groups are populated in DB. The admin group check happens after filtering in `userInfoFromClaims`.

Wait — re-reading: `userInfoFromClaims` (line 394) calls `groupsFromClaims` which calls `filterGroup`? Let me re-check the call order.

Actually: `userInfoFromClaims` (line 394) sets `res.Groups, res.hasGroupClaim = groupsFromClaims(c, setting.GroupsClaim)`. This does NOT apply the `filterGroup` regex. The `filterGroup` is only applied in `populateGroupsDB` (line 455). The `AdminGroup` check at line 396 uses `res.Groups` which is the UNFILTERED group list from the OIDC claim. Therefore a group named to match `AdminGroup` would grant admin even if `GroupFilter` regex would exclude it from DB population.

Actually wait — `userInfoFromClaims.AdminGroup` check: if `slices.Contains(res.Groups, setting.AdminGroup)` — `res.Groups` comes from `groupsFromClaims` which does not apply the regex filter. The regex filter is only applied in `populateGroupsDB`. So admin group membership is determined from raw, unfiltered group list.

**Security consequence**: Any OIDC user whose provider places them in the `AdminGroup` (by name match) gains Harbor system admin rights. Malicious OIDC provider, compromised OIDC provider, or misconfiguration grants full admin.

**Severity estimate**: HIGH

**Status**: VALIDATED — admin group check uses unfiltered groups; filter is only applied to DB population.

---

## PH-05: Robot Secret SHA256 Offline Brute Force via SQL Injection / DB Leak

**Reasoning direction**: Working backward from "CI/CD robot account compromised after DB leak"

**Assumed broken trust**: Robot secrets are stored as `SHA256(password + salt)`. This is a fast, single-round hash. Given a DB dump (obtainable via SQL injection — a known Harbor vulnerability class), an attacker can brute-force robot secrets offline with GPU hardware.

**Attack input**: Robot table contents obtained via SQL injection or DB compromise. `robot.Secret` (SHA256 hash) and `robot.Salt` are used to mount a dictionary/brute-force attack.

**Code path**: `controller.go:424` -> `utils.Encrypt(pwd, saltTmp, utils.SHA256)` -> single SHA256 iteration. No bcrypt/argon2/scrypt.

**Comparison**: Harbor user passwords (local DB auth) use what algorithm? Let me note this for evidence harvester to verify. If user passwords use bcrypt but robot secrets use SHA256, robot accounts are significantly weaker.

**Sanitizers on path**: `IsValidSec` requires: length 8-128, lowercase, uppercase, digit. This is `utils.GenerateRandomString()` output which is typically 20+ random chars. The entropy is high enough that direct brute force is infeasible on strong secrets. However, user-specified robot secrets (not generated) could be weak.

**Note**: `robot_ctl.Ctl.Create` calls `CreateSec()` which generates a strong random secret. But robot secrets can be rotated/updated. The `Update` method at controller.go:180 updates the `secret` field — it's unclear if updated secrets are validated for strength.

**Security consequence**: If DB contents are leaked, robot secrets are more brute-forceable than user passwords. Compromised robot secrets enable supply chain attacks (image push/pull).

**Severity estimate**: MEDIUM (requires DB access to exploit fully, but SHA256 is architecturally weak)

**Status**: VALIDATED — single-round SHA256 confirmed in code.

---

## PH-06: Multi-Instance Lockout Bypass — Brute Force via Load Balancer Distribution

**Reasoning direction**: Working backward from "brute force attack succeeds despite lockout mechanism"

**Assumed broken trust**: The `lock` variable in `authenticator.go:35` is `NewUserLock(frozenTime)` — an in-memory data structure. In a multi-instance Harbor core deployment (common in Kubernetes), each instance has its own lock state. The lockout does not synchronize across instances.

**Attack input**: An attacker sends password-guessing requests distributed across multiple Harbor core instances (behind a load balancer). Each instance independently tracks lockout state. An instance locks the username for 1.5 seconds, but the attacker's next request goes to a different instance where the lockout is not active.

**Code path**: `authenticator.go:151` -> `lock.IsLocked(username)` -> in-memory check per instance -> `auth.core-pod-1` locks `admin` for 1.5s -> attacker routes to `auth.core-pod-2` which has no lock

**Sanitizers on path**: The `time.Sleep(frozenTime)` (1500ms) adds latency on the locking instance but has no effect on other instances.

**Security consequence**: Effectively unlimited brute force attempts against any account in multi-instance deployments. Combined with PH-01 (DB auth forced for admin), admin credentials can be brute-forced.

**Severity estimate**: HIGH

**Status**: VALIDATED — in-memory lock with no cross-instance synchronization confirmed.

---

## PH-07: OIDC Session Token Leakage — Full OIDC Token Stored in Redis Unprotected

**Reasoning direction**: Working backward from "OIDC refresh token stolen -> long-lived session hijack"

**Assumed broken trust**: `OIDCController.Callback` stores the full serialized OIDC token (including `RefreshToken`) in the Redis session at key `oidc_token`. The session data in Redis is not encrypted or HMAC-protected at the application layer. In default Harbor deployments, Redis has no password (`requirepass` not set).

**Attack input**: An attacker with network access to Redis (internal network, Kubernetes pod in same namespace) reads session keys and extracts the OIDC token JSON. The refresh token allows silent token renewal indefinitely.

**Code path**: `oidc.go:166` -> `oc.SetSession(tokenKey, tokenBytes)` -> stored in Redis -> attacker reads Redis key -> extracts `RefreshToken` -> calls OIDC provider `/token` endpoint with `grant_type=refresh_token` -> gets new access token -> authenticates as victim user

**Sanitizers on path**: Session cookie is signed/encrypted by beego's session manager (configurable). But this protects the session cookie in transit, not the session data at rest in Redis.

**Security consequence**: OIDC user session hijacking via Redis. Refresh token theft enables long-lived impersonation (until token revocation or rotation). Affects all OIDC users.

**Severity estimate**: HIGH

**Status**: VALIDATED — full token stored in session confirmed at `oidc.go:161-168`. Redis auth is not a code-level concern but is a deployment reality.

---

## PH-08: Auth Proxy Username Prefix — Hardcoded Prefix Allows Username Collision

**Reasoning direction**: Working backward from "auth proxy impersonates a regular user"

**Assumed broken trust**: `authProxy.Generate` requires username to start with `common.AuthProxyUserNamePrefix`. After stripping this prefix, the raw username is used to look up the Harbor user. The `common.AuthProxyUserNamePrefix` value — let me check what it is.

Looking at `auth_proxy.go:48`: `rawUserName, match = a.matchAuthProxyUserName(proxyUserName)`. The prefix value is `common.AuthProxyUserNamePrefix`. If this is an empty string or a predictable prefix, an attacker in HTTPAuth mode could supply a regular username with the prefix prepended to satisfy the prefix check.

**Attack input**: In HTTPAuth mode, attacker supplies `Authorization: Basic base64("harbor_auth_proxy_<username>:<token>")`. If the token review passes for `<username>`, the user is authenticated as that username. If the username is "admin", they could be onboarded or looked up as admin.

**Bypass condition**: The `tokenReviewStatus.User.Username` must match `rawUserName`. This binding check prevents direct username forgery without a matching token review. However, if the token review endpoint is attacker-controlled or misconfigured (returns any username), this binding check is trivially bypassed.

**Security consequence**: Username injection in auth proxy mode, potentially impersonating any Harbor user.

**Severity estimate**: MEDIUM (requires HTTPAuth mode and either control of token review endpoint or weak token review implementation)

**Status**: NEEDS-DEEPER — requires examining `common.AuthProxyUserNamePrefix` value and the token review endpoint implementation.

---

## PH-09: OIDC Redirect URL — Post-Auth Open Redirect via Onboard Flow

**Reasoning direction**: Working backward from "user redirected to attacker-controlled URL after OIDC login"

**Assumed broken trust**: `OIDCController.Callback` at line 203 performs `oc.Controller.Redirect(fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr), http.StatusFound)`. The `redirectURLStr` was stored in session from `RedirectLogin` after `utils.IsLocalPath` check. However, the `username` and `redirectURLStr` are interpolated directly into the URL without URL encoding.

**Attack input**: A username from OIDC that contains URL metacharacters (`?`, `&`, `#`, etc.) could manipulate the constructed onboarding URL. For example, OIDC username `foo&redirect_url=http://evil.com` in a URL-unencoded interpolation would construct `/oidc-onboard?username=foo&redirect_url=http://evil.com&redirect_url=<original>`. Browser query string parsing would use the first occurrence.

**Code path**: `oidc.go:176` -> `username = strings.Replace(username, " ", "_", -1)` -> `oidc.go:203` -> `fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr)` -> `oc.Controller.Redirect(url, 302)`

**Sanitizers on path**: `strings.Replace(username, " ", "_", -1)` — replaces spaces only. Does not encode `&`, `?`, `#`, `%`, `=` characters. Username comes from OIDC claim (attacker-controlled via malicious OIDC provider or IdP that allows special chars in usernames).

**Security consequence**: URL parameter injection in onboard redirect. Depending on frontend behavior, could enable open redirect (limited by `IsLocalPath` check on `redirect_url` when it was originally set), XSS via injected parameters, or CSRF via parameter pollution.

**Severity estimate**: MEDIUM

**Status**: VALIDATED — `fmt.Sprintf` interpolation without URL encoding confirmed at `oidc.go:203`. Character sanitization is limited to spaces.

---

## PH-10: Bearer Token Parsing Uses Split on "Bearer" Without Strict Prefix Check

**Reasoning direction**: Working backward from "attacker bypasses token check with malformed Authorization header"

**Assumed broken trust**: `bearerToken(utils.go:26-36)`:
```go
h := req.Header.Get("Authorization")
token := strings.Split(h, "Bearer")
if len(token) < 2 { return "" }
return strings.TrimSpace(token[1])
```
`strings.Split(h, "Bearer")` splits on the FIRST occurrence of "Bearer" anywhere in the string. A header value of `Basic Bearer actualtoken` would split into `["Basic ", " actualtoken"]` and return `actualtoken`. A header value like `Bearer Bearer token` would split into `["", " Bearer token"]` and return `" Bearer token"` -> `TrimSpace` -> `"Bearer token"` which is not a valid JWT.

More specifically: the check is not `strings.HasPrefix(h, "Bearer ")` (with space). This means the Bearer prefix can appear anywhere in the Authorization header value.

**Attack input**: `Authorization: Bearer Bearer <real_jwt>` — split produces `["", " Bearer <real_jwt>"]` -> `TrimSpace("Bearer <real_jwt>")` = `"Bearer <real_jwt>"` which would fail JWT parse (not a valid JWT). This specific case does not enable exploitation.

However: `Authorization: <something_containing_Bearer> <real_jwt>` might allow the v2Token generator to process a request that was intended to be processed by a different generator (e.g., if the request also has BasicAuth set). In practice the RFC says `Authorization: Bearer <token>` — but Harbor's split is lenient.

**More relevant**: if a request has `Authorization: Basic base64_creds_with_Bearer_embedded`, `bearerToken` would extract garbage. This would cause `v2Token.Generate` to attempt JWT parsing on garbage and fail, returning nil. Not exploitable directly.

**Assessment**: This is an architectural weakness (non-strict parsing) but not directly exploitable in the current code flow given how generators are ordered. The v2Token generator returns nil on JWT parse failure, falling through to subsequent generators.

**Severity estimate**: LOW

**Status**: NEEDS-DEEPER — the non-strict split could have subtle ordering interactions; not immediately exploitable.
