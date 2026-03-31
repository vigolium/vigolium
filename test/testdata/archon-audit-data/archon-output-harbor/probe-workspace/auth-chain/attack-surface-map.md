# Attack Surface Map: auth-chain

## Entry Points

- `src/server/middleware/security/security.go:56` — `Middleware` / generator chain — Accepts every HTTP request; iterates generators in priority order; first match sets security context
- `src/server/middleware/security/secret.go:29` — `secret.Generate` — Reads `Authorization: Harbor-Secret <val>` header; any request to any path
- `src/server/middleware/security/oidc_cli.go:48` — `oidcCli.Generate` — Accepts HTTP Basic Auth on `/v2/*`, `/service/token`, selected `/api/v2.0/*` paths when auth mode is OIDC
- `src/server/middleware/security/v2_token.go:44` — `v2Token.Generate` — Accepts Bearer token on any `/v2/*` path; parses JWT RS256 claims
- `src/server/middleware/security/idtoken.go:33` — `idToken.Generate` — Accepts Bearer token (OIDC ID token) on `/api/*` and `/service/token` paths when auth mode is OIDC
- `src/server/middleware/security/auth_proxy.go:35` — `authProxy.Generate` — Accepts HTTP Basic Auth on `/v2/*` when auth mode is HTTPAuth; username must match `AuthProxyUserNamePrefix`
- `src/server/middleware/security/robot.go:33` — `robot.Generate` — Accepts HTTP Basic Auth where username starts with configured robot prefix
- `src/server/middleware/security/basic_auth.go:60` — `basicAuth.Generate` — Accepts HTTP Basic Auth on any path; delegates to `auth.Login`
- `src/server/middleware/security/session.go` — `session.Generate` — Reads session cookie; any path
- `src/core/controllers/oidc.go:68` — `OIDCController.RedirectLogin` — `GET /c/oidc/login?redirect_url=` — reads `redirect_url` query param
- `src/core/controllers/oidc.go:109` — `OIDCController.Callback` — `GET /c/oidc/callback?code=X&state=Y` — reads attacker-controlled `code`, `state`, `error`, `error_description` from query string
- `src/core/controllers/oidc.go:360` — `OIDCController.Onboard` — `POST /c/oidc/onboard` — reads username from JSON body; reads OIDC token from session
- `src/core/auth/authproxy/auth.go:69` — `Auth.Authenticate` — forwards HTTP Basic credentials to configured proxy endpoint; reads response JSON
- `src/server/middleware/v2auth/auth.go:46` — `reqChecker.check` — Authorization gating for all `/v2/*` OCI registry requests
- `src/pkg/token/token.go:63` — `Parse` — Parses and validates JWT; called for v2 bearer tokens
- `src/pkg/oidc/helper.go:191` — `ExchangeToken` — Exchanges OAuth2 authorization code; called from OIDC callback
- `src/pkg/oidc/helper.go:282` — `UserInfoFromToken` — Fetches user info from both ID token and remote userinfo endpoint
- `src/pkg/oidc/helper.go:374` — `userInfoFromClaims` — Extracts username, groups, admin membership from OIDC claims
- `src/pkg/oidc/secret.go:86` — `defaultManager.VerifySecret` — Verifies OIDC CLI secret; decrypts and validates stored token; triggers refresh
- `src/controller/robot/controller.go:99` — `controller.Create` — Creates robot account; generates secret via SHA256(pwd + salt)

## Trust Boundary Crossings

- **TB-1/TB-2 (Internet -> Nginx -> Core)**: Every HTTP request enters `security.Middleware`. Attacker-controlled headers (`Authorization`, `Cookie`, session data) cross directly into the auth chain with no re-validation at TB-2.
- **TB-7 (Core -> OIDC Provider)**: In `OIDCController.Callback`, the `code` parameter is sent directly to the OIDC provider endpoint via `ExchangeToken`. The response (token, claims) is treated as trusted after signature verification only.
- **TB-7 (Core -> Auth Proxy)**: In `authProxy.Generate` and `Auth.Authenticate`, user-supplied Basic Auth credentials are forwarded to an admin-configured external HTTP endpoint. The endpoint response (including session ID and user attributes) is fully trusted.
- **TB-4 (Core -> Redis, session)**: The OIDC callback stores raw token bytes (`tokenBytes`) and user info JSON (`ouDataStr`) directly in the Redis-backed session. The `Onboard` flow reads these back and trusts them entirely without re-validation.
- **TB-6 (Core -> Registry)**: The v2auth middleware (`reqChecker.check`) consumes the security context set by `v2Token.Generate` which has already parsed and validated the JWT. Registry decisions are fully delegated to this security context.
- **TB-2 (Nginx -> Core) - Secret header**: The internal shared secret used by `secret.Generate` arrives as an HTTP header (`Authorization: Harbor-Secret`). If Nginx does not strip this header from external requests, external clients can inject it.

## Auth / AuthZ Decision Points

- `src/server/middleware/security/security.go:56-62` — generator loop — decides which identity type is assigned to the request context; first match wins; wrong ordering = wrong identity
- `src/server/middleware/security/v2_token.go:65-66` — `jwt.NewValidator` — validates JWT expiry and audience for v2 bearer tokens; uses `common.JwtLeeway`
- `src/server/middleware/security/v2_token.go:75-77` — `tokenIssuedAfterProjectCreation` — decides whether a valid JWT is still acceptable after project deletion/recreation
- `src/server/middleware/security/auth_proxy.go:63` — username vs tokenReviewStatus username comparison — decides whether the username in Basic Auth matches the token review result
- `src/server/middleware/security/oidc_cli.go:72` — `oidc.VerifySecret` — decides if OIDC CLI secret matches stored encrypted secret
- `src/server/middleware/security/robot.go:57` — `utils.Encrypt(secret, robot.Salt, utils.SHA256)` comparison — authenticates robot account
- `src/server/middleware/security/robot.go:61-68` — disabled and expiry checks — decides if robot account is active
- `src/server/middleware/security/idtoken.go:46` — `oidc.VerifyToken` — verifies OIDC ID token signature and expiry
- `src/core/auth/authenticator.go:142` — `IsSuperUser` check — forces DBAuth mode for the admin user regardless of configured auth mode
- `src/core/auth/authenticator.go:151` — `lock.IsLocked` — account lockout check
- `src/server/middleware/v2auth/auth.go:56-78` — `reqChecker.check` — full OCI registry RBAC authorization for all `/v2/*` requests
- `src/core/controllers/oidc.go:110` — state comparison — validates OIDC callback state against session-stored state
- `src/pkg/oidc/helper.go:301-303` — subject mismatch check — validates that subject from userinfo endpoint matches subject from ID token

## Validation / Sanitization Functions

- `src/server/middleware/security/oidc_cli.go:58` — `o.valid(req)` — restricts OIDC CLI auth to a specific whitelist of paths/methods; regex-based path matching
- `src/server/middleware/security/auth_proxy.go:48` — `matchAuthProxyUserName` — checks that username starts with `common.AuthProxyUserNamePrefix`; strips the prefix
- `src/server/middleware/security/robot.go:39` — `strings.HasPrefix(name, config.RobotPrefix)` — checks robot account prefix
- `src/core/controllers/oidc.go:82` — `utils.IsLocalPath(redirectURL)` — validates `redirect_url` is a local path before storing in session
- `src/core/controllers/oidc.go:367-373` — `utils.IsIllegalLength` and `strings.ContainsAny` — validates username in onboard request
- `src/pkg/oidc/helper.go:459-475` — `filterGroup` — regex filter applied to OIDC group names before DB population
- `src/pkg/oidc/helper.go:301-303` — subject binding check — prevents token substitution between OIDC users
- `src/pkg/token/token.go:68` — `jwt.WithValidMethods` — restricts JWT signing algorithms to configured method only (prevents alg confusion)
- `src/controller/robot/controller.go:434` — `IsValidSec` — enforces minimum strength requirements on robot secrets

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| Nginx (TB-1/TB-2) | Security Middleware | All external headers are legitimate; internal `Harbor-Secret` header is not forged by external clients | PARTIAL | Nginx config must strip `Authorization: Harbor-Secret` from external requests — no code-level enforcement; if misconfigured, external callers get full internal trust |
| Security Middleware | Handler/Controller | Security context is set and corresponds to the correct identity type for the request path | PARTIAL | `UnauthorizedMiddleware` assigns anonymous context if no generator matches — handlers must explicitly check `RequireAuthenticated`; missing check = anonymous access |
| OIDC Callback state check | Token Exchange | State in URL matches state stored in session, binding the callback to the original auth initiation | YES for web flow | PKCE code in session can be empty string (line 133: cast may produce empty string if key missing) — `pkce.Code("")` may produce no verifier, effectively disabling PKCE |
| ID Token Verification | User Lookup | ID token signature is valid and token was issued for this Harbor instance | YES (coreos/go-oidc verifies) | `parseIDToken` (called from `UserInfoFromIDToken`) uses `SkipClientIDCheck: true, SkipExpiryCheck: true` — bypasses audience and expiry checks when processing tokens stored in DB |
| OIDC UserInfo Merge | Group/Admin Assignment | Remote userinfo subject matches local ID token subject | YES (explicit check at line 301-303) | When remote userinfo fails (network error), fallback to ID token data occurs silently — groups/admin from stale ID token used |
| Auth Proxy Token Review | User Onboard | Token review endpoint returns authoritative identity; username in Basic Auth matches review result | PARTIAL | `SkipSearch` mode in authproxy: if enabled, user is accepted with the provided username without verification against any directory; `SearchUser` returns a stub user |
| v2 Bearer Token | Registry RBAC | Token was issued after current project creation (tokenIssuedAfterProjectCreation) | PARTIAL | Check is skipped entirely when `info.ProjectName == ""` (line 85-87); attacker-controlled URL paths that produce empty project name from `lib.GetArtifactInfo` bypass the project-creation timestamp check |
| Basic Auth | Auth Mode Dispatch | Auth mode at login matches current system auth mode | PARTIAL | `IsSuperUser` check (line 142) forces DBAuth for admin username regardless of configured mode — if LDAP/OIDC is configured and admin username is known, DB credentials are used, potentially enabling brute force even when LDAP mode is intended |
| Robot Secret Verification | Robot Context | Robot account is identified uniquely by name prefix lookup | PARTIAL | Robot list query uses `strings.TrimPrefix(name, config.RobotPrefix)` — if robot prefix is empty string (misconfigured), all usernames match the prefix check, causing the entire robot table to be queried |
| Session Generator | Session Context | Session data was populated by Harbor and not externally manipulated | DEPENDS | Redis session store — if Redis is unauthenticated (common deployment), session data can be injected/replayed from the network layer |

## Trust Chain Gaps

1. **Nginx secret header stripping (Gap: External Secret Injection)**: The `secret.Generate` checks only if the header value is non-empty and present in `config.SecretStore`. There is no code-level proof that Nginx strips the `Authorization: Harbor-Secret` header from external requests. A misconfigured Nginx (or direct internal network access) would allow any caller to forge full-trust internal identity.

2. **PKCE disabled silently on empty code (Gap: PKCE Bypass)**: In `OIDCController.Callback` at line 133, `pkceCode, _ := oc.GetSession(pkceCodeKey).(string)` — if the session key is missing or holds a non-string type, the cast silently produces `""`. Then `ExchangeToken` receives `pkce.Code("")`, and `pkceCode.Verifier()` is only appended if `len(pkceCode) > 0` (helper.go line 204). If the PKCE code is absent from session (e.g., session fixation attack that clears specific keys), PKCE verification is silently skipped.

3. **parseIDToken skips expiry and audience (Gap: Stale/Cross-Audience Token)**: `parseIDToken` is called from `UserInfoFromIDToken` (helper.go:366) with `SkipExpiryCheck: true` and `SkipClientIDCheck: true`. This is used when processing tokens stored in the DB for CLI secret verification (`secret.go:134`). A revoked or expired OIDC token stored in DB can still be used to extract user info and grant access.

4. **tokenIssuedAfterProjectCreation bypassed on empty ProjectName (Gap: Token Timestamp Check Skip)**: `v2_token.go:85-87` — the function returns `true` immediately when `info.ProjectName == ""`. The `ArtifactInfo` is populated by a separate middleware earlier in the chain. Requests to `/v2/` base endpoint or paths where `ArtifactInfo` is not populated will skip the project-creation-time check, potentially allowing stale tokens to authenticate.

5. **Auth mode switching / superuser forces DBAuth (Gap: LDAP/OIDC Bypass for Admin)**: `authenticator.go:142` — when `IsSuperUser` returns true, the auth mode is forced to `common.DBAuth` regardless of configured system auth mode. This means even in OIDC-only or LDAP-only deployments, the admin account (user ID == 1) is always authenticated against the local DB, enabling credential-stuffing or brute-force against the DB credential even when external auth is configured.

6. **Redis session as unauthenticated trust boundary (Gap: Session Data Injection)**: The session generator and OIDC flow store sensitive data (OIDC tokens, user info JSON) in Redis without application-level integrity protection. In default Harbor deployments, Redis has no password. An attacker with network access to Redis can inject or modify session data to hijack authenticated sessions or forge OIDC user info.

7. **Auth proxy SkipSearch mode (Gap: Unauthenticated User Acceptance)**: When `SkipSearch` is true in auth proxy configuration, `SearchUser` returns a stub user model for any provided username without any lookup. The `PostAuthenticate` flow will then onboard this user into Harbor. Combined with a misconfigured token review endpoint, this could allow arbitrary username injection.
