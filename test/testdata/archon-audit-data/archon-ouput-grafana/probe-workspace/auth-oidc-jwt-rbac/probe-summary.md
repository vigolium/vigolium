# Deep Probe Summary: Authentication, OIDC/OAuth, JWT, and RBAC

**Status**: complete
**Rounds**: 5
**Total hypotheses generated**: 25
**Validated**: 17
**Stop reason**: 5 rounds completed

## Attack Surface Map Reference
`security/probe-workspace/auth-oidc-jwt-rbac/attack-surface-map.md`

## Validated Hypotheses

### PH-01: JWT tokens without `exp` claim accepted as never-expiring
- **Input path**: `pkg/services/auth/jwt/validation.go:55-117` -- `validateClaims` -- when `exp` key absent from claims map
- **Assumption broken**: The code does not require the `exp` claim in JWT tokens. If absent, `registeredClaims.Expiry` stays nil, and go-jose v4 `Validate()` skips expiry check entirely (validation.go:116).
- **Attack input**: JWT token with valid signature but NO `exp` claim in payload
- **Code path**: `authn/clients/jwt.go:66` -> `auth/jwt/auth.go:69` -> `validation.go:55-121` -> `go-jose/v4/jwt/validation.go:116` (skipped when Expiry nil)
- **Sanitizers on path**: None -- no code in Grafana requires exp to be present
- **Security consequence**: Stolen or compromised JWT tokens without exp claim are valid FOREVER. There is no mechanism to force expiry.
- **Severity estimate**: HIGH
- **Evidence file**: `round-1-evidence.md`

### PH-03: JWT `exp: null` explicitly bypasses expiry via nil check
- **Input path**: `pkg/services/auth/jwt/validation.go:86-89` -- `if value == nil { continue }`
- **Assumption broken**: The code explicitly handles `exp: null` by continuing (skipping), treating it the same as missing `exp`. A JWT with `{"exp": null}` bypasses all temporal validation.
- **Attack input**: JWT with `{"exp": null, "nbf": null}` in payload
- **Code path**: `validation.go:87-88` -> `continue` -> `registeredClaims.Expiry` stays nil -> go-jose skips check
- **Sanitizers on path**: None
- **Security consequence**: Attacker crafting JWTs can explicitly include `exp: null` and `nbf: null` to create never-expiring tokens that bypass all temporal validation while still including all other required claims (iss, aud, sub).
- **Severity estimate**: HIGH
- **Evidence file**: `round-1-evidence.md`

### PH-02: JWT tokens without `nbf` claim bypass not-before validation
- **Input path**: `pkg/services/auth/jwt/validation.go:96-99` -- same nil/missing pattern as exp
- **Assumption broken**: `nbf` validation skipped when claim missing or nil
- **Attack input**: JWT with future `iat` but no `nbf` claim
- **Code path**: Same as PH-01/PH-03 pattern
- **Sanitizers on path**: None
- **Security consequence**: Token timing validation can be entirely bypassed by omitting temporal claims
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`

### PH-05: `/api/gnet/*` proxy accessible to anonymous users
- **Input path**: `pkg/api/api.go:602` -- `r.Any("/api/gnet/*", ..., reqSignedIn, hs.ProxyGnetRequest)`
- **Assumption broken**: Gnet proxy uses `reqSignedIn` without RBAC, allowing anonymous users when anonymous auth enabled
- **Attack input**: Anonymous request to `/api/gnet/api/plugins` when `[auth.anonymous] enabled = true`
- **Code path**: `api.go:602` -> `middleware/auth.go:216` (requireLogin=false when anonymous) -> `grafana_com_proxy.go:52-57` (proxies with server's API token)
- **Sanitizers on path**: None -- no RBAC, no additional auth check
- **Security consequence**: Anonymous users proxy requests through Grafana to grafana.com API using the server's `GrafanaComSSOAPIToken`. Information disclosure about available plugins and potential credential leakage.
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`

### PH-06: `/render/*` endpoint accessible to anonymous users
- **Input path**: `pkg/api/api.go:599` -- `r.Get("/render/*", ..., reqSignedIn, hs.RenderHandler)`
- **Assumption broken**: Render endpoint uses `reqSignedIn` without RBAC
- **Attack input**: Anonymous request to render endpoint when anonymous auth enabled
- **Code path**: `api.go:599` -> auth middleware passes anonymous -> `render.go:18` RenderHandler
- **Sanitizers on path**: Render service requires renderer to be configured and running
- **Security consequence**: Anonymous users can trigger server-side rendering (CPU/memory DoS vector)
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`

### PH-07: OAuth `sub` claim not required by default
- **Input path**: `pkg/services/authn/clients/oauth.go:189-195` -- sub claim check gated by feature flag
- **Assumption broken**: OAuth authentication proceeds without a stable identity anchor when `FlagOauthRequireSubClaim` is disabled (default: false)
- **Attack input**: OAuth provider returning token without `sub` claim
- **Code path**: `oauth.go:189` -> `features.IsEnabledGlobally(FlagOauthRequireSubClaim)` returns false -> warning logged, authentication continues
- **Sanitizers on path**: Feature flag `oauthRequireSubClaim` (disabled by default)
- **Security consequence**: Users authenticated without stable `sub` identity. Combined with `oauth_allow_insecure_email_lookup = true`, enables account takeover via email-based lookup.
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`

### PH-09: Generic OAuth ID token signature not verified by default
- **Input path**: `pkg/login/social/connectors/generic_oauth.go:440-454` -- `extractFromIDToken`
- **Assumption broken**: ID token claims are extracted and trusted without any cryptographic signature verification when `validate_id_token = false` (default)
- **Attack input**: Forged/modified ID token from MITM or compromised OAuth provider
- **Code path**: `oauth.go:180` -> `generic_oauth.go:266` -> `extractFromIDToken:440` -> condition `s.info.ValidateIDToken && s.info.JwkSetURL != ""` is false -> `retrieveRawJWTPayload:449` extracts claims via base64 decode only
- **Sanitizers on path**: TLS on token exchange (if configured), `validate_id_token` config option (disabled by default)
- **Security consequence**: ID token claims (email, login, roles, groups) can be forged by MITM attacker or compromised provider. Enables user impersonation and role escalation.
- **Severity estimate**: HIGH
- **Evidence file**: `round-2-evidence.md`

### PH-10: Multiple API endpoints accessible to anonymous without RBAC
- **Input path**: `pkg/api/api.go` -- routes at lines 452, 475, 500, 517 within `reqSignedIn` group
- **Assumption broken**: Several API endpoints within the `reqSignedIn` group lack explicit RBAC `authorize()` calls
- **Attack input**: HTTP requests with no auth when `[auth.anonymous] enabled = true`
- **Code path**: `api.go:560` (reqSignedIn group) -> specific routes without `authorize()` -> handlers execute with anonymous Viewer permissions
- **Sanitizers on path**: `reqSignedIn` (bypassed by anonymous auth); some handlers may have internal permission checks
- **Security consequence**: Information disclosure: `GET /api/frontend/settings/` leaks auth config and feature flags; `GET /api/plugins` enumerates plugins; `GET /api/search/` lists accessible dashboards; `GET /api/dashboards/home` reveals home dashboard content
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-2-evidence.md`

### PH-12: Access token claims extracted without signature verification
- **Input path**: `pkg/login/social/connectors/generic_oauth.go:459-473` -- `extractFromAccessToken`
- **Assumption broken**: Access token claims are NEVER signature-verified (unlike ID tokens which at least have optional verification)
- **Attack input**: Modified OAuth access token in transit
- **Code path**: `generic_oauth.go:276` -> `extractFromAccessToken:459` -> `retrieveRawJWTPayload:468` -> base64 decode only
- **Sanitizers on path**: Server-to-server TLS on token exchange
- **Security consequence**: Access token claims used for user info without verification. Lower risk than ID token since access tokens come from server-to-server exchange.
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-2-evidence.md`

### PH-13: OAuth state hash uses default `secret_key` -- forgeable
- **Input path**: `pkg/services/authn/clients/oauth.go:363-375` -- `genOAuthState` and `hashOAuthState`
- **Assumption broken**: OAuth CSRF protection relies on `secret_key` which defaults to well-known value `SW2YcwTIb9zpOOhoPsMm`
- **Attack input**: Precomputed state hash using default `secret_key` and known `client_secret`
- **Code path**: `oauth.go:279` -> `genOAuthState(c.cfg.SecretKey, oauthCfg.ClientSecret)` -> `SHA256(state + secret + seed)`
- **Sanitizers on path**: None if default key used; client_secret also needed but may be known
- **Security consequence**: OAuth CSRF protection bypassed on instances with default `secret_key`. Enables login CSRF attacks (forcing victim to authenticate with attacker's OAuth account).
- **Severity estimate**: MEDIUM-HIGH
- **Evidence file**: `round-2-evidence.md`

### PH-14: Auth proxy IP whitelist bypassed when empty (default)
- **Input path**: `pkg/services/authn/clients/proxy.go:200-203` -- `isAllowedIP` returns true when whitelist empty
- **Assumption broken**: Empty whitelist means ALL IPs accepted, not NONE
- **Attack input**: Direct request with auth proxy header from any IP
- **Code path**: `proxy.go:79` -> `isAllowedIP` -> `len(c.acceptedIPs) == 0` returns true -> proceeds to authenticate
- **Sanitizers on path**: Auth proxy disabled by default; header must match configured name
- **Security consequence**: When auth proxy enabled without whitelist, any client can impersonate any user by sending the configured header.
- **Severity estimate**: HIGH (when auth proxy enabled without whitelist)
- **Evidence file**: `round-3-evidence.md`

### PH-17: Auth proxy header injection -- full auth bypass
- **Input path**: `pkg/services/authn/clients/proxy.go:250-258` -- `getProxyHeader` reads header without origin validation
- **Assumption broken**: Combined with PH-14, any client can send auth proxy header and authenticate as any user
- **Attack input**: `X-WEBAUTH-USER: admin` header from any IP when auth proxy enabled with empty whitelist
- **Code path**: `proxy.go:83` -> `getProxyHeader` -> reads header -> `proxy.go:105` -> `proxyClient.AuthenticateProxy(ctx, r, username, additional)` -> user created/found by username -> authenticated
- **Sanitizers on path**: Auth proxy must be explicitly enabled; whitelist should be configured
- **Security consequence**: Complete authentication bypass when auth proxy is enabled without IP whitelist.
- **Severity estimate**: CRITICAL (when misconfigured)
- **Evidence file**: `round-3-evidence.md`

### PH-19: Renderer JWT forgery with default secret "-"
- **Input path**: `pkg/services/rendering/auth.go:56-68` -- `getRenderUserFromJWT`
- **Assumption broken**: Default renderer auth token is `"-"` (single character), trivially used as HMAC key
- **Attack input**: JWT signed with HS512 using key `"-"` containing `{"org_id":1, "user_id":1, "org_role":"Admin"}`
- **Code path**: `render.go:37` (`getRenderKey`) -> `auth.go:34` (`GetRenderUser`) -> `auth.go:41` (check `FlagRenderAuthJWT` + `looksLikeJWT`) -> `auth.go:56` (verify with default key)
- **Sanitizers on path**: Feature flag `renderAuthJWT` must be enabled (default: false, preview)
- **Security consequence**: When `renderAuthJWT` flag enabled with default `renderer_token`, any user can forge JWT to authenticate as any user with Admin role via the render key cookie.
- **Severity estimate**: CRITICAL (when feature flag enabled + default token)
- **Evidence file**: `round-4-evidence.md`

## NEEDS-DEEPER (unresolved, for Phase 8 chambers)

### PH-04: reqSignedIn vs reqSignedInNoAnonymous -- systematic audit needed
- **Why unresolved**: Confirmed that many routes use `reqSignedIn` instead of `reqSignedInNoAnonymous`, but the security impact depends on which handlers have internal authorization checks and which don't. A systematic audit of every handler within the `reqSignedIn` groups is needed.
- **Suggested follow-up**: Enumerate every handler in the `reqSignedIn` API groups (lines 292-560, 563-578, 580-596 of api.go) and categorize which lack BOTH `authorize()` middleware AND internal auth checks.

### PH-21: Redirect validation query string handling
- **Why unresolved**: Query string content is not validated in `ValidateRedirectTo`. While this doesn't enable classic open redirect (since it's a relative URL in Location header), edge cases with browser-specific behavior may exist.
- **Suggested follow-up**: Test with various browsers to see if query-string-based protocol smuggling is possible in Location headers with relative URLs.

### PH-23: Authn client priority ordering security implications
- **Why unresolved**: The priority ordering means render client (priority 10) is tested before JWT (20) and session (60). While failed render auth falls through correctly, there may be edge cases where client interaction creates unexpected auth behavior.
- **Suggested follow-up**: Fuzz the auth pipeline with combinations of multiple auth mechanisms in the same request (e.g., render cookie + JWT header + session cookie) to test for unexpected interactions.

## KB Domain Research Used

### OAuth2/OIDC Attack Patterns Applied
- **M1 (claim validation)**: Confirmed generic_oauth default config does not validate aud/iss/sub claims. Sub claim check is behind a feature flag (PH-07).
- **M4 (signature verification)**: Confirmed `validate_id_token = false` by default, meaning ID token signatures are not verified in generic_oauth (PH-09).
- **State CSRF**: Confirmed state parameter protection relies on default `secret_key` (PH-13).

### JWT Attack Patterns Applied
- **M3/M15-M17 (exp enforcement)**: Confirmed JWT exp claim is NOT required -- missing or null exp bypasses temporal validation entirely (PH-01, PH-03).
- **M19 (nbf enforcement)**: Same pattern -- nbf not enforced when missing or null (PH-02).
- **Renderer JWT default secret**: Confirmed default token is `"-"`, trivially forgeable (PH-19).
- **Algorithm confusion**: INVALIDATED -- go-jose v4 correctly validates key-algorithm compatibility.

### Anonymous Auth Bypass Patterns Applied
- **reqSignedIn bypass**: Confirmed multiple endpoints beyond avatar use `reqSignedIn` and are accessible to anonymous users, including gnet proxy, render endpoint, and numerous API routes without RBAC (PH-04, PH-05, PH-06, PH-10).
- **Systematic gap**: Only 7 route definitions use `reqSignedInNoAnonymous`; over 40 use `reqSignedIn`.

### Auth Proxy Attack Patterns Applied
- **Empty whitelist**: Confirmed empty whitelist allows all IPs (PH-14). Combined with header injection (PH-17), creates a complete auth bypass when misconfigured.
