# Attack Surface Map: Authentication, OIDC/OAuth, JWT, and RBAC

## Entry Points

### HTTP Endpoints (Login/OAuth)
- `pkg/api/api.go:92` -- `GET /` -- `reqSignedIn` -- Index page, bypassed by anonymous auth
- `pkg/api/api.go:605` -- `GET /avatar/:hash` -- `reqSignedIn` -- Avatar proxy, CONFIRMED anon bypass (CVE-2026-21720)
- `pkg/api/login.go:242` -- `POST /login` -- `LoginPost` -- Form-based login (credential brute-force)
- `pkg/api/login.go:97` -- `GET /login` -- `LoginView` -- Login view with auto-login redirect
- `pkg/api/login.go:256` -- `POST /login/passwordless` -- `LoginPasswordless` -- Passwordless login
- `pkg/api/login.go:268` -- `GET /login/passwordless` -- `StartPasswordless` -- Start passwordless flow
- `pkg/api/login.go:301` -- `GET /logout` -- `Logout` -- Logout handler with SAML/OAuth redirect

### HTTP Endpoints (OAuth/OIDC Callback)
- `pkg/services/authn/clients/oauth.go:105` -- `OAuth.Authenticate` -- OAuth2 code exchange callback
- `pkg/services/authn/clients/oauth.go:253` -- `OAuth.RedirectURL` -- OAuth2 redirect URL generation

### HTTP Headers (JWT/ExtJWT)
- `pkg/services/authn/clients/jwt.go:167-173` -- `JWT.retrieveToken` -- `Authorization` header (configurable via `HeaderName`) or `auth_token` query param
- `pkg/services/authn/clients/ext_jwt.go:363-368` -- `ExtendedJWT.retrieveAuthenticationToken` -- `X-Access-Token` header
- `pkg/services/authn/clients/ext_jwt.go:371-376` -- `ExtendedJWT.retrieveAuthorizationToken` -- `X-Grafana-Id` header

### HTTP Headers (Auth Proxy)
- `pkg/services/authn/clients/proxy.go:76` -- `Proxy.Authenticate` -- Configurable header (e.g., `X-WEBAUTH-USER`)

### HTTP Cookies
- `pkg/services/authn/clients/session.go` -- `Session.Authenticate` -- `grafana_session` cookie
- `pkg/services/authn/clients/render.go:84-90` -- `Render.getRenderKey` -- `renderKey` cookie
- `pkg/services/authn/clients/oauth.go:117-131` -- OAuth state cookie `oauth_state`, PKCE cookie `oauth_code_verifier`

### API Key / Basic Auth
- `pkg/services/authn/clients/api_key.go` -- `APIKey.Authenticate` -- `Authorization: Bearer <key>` header
- `pkg/services/authn/clients/basic.go` -- `Basic.Authenticate` -- `Authorization: Basic <b64>` header

### Routes Using `reqSignedIn` (Vulnerable to Anonymous Bypass)
When `[auth.anonymous] enabled = true`, ALL these routes become accessible without real auth:
- `pkg/api/api.go:111` -- `GET /dashboard/import/`
- `pkg/api/api.go:151` -- `GET /styleguide`
- `pkg/api/api.go:173-174` -- `GET /a/:id/*` -- App plugin pages
- `pkg/api/api.go:176-190` -- `GET /d/:uid/*`, `GET /dashboard/*`, `GET /dashboards/*` -- Dashboard views
- `pkg/api/api.go:218-228` -- `GET /playlists/*`, `GET /alerting/*`, `GET /monitoring/*`
- `pkg/api/api.go:262` -- `GET /dashboard/snapshots/`
- `pkg/api/api.go:524` -- `GET /alert-notifiers`
- `pkg/api/api.go:560-596` -- Multiple API route groups using `reqSignedIn`
- `pkg/api/api.go:599` -- `GET /render/*` -- Render handler
- `pkg/api/api.go:602` -- `GET /api/gnet/*` -- Gnet proxy
- `pkg/api/api.go:605` -- `GET /avatar/:hash` -- Avatar (CONFIRMED issue)
- `pkg/api/api.go:608` -- `GET /api/snapshot/shared-options/`

### Routes Using `reqSignedInNoAnonymous` (Properly Protected)
Only these routes explicitly block anonymous:
- `pkg/api/api.go:93-94` -- `GET /profile/`, `GET /profile/password`
- `pkg/api/api.go:96` -- `GET /profile/switch-org/:id`
- `pkg/api/api.go:239-240` -- Email update/verify endpoints
- `pkg/api/api.go:317` -- User-related API routes group

## Trust Boundary Crossings

1. **Internet -> Grafana HTTP Server** (TB-2): All HTTP requests cross this boundary
2. **IdP -> Grafana** (TB-IdP): OAuth2 tokens/codes, SAML assertions, OIDC ID tokens -- attacker-controlled if IdP compromised or generic_oauth configured without signature verification
3. **Anonymous -> Authenticated context** (TB-Anon): When anonymous auth enabled, `AllowAnonymous=true` is set on context, `requireLogin` becomes false, enabling access to `reqSignedIn` routes
4. **RBAC Evaluator** (TB-4): Scope injection via URL params flows into template execution (`text/template`) in `scopeInjector`
5. **ExtJWT Namespace boundary**: ExtJWT tokens carry namespace claims that must match configured namespace; wildcard `*` allowed in access tokens

## Parser / Serialization Functions

- `pkg/services/auth/jwt/auth.go:69-106` -- `AuthService.Verify` -- JWT token parsing with go-jose/v4; accepts EdDSA, HS256-512, RS256/512, ES256-512, PS256-512
- `pkg/services/auth/jwt/auth.go:62-67` -- `sanitizeJWT` -- Strips `=` padding from JWT tokens
- `pkg/services/auth/jwt/validation.go:55-136` -- `validateClaims` -- Validates exp/nbf/iat/iss/sub/aud and custom claims
- `pkg/services/authn/clients/ext_jwt.go:81-110` -- `ExtendedJWT.Authenticate` -- Dual token parsing (access + ID token)
- `pkg/services/authn/clients/oauth.go:127-131` -- OAuth state validation via SHA256 hash comparison
- `pkg/services/authn/clients/jwt.go:59-148` -- `JWT.Authenticate` -- JWT claim extraction for user identity
- `pkg/services/accesscontrol/scope.go:14-28` -- `SplitScope` -- Scope string parsing (colon-delimited)
- `pkg/services/accesscontrol/middleware.go:409-421` -- `scopeInjector` -- Go `text/template` execution on scope strings with URL params

## Auth / AuthZ Decision Points

- `pkg/middleware/auth.go:202-234` -- `Auth()` -- Central auth middleware; decides `requireLogin` based on `AllowAnonymous`, `forceLogin`, `ReqNoAnonymous`
- `pkg/middleware/auth.go:216` -- `requireLogin := !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- THE critical anonymous bypass decision
- `pkg/services/authn/authnimpl/service.go:107-147` -- `Service.Authenticate` -- Iterates client queue, first match wins (priority-ordered)
- `pkg/services/accesscontrol/middleware.go:30-64` -- `Middleware()` -- RBAC middleware; evaluates permission+scope
- `pkg/services/accesscontrol/middleware.go:66-85` -- `authorize()` -- Core RBAC evaluation with scope injection
- `pkg/services/accesscontrol/evaluator.go:40-59` -- `permissionEvaluator.Evaluate` -- Permission matching with wildcard support
- `pkg/services/accesscontrol/evaluator.go:61-80+` -- `match()` -- Scope matching with prefix wildcard
- `pkg/services/accesscontrol/middleware.go:235-276` -- `AuthorizeInOrgMiddleware` -- Cross-org authorization; resolves identity in target org

## Validation / Sanitization Functions

- `pkg/services/auth/jwt/validation.go:12-53` -- `initClaimExpectations` -- Parses expected claims from config (iss/sub/aud)
- `pkg/services/auth/jwt/validation.go:55-136` -- `validateClaims` -- Validates JWT registered claims (exp, nbf, iat, iss, sub, aud); **NOTE: exp=nil and nbf=nil are silently skipped (lines 87-88, 97-98)**
- `pkg/services/authn/clients/oauth.go:189-195` -- OAuth sub claim check -- Only enforced when `FlagOauthRequireSubClaim` feature flag is enabled; otherwise just warns
- `pkg/services/authn/clients/oauth.go:198-204` -- Email required check + email domain allowlist
- `pkg/services/authn/clients/jwt.go:72-75` -- JWT sub claim required check
- `pkg/services/authn/clients/ext_jwt.go:121-129` -- ExtJWT namespace matching
- `pkg/api/login.go:54-82` -- `ValidateRedirectTo` -- Redirect URL validation (blocks absolute URLs, `//`, `..`)
- `pkg/services/accesscontrol/filter.go:38-41` -- `Filter` SQL ID accept list -- prevents SQL injection in RBAC filters
- `pkg/services/accesscontrol/scope.go:46-48` -- `ScopeSuffix` -- Extracts scope identifier (no sanitization)

## KB Domain Research Highlights

### OAuth2/OIDC Attack Patterns
- **M1**: OIDC `aud`, `iss`, `sub` claims NOT enforced on `generic_oauth` by default
- **M4**: `generic_oauth` has no ID token signature verification by default
- **Nonce replay**: Nonce not always enforced in OIDC flows
- **PKCE**: Supported but optional per-provider
- **State CSRF**: Implemented via SHA256(state + secret_key + client_secret)

### JWT Attack Patterns
- **M3/M15-M17**: JWT `exp` enforcement is optional -- `nil` exp values silently skip validation in `validateClaims` (line 87-88)
- **M19**: `nbf` similarly optional -- nil values skipped (line 97-98)
- **Renderer JWT**: Default shared secret is `-` (single dash) -- trivially forgeable
- **HasSubClaim**: Uses `UnsafeClaimsWithoutVerification` but only in `Test()` probe -- not auth-critical
- **Algorithm confusion**: Wide algorithm accept list (EdDSA, HS*, RS*, ES*, PS*) -- potential for key confusion if HMAC key == RSA public key

### RBAC Attack Patterns
- **Scope injection**: `scopeInjector` uses Go `text/template` on URL params -- potential template injection
- **Missing scope**: Unscoped `EvalPermission(action)` grants access to ALL resources of that type
- **Wildcard match**: Scope `dashboards:*` matches all dashboards; `*` matches everything
- **Cache consistency**: Permission cache may not invalidate immediately on role changes

### Anonymous Auth Bypass
- **reqSignedIn vs reqSignedInNoAnonymous**: When anonymous auth enabled, `reqSignedIn` allows anonymous users through
- **Avatar is confirmed**: Only avatar identified so far, but MANY endpoints use `reqSignedIn`
- **Viewer-equivalent access**: Anonymous users get Viewer-level org permissions
