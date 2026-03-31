# Round 1 Evidence: JWT exp/nbf bypass, Anonymous auth scope, OAuth claim gaps

## PH-01: JWT tokens without `exp` claim accepted as never-expiring -- VALIDATED

**Evidence:**
1. `pkg/services/auth/jwt/validation.go:55-117`: The `validateClaims` function iterates over claims map. If the `exp` key is simply absent from the JWT payload, the for-loop never enters the `case "exp"` branch. Thus `registeredClaims.Expiry` remains `nil`.
2. `go-jose/v4@v4.1.3/jwt/validation.go:116`: `if c.Expiry != nil && ...` -- when `Expiry` is nil, validation is SKIPPED entirely.
3. The `expectRegistered` struct (from config) does NOT set any `Expiry` expectation -- it only sets Issuer/Subject/AnyAudience from `ExpectClaims` config.
4. There is no code anywhere in Grafana that requires the `exp` claim to be present.

**Code path:**
- `pkg/services/authn/clients/jwt.go:66` -> `s.jwtService.Verify(ctx, jwtToken)` -> `pkg/services/auth/jwt/auth.go:69` -> `s.validateClaims(claims)` -> `pkg/services/auth/jwt/validation.go:55`
- Claims map without `exp` key -> `registeredClaims.Expiry` stays nil -> `registeredClaims.Validate(expectRegistered)` -> go-jose skips expiry check -> PASSES

**Security consequence:** An attacker who obtains a JWT signing key (or a JWT is stolen) can use the token indefinitely. A stolen JWT with no `exp` claim never expires.
**Severity:** HIGH

## PH-02: JWT tokens without `nbf` claim bypass not-before validation -- VALIDATED

**Evidence:**
1. Same mechanism as PH-01. If `nbf` key absent from claims, `registeredClaims.NotBefore` stays nil.
2. `go-jose/v4@v4.1.3/jwt/validation.go:112`: `if c.NotBefore != nil && ...` -- skipped when nil.
3. Lower severity since `nbf` bypass alone doesn't grant access, but combined with PH-01 allows tokens valid at any time.

**Security consequence:** Token timing validation can be entirely bypassed by omitting temporal claims.
**Severity:** MEDIUM

## PH-03: JWT `exp: null` explicitly bypasses expiry via nil check -- VALIDATED

**Evidence:**
1. `pkg/services/auth/jwt/validation.go:86-89`:
   ```go
   case "exp":
       if value == nil {
           continue
       }
   ```
   When JSON payload contains `"exp": null`, JSON unmarshaling produces `claims["exp"] = nil`. The explicit nil check causes the code to `continue`, leaving `registeredClaims.Expiry` as nil.
2. This is DISTINCT from PH-01 (missing exp) -- here `exp` IS present in the claims but set to `null`.
3. Same bypass applies to `nbf: null` (line 97-98) and `iat: null` (line 107-108).

**Security consequence:** Even a JWT that explicitly includes temporal claims can bypass them by setting values to `null`. This means an attacker forging JWTs can craft tokens that pass all other validation (iss, aud, sub, custom claims) but never expire.
**Severity:** HIGH

## PH-04: Multiple endpoint groups use `reqSignedIn` allowing anonymous access -- VALIDATED (with RBAC caveat)

**Evidence:**
1. `pkg/api/api.go:560`: The main `/api` route group (containing annotations, live, frontend-metrics, etc.) uses `reqSignedIn` not `reqSignedInNoAnonymous`.
2. `pkg/api/api.go:578`: The `/api/admin` route group (settings, stats, provisioning reload) uses `reqSignedIn`.
3. `pkg/api/api.go:596`: The `/api/admin/users` route group uses `reqSignedIn`.
4. When `[auth.anonymous] enabled = true`, `middleware/auth.go:216`: `requireLogin := !c.AllowAnonymous || ...` evaluates to `false`, so anonymous users pass the auth middleware.
5. **RBAC caveat**: Most of these routes have RBAC `authorize()` middleware AFTER `reqSignedIn`. The RBAC middleware at `pkg/services/accesscontrol/middleware.go:37-48` also has anonymous handling but still evaluates permissions. Anonymous users typically get Viewer role, which may not have admin permissions.
6. However, routes WITHOUT explicit RBAC (e.g., `apiRoute.Post("/frontend-metrics", routing.Wrap(hs.PostFrontendMetrics))` at line 541) are fully accessible.

**Security consequence:** When anonymous auth is enabled, unauthenticated users can access endpoints in the `/api` group that lack explicit RBAC middleware. For RBAC-protected endpoints, the anonymous user's Viewer-level permissions are evaluated.
**Severity:** MEDIUM (depends on which endpoints lack RBAC within the group)

## PH-05: `/api/gnet/*` proxy accessible to anonymous users -- VALIDATED

**Evidence:**
1. `pkg/api/api.go:602`: `r.Any("/api/gnet/*", ..., reqSignedIn, hs.ProxyGnetRequest)` -- uses `reqSignedIn`, no RBAC.
2. `pkg/api/grafana_com_proxy.go:52-57`: `ProxyGnetRequest` proxies to `hs.Cfg.GrafanaComAPIURL` using the server's API token.
3. No additional auth checks inside the handler.
4. When anonymous auth enabled, unauthenticated users can make requests proxied to grafana.com API through the Grafana instance.

**Security consequence:** Anonymous users can use Grafana as a proxy to grafana.com API, potentially accessing plugin catalog, etc. The server's `GrafanaComSSOAPIToken` is injected into requests, so anonymous users effectively use the server's grafana.com credentials.
**Severity:** MEDIUM (leaks server's grafana.com API token usage to anonymous users)

## PH-06: `/render/*` endpoint accessible to anonymous users -- VALIDATED (with practical limitation)

**Evidence:**
1. `pkg/api/api.go:599`: `r.Get("/render/*", ..., reqSignedIn, hs.RenderHandler)` -- uses `reqSignedIn`, no RBAC.
2. `pkg/api/render.go:18`: `RenderHandler` checks `c.SignedInUser` for user context but does not explicitly reject anonymous.
3. The rendering process requires a functioning image renderer service and creates a render key tied to the user context.
4. Practical limitation: Anonymous rendering would use the anonymous user's limited permissions.

**Security consequence:** When anonymous auth enabled, unauthenticated users can trigger server-side rendering, consuming server resources. This is a DoS vector similar to the avatar bypass.
**Severity:** MEDIUM

## PH-07: OAuth `sub` claim not required by default -- VALIDATED

**Evidence:**
1. `pkg/services/authn/clients/oauth.go:189-195`:
   ```go
   if userInfo.Id == "" {
       if c.features.IsEnabledGlobally(featuremgmt.FlagOauthRequireSubClaim) {
           return nil, errOAuthUserInfo.Errorf("missing required sub claims")
       } else {
           c.log.Warn("Missing sub claim...")
       }
   }
   ```
2. `pkg/services/featuremgmt/toggles_gen.csv:115`: `oauthRequireSubClaim` defaults to `false`.
3. Without a `sub` claim, the user identity may rely solely on email, which is less stable and could lead to account confusion if the IdP changes email mappings.

**Security consequence:** OAuth providers returning tokens without `sub` claim are accepted. Combined with `oauth_allow_insecure_email_lookup = true`, this could enable account takeover via email-based lookup without a stable identity anchor.
**Severity:** MEDIUM (requires configuration combination)

## PH-08: RBAC scope injection via Go template -- INVALIDATED

**Evidence:**
1. `pkg/services/accesscontrol/scope.go:89-91`: `Parameter(":id")` generates `{{ index .URLParams ":id" }}` -- this is the TEMPLATE string.
2. `pkg/services/accesscontrol/middleware.go:409-421`: The template is the scope definition from code (e.g., `users:id:{{ index .URLParams ":id" }}`). URL params are passed as DATA to `tmpl.Execute(&buf, params)`.
3. User-controlled URL params flow into `params.URLParams` map, which is accessed via `{{ index .URLParams ... }}` template action. The URL param VALUES are never interpreted as template syntax.
4. The template string itself comes from hardcoded `Parameter()` calls in route definitions, not from user input.

**Conclusion:** SAFE. The template pattern correctly separates template logic from user data. URL params are data values, not template code.
**Severity:** N/A
