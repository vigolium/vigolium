# Round 3 Evidence

## PH-14: Auth proxy IP whitelist bypassed if empty -- VALIDATED (by design, but dangerous)

**Evidence:**
1. `pkg/services/authn/clients/proxy.go:200-203`:
   ```go
   func (c *Proxy) isAllowedIP(r *authn.Request) bool {
       if len(c.acceptedIPs) == 0 {
           return true
       }
   ```
2. `pkg/services/authn/clients/proxy.go:220-223`: `parseAcceptList` returns nil when whitelist string is empty
3. Default auth proxy whitelist is empty string
4. Auth proxy is disabled by default (`AuthProxy.Enabled = false`), so this only matters when auth proxy is explicitly enabled
5. When enabled with empty whitelist, ANY client IP can send the auth proxy header and authenticate as any user

**Security consequence:** If admin enables auth proxy but forgets to set the IP whitelist, any network client can impersonate any user by sending the configured header (default: `X-WEBAUTH-USER`). This is documented behavior but a dangerous default.
**Severity:** HIGH (when auth proxy enabled without whitelist -- misconfiguration risk)

## PH-15: RBAC evaluator with zero scopes grants action-wide access -- VALIDATED (by design)

**Evidence:**
1. `pkg/services/accesscontrol/evaluator.go:46-48`:
   ```go
   if len(p.Scopes) == 0 {
       return true
   }
   ```
2. When `EvalPermission(action)` is called without scope arguments, the user only needs to have the action permission -- it matches regardless of which specific resources the user has the action on.
3. This is by design for action-level permissions (e.g., `ActionAnnotationsRead` without a specific annotation ID)
4. However, route definitions that SHOULD be scoped but aren't will grant access to ALL resources of that type. The KB notes this as a pattern to audit.

**Security consequence:** Routes using unscoped `EvalPermission` grant access to all resources of that type. This is correct for list/search operations but would be a vulnerability if used for write/delete operations that should be resource-scoped.
**Severity:** LOW (by design, but a correctness risk in route definitions)

## PH-16: ExtJWT RenderService type gets Admin role -- VALIDATED (by design)

**Evidence:**
1. `pkg/services/authn/clients/ext_jwt.go:184-190`:
   ```go
   if t == claims.TypeRenderService {
       identity.OrgRoles = map[int64]org.RoleType{
           s.cfg.DefaultOrgID(): org.RoleAdmin,
       }
   ```
2. Same pattern at ext_jwt.go:320-324 for OBO path
3. Also in `render.go:44-57` for the render client
4. ExtJWT validation does verify the token signature via `accessTokenVerifier.Verify`, and the token must have the correct namespace
5. The risk is limited because creating a valid ExtJWT requires the signing key from the JWKS endpoint

**Security consequence:** Any valid ExtJWT token with a `render` subject type automatically gets Admin-level access. If the JWKS signing key is compromised, attacker can get Admin access by crafting a token with render type.
**Severity:** LOW (requires JWKS key compromise, which is already a critical compromise)

## PH-17: Auth proxy header injection -- VALIDATED (when enabled without proper setup)

**Evidence:**
1. `pkg/services/authn/clients/proxy.go:250-258`: `getProxyHeader` simply reads `r.HTTPRequest.Header.Get(headerName)` -- no validation of header origin
2. `proxy.go:148-149`: `Test()` returns true if the proxy header is present in the request
3. Priority is 50 (`proxy.go:152-154`), which is lower than session (60) but comes before anonymous
4. If auth proxy is enabled, ANY request with the proxy header name will trigger proxy auth BEFORE falling through to other clients
5. The critical protection is the IP whitelist (`isAllowedIP`), which as shown in PH-14 accepts all IPs when empty

**Security consequence:** When auth proxy is enabled with empty whitelist, any client can send `X-WEBAUTH-USER: admin` header to authenticate as the admin user. This is a complete authentication bypass.
**Severity:** CRITICAL (when auth proxy enabled without whitelist -- full auth bypass)

## PH-18: Session token not bound to IP or user-agent -- VALIDATED (known limitation)

**Evidence:**
1. `pkg/services/authn/clients/session.go:46-74`: Session authentication only validates the session token via `LookupToken` -- no IP or UA binding
2. `pkg/services/auth/authimpl/auth_token.go`: Token service records IP and UA at creation but doesn't verify them at lookup
3. This is standard behavior for web applications (binding to IP breaks mobile users, users behind rotating proxies, etc.)
4. Grafana does have token rotation (`NeedsRotation` at session.go:62) which limits the window of stolen session reuse

**Security consequence:** Stolen session cookies can be replayed from any IP/UA. This is a standard limitation mitigated by token rotation, secure cookie flags, and HTTPS.
**Severity:** LOW (standard web app behavior, mitigated by other controls)
