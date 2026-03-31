# Round 5 Evidence

## PH-23: Render client high priority allows preempting other auth -- NEEDS-DEEPER

**Evidence:**
1. Priority order: Provisioning(5) -> Render(10) -> ExtJWT(15) -> JWT(20) -> APIKey(30) -> Basic(40) -> Proxy(50) -> Session(60)
2. `pkg/services/authn/clients/render.go:73-78`: `Test()` returns true if `renderKey` cookie is present (any non-empty value)
3. `pkg/services/authn/authnimpl/service.go:118-131`: If a client's `Test()` returns true and `Authenticate()` fails, the error is joined (`authErr = errors.Join(authErr, err)`) and the loop continues to the next client
4. So if an attacker sets a renderKey cookie with an invalid value, render auth fails but falls through to the next client (ExtJWT, JWT, etc.)
5. The render client failure doesn't block subsequent auth attempts -- this is safe behavior

**Security consequence:** No security issue. The priority ordering and fallthrough behavior are correct -- failed render auth does not block valid JWT/session auth.
**Severity:** N/A (correct behavior confirmed)

## PH-24: JWT Test() using UnsafeClaimsWithoutVerification -- VALIDATED (minor)

**Evidence:**
1. `pkg/services/auth/jwt/auth.go:110-123`: `HasSubClaim` uses `parsed.UnsafeClaimsWithoutVerification(&claims)` to check if `sub` is present without verifying signature
2. This is used in `pkg/services/authn/clients/jwt.go:188`: `if !authJWT.HasSubClaim(jwtToken) { return false }` -- determines whether JWT client handles this token
3. If a JWT without `sub` claim is sent, the JWT client's `Test()` returns false and auth falls through to API key, basic auth, etc.
4. An attacker could craft a JWT-like token without `sub` to avoid JWT validation and potentially match a different auth client
5. However, to match another client, the request would need the appropriate credentials (API key, basic auth, etc.) -- the JWT-like token itself wouldn't authenticate via other clients

**Security consequence:** Minor design concern -- the JWT client probes claims without verification to decide if it should handle the token. The fallthrough does not create an exploitable bypass since other clients validate their own credentials independently.
**Severity:** LOW (defense-in-depth improvement opportunity)

## PH-25: RBAC permission sync timing gap -- VALIDATED (known limitation)

**Evidence:**
1. `pkg/services/authn/authnimpl/sync/rbac_sync.go:47-61`: `SyncPermissionsHook` is called as a post-auth hook during authentication
2. Permissions are fetched fresh on each authentication (not cached between requests)
3. However, session-based auth (`Session.Authenticate`) does NOT trigger a full re-sync on every request -- it relies on the permissions cached in the session
4. `pkg/services/authn/clients/session.go:70-72`: `SyncPermissions: true` is set, which means permissions ARE synced on each request via the post-auth hook
5. The sync fetches from the database/store, which reflects the latest role assignments
6. There could be a small window between a role change and the next request where stale permissions are used (within the same request processing)

**Security consequence:** Permissions are synced per-request via post-auth hooks. The timing window is minimal (single request duration). This is standard RBAC behavior.
**Severity:** LOW (minimal timing window, standard behavior)
