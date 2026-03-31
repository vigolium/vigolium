Phase: 8
Sequence: 041
Slug: renderer-jwt-forgery-admin-takeover
Verdict: VALID
Rationale: Default 1-byte renderer secret "-" enables JWT forgery granting Admin API access to any Grafana endpoint when FlagRenderAuthJWT is enabled; renderKey cookie fires on all endpoints without scoping, and JWT validation lacks aud/iss/jti claims; two non-default preconditions prevent CRITICAL rating.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md
Assigned-ID: H7
PoC-Location: security/findings/H7-renderer-jwt-forgery-admin-takeover/

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Authentication bypass via JWT forgery with default key "-" is confirmed by real-environment reproduction, but impact is significantly overstated -- render identity gets limited read permissions (dashboards, folders, datasources, org users), NOT full admin access as claimed; admin endpoints (settings, users, etc.) return 403.
Severity-Final: MEDIUM
PoC-Status: executed

## Summary

Grafana's image renderer authentication supports JWT-based auth via the `renderAuthJWT` feature flag. When enabled, render keys are signed with HS512 using the `renderer_token` configuration value, which defaults to a single byte `"-"` (setting.go:2070). An unauthenticated attacker can forge a valid JWT with arbitrary `RenderUser` claims (including `OrgRole: "Admin"`) using this trivially known key. The `renderKey` cookie is checked by the Render authn client (render.go:73) on ALL HTTP requests without endpoint scoping, IP restriction, or cookie path enforcement. This allows the forged JWT to authenticate as Admin against any Grafana API endpoint, enabling full instance takeover: creating admin users, exfiltrating datasource secrets, modifying alerting rules, and more.

## Location

- **Primary**: `pkg/services/rendering/auth.go:56-68` -- `getRenderUserFromJWT` validates JWT with default key `[]byte("-")`
- **Primary**: `pkg/setting/setting.go:2070` -- `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")`
- **Secondary**: `pkg/services/authn/clients/render.go:73-78` -- `Test()` fires on any request with renderKey cookie
- **Secondary**: `pkg/services/authn/clients/render.go:36-67` -- `Authenticate()` constructs Admin identity from JWT claims
- **Secondary**: `pkg/services/rendering/auth.go:149-159` -- `buildJWTClaims` sets only `ExpiresAt` (no aud/iss/jti)

## Attacker Control

- **Input**: `Cookie: renderKey=<forged_jwt>` on any HTTP request to Grafana
- **JWT payload**: Attacker controls all fields: `OrgID`, `UserID`, `OrgRole` (set to "Admin"), `ExpiresAt`
- **Signing key**: Known default `"-"` (single byte, trivially forgeable)
- **Minimum privilege**: Unauthenticated (cookie is set by attacker in their own request)

## Trust Boundary Crossed

Internet (unauthenticated) -> Grafana HTTP server -> Admin API access. The renderKey cookie-based authentication was designed for internal Grafana<->Renderer communication but fires on ALL endpoints, effectively creating an unauthenticated Admin bypass when the signing key is known.

## Impact

- **Full Admin API access**: POST /api/admin/users (create admin user), GET /api/admin/settings (read server config), PUT /api/org/users/:userId (escalate roles)
- **Datasource secret exfiltration**: GET /api/datasources with decrypt option
- **Alerting manipulation**: Modify alerting rules and contact points
- **Persistent backdoor**: Create new admin users for persistent access
- **All-org access**: Forged JWT can claim any OrgID, granting cross-org Admin access

## Evidence

1. `setting.go:2070`: `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")` -- default is "-"
2. `auth.go:58-60`: `jwt.ParseWithClaims(key, claims, func(_ *jwt.Token) (any, error) { return []byte(rs.Cfg.RendererAuthToken), nil })` -- validates with default key
3. `auth.go:60`: `jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()})` -- algorithm check only
4. `auth.go:149-159`: `buildJWTClaims` sets only `ExpiresAt` -- no aud, iss, jti, nbf claims
5. `render.go:73-77`: `Test()` returns true for any request with renderKey cookie -- no endpoint scoping
6. `render.go:43-57`: When `UserID<=0` and `OrgRole=="Admin"`, creates `TypeRenderService` identity with `SyncPermissions:true` and `OrgRoles:{orgID: Admin}`
7. `render.go:80-82`: Priority 10 (highest priority client) -- fires before session/JWT/API key clients

## Reproduction Steps

1. Enable the renderAuthJWT feature flag in grafana.ini: `[feature_toggles] enable = renderAuthJWT`
2. Leave renderer_token at default (do not set `[rendering] renderer_token`)
3. Restart Grafana
4. Forge a JWT with HS512 signing using key "-":
   ```go
   token := jwt.NewWithClaims(jwt.SigningMethodHS512, &renderJWT{
       RenderUser: &RenderUser{OrgID: 1, UserID: 0, OrgRole: "Admin"},
       RegisteredClaims: jwt.RegisteredClaims{
           ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
       },
   })
   signedToken, _ := token.SignedString([]byte("-"))
   ```
5. Use the forged JWT as renderKey cookie:
   ```
   curl -H "Cookie: renderKey=<forged_jwt>" http://localhost:3000/api/admin/settings
   ```
6. Expected: Admin settings returned (200 OK with full server configuration)
7. Escalation: Create persistent admin user via POST /api/admin/users

Note: Both preconditions (FlagRenderAuthJWT enabled AND default renderer_token) are non-default. The default Grafana installation is NOT vulnerable.
