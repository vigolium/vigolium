Phase: 7
Sequence: 041
Slug: renderer-jwt-forgery-default-token
Verdict: VALID
Rationale: When renderAuthJWT feature flag is enabled with the default renderer token "-", a 1-byte HMAC-HS512 key allows trivial JWT forgery granting admin access to any org. Feature flag is PublicPreview/disabled by default, preventing CRITICAL rating, but deployments enabling it without changing the token are fully compromised.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The Grafana image rendering service supports JWT-based authentication (feature flag `renderAuthJWT`, PublicPreview stage). When enabled, render keys are signed as JWTs using HMAC-HS512 with the `RendererAuthToken` configuration value as the signing key (`auth.go:144-146`). The default value for this token is `"-"` (`setting.go:2070`), a single-character string that creates a trivially weak HMAC key.

An attacker who knows this default can forge a JWT containing arbitrary `RenderUser` claims (OrgID, UserID, OrgRole), present it as the `renderKey` cookie on any HTTP request to Grafana, and the `Render` authn client (`render.go:36-67`) will accept it and construct an identity with the attacker-chosen permissions. With `UserID=0` and `OrgRole="Admin"`, the identity type becomes `TypeRenderService` with full admin permissions in the specified org.

The `renderKey` cookie is checked on ALL HTTP endpoints (render.go:73-78), not just renderer-related ones, making this a complete authentication bypass.

## Location

- **JWT signing:** `pkg/services/rendering/auth.go:144-147` -- `jwtRenderKeyProvider.get()` signs with `j.authToken`
- **Default key:** `pkg/setting/setting.go:2070` -- `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")`
- **JWT validation:** `pkg/services/rendering/auth.go:56-68` -- `getRenderUserFromJWT()` validates with same key
- **Identity construction:** `pkg/services/authn/clients/render.go:36-67` -- constructs Identity from JWT claims
- **Cookie reading:** `pkg/services/authn/clients/render.go:84-90` -- reads `renderKey` cookie from ANY request
- **Feature flag:** `pkg/services/featuremgmt/registry.go:181-185` -- `renderAuthJWT`, PublicPreview, Expression: "false"

## Attacker Control

Any network client that can send HTTP requests to the Grafana server. The attacker controls all JWT claims: OrgID (arbitrary org), UserID (0 for service identity), OrgRole ("Admin" for full access). The JWT is presented as a cookie, not requiring any prior authentication.

## Trust Boundary Crossed

TB6 (Renderer Boundary) -> TB2 (Authentication Gate). The renderer authentication mechanism (designed for trusted internal communication between Grafana and the image renderer) is exploited to bypass the primary authentication gate. The attacker crosses from unauthenticated internet access to full admin in any org.

## Impact

Complete authentication bypass: admin access to any organization in the Grafana instance. The attacker can read all dashboards, datasource configurations (including encrypted credentials via the admin API), user data, and can modify any configuration. This is equivalent to server admin access within the targeted org.

Preconditions: (1) `renderAuthJWT` feature flag explicitly enabled, (2) default renderer token "-" unchanged, (3) network access to Grafana HTTP port.

## Evidence

1. `auth.go:144-146`: `token := jwt.NewWithClaims(jwt.SigningMethodHS512, j.buildJWTClaims(opts)); return token.SignedString(j.authToken)` -- signs with auth token
2. `setting.go:2070`: Default `"-"` token
3. `auth.go:58-60`: `jwt.ParseWithClaims(key, claims, func(_ *jwt.Token) (any, error) { return []byte(rs.Cfg.RendererAuthToken), nil })` -- validates with same default key
4. `render.go:43-57`: `if renderUsr.UserID <= 0 { if org.RoleType(renderUsr.OrgRole) == org.RoleAdmin { identityType = claims.TypeRenderService } }` -- admin identity from forged claims
5. `registry.go:183`: `Stage: FeatureStagePublicPreview, Expression: "false"` -- disabled by default

## Reproduction Steps

1. Ensure `renderAuthJWT` feature flag is enabled in Grafana configuration
2. Confirm default renderer token is "-" (check grafana.ini [rendering] section)
3. Forge JWT: `{"RenderUser":{"org_id":1,"user_id":0,"org_role":"Admin"},"exp":<future_timestamp>}` signed with HMAC-HS512 using key `"-"`
4. Send any HTTP request to Grafana with `Cookie: renderKey=<forged-JWT>`
5. Observe the request is processed with Admin permissions in org 1
6. Verify by accessing admin-only endpoints (e.g., `GET /api/admin/settings`)

## Cold Verification

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: JWT forgery with default 1-byte key "-" is cryptographically proven; no validation prevents use of default key when renderAuthJWT is enabled; identity construction grants admin with no additional checks.
Severity-Final: HIGH
PoC-Status: executed

### Independent Code Path Verification

Each claim in the finding was independently verified by reading source files:

**Claim 1: Default renderer auth token is "-"**
- CONFIRMED. `conf/defaults.ini:1952`: `renderer_token = -`
- CONFIRMED. `pkg/setting/setting.go:2070`: `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")`

**Claim 2: When renderAuthJWT is enabled, this token signs JWTs**
- CONFIRMED. `pkg/services/rendering/rendering.go:113-118`: When `FlagRenderAuthJWT` is enabled globally, a `jwtRenderKeyProvider` is created with `authToken: []byte(cfg.RendererAuthToken)`.
- CONFIRMED. `pkg/services/rendering/auth.go:144-146`: The `get()` method signs JWTs with `j.authToken` using HS512.

**Claim 3: Anyone reaching Grafana's HTTP endpoint can forge a JWT**
- CONFIRMED. `pkg/services/authn/clients/render.go:73-78,84-89`: The Render client's `Test()` method checks for a `renderKey` cookie on any HTTP request. No IP restriction, no endpoint restriction.
- CONFIRMED. `pkg/services/rendering/auth.go:56-60`: `getRenderUserFromJWT()` verifies with `[]byte(rs.Cfg.RendererAuthToken)` -- the same 1-byte default key.
- CONFIRMED by PoC: A JWT signed with `[]byte("-")` passes verification with the same key function.

**Claim 4: Forged JWT grants admin identity to any org**
- CONFIRMED. `pkg/services/authn/clients/render.go:43-57`: When `UserID <= 0` and `OrgRole == "Admin"`, identity type is set to `TypeRenderService` with `OrgRoles: {attacker_chosen_org: "Admin"}` and `SyncPermissions: true`.

**Claim 5: renderAuthJWT is PublicPreview, disabled by default**
- CONFIRMED. `pkg/services/featuremgmt/registry.go:181-185`: `Name: "renderAuthJWT"`, `Stage: FeatureStagePublicPreview`, `Expression: "false"`.

### Protections Evaluated

- No startup validation rejects default/weak token when JWT mode is enabled
- No minimum key length enforcement in jwt signing/verification path
- No IP allowlist on render authentication
- No rate limiting specific to render auth attempts
- Feature flag disabled by default is the only meaningful protection

### PoC Results

Standalone PoC (`security/real-env-evidence/renderer-jwt-forgery-default-token/`) successfully:
1. Generated a JWT with HMAC-HS512 signed by `[]byte("-")` containing admin claims
2. Verified the JWT passes the identical verification logic used in `getRenderUserFromJWT()`
3. Confirmed the JWT starts with `"eyJ"` (passes `looksLikeJWT()` check)
4. Unit test passed: `PASS ok forge_jwt 0.510s`

Full end-to-end HTTP test was not performed (no running Grafana instance), but the cryptographic core of the attack is proven and the remaining code path (cookie extraction -> identity construction) contains no additional security controls.
