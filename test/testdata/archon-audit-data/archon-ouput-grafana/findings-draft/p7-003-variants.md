# Variant Analysis: p7-003-jwt-missing-exp-enforcement

**Origin finding**: security/findings-draft/p7-003-jwt-missing-exp-enforcement.md
**Origin pattern**: AP-003 (JWT Missing Expiry Enforcement for Absent Claims)
**Analysis date**: 2026-03-20
**NNN range assigned**: p7-075 to p7-077
**Variants confirmed**: 3

---

## Search Strategy Summary

### 1. Registry-Driven Search

AP-003 detection signature (`case.*exp.*value.*nil.*continue`) was searched across the codebase. One match confirmed (the original finding location). No additional switch-case exp patterns found.

Extended search to the broader root cause: "absent exp field treated as no-expiry." This required searching for:
- `VerifyExpiresAt` with `required=false` (golang-jwt/v4 pattern)
- `Claims.Validate` calls without explicit exp enforcement (go-jose pattern)
- Any JWT parsing code that accepts tokens without exp

### 2. AST-Level Structural Search (Manual)

Three additional JWT validation code paths were identified in the Grafana codebase:

| Path | Library | Mechanism |
|------|---------|-----------|
| `pkg/services/rendering/auth.go:56-68` | `golang-jwt/v4` | `ParseWithClaims` → `VerifyExpiresAt(required=false)` |
| `pkg/services/authn/clients/ext_jwt.go:87` | authlib → go-jose | `VerifierBase.Verify()` → `Claims.Validate(Time=now)` with nil-Expiry bypass |
| `pkg/storage/unified/sql/service.go:196` | authlib → go-jose | `grpcutils.NewAuthenticator` → same `VerifierBase.Verify()` path |

### 3. Phase 7 Addendum Targets

The Phase 7 Addendum (knowledge-base-report.md §Phase 7 Addendum, Chamber 1) identified:
- "JWT auth service: switch-based claim iteration means absent exp key leaves Expiry=nil, go-jose Validate() skips nil Expiry enforcement"

This confirmed the root cause was known. Phase 9 variant analysis extended the search to other JWT validation paths sharing the root cause.

### 4. Chamber Variant Candidates

No pre-identified variant candidates found in `security/chamber-workspace/*/variant-candidates/`.

### 5. Flow Shape Search

Flow shape: `JWT string (attacker-controlled or leaked) → JWT library parse → typed Claims struct → library Validate(Time=now) → nil-Expiry skip → authentication success`

This flow was confirmed in three locations beyond the original finding.

---

## Questions from Orchestrator — Analysis Results

### Q1: Are other JWT claims (nbf, iss, aud) also silently skipped when absent in the switch-case pattern at validation.go?

**Answer: nbf is silently skipped (same pattern) but is NOT a security vulnerability. iss and aud are NOT silently bypassed.**

#### nbf (Not Before) — validation.go:96-105

The `case "nbf"` handler at lines 96-105 uses the identical `if value == nil { continue }` pattern as `case "exp"`. When "nbf" is absent from the claims map, `registeredClaims.NotBefore` stays nil and go-jose's nil guard at `jwt/validation.go:112` skips the not-before check.

**Security assessment**: NOT a meaningful security bypass. The `nbf` claim defines the earliest time a token is valid. An absent `nbf` means "valid from the beginning of time," which is the standard permissive interpretation. Unlike `exp`, a missing `nbf` does NOT create a "permanently valid" credential — it only removes the not-before restriction. This is a code-pattern consistency issue (the fix for AP-003 should be applied symmetrically to preserve code uniformity), but the security impact is low.

**Note**: This is already captured as p9-067 (pre-existing variant finding).

#### iss (Issuer) — validation.go:59-64

When "iss" is absent from the claims map, `registeredClaims.Issuer` stays `""` (empty string). If the operator configures `ExpectClaims = {"iss": "http://foo"}`, `expectRegistered.Issuer = "http://foo"`. go-jose's check: `if e.Issuer != "" && e.Issuer != c.Issuer` → `"http://foo" != "" && "http://foo" != ""` → `true` → `ErrInvalidIssuer`.

**Security assessment**: CORRECTLY ENFORCED. An absent `iss` claim fails validation when `iss` is configured in `ExpectClaims`. No bypass.

#### aud (Audience) — validation.go:71-85

When "aud" is absent, `registeredClaims.Audience` stays empty. If `ExpectClaims` configures `aud`, `expectRegistered.AnyAudience` is non-empty. go-jose's check: `if len(e.AnyAudience) != 0` → true → `c.Audience.Contains(v)` returns false for any expected value → `ErrInvalidAudience`.

**Security assessment**: CORRECTLY ENFORCED. An absent `aud` claim fails validation when `aud` is configured in `ExpectClaims`. No bypass.

#### Conclusion for Q1

Only `exp` (original finding) and `nbf` (p9-067) exhibit the absent-key bypass. The `iss` and `aud` claims are correctly enforced by go-jose when configured via `ExpectClaims`. The security vulnerability is specific to the "no expiry enforcement" semantic of missing `exp`.

### Q2: Are there other JWT validation paths in Grafana (not just pkg/services/auth/jwt/) with similar gaps?

**Answer: YES — three additional paths confirmed.**

| Finding | Location | Library | Root Cause Mechanism |
|---------|----------|---------|---------------------|
| p7-075 | `pkg/services/rendering/auth.go:56-68` | `golang-jwt/v4` | `VerifyExpiresAt(now, required=false)` returns true when ExpiresAt is nil |
| p7-076 | `pkg/services/authn/clients/ext_jwt.go:87` (via authlib) | go-jose (via authlib) | `VerifierBase.Verify()` → `Claims.Validate(Time=now)` → nil-Expiry skip |
| p7-077 | `pkg/storage/unified/sql/service.go:196` (via grpcutils) | go-jose (via authlib) | Same `VerifierBase.Verify()` path, gRPC transport |

All three share the same root cause: when a JWT token is issued without an `exp` field, the library decodes the token into a struct where the expiry field is nil/zero, and the validation logic treats nil as "no expiry restriction" rather than "reject token."

### Q3: Does the ext_jwt.go client (pkg/services/authn/clients/ext_jwt.go) have separate claim validation?

**Answer: NO — ext_jwt.go fully delegates to authlib's VerifierBase, which has the nil-Expiry bypass.**

`ext_jwt.go` does NOT perform any additional claim validation beyond what `authlib.VerifierBase.Verify()` provides. The verifier:
1. Parses the JWT with go-jose
2. Fetches the JWKS key and verifies the signature
3. Decodes claims into a typed `jwt.Claims` struct (absent `exp` → nil Expiry)
4. Calls `claims.Validate(jwt.Expected{AnyAudience: ..., Time: time.Now()})`
5. go-jose's `ValidateWithLeeway` skips expiry check when `c.Expiry == nil`

The `AnyAudience` check (`["grafana"]`) IS enforced. The namespace check in `authenticateAsService()` and `authenticateAsUserViaIDToken()` IS enforced. But expiry is not enforced when absent.

Exploitation precondition: access to Grafana Cloud's access token signing private key (ECDSA ES256). This is held by Grafana Cloud infrastructure, not by operators, making this variant higher-trust-boundary but still valid.

### Q4: Are there any JWTs used for service account authentication that might lack exp?

**Answer: Grafana's OWN token issuance always sets exp. The vulnerability is on the VALIDATION side, not the issuance side.**

`pkg/services/auth/idimpl/service.go:95-108` shows Grafana's internal ID token signing ALWAYS sets `Expiry: jwt.NewNumericDate(now.Add(tokenTTL))`. Similarly, `pkg/services/rendering/auth.go:149-160` (`jwtRenderKeyProvider.buildJWTClaims`) always sets `ExpiresAt`.

The vulnerability arises when:
1. An external system issues JWTs to Grafana's JWT auth service without including `exp` (many JWT libraries and IdPs allow this — RFC 7519 makes `exp` optional)
2. Grafana's own tokens are leaked/replayed (they do have `exp`, but the validation path accepts tokens without it)
3. A compromised or misconfigured token issuance system omits `exp`

Service accounts using the `auth.jwt` path are in scope for the original AP-003 finding. The ext_jwt path (p7-076) is specifically for Grafana's own internal service account tokens (access policies).

---

## Variants Confirmed

### p7-075: Renderer JWT Absent-Exp Bypass (golang-jwt/v4)

**File**: `security/findings-draft/p7-075-renderer-jwt-absent-exp-bypass.md`
**Severity**: MEDIUM
**Key differentiator**: Uses `golang-jwt/v4` library (not go-jose); `VerifyExpiresAt(required=false)` pattern; compounded by AP-041 default signing key `"-"`; gated by `FlagRenderAuthJWT` feature flag

### p7-076: Extended JWT Absent-Exp Bypass via authlib (HTTP)

**File**: `security/findings-draft/p7-076-ext-jwt-absent-exp-bypass.md`
**Severity**: MEDIUM
**Key differentiator**: authlib `VerifierBase.Verify()` wraps go-jose and inherits nil-Expiry bypass; HTTP transport via `X-Access-Token` header; signing key held by Grafana Cloud infrastructure

### p7-077: Unified Storage gRPC JWT Absent-Exp Bypass via authlib

**File**: `security/findings-draft/p7-077-grpc-storage-jwt-absent-exp-bypass.md`
**Severity**: MEDIUM
**Key differentiator**: Same authlib `VerifierBase` nil-Expiry bypass as p7-076; gRPC transport (not HTTP); affects unified storage service (dashboards, alert rules, etc.); internal network path

---

## Candidates Examined but NOT Confirmed as Variants

### `nbf` absent-key pattern (validation.go:96-105)

Pattern present: YES. Security vulnerability: NO (absent nbf is permissive but not a security bypass). Already captured in p9-067 for code-pattern consistency reasons.

### `iss` and `aud` absent-claim bypass

Pattern absent: go-jose correctly enforces `iss` and `aud` when configured via `ExpectClaims`. An absent `iss` in the token will cause `registeredClaims.Issuer = ""` which FAILS the go-jose issuer check when an expected issuer is configured. An absent `aud` similarly fails the audience check. No bypass.

### `pkg/services/auth/idimpl/service.go` — `extractTokenClaims`

Uses `UnsafeClaimsWithoutVerification` — but this is for extracting the expiry time from a token Grafana JUST issued, not for authentication. The result is used only to compute cache TTL. Not a JWT validation path for authentication.

### `pkg/login/social/connectors/social_base.go` — `validateIDTokenSignatureWithURLs`

This path is AP-001 (OIDC missing claim validation), not AP-003. The mechanism is different (no Validate call at all, not a nil-Expiry bypass). Already captured in p7-001/p9-066.

---

## Registry Update

AP-003 in `security/attack-pattern-registry.json` updated:
- Extended `description` to cover all three bypass mechanisms
- Extended `detection_signature.grep` pattern
- Added p7-075, p7-076, p7-077 to `confirmed_instances`

---

## Recommended Fix Scope

All four confirmed instances of AP-003 (p7-003, p7-075, p7-076, p7-077) share the same fix approach:

1. **p7-003** (`validation.go`): Add explicit check after `validateClaims()` — if `registeredClaims.Expiry == nil`, return error. Or add a config option `require_exp = true`.

2. **p7-075** (`rendering/auth.go`): Change `jwt.ParseWithClaims` call to require expiry by calling `claims.VerifyExpiresAt(time.Now(), true)` after parsing, or use `jwt.WithExpirationRequired()` parser option (available in golang-jwt/v4+).

3. **p7-076/p7-077** (authlib `VerifierBase`): Requires fix in the `github.com/grafana/authlib` library — add check after `claims.Validate()` to reject tokens with nil `Expiry`. Alternatively, Grafana's ext_jwt.go and gRPC authenticator wrappers can add post-verification expiry checks.
