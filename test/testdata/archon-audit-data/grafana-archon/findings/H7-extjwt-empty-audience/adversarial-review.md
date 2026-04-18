# Adversarial Review: extjwt-empty-audience

## Step 1 - Restatement and Decomposition

**Restated claim**: The ExtendedJWT authentication client deliberately skips audience validation on ID tokens. In environments where multiple services share the same JWKS signing keys and namespace, a JWT ID token issued for a different service can be presented to Grafana. If the token's subject is `render:<id>`, Grafana grants Admin role in the default organization without further checks.

**Sub-claims**:

- **Sub-claim A**: Attacker can obtain or present a valid ID token with `sub=render:X` and a matching namespace, signed by the shared JWKS key.
- **Sub-claim B**: The ID token verifier in Grafana skips audience validation, so a token intended for another service passes verification.
- **Sub-claim C**: An authenticated identity with TypeRenderService gets Admin role in the default org.

All sub-claims are coherent and internally consistent.

## Step 2 - Independent Code Path Trace

**Entry point**: `ExtendedJWT.Authenticate()` at `pkg/services/authn/clients/ext_jwt.go:81`

1. **Line 85-89**: Access token extracted from `X-Access-Token` header and verified via `accessTokenVerifier.Verify()`. This verifier IS configured with `cfg.ExtJWTAuth.Audiences` (line 55), so audience IS validated on the access token.

2. **Line 92-97**: ID token extracted from `X-Grafana-Id` header. Verified via `idTokenVerifier.Verify()`, which was constructed with empty `VerifierConfig{}` (line 60), meaning `AllowedAudiences` is nil/empty.

3. **authlib `VerifierBase.Verify()`** (verifier.go:88-123): Calls `claims.Validate()` with `AnyAudience: jwt.Audience(v.cfg.AllowedAudiences)`. When empty, this produces an empty slice.

4. **go-jose `ValidateWithLeeway()`** (validation.go:92): `if len(e.AnyAudience) != 0` -- when AnyAudience is empty, the entire audience check is skipped. **CONFIRMED: no audience validation on ID tokens.**

5. **Line 99**: `authenticateAsUserViaIDToken()` called with both claims.

6. **Line 122-123**: Namespace from ID token must match Grafana's configured namespace. This is a real check.

7. **Line 127-129**: Access token namespace must match ID token namespace (or be wildcard).

8. **Line 131-139**: Access token subject MUST be `TypeAccessPolicy`. This means the attacker needs a legitimate access-policy token for Grafana.

9. **Line 142-149**: ID token subject parsed. Must be TypeUser, TypeServiceAccount, TypeRenderService, or TypeAnonymous.

10. **Line 184-190**: If TypeRenderService, identity gets `org.RoleAdmin` in the default org with `FetchSyncedUser=false`.

**Validations on the path**:
- Access token: signature check, audience check, expiry check, TypeAccessPolicy subject check
- ID token: signature check, expiry check, token type check (`jwt` header), namespace check
- Missing on ID token: audience check (intentionally skipped per code comment)

## Step 3 - Protection Surface Search

| Layer | Protection | Assessment |
|-------|-----------|------------|
| Crypto | JWKS signature verification on both tokens | Attacker must have tokens signed by the configured JWKS key. In shared-JWKS deployments, another service issues these. |
| Application | Access token audience validation | The access token MUST pass audience check. Attacker needs a token specifically authorized for Grafana's audience. This is a significant barrier. |
| Application | Access token TypeAccessPolicy check | Attacker must have an access-policy token, not a user/service token. |
| Application | Namespace match | Both tokens must have namespace matching the Grafana instance. In shared-namespace deployments, this is satisfied. |
| Application | ID token audience check | ABSENT - intentionally skipped (comment at line 58-59) |
| Design | Intentional comment | "For ID tokens, we explicitly do not validate audience" -- this is a deliberate design decision, not an oversight. |

**Key finding**: The access token audience check is the primary defense. The attacker needs a VALID access token that passes Grafana's audience check. This means:
- The attacker already has a token authorized to access Grafana
- The escalation is from "has valid access-policy token for Grafana" to "Admin role via render subject in ID token"

## Step 4 - Real-Environment Reproduction

**PoC-Status: blocked**

Reproduction requires:
1. A functioning JWKS endpoint shared between multiple services
2. Two services in the same namespace where one can issue render-subject ID tokens
3. Grafana configured with `ExtJWTAuth.Enabled=true`

This is a non-default, infrastructure-dependent deployment topology (Grafana Cloud or similar multi-service setup). Cannot be reproduced with a standalone Grafana instance. The finding is theoretical for self-hosted deployments.

## Step 5 - Prosecution and Defense Briefs

### Prosecution Brief

The code at `ext_jwt.go:60` explicitly creates an ID token verifier with no audience validation. This is confirmed by tracing through authlib's `VerifierBase.Verify()` and go-jose's `ValidateWithLeeway()` where `len(e.AnyAudience) != 0` evaluates to false, completely bypassing the audience check.

In a shared-JWKS deployment (e.g., Grafana Cloud), if Service-B issues an ID token with `sub=render:0` for its own purposes, that token can be presented to Grafana as the `X-Grafana-Id` header. Combined with a valid access token (which the attacker must have for Grafana), this results in Admin role assignment at line 184-190.

The test at ext_jwt_test.go line 438-458 confirms that `TypeRenderService` with `render:0` subject produces an identity with `org.RoleAdmin`, proving the code path is exercised and expected.

The privilege escalation is real: an entity with a valid access-policy token (potentially limited permissions via DelegatedPermissions) can escalate to full Admin by substituting a render-subject ID token.

### Defense Brief

1. **Intentional design**: The code comment at line 58 explicitly states this is intentional: "For ID tokens, we explicitly do not validate audience, hence an empty AllowedAudiences. Namespace claim will be checked." The developers chose namespace as the trust boundary for ID tokens.

2. **Access token audience gate**: The attacker MUST already possess a valid access token that passes Grafana's audience check (line 54-56 with `cfg.ExtJWTAuth.Audiences`). This means the attacker already has authorized access to Grafana's token ecosystem. The escalation is from "authorized access-policy holder" to "Admin", not from "unauthenticated" to "Admin".

3. **Namespace check is present**: The ID token namespace MUST match the Grafana instance's namespace (line 122-123). This is the intended defense as stated in the code comment.

4. **Non-default configuration**: ExtJWTAuth is disabled by default (`s.cfg.ExtJWTAuth.Enabled`). It requires explicit configuration with a JWKS URL. Shared-JWKS is a further deployment constraint.

5. **Render service tokens are domain-specific**: In practice, render service tokens are issued by Grafana's own rendering infrastructure. Another service issuing `render:X` subjects would need to deliberately use Grafana's identity type vocabulary.

6. **Theoretical only**: No reproduction was possible. The scenario requires a specific multi-service deployment topology.

## Step 6 - Severity Challenge

Starting at MEDIUM:

**Upgrade signals**:
- Privilege escalation to Admin is a meaningful impact
- If exploitable, it crosses a trust boundary (access-policy to Admin)

**Downgrade signals**:
- Requires non-default configuration (ExtJWTAuth must be enabled)
- Requires shared-JWKS deployment topology (uncommon for self-hosted)
- Attacker must already have a valid access-policy token for Grafana (significant precondition)
- Namespace must match (limits cross-tenant attacks)
- Intentional design decision documented in code
- Theoretical only - no reproduction

The original severity was HIGH. Given the significant preconditions (non-default config, shared-JWKS, existing valid access token), the challenged severity is **MEDIUM**.

## Step 7 - Verdict

The missing audience check on ID tokens is real and confirmed in code. The TypeRenderService to Admin escalation path is confirmed. However:

1. This is an explicitly intentional design decision documented in the source code
2. Exploitation requires significant preconditions: non-default config, shared-JWKS, valid access-policy token
3. Reproduction was blocked due to infrastructure requirements
4. The namespace check is the intended defense (per code comment)

The finding describes a genuine design weakness in a specific deployment model, but the combination of intentional design, significant preconditions, and theoretical-only status means this is a design concern rather than a confirmed exploitable vulnerability.

```
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: The missing audience validation on ID tokens is verified in code (go-jose skips check when AnyAudience is empty), and the render-service-to-Admin escalation path is confirmed at ext_jwt.go:184-190, but exploitation requires non-default shared-JWKS deployment with an existing valid access-policy token.
Severity-Final: MEDIUM
PoC-Status: theoretical
```

The verdict is CONFIRMED because:
- The code path is traceable and the missing audience check is real
- The escalation to Admin via TypeRenderService is confirmed
- Reproduction was blocked due to infrastructure requirements, not due to a discovered protection
- No blocking protection was found in the defense brief -- the namespace check does not prevent same-namespace cross-service token reuse

However, severity is downgraded from HIGH to MEDIUM due to the significant preconditions required.
