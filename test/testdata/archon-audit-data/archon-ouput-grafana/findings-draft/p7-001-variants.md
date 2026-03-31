# Variant Analysis Summary: p7-001 OIDC Missing Claim Validation

**Phase:** 9 -- Variant Hunt
**Origin Finding:** security/findings-draft/p7-001-oidc-missing-claim-validation.md
**Attack Pattern:** AP-001 (OIDC Missing Claim Validation After Signature Verification)
**Analyst:** Phase 9 Variant Agent
**Date:** 2026-03-20
**NNN Range Assigned:** p7-066 to p7-068

---

## Search Methodology

### Strategy 1: Registry-Driven grep

Ran AP-001's detection signature (`parsedToken.Claims.*claims.*return.*rawJSON.*nil`) and identified the single shared implementation `validateIDTokenSignatureWithURLs()` in `social_base.go`. All four callers (generic, gitlab, google, okta) route through the same function.

Ran `UnsafeClaimsWithoutVerification` grep across `pkg/` to identify all locations where JWT claims are read without signature verification -- found 7 call sites.

### Strategy 2: AST-Level Structural Search (manual)

CodeQL database available at `security/codeql-artifacts/db/`. No formal CodeQL query was run (no QL tooling available in this environment). Manual AST-level search was performed by tracing all callers of `parsedToken.Claims(key, &claims)` followed by `return rawJSON, nil` without an intervening call to a validation function.

### Strategy 3: Flow Shape Search

Target shape: `OAuth token source -> JWT parse + JWKS signature verify -> claims used for identity without temporal/identity validation`

Searched across:
- All OAuth connectors: `github_oauth.go`, `gitlab_oauth.go`, `google_oauth.go`, `okta_oauth.go`, `generic_oauth.go`, `azuread_oauth.go`
- JWT auth service: `pkg/services/auth/jwt/auth.go`, `validation.go`
- Extended JWT client: `pkg/services/authn/clients/ext_jwt.go`
- OAuth token refresh service: `pkg/services/oauthtoken/oauth_token.go`

### Strategy 4: Phase 7 Addendum Targets

The Phase 7 Addendum in `security/knowledge-base-report.md` explicitly listed:
- "OIDC `validateIDTokenSignature` uses go-jose `Claims()` on `map[string]any` target -- cryptographic-only verification, no `Claims.Validate()` called -- affects gitlab, google, okta, generic oauth connectors"
- "JWT auth service: switch-based claim iteration means absent `exp` key leaves `Expiry=nil`..."

The Addendum did not mention the AzureAD incomplete validation gap (it cited AzureAD as the correct exception), which this analysis corrects.

### Strategy 5: Chamber Workspace

No pre-identified variant candidates in `security/chamber-workspace/*/variant-candidates/` (directories not present). The chamber-1/debate.md confirmed H-01 (generic/gitlab/google/okta) but did not revisit the AzureAD "known_exception" claim.

---

## Candidate Evaluation

### Candidate A: GitLab OAuth -- validateIDTokenSignature caller

**File:** `pkg/login/social/connectors/gitlab_oauth.go:295-308`
**Root cause match:** YES -- calls `validateIDTokenSignature` -> `validateIDTokenSignatureWithURLs` with no post-call claim check
**Distinct from p7-001?** NO -- p7-001 explicitly lists gitlab_oauth.go:295 as a confirmed caller without post-facto validation. All callers share the same vulnerable shared function. Creating a separate finding would double-count the same defect at the sink level.
**Verdict:** NOT A NEW VARIANT -- already covered by p7-001

### Candidate B: Google OAuth -- validateIDTokenSignature caller

**File:** `pkg/login/social/connectors/google_oauth.go:265-278`
**Root cause match:** YES -- identical pattern to GitLab
**Distinct from p7-001?** NO -- same reasoning as Candidate A. p7-001 explicitly lists google_oauth.go:265.
**Verdict:** NOT A NEW VARIANT -- already covered by p7-001

### Candidate C: Okta OAuth -- validateIDTokenSignature caller

**File:** `pkg/login/social/connectors/okta_oauth.go:135-143`
**Root cause match:** YES -- identical pattern
**Distinct from p7-001?** NO -- p7-001 explicitly lists okta_oauth.go:135.
**Verdict:** NOT A NEW VARIANT -- already covered by p7-001

### Candidate D: AzureAD OAuth -- validateClaims() missing exp and iss

**File:** `pkg/login/social/connectors/azuread_oauth.go:416-441`
**Root cause match:** YES -- same flow: `validateIDTokenSignatureWithURLs` returns verified claims, then only `aud` (audience) and `tid` (tenant) are checked; `exp` and `iss` are not in the `azureClaims` struct and not validated
**Distinct from p7-001?** YES -- p7-001 cites AzureAD as the "known_exception" connector that validates correctly. This is incorrect: AzureAD only validates audience and tenant. The `azureClaims` struct has no `Exp` field (confirmed at line 66-78). The AP-001 registry entry's `known_exception` field also incorrectly characterizes AzureAD as fully compliant.
**Attacker control:** Same as p7-001 (IdP token endpoint controls content; standard OAuth flow barriers apply)
**Blocking protection absent from original?** No -- AzureAD has one additional protection (audience check) vs. other connectors, but exp/iss gaps are identical
**Severity:** MEDIUM (same as p7-001; audience check provides partial mitigation but exp/iss remain unvalidated)
**Verdict:** VALID VARIANT -- new finding p9-066

### Candidate E: JWT auth service -- nbf claim absent-key bypass

**File:** `pkg/services/auth/jwt/validation.go:96-105`
**Root cause match:** YES -- same switch-key-iteration pattern as AP-003. The `nbf` case is structurally identical to the `exp` case: when the key is absent from the claims map, the case is never entered, `NotBefore` stays nil, and go-jose's nil guard skips the not-before check.
**Distinct from p7-001?** YES -- this is in the JWT auth service (AP-003 domain), not the OIDC connector. However it shares the same structural code pattern as AP-003 (p7-003) rather than AP-001. The question is whether it deserves a standalone finding.
**Distinct from p7-003?** YES -- p7-003 covers the `exp` absent-key bypass. The `nbf` bypass is a second dimension of the same structural failure, but with different security semantics (not-before window vs. expiration). It requires a separate code fix.
**Attacker control:** Same as p7-003 (JWT auth must be enabled; attacker must have a key-signed token; JWT can omit nbf claim)
**Severity:** MEDIUM (same opt-in nature as p7-003; practical impact lower since nbf is less commonly used as a security control than exp)
**Verdict:** VALID VARIANT -- new finding p9-067

### Candidate F: GetIDTokenExpiry -- UnsafeClaimsWithoutVerification on stored ID token

**File:** `pkg/services/oauthtoken/oauth_token.go:609-633`
**Root cause match:** PARTIAL -- uses `UnsafeClaimsWithoutVerification` to read exp from an ID token stored in the database
**Security-relevant?** NO -- this function is only used to determine whether a token refresh is needed. It reads from a token that was already validated during the initial authentication flow and stored in `user_auth` or `user_external_session`. The parsed exp value is used only for refresh-triggering logic, not for authentication decisions. An attacker cannot influence the stored token value without first authenticating.
**Verdict:** FALSE POSITIVE -- not a security-relevant gap

### Candidate G: ext_jwt.go Test() -- UnsafeClaimsWithoutVerification

**File:** `pkg/services/authn/clients/ext_jwt.go:340-351`
**Root cause match:** PARTIAL -- uses `UnsafeClaimsWithoutVerification` on the access token
**Security-relevant?** NO -- the `Test()` function only determines whether the `ExtendedJWT` client should attempt to authenticate the request (returns bool). The actual authentication is in `Authenticate()` which calls `s.accessTokenVerifier.Verify()` and `s.idTokenVerifier.Verify()` -- both from the `authlib` library with proper claim validation. The `UnsafeClaimsWithoutVerification` in `Test()` is used only as a cheap pre-filter.
**Verdict:** FALSE POSITIVE -- the unsafe claims read is in the detection probe, not the authentication path

### Candidate H: GitHub OAuth -- ID token handling

**File:** `pkg/login/social/connectors/github_oauth.go`
**Root cause match:** N/A -- GitHub's OAuth implementation does not issue OIDC ID tokens. GitHub's auth flow uses access tokens and the GitHub API to retrieve user info. No `id_token` or JWT signature verification is present.
**Verdict:** NOT APPLICABLE -- GitHub is not an OIDC provider

### Candidate I: JWT auth service -- iss claim absent validation when no expectClaims configured

**File:** `pkg/services/auth/jwt/validation.go:55-136`
**Analysis:** When `expect_claims` in the config does not include `iss`, the `s.expectRegistered.Issuer` is empty string. go-jose's `Validate()` only enforces issuer when `Expected.Issuer != ""`. So if no issuer is configured in `expect_claims`, any JWT with a valid signature is accepted regardless of `iss`. However, this is a configuration gap (operators should set expected claims including iss), not a code-level bug. The `initClaimExpectations()` function at `validation.go:12-53` provides the mechanism to require iss. Absent configuration is by design for deployments using single trusted key sets.
**Verdict:** KNOWN DESIGN DECISION -- out of scope for this variant hunt (requires misconfiguration, not a code-level bypass)

---

## Variant Results Summary

| Candidate | File | Verdict | Finding |
|-----------|------|---------|---------|
| A: GitLab validateIDTokenSignature caller | gitlab_oauth.go:295 | NOT NEW -- covered by p7-001 | -- |
| B: Google validateIDTokenSignature caller | google_oauth.go:265 | NOT NEW -- covered by p7-001 | -- |
| C: Okta validateIDTokenSignature caller | okta_oauth.go:135 | NOT NEW -- covered by p7-001 | -- |
| D: AzureAD missing exp + iss validation | azuread_oauth.go:416-441 | VALID VARIANT | p9-066 |
| E: JWT auth nbf absent-key bypass | validation.go:96-105 | VALID VARIANT | p9-067 |
| F: GetIDTokenExpiry UnsafeClaimsWithoutVerification | oauth_token.go:609-633 | FALSE POSITIVE | -- |
| G: ext_jwt.go Test() UnsafeClaimsWithoutVerification | ext_jwt.go:340-351 | FALSE POSITIVE | -- |
| H: GitHub OAuth ID token | github_oauth.go | NOT APPLICABLE | -- |
| I: JWT auth iss when no expectClaims | validation.go:55-136 | KNOWN DESIGN DECISION | -- |

---

## Key Structural Observations

### 1. All Non-AzureAD OAuth Connectors Share One Sink

The `validateIDTokenSignatureWithURLs()` function at `social_base.go:385-449` is the single vulnerable implementation. All four connectors (generic, gitlab, google, okta) that lack post-validation route through it identically. A patch to this function fixes all four simultaneously.

### 2. AzureAD Is Partially Patched -- Not Fully Safe

The original finding's registry entry (`AP-001`) incorrectly classified AzureAD as a `known_exception` that validates correctly. AzureAD only validates `aud` (audience against client_id) and `tid` (tenant). The `azureClaims` struct does not define an `Exp` or `Iss` field. `exp` and `iss` are not validated. The registry entry has been corrected in this analysis.

### 3. JWT Auth Has a Symmetric nbf Gap (AP-003 Pattern)

The same switch-key-iteration code structure that causes the `exp` bypass (AP-003, p7-003) also causes the `nbf` bypass. Both arise because the switch only processes claims that ARE present in the map. Both bypass mechanisms have identical go-jose library nil guards. The fix for AP-003 (requiring `exp` or making absence an error) should be applied symmetrically to `nbf`.

### 4. UnsafeClaimsWithoutVerification Uses Are Not All Auth-Critical

Of the 7 `UnsafeClaimsWithoutVerification` call sites found, only 2 are in security-critical paths (Okta's non-validated fallback at okta_oauth.go:152, and the JWT auth's HasSubClaim helper at auth.go:118). Neither is in the main authentication path (both are in detection/pre-filter code). The `GetIDTokenExpiry` usage is purely for refresh scheduling.

---

## Attack Pattern Registry Updates

- **AP-001**: Added confirmed instance for AzureAD (p9-066); corrected `known_exception` description
- **AP-003**: Added confirmed instance for nbf bypass (p9-067)

---

## Findings Written

1. `security/findings-draft/p9-066-azuread-missing-exp-iss-validation.md` -- AzureAD missing exp and iss validation (MEDIUM)
2. `security/findings-draft/p9-067-jwt-missing-nbf-enforcement.md` -- JWT auth missing nbf enforcement (MEDIUM)

Slot p7-068 was not used (no third distinct variant found).
