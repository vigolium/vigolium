Phase: 9
Sequence: 066
Slug: azuread-missing-exp-iss-validation
Verdict: VALID
Rationale: AzureAD's validateClaims() validates audience and tenant after JWKS signature verification but does not validate exp or iss, leaving AzureAD-authenticated Grafana instances accepting expired tokens and tokens from any issuer sharing the same JWKS.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-001-oidc-missing-claim-validation.md
Origin-Pattern: AP-001

## Summary

The AzureAD OAuth connector's `validateClaims()` function at `pkg/login/social/connectors/azuread_oauth.go:416-441` was cited in p7-001 as "the connector WITH post-facto validation," making it appear safe relative to the other connectors. In reality it is only partially correct: it validates `aud` (audience against `client_id`) and `tid` (tenant ID against `allowedOrganizations`) but does NOT validate `exp` (expiration) or `iss` (issuer). The `azureClaims` struct does not even include an `Exp` field. After `validateIDTokenSignatureWithURLs()` succeeds, the raw JSON is unmarshalled into `azureClaims`, and the only checks performed are audience equality and tenant allow-list. An expired AzureAD ID token with a still-active signing key in the JWKS is accepted as valid.

## Location

- **Primary**: `pkg/login/social/connectors/azuread_oauth.go:416-441` -- `validateClaims()` function
- **Missing exp field**: `pkg/login/social/connectors/azuread_oauth.go:66-78` -- `azureClaims` struct has no `Exp` field
- **Shared base function**: `pkg/login/social/connectors/social_base.go:388-449` -- `validateIDTokenSignatureWithURLs()` returns raw claims without exp/iss validation (same as p7-001)

## Attacker Control

Same transport-level constraints as p7-001: the ID token arrives via server-to-server HTTPS OAuth2 token exchange (`connector.Exchange()`), not from attacker-supplied input directly. Exploitation requires:
- An expired AzureAD ID token whose signing key is still present in the Azure JWKS endpoint
- The IdP returning this expired token in a token exchange response (requires IdP misconfiguration or token response interception)

## Trust Boundary Crossed

TB2 -- Authentication Gate. An expired AzureAD ID token with a valid signature is accepted, allowing authentication after the intended session lifetime for AzureAD-backed Grafana instances.

## Impact

- **Expired token acceptance**: A user whose AzureAD account was disabled or whose session was revoked could re-authenticate if an old, expired ID token is returned by the AzureAD token endpoint
- **Incomplete validation citation**: p7-001 cited AzureAD as the "known_exception" that validates correctly (registry entry AP-001 `known_exception`), meaning the AzureAD gap was not tracked. This variant corrects that assessment
- **Issuer confusion**: Tokens claiming to be from a different issuer but sharing the same JWKS key material would be accepted (iss claim is not checked)
- The audience check (client_id equality) IS present and correct, reducing the cross-audience dimension of the attack relative to the other connectors

## Evidence

```go
// azuread_oauth.go:66-78 -- azureClaims struct: no Exp field
type azureClaims struct {
    Audience          string                 `json:"aud"`
    Email             string                 `json:"email"`
    PreferredUsername string                 `json:"preferred_username"`
    Roles             []string               `json:"roles"`
    Groups            []string               `json:"groups"`
    Name              string                 `json:"name"`
    ID                string                 `json:"oid"`
    ClaimNames        claimNames             `json:"_claim_names,omitempty"`
    ClaimSources      map[string]claimSource `json:"_claim_sources,omitempty"`
    TenantID          string                 `json:"tid,omitempty"`
    OAuthVersion      string                 `json:"ver,omitempty"`
    // NO Exp field -- expiration is not captured or validated
}

// azuread_oauth.go:416-441 -- validateClaims: validates aud and tid, NOT exp or iss
func (s *SocialAzureAD) validateClaims(ctx context.Context, client *http.Client, idTokenString string) (*azureClaims, error) {
    rawJSON, err := s.validateIDTokenSignatureWithURLs(ctx, client, idTokenString, s.getAzureJWKSURLs())
    if err != nil {
        return nil, fmt.Errorf("error validating id token signature: %w", err)
    }

    var claims azureClaims
    if err := json.Unmarshal(rawJSON, &claims); err != nil {
        return nil, fmt.Errorf("error parsing id token claims: %w", err)
    }

    if claims.OAuthVersion == "1.0" {
        return nil, &SocialError{"AzureAD OAuth: version 1.0 is not supported..."}
    }

    // Validates aud -- CORRECT
    if claims.Audience != s.ClientID {
        return nil, &SocialError{"AzureAD OAuth: audience mismatch"}
    }

    // Validates tid -- CORRECT but insufficient
    if !s.isAllowedTenant(claims.TenantID) {
        return nil, &SocialError{"AzureAD OAuth: tenant mismatch"}
    }
    // NO exp validation -- expired tokens pass
    // NO iss validation -- wrong-issuer tokens pass
    return &claims, nil
}
```

## Reproduction Steps

1. Configure Grafana with the AzureAD OAuth connector (`auth.azuread`), with `client_id` and `client_secret` matching an Azure App Registration
2. At the test Azure App Registration, obtain an ID token for a valid user with a future expiry
3. Using a test AzureAD token endpoint, return this token in a token exchange response where `exp` is in the past but the signing key is still present in Azure's JWKS
4. Trigger an OAuth callback to Grafana
5. Observe that Grafana's `validateClaims()` at `azuread_oauth.go:416-441` accepts the expired token (aud and tid pass, exp is never checked)

Note: Direct injection of the ID token is not possible through the standard OAuth flow. Testing requires controlling the AzureAD token endpoint response (a test tenant or mock IdP sharing the same JWKS key).

## Comparison with Origin Finding

| Dimension | p7-001 (Generic/GitLab/Google/Okta) | p9-066 (AzureAD) |
|-----------|--------------------------------------|------------------|
| Missing exp | Yes | Yes |
| Missing iss | Yes | Yes |
| Missing aud | Yes | **No -- aud IS validated** |
| Missing tid/tenant | N/A | No -- tid IS validated |
| Cited as "safe" in p7-001 | No | **Yes -- false exception** |

AzureAD is more protected than the other connectors (audience confusion attack is blocked) but still vulnerable to expired token acceptance and issuer confusion.
