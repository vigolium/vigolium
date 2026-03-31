Phase: 7
Sequence: 004
Slug: oauth-default-no-signature-verification
Verdict: VALID
Rationale: Generic OAuth (and GitLab, Okta, Google connectors) extract ID token claims without signature verification in the default configuration (validate_id_token=false or jwk_set_url empty). The HTTPS transport provides strong but imperfect protection. This violates OIDC Core 1.0 Section 3.1.3.7 requirement 6 and inverts the security model (verification is opt-in rather than opt-out).
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-1/debate.md

## Summary

When `validate_id_token` is `false` (the default) or `jwk_set_url` is not configured, the Generic OAuth connector at `generic_oauth.go:447-453` calls `retrieveRawJWTPayload()` to extract ID token claims. This function at `social_base.go:233-287` simply base64-decodes the JWT payload segment without any signature verification. The signature segment of the JWT is completely ignored. The decoded payload is then used for user authentication via `parseUserInfoFromJSON()`, which extracts email, name, groups, and role claims. The same pattern exists in the GitLab (`gitlab_oauth.go:295`), Okta (`okta_oauth.go:135`), and Google (`google_oauth.go:265`) OAuth connectors. This is the DEFAULT code path for all generic OAuth deployments.

## Location

- **Primary**: `pkg/login/social/connectors/generic_oauth.go:439-454` -- conditional branch selecting signature-verified vs unverified path
- **Unverified extraction**: `pkg/login/social/connectors/social_base.go:233-287` -- `retrieveRawJWTPayload()` base64 decode only
- **Same pattern in other connectors**:
  - `pkg/login/social/connectors/gitlab_oauth.go:295`
  - `pkg/login/social/connectors/okta_oauth.go:135`
  - `pkg/login/social/connectors/google_oauth.go:265`
- **Configuration**: `validate_id_token` defaults to `false` across all generic OAuth configurations

## Attacker Control

The ID token arrives within the OAuth token exchange response, which is an HTTPS POST from Grafana to the IdP's token endpoint, authenticated with client_secret. In the standard flow, the attacker does not directly control the ID token content. However, the unverified extraction creates risk when:
1. The token_url is misconfigured to use HTTP (no transport-level integrity)
2. The IdP is compromised and returns modified tokens
3. The token response is cached, logged, or intercepted by middleware/CDN/proxy
4. A reverse proxy or load balancer modifies the response body

## Trust Boundary Crossed

TB2 -- Authentication Gate. Unverified identity claims from the ID token are used to authenticate users and create sessions. The HTTPS transport provides transport-level integrity but is not equivalent to cryptographic signature verification per OIDC spec.

## Impact

- **Authentication bypass (with transport compromise)**: An attacker who can modify the token response can inject arbitrary email, name, groups, and role claims, impersonating any Grafana user
- **Spec violation**: OIDC Core 1.0 Section 3.1.3.7 requirement 6 mandates signature verification
- **Inverted security model**: Verification is opt-in (requires explicit configuration of both validate_id_token=true AND jwk_set_url), violating the principle of secure defaults

## Evidence

```go
// generic_oauth.go:439-454 -- default path uses unverified extraction
if s.info.ValidateIDToken && s.info.JwkSetURL != "" {
    // Validated path: signature verification
    rawJSON, err = s.validateIDTokenSignature(ctx, http.DefaultClient, idTokenString, s.info.JwkSetURL)
    if err != nil {
        s.log.Warn("Error validating ID token signature", "error", err)
        return nil, err
    }
} else {
    // DEFAULT path: NO signature verification
    rawJSON, err = s.retrieveRawJWTPayload(idTokenString)
    if err != nil {
        s.log.Warn("Error retrieving id_token payload", "error", err, "token", fmt.Sprintf("%+v", token))
        return nil, nil
    }
}
return s.parseUserInfoFromJSON(rawJSON, "id_token"), nil
```

```go
// social_base.go:233-287 -- pure base64 decode, signature is ignored
func (s *SocialBase) retrieveRawJWTPayload(token any) ([]byte, error) {
    tokenString, ok := token.(string)
    // ...
    jwtRegexp := regexp.MustCompile("^([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)$")
    matched := jwtRegexp.FindStringSubmatch(tokenString)
    // ...
    rawJSON, err := base64.RawURLEncoding.DecodeString(matched[2])  // payload only, signature (matched[3]) ignored
    // ...
    return rawJSON, nil
}
```

## Reproduction Steps

1. Configure Grafana with Generic OAuth pointing to a test IdP
2. Ensure `validate_id_token` is not set (defaults to false) or `jwk_set_url` is empty
3. Set up a test IdP that returns an ID token with modified claims in the token exchange response
4. Perform OAuth login flow through the browser
5. Observe that Grafana accepts the modified claims without any signature verification
6. Compare with `validate_id_token=true` and `jwk_set_url` configured, where signature verification occurs

Note: Modifying the token response requires controlling the IdP's token endpoint. This test requires a custom IdP implementation or a proxy that modifies the token response body.
