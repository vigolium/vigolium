Phase: 8
Sequence: 043
Slug: oauth-insecure-email-lookup
Verdict: VALID
Rationale: When oauth_allow_insecure_email_lookup is enabled (non-default, explicitly warned), email-only user matching enables account takeover from any OAuth provider that can present arbitrary email claims.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-3/debate.md

## Summary

When `oauth_allow_insecure_email_lookup=true` is configured in `[auth]`, the OAuth authentication client at `pkg/services/authn/clients/oauth.go:206-210` matches users solely by email address instead of requiring AuthID/sub claim matching. An attacker controlling an OAuth provider (or any configured provider that allows arbitrary email claims) can present any victim's email address during OAuth callback and take over the victim's Grafana account.

## Location

- `pkg/services/authn/clients/oauth.go:206-210` — insecure email lookup logic
- Configuration key: `[auth] oauth_allow_insecure_email_lookup`

## Attacker Control

Full control over the email claim returned by the OAuth provider. The attacker needs either:
- Control of one of the configured OAuth providers
- A configured OAuth provider that allows users to set arbitrary email addresses
- A compromised OAuth provider

## Trust Boundary Crossed

OAuth provider email claim -> victim user account session. The trust boundary is the assumption that email uniquely and securely identifies a user, which is violated when multiple OAuth providers are configured or when a provider allows arbitrary email claims.

## Impact

Complete account takeover for any Grafana user whose email matches the attacker-controlled email claim:
- Full access to victim's dashboards and datasources
- If victim is admin, full administrative control
- Persistent access via the attacker's OAuth session

## Evidence

```go
// pkg/services/authn/clients/oauth.go:206-210
lookupParams := login.UserLookupParams{}
allowInsecureEmailLookup := c.settingsProviderSvc.KeyValue("auth", "oauth_allow_insecure_email_lookup").MustBool(false)
if allowInsecureEmailLookup {
    lookupParams.Email = &userInfo.Email  // Only email used for matching
}
```

## Reproduction Steps

1. Configure Grafana with `[auth] oauth_allow_insecure_email_lookup = true`
2. Configure two OAuth providers (or one attacker-controlled provider)
3. Create a victim user via Provider-A with email `victim@example.com`
4. As attacker, authenticate via Provider-B presenting email `victim@example.com`
5. Observe: attacker is logged in as the victim user because lookup matched on email alone
6. Verify: without the setting, AuthID/sub matching would prevent this attack
