---
id: p8-026
title: OAuth Connector Empty allowed_domains Default Permits Any-Domain Login
severity: MEDIUM
status: VALID
verdict: VALID
cluster: Authentication & Authorization
---

Phase: 10
Sequence: 026
Slug: oauth-allowed-domains-empty-bypass
Verdict: VALID
Rationale: The `isEmailAllowed()` function in `pkg/login/social/connectors/common.go:65-68` returns `true` when `allowedDomains` is empty (the default for all OAuth providers in conf/defaults.ini). This is the same "empty allowlist = allow all" root cause as p8-004, applied to OAuth email-domain restriction. When an operator enables an OAuth provider without configuring allowed_domains, any user who authenticates successfully with that OAuth provider — regardless of their email domain — is granted access to Grafana.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-004-auth-proxy-empty-whitelist-bypass.md
Origin-Pattern: AP-047

## Summary

`isEmailAllowed()` at `pkg/login/social/connectors/common.go:65-68` is a domain restriction check shared by all OAuth connectors (GitHub, GitLab, Google, Azure AD, Okta, generic OAuth). It returns `true` unconditionally when the `allowedDomains` slice is empty. Every OAuth provider defaults to `allowed_domains = ` (empty) in `conf/defaults.ini`.

When an operator enables an OAuth provider (e.g., `[auth.github] enabled = true`) without configuring `allowed_domains`, the empty-default means Grafana accepts any user who successfully authenticates with that OAuth provider, regardless of email domain. For public OAuth providers (GitHub, Google), this means any person with a GitHub or Google account can obtain a Grafana login if `allow_sign_up = true` (also the default).

The structural root cause is identical to `proxy.go:200-203`: a list-based allowlist check that treats an empty list as "no restriction" rather than "deny all."

## Location

- `pkg/login/social/connectors/common.go:65-68` — `isEmailAllowed()`: returns `true` when `len(allowedDomains) == 0`
- `pkg/login/social/connectors/common.go:51-56` — `SocialBase.IsEmailAllowed()`: delegates to `isEmailAllowed()` with `s.info.AllowedDomains`
- `pkg/services/authn/clients/oauth.go:202-204` — OAuth authn client calls `connector.IsEmailAllowed(userInfo.Email)` after OAuth token validation; a `true` return allows login
- `pkg/login/social/social.go:66` — `AllowedDomains` field, parsed from `allowed_domains` ini key
- `conf/defaults.ini:741,770,800,859,888,933` — All six OAuth providers default to `allowed_domains =` (empty)

## Attacker Control

The attacker must have a valid account at the configured OAuth provider. For public providers (GitHub, Google), any person on the internet qualifies. The attacker:

1. Navigates to `GET /login/<provider>` to initiate OAuth flow.
2. Authenticates with their personal GitHub/Google account.
3. Because `isEmailAllowed()` returns `true` for any email when `allowed_domains` is empty, they receive a Grafana session.
4. With `auto_sign_up = true` (default), a new Grafana user account is automatically created.

The attacker has no direct control over Grafana configuration; they exploit the consequence of the empty default.

## Trust Boundary Crossed

TB-2 (Auth Gate): The `allowed_domains` check is the domain-restriction layer of the OAuth authentication boundary. With an empty allowlist, the boundary collapses to the OAuth provider's authentication — any authenticated user of the provider gains Grafana access, regardless of organizational affiliation.

## Impact

- **Unauthorized access to Grafana**: Any person with a GitHub/Google/etc. account can create a Grafana session on instances that have enabled OAuth without configuring domain restrictions.
- **Account creation (auto_sign_up default true)**: New accounts are provisioned automatically for unauthenticated attackers.
- **Initial access to dashboards and data sources**: Default role for new OAuth users depends on `role_attribute_path` and `default_role`; if set to Viewer (common default), the attacker gains read access to all dashboards in the default org.
- **Privilege escalation via role claim**: If `role_attribute_path` is configured to read roles from OAuth claims, an attacker controlling their own GitHub org metadata may be able to inject roles.

Note: Severity is MEDIUM rather than HIGH because this requires explicit operator action to enable an OAuth provider. Auth proxy (p8-004) requires only enabling one flag; OAuth additionally requires configuring a client_id, client_secret, and redirect URI. However, the empty-default threat model is identical and operators enabling OAuth for "single sign-on convenience" routinely omit domain restrictions.

## Evidence

1. `common.go:65-68`:
   ```go
   func isEmailAllowed(email string, allowedDomains []string) bool {
       if len(allowedDomains) == 0 {
           return true  // ALL emails accepted when domain list is empty (the default)
       }
       // ... domain suffix check ...
   }
   ```

2. `oauth.go:202-204`:
   ```go
   if !connector.IsEmailAllowed(userInfo.Email) {
       return nil, errOAuthEmailNotAllowed.Errorf("provided email is not allowed")
   }
   // When IsEmailAllowed returns true (empty allowedDomains), execution continues to grant session
   ```

3. `defaults.ini` (GitHub example, same for all providers):
   ```ini
   [auth.github]
   enabled = false
   allow_sign_up = true
   allowed_domains =       # empty -- isEmailAllowed() returns true for any email
   ```

4. Identical pattern to `proxy.go:200-203` (p8-004):
   - Both: `if len(<list>) == 0 { return true }`
   - Both: list populated from ini setting defaulting to empty string
   - Both: empty = unrestricted access, non-empty = restricted access

## Additional Instances of Same Pattern in OAuth Connectors

The same "empty allowlist = allow all" pattern also appears in sibling membership checks across OAuth connectors:

- `pkg/login/social/connectors/social_base.go:218-219` — `isGroupMember()`: `if len(s.info.AllowedGroups) == 0 { return true }` — used by Google, GitLab, Azure AD, Okta, generic OAuth
- `pkg/login/social/connectors/github_oauth.go:160-161` — `isTeamMember()`: `if len(s.teamIds) == 0 { return true }` — GitHub team restriction
- `pkg/login/social/connectors/github_oauth.go:182-183` — `isOrganizationMember()`: `if len(s.allowedOrganizations) == 0 { return true }` — GitHub org restriction
- `pkg/login/social/connectors/generic_oauth.go:168-169` — `isTeamMember()`: same pattern for generic OAuth
- `pkg/login/social/connectors/generic_oauth.go:189-190` — `isOrganizationMember()`: same pattern
- `pkg/login/social/connectors/grafana_com_oauth.go:119-120` — `isOrganizationMember()`: same pattern for Grafana.com OAuth

All of these follow the same root cause: membership/restriction checks that are silently no-ops when the corresponding configuration list is empty (the default).

## Reproduction Steps

1. Configure Grafana with `[auth.github] enabled = true`, `client_id = <id>`, `client_secret = <secret>` — all other settings at default (no `allowed_domains`).
2. Navigate to `http://grafana:3000/login/github`.
3. Authenticate with any GitHub account (personal account, unrelated to the target organization).
4. Expected (secure default): 403 — unauthorized email domain.
5. Actual: Successful login, new Grafana user account created with Viewer role.

## Defense Brief

- **Intentional design**: The empty-default for `allowed_domains` is intentional — operators who want to allow all users of an IdP to log in should not need to enumerate domains.
- **Operator responsibility**: Grafana documentation recommends setting `allowed_domains` when access should be restricted to specific organizations.
- **Counter-argument**: For public OAuth providers (GitHub, Google), the empty default means "any person on the internet can log in" when OAuth is enabled — this is not the expected security posture for most deployments. The secure default should prompt operators to configure domain restrictions or default to deny-all when no domain list is provided.
