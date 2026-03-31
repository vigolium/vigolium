Phase: 10
Sequence: 052
Slug: oauth-state-csrf-known-default-secret-key
Verdict: VALID
Rationale: The OAuth CSRF state token is verified by computing SHA256(state + cfg.SecretKey + clientSecret) and comparing to the stored cookie; when cfg.SecretKey is the publicly known default "SW2YcwTIb9zpOOhoPsMm" and the OAuth client secret is empty or known, an attacker can forge a valid OAuth state token, enabling a CSRF attack that forces the victim's Grafana account to be linked to an attacker-controlled OAuth identity.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-041-renderer-jwt-forgery-admin-takeover.md
Origin-Pattern: AP-041

## Summary

Grafana's OAuth authentication flow uses a state token to prevent CSRF attacks on the OAuth callback. The state verification in `pkg/services/authn/clients/oauth.go:127` computes:

```go
stateQuery := hashOAuthState(r.HTTPRequest.URL.Query().Get(oauthStateQueryName), c.cfg.SecretKey, oauthCfg.ClientSecret)
```

where `hashOAuthState(state, secret, seed) = hex(SHA256(state + secret + seed))`.

The `secret` parameter is `cfg.SecretKey`, which defaults to `"SW2YcwTIb9zpOOhoPsMm"` — the same publicly known default documented in `conf/defaults.ini:387` and exploited by findings M14 (password reset forgery) and H3 (credential decryption).

When EITHER of the following conditions holds:
- **Condition A**: `cfg.SecretKey` is the default AND the OAuth `client_secret` is empty (e.g., generic_oauth PKCE flows, public clients, or misconfigured providers)
- **Condition B**: `cfg.SecretKey` is the default AND the `client_secret` value is known to the attacker (e.g., it is also a default value, or is disclosed via the `/api/admin/settings` endpoint)

An attacker can forge a valid state token by:
1. Generating a random `state` value (as Grafana would)
2. Computing `forgedHash = hex(SHA256(state + "SW2YcwTIb9zpOOhoPsMm" + clientSecret))`
3. Initiating an OAuth flow with the victim, injecting their crafted `state` and a matching `oauth_state` cookie value
4. Completing the OAuth callback with the forged state, causing Grafana to bind the victim's session to the attacker's OAuth identity

This enables OAuth account takeover (attacker's OAuth provider account gets linked to victim's Grafana account) or forced-login to an attacker-controlled OAuth identity.

The root cause pattern is identical to the confirmed finding: a cryptographic operation uses `cfg.SecretKey` (or `cfg.RendererAuthToken`) with a publicly known default value as the critical secret.

## Location

- **Primary**: `pkg/services/authn/clients/oauth.go:127` — state comparison: `hashOAuthState(stateFromCallback, cfg.SecretKey, clientSecret)`
- **Primary**: `pkg/services/authn/clients/oauth.go:279` — state generation: `genOAuthState(cfg.SecretKey, clientSecret)`
- **Primary**: `pkg/services/authn/clients/oauth.go:372-375` — `hashOAuthState` implementation: `sha256.Sum256([]byte(state + secret + seed))`
- **Secondary**: `pkg/setting/setting.go:1802` — `cfg.SecretKey = valueAsString(security, "secret_key", "")` reads from `[security]`
- **Secondary**: `conf/defaults.ini:387` — `secret_key = SW2YcwTIb9zpOOhoPsMm`

## Attacker Control

**Full control when Condition A (empty client_secret)**:
- `hashOAuthState(state, "SW2YcwTIb9zpOOhoPsMm", "")` = `hex(SHA256(state + "SW2YcwTIb9zpOOhoPsMm"))`
- Attacker chooses any `state` value and computes the correct hash with only the known default `SecretKey`
- No need to know `clientSecret`

**Partial control when Condition B (known client_secret)**:
- For some OAuth providers (or self-hosted instances), `client_secret` may also be a known value
- The Grafana advisor does not check `client_secret` entropy
- `/api/admin/settings` (requires Admin) returns `client_secret` masked, but it may be readable via backup/config file access

**Attack target**: Victim who is logged into Grafana with an active session, clicks an attacker-crafted OAuth link.

## Trust Boundary Crossed

OAuth provider (external IdP) → Grafana authentication layer (TB: Grafana authentication). The CSRF protection on the OAuth callback is defeated, allowing an attacker to inject a crafted OAuth callback that binds the victim's Grafana session to an attacker-controlled OAuth identity (account takeover) or forces re-authentication as an attacker-chosen identity.

## Impact

- **OAuth account linkage hijacking**: Force victim's Grafana account to be associated with attacker's OAuth provider account
- **Forced re-authentication**: CSRF victim completes OAuth flow as attacker-controlled identity, potentially downgrading permissions or switching organizations
- **Combined with M4 (no ID token signature verification)**: If `validate_id_token=false`, attacker can also craft the identity claims, potentially escalating to Admin
- Affects all OAuth providers configured in Grafana (GitHub, Google, Azure AD, GitLab, Okta, generic_oauth)

The impact is constrained compared to the original finding because:
1. Requires social engineering (victim must click OAuth link)
2. Requires `clientSecret` to be empty OR known
3. The attack affects the OAuth binding rather than directly granting API access

## Evidence

1. `oauth.go:372-375`: `hashOAuthState` = `sha256.Sum256([]byte(state + secret + seed))` — HMAC-like but using SHA256 concatenation, not keyed HMAC
2. `oauth.go:127`: `stateQuery := hashOAuthState(state, c.cfg.SecretKey, oauthCfg.ClientSecret)` — state comparison uses `cfg.SecretKey` as critical secret
3. `oauth.go:129`: `if stateQuery != stateCookie.Value` — forged hash passes this check
4. `conf/defaults.ini:387`: `secret_key = SW2YcwTIb9zpOOhoPsMm` — publicly known default
5. `setting.go:1802`: Go-level default is `""` (empty string) — if ini file default is also used, the hash becomes `SHA256(state + "SW2YcwTIb9zpOOhoPsMm" + clientSecret)`
6. No minimum entropy requirement for `clientSecret` exists in `readOAuthSection()`

## Reproduction Steps

1. Configure Grafana with generic_oauth and leave `secret_key` at default
2. Configure oauth with empty `client_secret` (public client / PKCE flow):
   ```ini
   [auth.generic_oauth]
   enabled = true
   client_id = myapp
   client_secret =
   ```
3. As attacker, generate a random state: `state = base64url(rand(32))`
4. Compute forged hash: `hash = hex(SHA256(state + "SW2YcwTIb9zpOOhoPsMm" + ""))` (using Python: `import hashlib; hashlib.sha256((state+"SW2YcwTIb9zpOOhoPsMm").encode()).hexdigest()`)
5. Craft OAuth callback URL: `http://grafana/login/generic_oauth?state=<state>&code=<attacker-oauth-code>`
6. Set victim's `oauth_state` cookie: `oauth_state=<forged_hash>`
7. Induce victim to visit the callback URL (e.g., via CSRF on the `GET /login/generic_oauth` endpoint)
8. Grafana verifies: `hashOAuthState(state, secretKey, clientSecret) == forged_hash` → passes
9. OAuth exchange completes as attacker's OAuth identity

Note: This attack requires CSRF delivery to the victim's browser AND either empty `client_secret` or known `client_secret`.
