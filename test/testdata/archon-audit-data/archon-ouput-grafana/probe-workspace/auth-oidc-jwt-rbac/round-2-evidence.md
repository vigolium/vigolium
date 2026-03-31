# Round 2 Evidence

## PH-09: Generic OAuth ID token signature not verified by default -- VALIDATED

**Evidence:**
1. `pkg/services/ssosettings/strategies/oauth_strategy.go:112`: `"validate_id_token": section.Key("validate_id_token").MustBool(false)` -- defaults to `false`
2. `pkg/login/social/connectors/generic_oauth.go:440`: `if s.info.ValidateIDToken && s.info.JwkSetURL != ""` -- BOTH conditions must be true for signature verification
3. `pkg/login/social/connectors/generic_oauth.go:449`: `rawJSON, err = s.retrieveRawJWTPayload(idTokenString)` -- when validation disabled, JWT payload is base64-decoded without any signature check
4. `pkg/login/social/connectors/social_base.go:233-248`: `retrieveRawJWTPayload` simply base64-decodes the middle part of the JWT -- no crypto at all
5. This applies to ALL OAuth connectors (generic_oauth, google, gitlab, okta) -- they all follow the same pattern

**Code path:**
- OAuth callback -> `oauth.go:180` UserInfo -> `generic_oauth.go:228` -> `collectUserInfoData:266` -> `extractFromIDToken:415` -> `retrieveRawJWTPayload:449` (no verification)
- Claims from unverified JWT used to set user identity (email, login, roles, groups)

**Security consequence:** When `validate_id_token = false` (default) and no `jwk_set_url` configured, an attacker performing MITM on the OAuth token exchange or controlling a malicious OAuth provider can forge ID token claims to impersonate any user or escalate roles.
**Severity:** HIGH (requires MITM or compromised IdP, but default config is vulnerable)

## PH-10: Multiple API endpoints accessible to anonymous users without RBAC -- VALIDATED

**Evidence:**
Routes within the `reqSignedIn` API group at `pkg/api/api.go:560` that lack `authorize()`:
1. `line 411`: `POST /api/preferences/set-home-dash` -- sets user preferences; anonymous user gets `c.GetID()` which would be empty/anonymous ID, likely errors out. LOW risk.
2. `line 452`: `GET /api/plugins` -- lists all plugins. Information disclosure about installed plugins.
3. `line 453`: `GET /api/plugins/:pluginId/settings` -- plugin settings. RBAC "in handler" but app plugins only.
4. `line 454`: `GET /api/plugins/:pluginId/markdown/:name` -- plugin markdown docs. LOW risk.
5. `line 455`: `GET /api/plugins/:pluginId/health` -- plugin health check. Can trigger plugin backend calls.
6. `line 458`: `GET /api/plugins/errors` -- plugin error list. Information disclosure.
7. `line 475`: `GET /api/frontend/settings/` -- frontend configuration. Leaks auth config, feature flags, build info.
8. `line 476`: `GET /api/frontend/assets` -- frontend asset list. LOW risk.
9. `line 500`: `GET /api/dashboards/home` -- home dashboard data. Dashboard content disclosure.
10. `line 501`: `GET /api/dashboards/tags` -- dashboard tag list. Information disclosure.
11. `line 516`: `GET /api/search/sorting` -- sort options. LOW risk.
12. `line 517`: `GET /api/search/` -- dashboard search. Search results based on anonymous Viewer permissions.
13. `line 541`: `POST /api/frontend-metrics` -- metric ingestion. Can inject metric data.

**Most significant findings:**
- `GET /api/frontend/settings/` -- leaks server configuration including auth providers, OAuth config, feature flags
- `GET /api/plugins` -- enumerates installed plugins (useful for targeted attacks)
- `GET /api/search/` -- lists accessible dashboards
- `GET /api/dashboards/home` -- home dashboard content

**Security consequence:** When anonymous auth enabled, unauthenticated users can enumerate plugins, search dashboards, view frontend settings (auth config), and access home dashboard content.
**Severity:** MEDIUM (information disclosure; requires anonymous auth enabled)

## PH-11: JWT algorithm confusion -- INVALIDATED

**Evidence:**
1. `pkg/services/auth/jwt/auth.go:73-74`: Wide algorithm set accepted in `ParseSigned`
2. However, go-jose v4 `Claims()` method at auth.go:91 passes the key directly: `token.Claims(key, &claims)`. go-jose internally verifies that the key type matches the algorithm in the token header.
3. go-jose v4.1.3 correctly rejects HMAC key used with RSA algorithm and vice versa -- the `Claims` method returns an error if key type doesn't match the signing algorithm.
4. The key set (`s.keySet.Key()`) returns keys that are typed (RSA, ECDSA, HMAC bytes) -- go-jose enforces type-algorithm compatibility.

**Conclusion:** go-jose v4 prevents algorithm confusion attacks by validating key-algorithm compatibility during Claims() extraction. SAFE.

## PH-12: Access token claims extracted without signature verification in generic OAuth -- VALIDATED

**Evidence:**
1. `pkg/login/social/connectors/generic_oauth.go:459-473`: `extractFromAccessToken` calls `retrieveRawJWTPayload(accessToken)` -- NO signature verification ever.
2. Unlike ID token extraction (which has the optional `validate_id_token` gate), access token extraction NEVER verifies signatures.
3. Access token claims are used in `buildUserInfo` alongside ID token and API data.
4. The access token is received from the OAuth token exchange (server-to-server TLS), so the risk is lower than ID token, but still relevant if the token exchange isn't over HTTPS or if the provider is compromised.

**Security consequence:** Access token claims are trusted without any cryptographic verification. If an attacker can intercept/modify the OAuth token exchange response, they can inject arbitrary claims.
**Severity:** MEDIUM (lower than ID token since access token comes from server-to-server exchange)

## PH-13: OAuth state hash uses default `secret_key` -- VALIDATED

**Evidence:**
1. `pkg/services/authn/clients/oauth.go:363-370`: `genOAuthState(c.cfg.SecretKey, oauthCfg.ClientSecret)` -- state generated with `cfg.SecretKey` and client secret
2. `pkg/services/authn/clients/oauth.go:372-375`: `hashOAuthState(state, secret, seed)` uses `SHA256(state + secret + seed)`
3. Default `secret_key` is `SW2YcwTIb9zpOOhoPsMm` (from `conf/defaults.ini:387`)
4. OAuth client secret is also known if the attacker has access to Grafana config
5. With both values known, attacker can precompute valid state hashes to bypass CSRF protection

**Security consequence:** On instances using the default `secret_key`, OAuth CSRF protection can be bypassed. An attacker can craft a login URL with a known state value and its valid hash, then trick a victim into clicking it to complete an OAuth flow with an attacker-controlled account (login CSRF / account linking attack).
**Severity:** MEDIUM-HIGH (requires default secret_key, which is common in dev/misconfigured deployments)
