# Round 2 Hypotheses: OAuth ID token validation, unprotected endpoints, JWT algorithm

## PH-09: Generic OAuth ID token signature not verified by default
- **Assumption broken**: OAuth ID tokens are trusted without cryptographic verification
- **Input path**: `pkg/login/social/connectors/generic_oauth.go:440-454` -- `extractFromIDToken`
- **Attack input**: MITM or compromised OAuth provider returns forged ID token with manipulated claims
- **Expected behavior**: When `validate_id_token = false` (default), claims extracted via `retrieveRawJWTPayload` without signature check

## PH-10: Multiple API endpoints accessible to anonymous users without RBAC
- **Assumption broken**: Endpoints within `reqSignedIn` groups without explicit `authorize()` are accessible to anonymous
- **Input path**: `pkg/api/api.go` lines 411, 452-458, 475-476, 500-501, 516-517, 541
- **Attack input**: HTTP requests with no auth when anonymous enabled
- **Expected behavior**: Endpoints like `/api/plugins`, `/api/search/`, `/api/dashboards/home`, `/api/frontend/settings/` accessible to anonymous

## PH-11: JWT algorithm confusion -- HMAC key treated as RSA public key
- **Assumption broken**: JWT parsing accepts wide algorithm set without restricting to configured key type
- **Input path**: `pkg/services/auth/jwt/auth.go:73-74` -- accepts EdDSA, HS256-512, RS256-512, ES256-512, PS256-512
- **Attack input**: If configured with RSA key, attacker crafts JWT signed with HMAC using RSA public key as secret
- **Expected behavior**: go-jose v4 may reject algorithm mismatch based on key type, but needs verification

## PH-12: Access token claims extracted without signature verification in generic OAuth
- **Assumption broken**: Access token claims used for identity even without JWT verification
- **Input path**: `pkg/login/social/connectors/generic_oauth.go:459-473` -- `extractFromAccessToken` uses `retrieveRawJWTPayload`
- **Attack input**: Crafted OAuth access token with manipulated claims
- **Expected behavior**: Access token claims extracted without signature check, used for user info

## PH-13: OAuth state hash uses default `secret_key` -- forgeable with known default
- **Assumption broken**: OAuth state parameter CSRF protection relies on `secret_key` which defaults to known value
- **Input path**: `pkg/services/authn/clients/oauth.go:372-375` -- `hashOAuthState(state, secret, seed)` uses `cfg.SecretKey`
- **Attack input**: With default `secret_key = SW2YcwTIb9zpOOhoPsMm`, attacker can compute valid state hashes
- **Expected behavior**: OAuth CSRF protection bypassed, enabling login CSRF attacks
