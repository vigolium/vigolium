# Attack Surface Map: Auth flows (OAuth, SAML, LDAP, JWT, Remote User)

## Entry Points
- `redash/handlers/authentication.py:176` — `login` — password login form inputs (`email`, `password`) and `next` query param
- `redash/authentication/google_oauth.py:80` — `authorize_org` — `next` query param + org slug routing
- `redash/authentication/google_oauth.py:85` — `authorize` — OAuth initiation (session `next_url` from query param)
- `redash/authentication/google_oauth.py:97` — `callback` — OAuth callback; userinfo and access token from IdP
- `redash/authentication/saml_auth.py:109` — `idp_initiated` — `SAMLResponse` POST body (assertion)
- `redash/authentication/saml_auth.py:149` — `sp_initiated` — SP-initiated login redirect to IdP
- `redash/authentication/ldap_auth.py:32` — `login` — LDAP login form inputs (`email`, `password`) and `next` query param
- `redash/authentication/remote_user_auth.py:19` — `login` — trusted header `REMOTE_USER_HEADER` (default X-Forwarded-Remote-User) + `next` query param
- `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request` — JWT token from cookie or header (org settings)

## Trust Boundary Crossings
- `redash/authentication/remote_user_auth.py:28` — Remote User header crosses proxy trust boundary into authenticated session creation
- `redash/authentication/google_oauth.py:101` — OAuth callback (IdP-controlled response) crosses into local session creation
- `redash/authentication/saml_auth.py:117` — SAMLResponse parsing crosses IdP -> SP trust boundary
- `redash/authentication/ldap_auth.py:72` — LDAP bind/search crosses app -> directory service boundary
- `redash/authentication/__init__.py:176` — JWT token (external issuer) crosses into authenticated session creation

## Auth / AuthZ Decision Points
- `redash/authentication/__init__.py:176` — `jwt_token_load_user_from_request` — accepts/rejects JWT based on issuer/audience/algorithms
- `redash/authentication/google_oauth.py:123` — `verify_profile` — allowlist decision (domain/org membership)
- `redash/authentication/saml_auth.py:109` — `idp_initiated` — accepts SAML response; JIT user provisioning
- `redash/authentication/ldap_auth.py:72` — `auth_ldap_user` — LDAP bind + search determines login success
- `redash/authentication/remote_user_auth.py:24` — `login` — remote user enabled + header present gates login
- `redash/handlers/authentication.py:192` — `login` — password verification for local accounts

## Validation / Sanitization Functions
- `redash/authentication/__init__.py:301` — `get_next_path` — strips scheme/netloc to prevent open redirect
- `redash/authentication/ldap_auth.py:73` — `escape_filter_chars` — escapes LDAP search filter input
- `redash/authentication/google_oauth.py:123` — `verify_profile` — restricts Google OAuth to org domain/users
- `redash/authentication/jwt_auth.py:58` — `verify_jwt_token` — validates JWT issuer/audience/algorithms

## Layer Trust Chain

For each layer transition in this component:

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| Browser | Web login handler | CSRF protections apply to login POSTs | PARTIAL | OAuth/SAML/Remote User/JWT flows are CSRF-exempt (blueprints exempted) |
| Web handler | Auth provider (OAuth/SAML/LDAP/JWT issuer) | IdP assertions/tokens are verified | PARTIAL | Remote User relies on proxy header (no IdP verification) |
| Auth provider | Session creation | Identity claims map to correct org/user | PARTIAL | JIT provisioning creates accounts without pre-approval in SAML/OAuth/JWT |
| Proxy | Web handler (Remote User) | Proxy strips/controls REMOTE_USER_HEADER | NO | Direct internet clients can supply header if proxy misconfigured |
| Request params | Redirect target | `next` is sanitized to local path | YES | None observed |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)
- Login POST CSRF assumption is bypassed for OAuth/SAML/Remote User/JWT flows (CSRF exemptions on auth blueprints).
- IdP verification assumption does not hold for Remote User header path (proxy-trust only).
- Identity mapping assumption weakened by JIT provisioning across OAuth/SAML/JWT (no pre-existing user requirement).
- Remote User proxy trust boundary can be bypassed if headers are not stripped at the edge.
