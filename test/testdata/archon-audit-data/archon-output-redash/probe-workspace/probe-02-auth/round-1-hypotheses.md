# Round 1 Hypotheses — Auth flows (OAuth, SAML, LDAP, JWT, Remote User)

## PH-01: Credential-stuffing via password login yields full org access

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/handlers/authentication.py:176` — `login`
- **Attacker starting position**: unauthenticated
- **Attack input**: HTTP POST `/login?next=/` with form `email=finance-admin@org.example` and `password=Winter2025!`
- **Chain**: attacker obtains a valid password → posts credentials to `authentication.login` → `user.verify_password()` succeeds and `login_user()` creates session → attacker reaches protected dashboards
- **Catastrophe / Dangerous fallback**: unauthorized read of organization dashboards, queries, and data sources
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether rate limiting or 2FA is enforced around `login` and whether failed logins are throttled

---

## PH-02: OAuth callback + JIT provisioning grants access to any account in allowed domain

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/authentication/google_oauth.py:97` — `authorized`
- **Attacker starting position**: unauthenticated
- **Attack input**: GET `/oauth/google/login?next=/` followed by OAuth callback with access token for `attacker@org.example`
- **Chain**: attacker completes Google OAuth flow → `get_user_profile()` returns profile for `attacker@org.example` → `verify_profile()` passes domain/org check → `create_and_login_user()` JIT-provisions account → attacker gains org session
- **Catastrophe / Dangerous fallback**: unauthorized org membership for any external account that can obtain an IdP token in the allowed domain
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: check how `verify_profile()` restricts domain/org membership and whether org settings permit broad domain access

---

## PH-03: SAML IdP-initiated assertion forges privileged user via JIT + group mapping

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/authentication/saml_auth.py:109` — `idp_initiated`
- **Attacker starting position**: network-adjacent (can submit SAMLResponse) or compromised IdP user
- **Attack input**: HTTP POST `SAMLResponse=<base64 assertion with NameID=admin@org.example and Groups=admin>`
- **Chain**: crafted SAMLResponse reaches `idp_initiated` → SAML parsing succeeds → `create_and_login_user()` JIT-provisions user → `user.update_group_assignments()` applies attacker-controlled groups → session created as privileged user
- **Catastrophe / Dangerous fallback**: privilege escalation to admin within Redash via forged SAML attributes
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: validate how group assignments are derived from SAML attributes and whether admin roles can be mapped from external groups

---

## PH-04: LDAP login enables any directory user to self-provision Redash access

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/authentication/ldap_auth.py:32` — `login`
- **Attacker starting position**: unauthenticated with valid LDAP credentials
- **Attack input**: HTTP POST `/ldap/login?next=/` with form `email=contractor@org.example` and `password=<valid LDAP password>`
- **Chain**: attacker authenticates against LDAP via `auth_ldap_user()` → LDAP bind/search succeeds → `create_and_login_user()` creates Redash account → attacker accesses org data without pre-approval
- **Catastrophe / Dangerous fallback**: expansion of Redash access to any directory user (including contractors) leading to data exposure
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether LDAP search filter or group checks restrict which directory users can authenticate

---

## PH-05: Remote User header spoofing creates session for arbitrary email

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/authentication/remote_user_auth.py:19` — `login`
- **Attacker starting position**: unauthenticated, direct internet access to app
- **Attack input**: HTTP GET `/remote-user/login?next=/` with header `X-Forwarded-Remote-User: admin@org.example`
- **Chain**: attacker supplies trusted header → `remote_user_auth.login` treats header as email → `create_and_login_user()` provisions user if missing → session established for chosen identity
- **Catastrophe / Dangerous fallback**: full account takeover for any email address if proxy header stripping is misconfigured
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify where `REMOTE_USER_HEADER` is enforced and whether edge proxies strip or overwrite external headers

---

## PH-06: JWT bearer token with arbitrary email yields JIT access

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request`
- **Attacker starting position**: unauthenticated with access to a valid IdP-issued JWT
- **Attack input**: HTTP request with `Authorization: Bearer <JWT>` where payload includes `email=attacker@org.example`, `aud=<expected>`, `iss=<expected>`
- **Chain**: request loader extracts JWT → `verify_jwt_token()` validates signature/claims → `create_and_login_user()` JIT-provisions user → session created for attacker email
- **Catastrophe / Dangerous fallback**: unauthorized access for any principal that can obtain a valid JWT from the trusted issuer
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm claim validation (issuer/audience) and whether email domain/org membership is constrained

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| `redash/handlers/authentication.py:176` — `login` | PH-01 | PH-01 |
| `redash/authentication/google_oauth.py:80` — `authorize_org` | PH-02 | PH-02 |
| `redash/authentication/google_oauth.py:85` — `authorize` | PH-02 | PH-02 |
| `redash/authentication/google_oauth.py:97` — `callback` | PH-02 | PH-02 |
| `redash/authentication/saml_auth.py:109` — `idp_initiated` | PH-03 | PH-03 |
| `redash/authentication/saml_auth.py:149` — `sp_initiated` | PH-03 | PH-03 |
| `redash/authentication/ldap_auth.py:32` — `login` | PH-04 | PH-04 |
| `redash/authentication/remote_user_auth.py:19` — `login` | PH-05 | PH-05 |
| `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request` | PH-06 | PH-06 |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| `redash/handlers/authentication.py:37-50` try/catch token errors | NO — not applicable: error page only, no fallback access |
| `redash/handlers/authentication.py:61-70` invitation state check | NO — not applicable: rejects invalid invitation state |
| `redash/handlers/authentication.py:74-83` missing/short password | PH-01 — implies password-only barrier for login flows |
| `redash/handlers/authentication.py:125-133` verify try/catch | NO — not applicable: error page on invalid token |
| `redash/handlers/authentication.py:148-149` password login disabled | NO — not applicable: feature gate only |
| `redash/handlers/authentication.py:158-164` forgot password NoResultFound | NO — not applicable: avoids enumeration, no access granted |
| `redash/handlers/authentication.py:179-185` current_org null redirect | NO — not applicable: setup gating only |
| `redash/handlers/authentication.py:189-190` already-authenticated redirect | NO — not applicable: avoids redundant login |
| `redash/handlers/authentication.py:192-205` password login disabled flash | NO — not applicable: feature messaging only |
| `redash/authentication/__init__.py:35-37` sign key falsy | NO — not applicable: SECRET_KEY required elsewhere |
| `redash/authentication/__init__.py:52-60` load_user try/catch | NO — not applicable: returns None on invalid session |
| `redash/authentication/__init__.py:70-71` AUTH_TYPE fallback to HMAC | NO — not applicable: config fallback only |
| `redash/authentication/__init__.py:85-105` HMAC time bounds | NO — not applicable: strict bounds reduce replay |
| `redash/authentication/__init__.py:109-110` missing API key | NO — not applicable: rejects unauthenticated API key access |
| `redash/authentication/__init__.py:118-119` disabled user check | NO — not applicable: denies disabled accounts |
| `redash/authentication/__init__.py:169-174` JWT cookie/header not configured | NO — not applicable: prevents JWT auth activation |
| `redash/authentication/__init__.py:184-185` invalid JWT guard | NO — not applicable: rejects invalid tokens |
| `redash/authentication/__init__.py:187-188` null JWT payload | NO — not applicable: denies login on missing claims |
| `redash/authentication/__init__.py:190-192` JWT missing email | PH-06 — highlights reliance on email claim for identity mapping |
| `redash/authentication/__init__.py:218-221` XHR/API redirect_to_login | NO — not applicable: 404 for unauthenticated API |
| `redash/authentication/__init__.py:230-236` current_org null | NO — not applicable: redirect only |
| `redash/authentication/__init__.py:302-316` open redirect mitigation | NO — not applicable: mitigates redirect abuse |
| `redash/authentication/google_oauth.py:36-38` 401 profile check | NO — not applicable: login fails cleanly |
| `redash/authentication/google_oauth.py:108-116` null token/profile | NO — not applicable: rejects invalid OAuth response |
| `redash/authentication/google_oauth.py:123-130` verify_profile false | PH-02 — shows reliance on domain/org membership validation |
| `redash/authentication/saml_auth.py:111-114` SAML disabled gate | NO — not applicable: feature gate only |
| `redash/authentication/saml_auth.py:116-123` SAML parse try/catch | NO — not applicable: login fails on parse error |
| `redash/authentication/saml_auth.py:157-159` nameid_format fallback | NO — not applicable: format selection only |
| `redash/authentication/ldap_auth.py:38-41` LDAP disabled gate | NO — not applicable: feature gate only |
| `redash/authentication/ldap_auth.py:42-43` already-authenticated redirect | NO — not applicable: avoids redundant login |
| `redash/authentication/ldap_auth.py:92-93` empty LDAP search results | PH-04 — highlights reliance on LDAP search result for access |
| `redash/authentication/ldap_auth.py:97-98` LDAP rebind failure | NO — not applicable: denies login on auth failure |
| `redash/authentication/remote_user_auth.py:24-26` remote user disabled | NO — not applicable: feature gate only |
| `redash/authentication/remote_user_auth.py:34-36` "(null)" header | PH-05 — indicates fragile header trust boundary |
| `redash/authentication/remote_user_auth.py:37-43` missing header | PH-05 — shows header presence is sole gate for login |
| `redash/authentication/jwt_auth.py:45-52` key cache check | NO — not applicable: perf optimization only |
| `redash/authentication/jwt_auth.py:64-67` key-id filter | NO — not applicable: key selection only |
| `redash/authentication/jwt_auth.py:71-81` decode try/catch | NO — not applicable: rejects invalid JWTs |
| `redash/authentication/account.py:39-41` token expiration | NO — not applicable: token expiry enforcement |
| `redash/settings/__init__.py:61-64` SECRET_KEY required | NO — not applicable: startup guard only |
| `redash/settings/organization.py:5-9` SAML metadata path guard | NO — not applicable: config deprecation exit |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| Login POST CSRF assumption bypassed for OAuth/SAML/Remote User/JWT flows | PH-02 / PH-03 / PH-05 / PH-06 |
| IdP verification assumption does not hold for Remote User header path | PH-05 |
| Identity mapping assumption weakened by JIT provisioning across OAuth/SAML/JWT | PH-02 / PH-03 / PH-06 |
| Remote User proxy trust boundary can be bypassed if headers not stripped | PH-05 |
