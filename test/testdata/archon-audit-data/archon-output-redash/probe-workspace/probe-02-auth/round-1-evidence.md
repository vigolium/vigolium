# Evidence — auth flows

## [HARVESTER] PH-01: Credential-stuffing via password login yields full org access

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/authentication.py:176-193` — `login` handles POST and checks `auth_password_login_enabled`.
2. `redash/handlers/authentication.py:195-198` — fetch user, `user.verify_password(...)`, then `login_user(...)` creates session.
3. `redash/handlers/authentication.py:199` — redirect to `next_path` (post-login access).

**Sanitizers on path**:
- `redash/handlers/authentication.py:177` — `@limiter.limit(settings.THROTTLE_LOGIN_PATTERN)` — Partial: throttles repeated attempts but does not block a valid credential pair.
- `redash/handlers/authentication.py:192` — `auth_password_login_enabled` gate — Partial: disables password login entirely if set; not a control when enabled.
- `redash/handlers/authentication.py:196` — `user.is_disabled` — Blocks: disabled accounts cannot log in.

**Verdict rationale**: With a valid email/password and password login enabled, the path reaches `login_user` with no additional blocking controls beyond throttling and disabled-account checks.

---

## [HARVESTER] PH-02: OAuth callback + JIT provisioning grants access to any account in allowed domain

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/google_oauth.py:98-113` — `authorized` exchanges code and fetches Google user profile.
2. `redash/authentication/google_oauth.py:123` → `redash/authentication/google_oauth.py:16-29` — `verify_profile` checks org/public domain or existing user.
3. `redash/authentication/google_oauth.py:132-134` → `redash/authentication/__init__.py:271-296` — `create_and_login_user` JIT-provisions and `login_user` creates session.

**Sanitizers on path**:
- `redash/authentication/google_oauth.py:16-29` — `verify_profile` — Partial: blocks users outside public org/domain or without existing account; allows any account inside allowed domain.

**Verdict rationale**: If the profile email is in an allowed Google Apps domain (or org is public), `verify_profile` passes and JIT provisioning proceeds to `login_user`.

---

## [HARVESTER] PH-03: SAML IdP-initiated assertion forges privileged user via JIT + group mapping

**Verdict**: INVALIDATED

**Code path**:
1. `redash/authentication/saml_auth.py:109-118` — `idp_initiated` parses `SAMLResponse` with `parse_authn_request_response`.
2. `redash/authentication/saml_auth.py:125-136` — extracts subject/email/name and calls `create_and_login_user`.
3. `redash/authentication/saml_auth.py:140-142` — applies `RedashGroups` via `user.update_group_assignments`.

**Sanitizers on path**:
- `redash/authentication/saml_auth.py:48-66` — SAML config `want_assertions_signed=True` — Blocks: unsigned/forged assertions should fail SAML validation during parsing.

**Verdict rationale**: The SAML client is configured to require signed assertions; a forged assertion without IdP signing should not pass `parse_authn_request_response`, preventing JIT provisioning or group assignment.

**Fragility Score** (INVALIDATED only): Fragile
- **Reason**: A single control (SAML signature validation) blocks the attack, and the SP settings are partially configuration-driven (`redash/authentication/saml_auth.py:96-99`), which could weaken signature requirements if misconfigured.

---

## [HARVESTER] PH-04: LDAP login enables any directory user to self-provision Redash access

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/ldap_auth.py:32-47` — `login` accepts POST and calls `auth_ldap_user`.
2. `redash/authentication/ldap_auth.py:72-98` — LDAP search and rebind validate credentials.
3. `redash/authentication/ldap_auth.py:49-53` → `redash/authentication/__init__.py:271-296` — `create_and_login_user` JIT-provisions and logs in.

**Sanitizers on path**:
- `redash/authentication/ldap_auth.py:97-98` — `conn.rebind(..., password=password)` — Blocks invalid LDAP credentials; does not restrict which directory users can authenticate.

**Verdict rationale**: Any LDAP user matching the search filter and presenting valid credentials is JIT-provisioned and logged in; there is no in-app group/allowlist restriction in this path.

---

## [HARVESTER] PH-05: Remote User header spoofing creates session for arbitrary email

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/remote_user_auth.py:19-28` — `login` reads `REMOTE_USER_HEADER` from request headers.
2. `redash/authentication/remote_user_auth.py:34-38` — only rejects `(null)` or missing header.
3. `redash/authentication/remote_user_auth.py:47-48` → `redash/authentication/__init__.py:271-296` — `create_and_login_user` JIT-provisions and logs in.

**Sanitizers on path**:
- `redash/authentication/remote_user_auth.py:34-38` — header presence check — Bypassable: any caller that can set the header supplies an arbitrary email.

**Verdict rationale**: The header value is trusted as the email identity; with a spoofed header the flow reaches `create_and_login_user` and creates a session.

---

## [HARVESTER] PH-06: JWT bearer token with arbitrary email yields JIT access

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/__init__.py:164-173` — `jwt_token_load_user_from_request` extracts JWT from configured cookie/header.
2. `redash/authentication/__init__.py:176-183` → `redash/authentication/jwt_auth.py:58-82` — `verify_jwt_token` validates signature, issuer, audience.
3. `redash/authentication/__init__.py:190-197` — requires `email` claim; if user missing, `create_and_login_user` is called.
4. `redash/authentication/__init__.py:271-296` — `create_and_login_user` logs user in.

**Sanitizers on path**:
- `redash/authentication/jwt_auth.py:58-82` — JWT signature/issuer/audience validation — Blocks invalid or incorrectly issued tokens; allows any valid token from the configured issuer.
- `redash/authentication/__init__.py:190-192` — email-claim presence check — Blocks tokens without `email`.

**Verdict rationale**: A valid JWT from the configured issuer/audience with an `email` claim JIT-provisions and authenticates the user with no additional approval gate.

---

## [HARVESTER] PH-07: Remote User header safety is confounded by upstream header stripping

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/remote_user_auth.py:19-28` — `login` trusts `REMOTE_USER_HEADER` from request headers.
2. `redash/authentication/remote_user_auth.py:37-43` — only rejects missing header, no provenance validation.
3. `redash/authentication/remote_user_auth.py:47-48` → `redash/authentication/__init__.py:271-296` — `create_and_login_user` logs in.

**Sanitizers on path**:
- `redash/authentication/remote_user_auth.py:37-43` — missing-header check — Bypassable: direct access with a spoofed header passes.

**Verdict rationale**: There is no in-app verification of header provenance; if upstream stripping is absent, a spoofed header reaches `create_and_login_user`.

---

## [HARVESTER] PH-08: Internal hop can impersonate users via Remote User header

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/remote_user_auth.py:19-28` — `login` reads `REMOTE_USER_HEADER` from the request.
2. `redash/authentication/remote_user_auth.py:37-43` — only checks presence, no trust boundary enforcement.
3. `redash/authentication/remote_user_auth.py:47-48` → `redash/authentication/__init__.py:271-296` — `create_and_login_user` logs in.

**Sanitizers on path**:
- `redash/authentication/remote_user_auth.py:37-43` — presence check — Bypassable: any internal hop that can set the header can impersonate.

**Verdict rationale**: The app layer does not verify that the header originates from a trusted proxy or is signed, so any internal component that can inject the header can impersonate users.

---

## [HARVESTER] PH-09: JIT provisioning guard is dormant; any IdP principal in allowed scope can self-provision

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/__init__.py:271-285` — `create_and_login_user` attempts lookup and on `NoResultFound` creates a new user.
2. `redash/authentication/__init__.py:285-294` — new user is added with default group and committed.
3. `redash/authentication/__init__.py:296` — `login_user` creates a session.

**Sanitizers on path**:
- `redash/authentication/__init__.py:274-275` — `is_disabled` check — Blocks only disabled existing users; does not gate new user creation.

**Verdict rationale**: When a user does not exist, the function unconditionally creates the account and logs it in, with no approval gate beyond upstream identity checks.

---

## [HARVESTER] PH-10: SAML IdP-initiated flow safety is confounded by IdP-only submission assumption

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/__init__.py:257-265` — CSRF is explicitly exempted for the `saml_auth` blueprint.
2. `redash/authentication/saml_auth.py:109-118` — `idp_initiated` accepts POSTed `SAMLResponse` and parses it.
3. `redash/authentication/saml_auth.py:125-136` → `redash/authentication/__init__.py:271-296` — `create_and_login_user` logs in the asserted identity.

**Sanitizers on path**:
- `redash/authentication/saml_auth.py:48-66` — signed-assertion requirement — Partial: validates assertion authenticity but does not bind it to a CSRF token or browser session.

**Verdict rationale**: The SAML endpoint is CSRF-exempt and does not bind the assertion to session state; a valid SAMLResponse for the attacker can be POSTed via a victim’s browser to create a login session.

---

## [HARVESTER] PH-05 (Round 2): JWT validation oracle via distinct unauthorized response

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/__init__.py:63-75` — `request_loader` invokes `jwt_token_load_user_from_request` when JWT auth is enabled.
2. `redash/authentication/__init__.py:176-185` — `verify_jwt_token` returns invalid, raising `Unauthorized("Invalid JWT token")`.

**Sanitizers on path**:
- `redash/authentication/jwt_auth.py:58-82` — JWT validation — Blocks invalid tokens, but the explicit `Unauthorized` exception can distinguish invalid-token errors from generic unauthenticated flows.

**Verdict rationale**: The code raises a specific `Unauthorized` error on invalid tokens, which is externally distinguishable from unauthenticated redirects/404s in other paths, enabling a validity oracle.
