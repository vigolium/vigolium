# Round 2 Hypotheses — Auth flows (OAuth, SAML, LDAP, JWT, Remote User)

## PH-01: Remote-User header impersonation if edge stripping fails

- **Reasoning-Model**: TRIZ
- **Target**: `redash/authentication/remote_user_auth.py:19` — `login`
- **Attacker starting position**: unauthenticated external client
- **Attack input / strategy**: Send `GET /remote_user/login?next=/` with header `X-Forwarded-Remote-User: victim@org.com` (default `REMOTE_USER_HEADER`), relying on a misconfigured edge that does not strip client-supplied headers.
- **Tension / Game**: Compatibility with proxy-auth SSO vs. enforcing IdP verification at the app layer.
- **What was sacrificed / Information accumulated**: Cryptographic identity verification is sacrificed in favor of trusting a single header.
- **Security consequence**: Attacker obtains an authenticated session as the victim (impersonation).
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm default header name, check deployment docs for header stripping, and verify any allowlist of trusted proxy IPs.

---

## PH-02: Internal service can impersonate users via Remote-User header

- **Reasoning-Model**: TRIZ
- **Target**: `redash/authentication/remote_user_auth.py:19` — `login`
- **Attacker starting position**: authenticated internal service / compromised reverse proxy
- **Attack input / strategy**: Issue `GET /remote_user/login?next=/queries` with `X-Forwarded-Remote-User: admin@org.com` from a trusted internal hop that can set headers.
- **Tension / Game**: Convenience of trusting upstream authentication vs. verifying IdP assertions in-app.
- **What was sacrificed / Information accumulated**: Any in-app validation of identity provenance is removed; any upstream that can set the header becomes an IdP.
- **Security consequence**: Lateral impersonation of any user by an internal service or compromised proxy.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Identify which upstream components are allowed to inject the header and whether mutual TLS or signed headers are enforced.

---

## PH-03: JIT provisioning allows unapproved org entry via IdP-controlled claims

- **Reasoning-Model**: TRIZ
- **Target**: `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request` (and `redash/authentication/__init__.py:271` — `create_and_login_user`)
- **Attacker starting position**: unauthenticated user holding a valid IdP token (OAuth/SAML/JWT)
- **Attack input / strategy**: Send a request with `Authorization: Bearer <valid-jwt>` where the payload includes `email: "newuser@org.com"` (or use SAML/OAuth login with a new account). The loader creates a new local user on first login.
- **Tension / Game**: Convenience of auto-provisioning vs. enforcing pre-existing user approval.
- **What was sacrificed / Information accumulated**: Pre-approval and explicit org membership checks are replaced by automatic account creation.
- **Security consequence**: Any valid IdP principal within the accepted domain can create a local account, potentially bypassing administrative onboarding.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Check org settings for domain allowlists and whether admin approval is required post-provisioning.

---

## PH-04: CSRF-exempt SSO flows enable login CSRF / session fixation

- **Reasoning-Model**: TRIZ
- **Target**: `redash/authentication/saml_auth.py:109` — `idp_initiated` (CSRF exemptions configured in `redash/authentication/__init__.py:240` — `init_app`)
- **Attacker starting position**: unauthenticated external client
- **Attack input / strategy**: Host an auto-submitting HTML form that POSTs `SAMLResponse=<attacker-assertion>` to `/saml/<org>/idp_initiated`. Victim visits the page; browser submits without CSRF token; session is created for the attacker’s IdP account.
- **Tension / Game**: SSO compatibility (IdP-initiated POSTs) vs. CSRF protection on authentication endpoints.
- **What was sacrificed / Information accumulated**: CSRF checks are skipped for SSO paths to allow IdP-initiated logins.
- **Security consequence**: Login CSRF (victim browser ends up authenticated as attacker), enabling session confusion and action mix-ups.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify whether SAML response is bound to relay state or CSRF-like state, and whether SameSite cookies reduce risk.

---

## PH-05: JWT validation oracle via distinct unauthorized response

- **Reasoning-Model**: Game-Theory
- **Target**: `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request`
- **Attacker starting position**: unauthenticated external client
- **Attack input / strategy**: Repeatedly call a protected endpoint with `Authorization: Bearer <candidate-jwt>`; distinguish `Unauthorized("Invalid JWT token")` from normal unauthenticated responses (e.g., redirect/404) to test token validity.
- **Tension / Game**: Clear error reporting vs. limiting feedback to unauthenticated users.
- **What was sacrificed / Information accumulated**: The attacker gains a validity oracle for JWTs and configuration (issuer/audience/algorithms) after multiple probes.
- **Security consequence**: Accelerated verification of stolen/guessed tokens and probing of signing/issuer constraints.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Check whether error status/messages differ at the HTTP layer and if rate limits exist on auth failures.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| `redash/handlers/authentication.py:176` — `login` | NO — password login path already expects CSRF/credentials; no distinct tension noted in anatomy | NO — no clear multi-interaction feedback described in anatomy |
| `redash/authentication/google_oauth.py:80` — `authorize_org` | NO — org slug routing only | NO — no repeated-interaction mechanism noted |
| `redash/authentication/google_oauth.py:85` — `login` | NO — OAuth initiation only | NO — no explicit interactive oracle noted |
| `redash/authentication/google_oauth.py:97` — `authorized` | PH-03 — JIT provisioning via IdP claims | NO — no explicit interactive oracle noted |
| `redash/authentication/saml_auth.py:109` — `idp_initiated` | PH-04 — CSRF-exempt SSO flow | NO — no repeated-interaction mechanism noted |
| `redash/authentication/saml_auth.py:149` — `sp_initiated` | NO — redirect only | NO — no repeated-interaction mechanism noted |
| `redash/authentication/ldap_auth.py:32` — `login` | NO — standard LDAP login | NO — no explicit interactive oracle noted |
| `redash/authentication/remote_user_auth.py:19` — `login` | PH-01 / PH-02 — proxy header trust tension | NO — no repeated-interaction mechanism noted |
| `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request` | PH-03 — JIT provisioning | PH-05 — JWT validation oracle |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| Login POST CSRF assumption is bypassed for OAuth/SAML/Remote User/JWT flows (CSRF exemptions on auth blueprints). | PH-04 — tension confirmed |
| IdP verification assumption does not hold for Remote User header path (proxy-trust only). | PH-02 — tension confirmed |
| Identity mapping assumption weakened by JIT provisioning across OAuth/SAML/JWT (no pre-existing user requirement). | PH-03 — tension confirmed |
| Remote User proxy trust boundary can be bypassed if headers are not stripped at the edge. | PH-01 — tension confirmed |

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| JWT invalid-token response differentiation (`Unauthorized` vs unauthenticated redirect/404) | PH-05 — token-validity oracle |
| OAuth authorized response differences (missing profile vs disallowed) | NO — insufficient evidence of externally observable distinction in anatomy |
| JIT provisioning state accumulation (`create_and_login_user`) | NO — tension captured in TRIZ (PH-03), not a multi-step attacker-learning mechanism |
| OAuth session `next_url` accumulation | NO — mitigated by `get_next_path`; no learning mechanism noted |
