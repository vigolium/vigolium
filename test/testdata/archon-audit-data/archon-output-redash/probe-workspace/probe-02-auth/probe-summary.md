# Deep Probe Summary: Auth flows (OAuth, SAML, LDAP, JWT, Remote User)

Status: complete
Loops: 2
Total hypotheses: 16
Validated: 15
Needs-Deeper: 0
Stop reason: covered all entry points

## Validated Hypotheses

### PH-01: Credential-stuffing via password login yields full org access
- Reasoning-Model: Pre-Mortem / Abductive
- Target: `redash/handlers/authentication.py:176` — `login`
- Attack input: POST `/login` with valid `email/password`
- Code path: `authentication.login` → `user.verify_password` → `login_user`
- Sanitizers on path: rate-limit + disabled-user checks (not blocking valid creds)
- Security consequence: unauthorized authenticated access with stolen credentials
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-02: OAuth callback + JIT provisioning grants access to any account in allowed domain
- Reasoning-Model: Pre-Mortem / Abductive
- Target: `redash/authentication/google_oauth.py:97` — `authorized`
- Attack input: OAuth callback for `user@allowed-domain`
- Code path: `authorized` → `verify_profile` → `create_and_login_user`
- Sanitizers on path: `verify_profile` domain/org checks (allows any user in allowed domain)
- Security consequence: unauthorized org membership for any allowed-domain principal
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-04: LDAP login enables any directory user to self-provision Redash access
- Reasoning-Model: Pre-Mortem / Abductive
- Target: `redash/authentication/ldap_auth.py:32` — `login`
- Attack input: POST `/ldap/login` with valid LDAP credentials
- Code path: `auth_ldap_user` → `create_and_login_user`
- Sanitizers on path: LDAP rebind only validates credentials
- Security consequence: unauthorized org access by any LDAP user matching filter
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-05: Remote User header spoofing creates session for arbitrary email
- Reasoning-Model: Pre-Mortem / Abductive
- Target: `redash/authentication/remote_user_auth.py:19` — `login`
- Attack input: `REMOTE_USER_HEADER: victim@org` on `/remote_user/login`
- Code path: `remote_user_auth.login` → `create_and_login_user`
- Sanitizers on path: header presence check only
- Security consequence: account takeover if header can be spoofed
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-06: JWT bearer token with arbitrary email yields JIT access
- Reasoning-Model: Pre-Mortem / Abductive
- Target: `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request`
- Attack input: valid JWT with `email` claim from configured issuer
- Code path: `verify_jwt_token` → `create_and_login_user`
- Sanitizers on path: JWT issuer/audience/signature validation only
- Security consequence: unauthorized org access for any valid IdP principal
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-07: Remote User header safety confounded by upstream header stripping
- Reasoning-Model: Causal
- Target: `redash/authentication/remote_user_auth.py:19` — `login`
- Attack input: direct request bypassing proxy with spoofed header
- Code path: header read → `create_and_login_user`
- Sanitizers on path: none for header provenance
- Security consequence: account takeover if proxy trust boundary fails
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-08: Internal hop can impersonate users via Remote User header
- Reasoning-Model: Causal
- Target: `redash/authentication/remote_user_auth.py:19` — `login`
- Attack input: internal service sends spoofed `REMOTE_USER_HEADER`
- Code path: header read → `create_and_login_user`
- Sanitizers on path: none for internal provenance
- Security consequence: lateral impersonation by internal services/proxies
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-09: JIT provisioning guard is dormant; any IdP principal can self-provision
- Reasoning-Model: Causal
- Target: `redash/authentication/__init__.py:271` — `create_and_login_user`
- Attack input: first-time login via OAuth/JWT/SAML for a new account
- Code path: `create_and_login_user` → `login_user`
- Sanitizers on path: disabled-user check only
- Security consequence: bypass of admin onboarding/approval for new IdP users
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-10: SAML IdP-initiated flow enables login CSRF/session confusion
- Reasoning-Model: Causal
- Target: `redash/authentication/saml_auth.py:109` — `idp_initiated`
- Attack input: auto-submitted POST with valid attacker SAMLResponse
- Code path: CSRF-exempt SAML POST → `create_and_login_user`
- Sanitizers on path: assertion signature check only (no session binding)
- Security consequence: victim browser logged into attacker account
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-05 (Round 2): JWT validation oracle via distinct unauthorized response
- Reasoning-Model: Game-Theory
- Target: `redash/authentication/__init__.py:176` — `jwt_token_load_user_from_request`
- Attack input: repeated requests with candidate JWTs
- Code path: `verify_jwt_token` → `Unauthorized("Invalid JWT token")`
- Sanitizers on path: none preventing error-disclosure distinction
- Security consequence: token validity oracle for probing JWTs/config
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-01 (SAML loop): Unsigned SAML assertion accepted after sp_settings override
- Reasoning-Model: Pre-Mortem
- Target: `redash/authentication/saml_auth.py:24` — `get_saml_client`
- Attack input: set `auth_saml_sp_settings` to disable signature requirements
- Code path: `sp_settings` merge → `parse_authn_request_response` → `create_and_login_user`
- Sanitizers on path: none (no validation of sp_settings overrides)
- Security consequence: unsigned assertion acceptance and account takeover
- Severity estimate: CRITICAL
- Evidence file: round-2-evidence.md

### PH-02 (SAML loop): SP-initiated redirect can be steered to attacker IdP metadata
- Reasoning-Model: Pre-Mortem / TRIZ
- Target: `redash/authentication/saml_auth.py:149` — `sp_initiated`
- Attack input: attacker-controlled `auth_saml_metadata_url` / metadata
- Code path: remote metadata → `prepare_for_authenticate` → redirect to `Location`
- Sanitizers on path: none (no metadata/redirect validation)
- Security consequence: rogue IdP login and unauthorized provisioning
- Severity estimate: HIGH
- Evidence file: round-2-evidence.md

### PH-03 (SAML loop): Config-driven signature requirements allow IdP-initiated bypass
- Reasoning-Model: Pre-Mortem / Abductive
- Target: `redash/authentication/saml_auth.py:109` — `idp_initiated`
- Attack input: `auth_saml_sp_settings` disables signatures + unsigned SAMLResponse
- Code path: `sp_settings` merge → parse response → `create_and_login_user`
- Sanitizers on path: none (signature enforcement configurable)
- Security consequence: arbitrary user login via unsigned assertion
- Severity estimate: CRITICAL
- Evidence file: round-2-evidence.md

### PH-301: SAML metadata integrity is a confounded protection
- Reasoning-Model: Causal
- Target: `redash/authentication/saml_auth.py:24` — `get_saml_client`
- Attack input: attacker controls metadata URL or tampers metadata
- Code path: remote metadata trust → `Saml2Client` → IdP-initiated login
- Sanitizers on path: none (no integrity checks/allowlist)
- Security consequence: attacker IdP becomes trusted, enabling login
- Severity estimate: HIGH
- Evidence file: round-2-evidence.md

### PH-302: SAML signature requirements are configurable and not causally necessary
- Reasoning-Model: Causal
- Target: `redash/authentication/saml_auth.py:24` — `get_saml_client`
- Attack input: set `auth_saml_sp_settings` to relax signatures
- Code path: config override → `Saml2Client` → parse response → login
- Sanitizers on path: none (no enforcement of signature requirements)
- Security consequence: unsigned assertions accepted under misconfiguration
- Severity estimate: HIGH
- Evidence file: round-2-evidence.md

## NEEDS-DEEPER

None.

## Coverage Summary
| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|------------|:-:|:-:|:-:|
| `redash/handlers/authentication.py:176` — `login` | PH-01 | NONE | NONE |
| `redash/authentication/google_oauth.py:80` — `authorize_org` | PH-02 | NONE | PH-09 |
| `redash/authentication/google_oauth.py:85` — `authorize` | PH-02 | NONE | PH-09 |
| `redash/authentication/google_oauth.py:97` — `callback` | PH-02 | NONE | PH-09 |
| `redash/authentication/saml_auth.py:109` — `idp_initiated` | PH-03 / PH-01 (SAML loop) | PH-02 (SAML loop) | PH-302 / PH-10 |
| `redash/authentication/saml_auth.py:149` — `sp_initiated` | PH-02 (SAML loop) | PH-01 (SAML loop) | PH-301 |
| `redash/authentication/ldap_auth.py:32` — `login` | PH-04 | NONE | NONE |
| `redash/authentication/remote_user_auth.py:19` — `login` | PH-05 | PH-01/PH-02 (round-2) | PH-07 / PH-08 |
| `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request` | PH-06 | PH-03 (round-2) / PH-05 (JWT oracle) | PH-09 |
