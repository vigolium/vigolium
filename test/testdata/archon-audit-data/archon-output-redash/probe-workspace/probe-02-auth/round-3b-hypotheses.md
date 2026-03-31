# Round 3 Hypotheses — Auth flows

## PH-301: SAML metadata integrity is a confounded protection

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-B01 (Round-1b PH-02 + Round-2b PH-01)
- **Target**: `redash/authentication/saml_auth.py:24` — `get_saml_client`
- **Attacker starting position**: authenticated org-admin or network-adjacent attacker able to tamper metadata response
- **Causal argument**: The apparent protection is “SAML signatures will be validated,” but that protection is confounded by the integrity of the IdP metadata fetched from `auth_saml_metadata_url`. If metadata is attacker-controlled, the code will trust the attacker’s IdP SSO URL and signing keys, so signature validation does not block attacker-issued assertions. The safety therefore depends on an external guarantee (metadata integrity/TLS/pinning) not enforced in code.
- **Real risk**: Rogue IdP metadata leads to trusted attacker assertions and unauthorized login/JIT provisioning.
- **Attack input**: Set `auth_saml_metadata_url` to `https://attacker.example/metadata.xml` (or MITM it) containing attacker SSO endpoint + signing cert; then deliver SAMLResponse signed by attacker.
- **Security consequence**: Account takeover or unauthorized account creation in the org.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify how `auth_saml_metadata_url` is provisioned (admin UI/API), whether pysaml2 validates metadata signatures, and whether TLS/pinning is enforced; check for any org setting validation.

---

## PH-302: SAML signature requirements are configurable and not causally necessary

- **Reasoning-Model**: Causal
- **Causal Test**: Counterfactual
- **Origin**: Cross-Model CROSS-B02 (Round-1b PH-01/PH-03 + Round-2b PH-02)
- **Target**: `redash/authentication/saml_auth.py:24` — `get_saml_client`
- **Attacker starting position**: authenticated org-admin (or attacker with org settings write access)
- **Causal argument**: The protection is “assertions are signed,” but its effectiveness is counterfactually untested because normal IdP traffic is always signed. If `auth_saml_sp_settings` disables `want_assertions_signed`/`want_response_signed`, there is no in-code guard preventing unsigned assertions, and the system will continue operating without alerting. This means the protection is dormant; developers rely on it and skip additional checks (e.g., enforcing signature requirements server-side).
- **Real risk**: Misconfiguration or malicious config change allows unsigned SAML assertions to authenticate users.
- **Attack input**: Set `auth_saml_sp_settings` to `{ "want_assertions_signed": false, "want_response_signed": false }`, then submit an unsigned SAMLResponse with a chosen email.
- **Security consequence**: Unauthorized login/JIT provisioning without IdP control.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm if org settings UI/API validates or rejects signature-disabling overrides; test whether pysaml2 defaults re-enable signature checks when these are false.

---

## PH-303: Remote user auth is confounded by upstream header enforcement

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Trust-Assumption (remote user header trusted)
- **Target**: `redash/authentication/remote_user_auth.py:19` — `login`
- **Attacker starting position**: unauthenticated attacker with direct network access to the app
- **Causal argument**: The protection is “REMOTE_USER header is trusted,” but that trust is external (reverse proxy / SSO gateway). If the app is reachable directly (internal service-to-service call, misconfigured ingress, test environment), the attacker can supply the header and bypass authentication. The code does not enforce provenance of the header, so security is confounded by deployment topology.
- **Real risk**: Header spoofing enables login as arbitrary users.
- **Attack input**: Direct request to `/remote_user/login` with `REMOTE_USER_HEADER: admin@example.com` when bypassing the proxy.
- **Security consequence**: Account takeover / privilege escalation.
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: Identify deployments where the app is reachable without the proxy; check for internal service routes, health endpoints, or test environments exposing the app.

---

## Coverage Check

| Round 1+2 Finding | Intervention tested? | Counterfactual tested? | Confounder tested? | New hypothesis? |
|-------------------|:-:|:-:|:-:|:-:|
| PH-01 | YES | YES | YES | PH-302 |
| PH-02 | YES | YES | YES | PH-301 |
| PH-03 | YES | YES | YES | PH-302 |
| PH-01 (Round-2b) | YES | YES | YES | PH-301 |
| PH-02 (Round-2b) | YES | YES | YES | PH-302 |

| Cross-Model Seed | Causal analysis done? | Hypothesis generated? |
|-----------------|:-:|:-:|
| CROSS-B01 | YES | PH-301 |
| CROSS-B02 | YES | PH-302 |

| Trust Assumption | Confounder test done? | Hypothesis generated? |
|----------------|:-:|:-:|
| `request.form["password"]` present for POST (`redash/handlers/authentication.py:74-87`) | YES | NO |
| `request.form["email"]` exists in POST (`redash/handlers/authentication.py:152-155`) | YES | NO |
| `request.form["email"]` and `request.form["password"]` exist (`redash/handlers/authentication.py:195-196`) | YES | NO |
| `request.view_args` contains `query_id` (`redash/authentication/__init__.py:81-83`) | YES | NO |
| JWT claims include expected `iss`/`aud` (`redash/authentication/__init__.py:177-183`) | YES | NO |
| `profile["email"]` contains `@` (`redash/authentication/google_oauth.py:20-24`) | YES | NO |
| `profile["picture"]` present (`redash/authentication/google_oauth.py:132`) | YES | NO |
| SAML attributes `FirstName`/`LastName` (`redash/authentication/saml_auth.py:127-131`) | YES | NO |
| LDAP POST provides `email`/`password` (`redash/authentication/ldap_auth.py:46`) | YES | NO |
| Remote user header value is email (`redash/authentication/remote_user_auth.py:28`) | YES | PH-303 |
| JWT payload includes `iss` (`redash/authentication/jwt_auth.py:74-75`) | YES | NO |
| `settings.SECRET_KEY` usable for serializer (`redash/authentication/account.py:11-15`) | YES | NO |
| `Organization.get_by_slug(slug)` succeeds (`redash/authentication/org_resolving.py:18`) | YES | NO |
