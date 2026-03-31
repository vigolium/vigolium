# Round 2 Hypotheses — Auth flows (OAuth, SAML, LDAP, JWT, Remote User)

## PH-01: SP-initiated SAML redirect trusts IdP metadata without local validation

- **Reasoning-Model**: TRIZ
- **Target**: `redash/authentication/saml_auth.py:149-167` — `sp_initiated`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: Attacker influences `auth_saml_metadata_url` (e.g., points org to an attacker-controlled metadata host, or swaps metadata via DNS/HTTP) then triggers `GET /<org>/saml/login`. The server builds the AuthnRequest and redirects the victim to the **Location** in metadata. Attacker IdP then returns a SAMLResponse signed by its own key (from the same metadata), which the SP accepts and JIT-provisions.
- **Tension / Game**: **Compatibility vs. validation** — the SP trusts metadata-driven IdP endpoints to support varied IdPs and “just works” SAML; it sacrifices strict local verification of the redirect target or IdP identity in the SP-initiated path.
- **What was sacrificed / Information accumulated**: The SP does not enforce a local allowlist or binding check for `redirect_url` pulled from SAML client headers; any IdP metadata that the org trusts becomes authoritative for redirects and certificate trust.
- **Security consequence**: IdP mix‑up / rogue IdP login: attacker can redirect users to a malicious IdP and mint assertions that the SP trusts, enabling unauthorized account creation and login.
- **Severity estimate**: HIGH
- **Read needed**: `redash/authentication/saml_auth.py:149-167`
- **Deepening direction**: Check how `auth_saml_metadata_url` is provisioned and whether it is fetched over insecure transport or can be updated by lower‑privilege admins; verify if metadata signatures are validated by pysaml2 in this config.

---

## PH-02: Config-driven SP overrides can relax SAML signature requirements

- **Reasoning-Model**: TRIZ + Game-Theory
- **Target**: `redash/authentication/saml_auth.py:48-67, 96-100, 109-138` — `get_saml_client` + `idp_initiated`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: If `auth_saml_sp_settings` overrides set `want_assertions_signed=false` or otherwise loosen signature expectations, attacker sends a **POST** to `/saml/callback` with a crafted **unsigned** `SAMLResponse` containing a chosen `NameID` and `FirstName/LastName`. If accepted, JIT provisioning creates/logs in that user. A probing attacker can first send a minimally‑valid unsigned assertion to detect acceptance (success redirect vs. “SAML login failed”) and then follow with a targeted identity.
- **Tension / Game**: **Compatibility vs. integrity** — administrators may relax signature requirements to support IdPs with incomplete signing, trading off assertion integrity. The attacker adapts by probing response behavior to determine whether signatures are enforced.
- **What was sacrificed / Information accumulated**: Signature verification integrity is sacrificed via `sp_settings` overrides; the attacker learns enforcement posture by observing success vs. failure in repeated SAMLResponse submissions.
- **Security consequence**: Unsigned assertion acceptance → arbitrary account creation or impersonation via JIT provisioning.
- **Severity estimate**: CRITICAL
- **Read needed**: `redash/authentication/saml_auth.py:48-67, 96-100, 109-138`
- **Deepening direction**: Identify concrete `auth_saml_sp_settings` values allowed by UI/API, and whether default configs or migrations ever set `want_assertions_signed=false` for compatibility.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| `redash/handlers/authentication.py:176` — `login` | NO — out of scope per strategist focus | NO — out of scope per strategist focus |
| `redash/authentication/google_oauth.py:80` — `authorize_org` | NO — out of scope per strategist focus | NO — out of scope per strategist focus |
| `redash/authentication/google_oauth.py:85` — `authorize` | NO — out of scope per strategist focus | NO — out of scope per strategist focus |
| `redash/authentication/google_oauth.py:97` — `callback` | NO — out of scope per strategist focus | NO — out of scope per strategist focus |
| `redash/authentication/saml_auth.py:109` — `idp_initiated` | PH-02 / YES — config-driven signature relaxation | PH-02 / YES — probing success vs failure |
| `redash/authentication/saml_auth.py:149` — `sp_initiated` | PH-01 / YES — metadata-driven redirect trust | NO — not applicable: no repeated interaction required |
| `redash/authentication/ldap_auth.py:32` — `login` | NO — out of scope per strategist focus | NO — out of scope per strategist focus |
| `redash/authentication/remote_user_auth.py:19` — `login` | NO — out of scope per strategist focus | NO — out of scope per strategist focus |
| `redash/authentication/__init__.py:164` — `jwt_token_load_user_from_request` | NO — out of scope per strategist focus | NO — out of scope per strategist focus |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| SAML sp_initiated path (`redash/authentication/saml_auth.py:149`) lacks validated coverage. | PH-01 / YES — tension confirmed |
| PH-03 invalidation is Fragile due to config-driven SAML signature requirements; examine contradictory assumptions/alternate branches where signature checks could be relaxed via `sp_settings` overrides. | PH-02 / YES — tension confirmed |

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| SAMLResponse parse outcomes in `idp_initiated` | PH-02 / YES — response difference reveals signature enforcement |
