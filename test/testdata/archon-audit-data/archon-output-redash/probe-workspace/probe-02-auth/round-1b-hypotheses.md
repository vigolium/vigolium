# Round 1 Hypotheses — Auth (SAML focus)

## PH-01: Unsigned SAML assertion accepted after sp_settings override

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/authentication/saml_auth.py:48-66,96-100` — `get_saml_client`
- **Attacker starting position**: authenticated org-admin (or attacker with access to org SAML settings store)
- **Attack input**: set org setting `auth_saml_sp_settings` to `{"want_assertions_signed": false, "want_response_signed": false}` and keep `auth_saml_enabled=true`
- **Chain**: attacker updates org SAML sp_settings → `get_saml_client` merges JSON into `service.sp` config → SAML client no longer requires signed assertions → attacker posts unsigned `SAMLResponse` to `/saml/callback` and JIT-provisions a user via `create_and_login_user` → attacker gets authenticated session
- **Catastrophe / Dangerous fallback**: forged SAML response yields account creation/login without IdP signature, enabling full org takeover
- **Severity estimate**: CRITICAL
- **Read needed**: `redash/authentication/saml_auth.py:48-100`
- **Deepening direction**: confirm whether `auth_saml_sp_settings` is admin-configurable via UI/API and whether `want_assertions_signed`/`want_response_signed` truly disable signature validation in pysaml2.

---

## PH-02: SP-initiated redirect can be steered to attacker IdP metadata

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/authentication/saml_auth.py:31-55,160-167` — `get_saml_client` + `sp_initiated`
- **Attacker starting position**: network-adjacent attacker able to tamper with IdP metadata fetch, or authenticated org-admin who can edit `auth_saml_metadata_url`
- **Attack input**: change `auth_saml_metadata_url` to attacker-controlled HTTPS endpoint returning metadata with `SingleSignOnService Location=https://evil.example/sso` and then trigger `GET /<org>/saml/login`
- **Chain**: attacker supplies malicious IdP metadata → `get_saml_client` loads remote metadata without pinning → `sp_initiated` extracts `Location` header from `prepare_for_authenticate` and issues 302 → victim is redirected to attacker IdP which can mint a SAMLResponse for arbitrary email → JIT provisioning logs attacker in
- **Catastrophe / Dangerous fallback**: SP-initiated login becomes a launchpad to rogue IdP, enabling attacker-controlled identity assertions
- **Severity estimate**: HIGH
- **Read needed**: `redash/authentication/saml_auth.py:31-55,160-167`
- **Deepening direction**: verify if metadata fetch uses HTTPS-only/pinning, and whether metadata URL is mutable by non-admin users or by SSRF-style config paths.

---

## PH-03: Config-driven signature requirements allow PH-03 invalidation bypass in IdP-initiated flow

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/authentication/saml_auth.py:60-67,96-100,109-136` — `get_saml_client` + `idp_initiated`
- **Attacker starting position**: authenticated org-admin (or attacker with write access to SAML config store)
- **Attack input**: set `auth_saml_sp_settings` to `{"want_assertions_signed": false}` and then POST `SAMLResponse=<unsigned assertion with email=admin@org>` to `/saml/callback`
- **Chain**: attacker weakens SP signature requirements via config → `idp_initiated` parses response without enforcing assertion signature → `create_and_login_user` JIT-provisions attacker-chosen identity → attacker gains session as arbitrary user
- **Catastrophe / Dangerous fallback**: signature validation is effectively disabled by configuration, allowing IdP-initiated login forgery
- **Severity estimate**: CRITICAL
- **Read needed**: `redash/authentication/saml_auth.py:60-136`
- **Deepening direction**: check pysaml2 behavior when `want_assertions_signed=False` and whether any additional signature verification exists elsewhere.

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| `redash/authentication/saml_auth.py:149` — `sp_initiated` | PH-02 | NO — not applicable: no defensive pattern tied to SP-initiated path in anatomy |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| `redash/authentication/saml_auth.py:157-159` — fallback to `NAMEID_FORMAT_TRANSIENT` | NO — not applicable: fallback affects NameID format only, no clear privilege gain without signature bypass |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| SAML sp_initiated path lacks validated coverage | PH-02 |
| PH-03 invalidation fragile via config-driven SAML signature requirements | PH-01 / PH-03 |
