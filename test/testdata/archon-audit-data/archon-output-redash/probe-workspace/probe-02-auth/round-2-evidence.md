# Evidence — redash/authentication (SAML)

## [HARVESTER] PH-01: Unsigned SAML assertion accepted after sp_settings override

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/saml_auth.py:36-37` — `get_saml_client` reads org setting `auth_saml_sp_settings`.
2. `redash/authentication/saml_auth.py:48-67` — default `service.sp` config includes signature requirements.
3. `redash/authentication/saml_auth.py:96-100` — `sp_settings` JSON is merged into `saml_settings["service"]["sp"]` with no validation.
4. `redash/authentication/saml_auth.py:101-105` — `Saml2Config` loaded with merged settings and `Saml2Client` created.
5. `redash/authentication/saml_auth.py:115-118` — `idp_initiated` parses `request.form["SAMLResponse"]` via `parse_authn_request_response` using that config.
6. `redash/authentication/saml_auth.py:125-136` — JIT provisioning via `create_and_login_user` with assertion data.

**Sanitizers on path**:
- None found in code (no validation of `sp_settings` before applying to `service.sp`).

**Verdict rationale**: The SP configuration is directly overridden from `auth_saml_sp_settings` without validation, so a setting that disables assertion/response signature requirements flows into the SAML client used to parse the incoming `SAMLResponse`. The code performs JIT provisioning based on parsed assertion data with no additional signature checks in this path.

---

## [HARVESTER] PH-02: SP-initiated redirect can be steered to attacker IdP metadata

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/saml_auth.py:35` — `get_saml_client` reads org setting `auth_saml_metadata_url`.
2. `redash/authentication/saml_auth.py:48-49` — metadata configured as `{"remote": [{"url": metadata_url}]}` with no allowlist or validation.
3. `redash/authentication/saml_auth.py:101-105` — `Saml2Client` created from metadata-backed config.
4. `redash/authentication/saml_auth.py:155-161` — `sp_initiated` calls `prepare_for_authenticate`, receiving headers derived from metadata.
5. `redash/authentication/saml_auth.py:163-167` — takes `Location` header as `redirect_url` and issues a 302 redirect.

**Sanitizers on path**:
- None found in code (no validation of `metadata_url` or `redirect_url`).

**Verdict rationale**: The SP-initiated flow trusts the IdP metadata URL from org settings and uses the `Location` header returned by the SAML client to redirect without local validation. If metadata is attacker-controlled, the redirect target can be attacker-chosen.

---

## [HARVESTER] PH-03: Config-driven signature requirements allow IdP-initiated bypass

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/saml_auth.py:36-37` — `get_saml_client` reads `auth_saml_sp_settings`.
2. `redash/authentication/saml_auth.py:96-100` — JSON is merged into `service.sp` without validation.
3. `redash/authentication/saml_auth.py:101-105` — SAML client built from merged settings.
4. `redash/authentication/saml_auth.py:115-118` — `idp_initiated` parses `SAMLResponse` using the configured client.
5. `redash/authentication/saml_auth.py:125-136` — uses assertion attributes for JIT provisioning via `create_and_login_user`.

**Sanitizers on path**:
- None found in code (no guard preventing disabling signature requirements via `sp_settings`).

**Verdict rationale**: The code applies `auth_saml_sp_settings` overrides directly to the SP config and then parses inbound assertions with that configuration, which can disable signature requirements without additional checks in the request handler.

---

## [HARVESTER] PH-301: SAML metadata integrity is a confounded protection

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/saml_auth.py:35` — `get_saml_client` reads `auth_saml_metadata_url` from org settings.
2. `redash/authentication/saml_auth.py:48-49` — metadata is configured as a remote URL without validation or pinning.
3. `redash/authentication/saml_auth.py:101-105` — SAML client is instantiated using that metadata.
4. `redash/authentication/saml_auth.py:115-118` — `idp_initiated` parses `SAMLResponse` with this client.
5. `redash/authentication/saml_auth.py:125-136` — assertion attributes drive JIT provisioning/login.

**Sanitizers on path**:
- None found in code (metadata integrity or trust constraints are not enforced here).

**Verdict rationale**: The trust anchor for SAML validation (IdP metadata) is taken directly from a remote URL configured per org, with no in-code integrity checks or allowlists before use in `Saml2Client`. This makes signature validation dependent on external metadata integrity rather than local enforcement.

---

## [HARVESTER] PH-302: SAML signature requirements are configurable and not causally necessary

**Verdict**: VALIDATED

**Code path**:
1. `redash/authentication/saml_auth.py:36-37` — `get_saml_client` reads `auth_saml_sp_settings`.
2. `redash/authentication/saml_auth.py:48-67` — defaults require signed assertions but are just part of the mutable config.
3. `redash/authentication/saml_auth.py:96-100` — `sp_settings` JSON overrides `service.sp` settings without validation.
4. `redash/authentication/saml_auth.py:101-105` — `Saml2Client` constructed from overridden config.
5. `redash/authentication/saml_auth.py:115-118` — `idp_initiated` parses incoming `SAMLResponse` with that config.
6. `redash/authentication/saml_auth.py:125-136` — JIT provisioning on parsed attributes.

**Sanitizers on path**:
- None found in code (no enforcement that signature requirements remain enabled).

**Verdict rationale**: The SP’s signature requirements are not fixed in code; they are overridden by org-supplied JSON and then used for parsing inbound assertions. There is no additional server-side guard to prevent operating with relaxed signature settings.

---
