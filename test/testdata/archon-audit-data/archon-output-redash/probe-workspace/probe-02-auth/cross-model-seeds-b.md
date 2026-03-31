## CROSS-B01: SAML sp_initiated trusts metadata-driven redirect target

Source-A: PH-02 from backward-reasoner (round-1b-hypotheses.md)
Source-B: PH-01 from contradiction-reasoner (round-2b-hypotheses.md)
Connection: Same `sp_initiated` endpoint and metadata-driven redirect; both hinge on trust in `auth_saml_metadata_url` and IdP metadata without local validation.
Combined hypothesis: If an attacker can influence or replace SAML metadata (via admin setting or network tampering), the SP-initiated flow redirects users to a rogue IdP whose assertions are then trusted, enabling unauthorized login/JIT provisioning.
Test direction for causal-verifier: Determine how metadata URL is provisioned and whether pysaml2 validates metadata signatures or enforces pinned certificates.

## CROSS-B02: Config overrides can disable SAML signature enforcement

Source-A: PH-01/PH-03 from backward-reasoner (round-1b-hypotheses.md)
Source-B: PH-02 from contradiction-reasoner (round-2b-hypotheses.md)
Connection: All target `get_saml_client` config merging of `sp_settings` and the `idp_initiated` signature checks.
Combined hypothesis: `auth_saml_sp_settings` overrides can reduce or disable signature requirements, allowing unsigned assertions to be accepted and used for JIT provisioning.
Test direction for causal-verifier: Confirm which sp_settings are accepted from org config and whether any UI/API validation prevents disabling `want_assertions_signed`.
