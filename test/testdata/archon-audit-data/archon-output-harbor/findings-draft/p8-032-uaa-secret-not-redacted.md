Phase: 8
Sequence: 032
Slug: uaa-secret-not-redacted
Verdict: VALID
Rationale: UAAClientSecret is defined as StringType (not PasswordType) in metadatalist.go, causing ConvertForGet to skip redaction; any system admin receives UAA client secret in plaintext via normal GET /configurations API call.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md

## Summary

The `UAAClientSecret` configuration field is incorrectly defined with `ItemType: &StringType{}` at `metadatalist.go:126`, while all other secret fields (LDAP password, OIDC client secret, PostgreSQL password, etc.) are correctly defined as `&PasswordType{}`. The `ConvertForGet` method in `controller.go:236-240` only strips fields typed as `*metadata.PasswordType`, so the UAA client secret survives the redaction pass and appears in plaintext in the API response for any system administrator.

## Location

- `src/lib/config/metadata/metadatalist.go:126` -- `UAAClientSecret` with `ItemType: &StringType{}` (should be `&PasswordType{}`)
- `src/controller/config/controller.go:236-240` -- `ConvertForGet` type-switch only matches `*metadata.PasswordType`

## Attacker Control

- Any system admin calls `GET /api/v2.0/configurations`
- UAA client secret returned in plaintext in response body
- No special authentication beyond system admin role required

## Trust Boundary Crossed

- Admin API to credential exposure -- admin should see config but NOT secrets

## Impact

- UAA client secret exposed to any system administrator
- Can be used to impersonate Harbor against UAA identity provider
- Enables token minting via UAA with Harbor's client identity
- Different root cause from H-00b (type annotation error vs. auth bypass)

## Evidence

- metadatalist.go:126: `ItemType: &StringType{}` (contrast line 141: OIDCClientSecret uses `&PasswordType{}`)
- controller.go:236-240: type switch only deletes PasswordType
- Bypass analysis bypass-85e756486: wrong LDAP redaction key identified similar pattern

## Reproduction Steps

1. Configure Harbor with UAA authentication mode and set a UAA client secret
2. Authenticate as system administrator (not solution-user)
3. Send: `GET /api/v2.0/configurations`
4. Verify `uaa_client_secret` field contains plaintext secret value
5. Contrast: `oidc_client_secret` field should be redacted (PasswordType)
