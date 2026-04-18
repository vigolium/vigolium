Phase: 10
Sequence: 048
Slug: update-contact-point-v1-redacted-bypass
Verdict: VALID
Rationale: UpdateContactPoint at contactpoints.go:271 hardcodes schema.V1 to determine which settings fields bearing the value "<REDACTED>" should be restored from storage, meaning any non-V1 secret field submitted with "<REDACTED>" value is left as the literal string "<REDACTED>" in the stored settings, silently corrupting the integration configuration without error.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-045-receiver-v1-schema-secret-leak.md
Origin-Pattern: AP-045

## Summary

In `UpdateContactPoint` at `pkg/services/ngalert/provisioning/contactpoints.go:271`, the function fetches the schema via `alertingNotify.GetSchemaVersionForIntegration(iType, schema.V1)` to determine which fields in the incoming contact point settings have the value `apimodels.RedactedValue` (`"<redacted>"`) and should be silently replaced with the actual value from the stored contact point. Only V1 secret fields are checked for the redacted sentinel value. Any integration secret field added after V1 that a client submits with `"<redacted>"` to signal "keep existing value" is NOT detected as a redacted-value sentinel; instead, the literal string `"<redacted>"` is stored in the database as the field's value. This silent write corruption leaves the integration misconfigured without returning an error, and exposes the sentinel string as plaintext in subsequent GET responses. Combined with the write-path V1 gap (crypto.go:88) and read-path V1 gap (compat.go:157), this creates a third site where V1 schema hardcoding causes incorrect behavior.

## Location

- `pkg/services/ngalert/provisioning/contactpoints.go:271` — `UpdateContactPoint` fetches V1 schema for redacted-value detection
- `pkg/services/ngalert/provisioning/contactpoints.go:281-286` — only V1 `secretPath` fields checked for `RedactedValue`
- `pkg/services/ngalert/provisioning/contactpoints.go:308` — `RemoveSecretsForContactPoint` also uses V1, creating compound missed-field problem
- Affected endpoint: `PUT /api/v1/provisioning/contact-points/{UID}`

## Attacker Control

An attacker with Editor-role (who can update contact points) submits a `PUT /api/v1/provisioning/contact-points/{UID}` request with `"<redacted>"` as the value for a non-V1 secret field (any field present in the stored contact point's Settings that is not in V1 secret paths). The code silently stores `"<redacted>"` as the actual field value rather than restoring the original secret. The integration will subsequently fail to authenticate because the field value is the sentinel string rather than the real credential. Additionally, a subsequent GET by a Viewer will see `"<redacted>"` as the `settings` value for that field, revealing it is a sentinel-string value rather than a real credential.

## Trust Boundary Crossed

Editor role -> incorrect mutation of contact point secrets without error feedback. This is a write-path integrity issue: the attacker (even a legitimate Editor) can silently corrupt a non-V1 secret field by submitting `<redacted>` which the code fails to recognize as the "preserve existing value" sentinel.

## Impact

- Silent write corruption: Editor submits `<redacted>` for a non-V1 secret field; code stores the literal sentinel string; integration breaks at next alert
- No error returned; the write appears successful
- Subsequent GET responses show `"<redacted>"` as plaintext in settings, which is confusing and exposes the sentinel pattern  
- Any integration type with non-V1 secret fields is vulnerable to this update path corruption
- Combined with p8-045 and p10-047: the full cycle is write-path misses encryption, read-path misses redaction, update-path misses sentinel detection — all three from same V1 hardcoding root cause

## Evidence

```go
// pkg/services/ngalert/provisioning/contactpoints.go:267-287
iType, err := alertingNotify.IntegrationTypeFromString(contactPoint.Type)
// ...
typeSchema, ok := alertingNotify.GetSchemaVersionForIntegration(iType, schema.V1)
// ^-- hardcoded schema.V1; only V1 secret paths will be checked for "<redacted>"
if !ok {
    return fmt.Errorf("%w: failed to get secret keys for contact point type %s", ErrValidation, contactPoint.Type)
}
rawContactPoint, err := ecp.getContactPointDecrypted(ctx, orgID, contactPoint.UID)
// ...
for _, secretPath := range typeSchema.GetSecretFieldsPaths() {
    secretKey := secretPath.String()
    secretValue := contactPoint.Settings.Get(secretKey).MustString()
    if secretValue == apimodels.RedactedValue {
        // Only V1 fields restored; non-V1 fields with "<redacted>" are NOT detected here
        contactPoint.Settings.Set(secretKey, rawContactPoint.Settings.Get(secretKey).MustString())
    }
}
```

```go
// pkg/services/ngalert/provisioning/contactpoints.go:308
extractedSecrets, err := RemoveSecretsForContactPoint(&contactPoint)
// RemoveSecretsForContactPoint ALSO uses schema.V1 (contactpoints.go:661)
// So the non-V1 field with literal "<redacted>" value:
// 1. Is not restored by the loop above (not a V1 secret path)
// 2. Is not moved to SecureSettings by RemoveSecretsForContactPoint (not a V1 secret path)
// 3. Is stored as-is in Settings with value "<redacted>" (literal string)
```

## Reproduction Steps

1. Create a contact point of type `webhook` with a non-V1 hypothetical secret field `futureSecret` using direct DB or config push
2. As Editor, `PUT /api/v1/provisioning/contact-points/{UID}` with body: `{"settings": {"futureSecret": "<redacted>", ...other fields...}}`
3. The loop at line 281 iterates only V1 paths (e.g., `password`, `authorization_credentials`, TLS nested fields) — `futureSecret` is NOT in V1 paths
4. `futureSecret` value `"<redacted>"` is NOT replaced with the stored value
5. `RemoveSecretsForContactPoint` also misses `futureSecret` (V1 only), so it stays in Settings
6. Database stores `{"futureSecret": "<redacted>"}` in settings column — literal string, not real credential
7. Next alert delivery fails because `futureSecret` = `"<redacted>"` is not the real token
8. GET response exposes `"<redacted>"` as plaintext in `settings.futureSecret`
