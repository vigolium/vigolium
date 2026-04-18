Phase: 10
Sequence: 046
Slug: provisioning-encrypt-v1-schema-gap
Verdict: VALID
Rationale: RemoveSecretsForContactPoint at contactpoints.go:661 and EncryptReceiverConfigSettings at alertmanager_config.go:341 share the identical V1 hardcoding root cause as crypto.go:88, creating a second and third site where secrets in newly-added integration fields escape encryption and redaction on both provisioning create/update and config GET paths.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-045-receiver-v1-schema-secret-leak.md
Origin-Pattern: AP-045

## Summary

Two functions share the same V1 schema hardcoding root cause as the confirmed finding at `crypto.go:88`: (1) `RemoveSecretsForContactPoint` at `pkg/services/ngalert/provisioning/contactpoints.go:661` which is called during `CreateContactPoint` and `UpdateContactPoint`, and (2) the `EncryptReceiverConfigSettings` call at `pkg/services/ngalert/notifier/alertmanager_config.go:341` on the full alertmanager config GET path. Both call `alertingNotify.GetSchemaVersionForIntegration(type, schema.V1)` and then call `GetSecretFieldsPaths()`, meaning only V1-defined secret fields are extracted from `Settings` into `SecureSettings`. Any secret field added to an integration schema after V1 (or in a future schema version) would remain plaintext in `Settings` and be stored in the database. On read, `Integration.Redact()` only redacts fields it recognizes from its assigned V1 `Config`, so the plaintext value is returned in API responses.

## Location

- `pkg/services/ngalert/provisioning/contactpoints.go:661` — `RemoveSecretsForContactPoint` hardcodes `schema.V1`
- `pkg/services/ngalert/provisioning/contactpoints.go:271` — `UpdateContactPoint` hardcodes `schema.V1` for the same purpose
- `pkg/services/ngalert/notifier/alertmanager_config.go:341` — `EncryptReceiverConfigSettings` called on GET path with V1-aware function
- Affected write endpoints: `POST /api/v1/provisioning/contact-points`, `PUT /api/v1/provisioning/contact-points/{UID}`
- Affected read endpoint: `GET /api/alertmanager/grafana/config/api/v1/alerts` (Admin only)

## Attacker Control

For `RemoveSecretsForContactPoint` (contactpoints.go:661): An admin creates or updates a contact point via the provisioning API. The contact point type has a secret field not recognized by V1 schema. That field stays plaintext in Settings in the database. Any user with `ActionAlertingNotificationsRead` (Viewer role) reading `GET /api/v1/provisioning/contact-points` subsequently receives the plaintext secret in the `settings` JSON.

For `EncryptReceiverConfigSettings` (alertmanager_config.go:341): An admin reads `GET /api/alertmanager/grafana/config/api/v1/alerts`. The function calls `EncryptReceiverConfigSettings` on V1 paths only. Any pre-existing plaintext secret in `Settings` for a non-V1 field is returned in the `GettableGrafanaReceiver.Settings` JSON response. This endpoint requires Admin, so the audience is limited.

## Trust Boundary Crossed

For the provisioning API path: Viewer role -> notification integration credentials stored as plaintext in `settings`. Same trust boundary as p8-045.

For the alertmanager config path: Admin users can already read secrets, so no new trust boundary is crossed. However, it represents a defense-in-depth failure.

## Impact

- Same systematic impact as p8-045 on the provisioning API create/update path
- Any integration type that gains a new secret field after V1 will store that field plaintext in Settings via both `encryptReceiverConfigs` (crypto.go:88) AND `RemoveSecretsForContactPoint` (contactpoints.go:661)
- The plaintext persists in database and is subsequently returned without redaction to Viewer-role users via `GET /api/v1/provisioning/contact-points`
- The `EncryptReceiverConfigSettings` call on the alertmanager config GET path also fails to encrypt such fields, meaning they appear in the full config export

## Evidence

```go
// pkg/services/ngalert/provisioning/contactpoints.go:658-676
func RemoveSecretsForContactPoint(e *apimodels.EmbeddedContactPoint) (map[string]string, error) {
    s := map[string]string{}
    typeSchema, ok := alertingNotify.GetSchemaVersionForIntegration(schema.IntegrationType(e.Type), schema.V1)
    // ^-- hardcoded schema.V1, same as crypto.go:88
    if !ok {
        return nil, fmt.Errorf("failed to get secret keys for contact point type %s", e.Type)
    }
    for _, secretPath := range typeSchema.GetSecretFieldsPaths() {
        // Only V1 secret fields extracted; non-V1 fields remain in Settings
```

```go
// pkg/services/ngalert/notifier/alertmanager_config.go:341-344
if err := EncryptReceiverConfigSettings(alertmanagerConfig.Receivers, func(ctx context.Context, payload []byte) ([]byte, error) {
    return moa.Crypto.Encrypt(ctx, payload, secrets.WithoutScope())
}); err != nil {
    // EncryptReceiverConfigSettings calls encryptReceiverConfigs with schema.V1
    // Non-V1 secret fields are NOT moved to SecureSettings
```

```go
// pkg/services/ngalert/provisioning/contactpoints.go:271-281 (UpdateContactPoint)
typeSchema, ok := alertingNotify.GetSchemaVersionForIntegration(iType, schema.V1)
// Used to restore "<REDACTED>" values; non-V1 fields cannot be redacted or restored
for _, secretPath := range typeSchema.GetSecretFieldsPaths() {
    secretKey := secretPath.String()
    secretValue := contactPoint.Settings.Get(secretKey).MustString()
    if secretValue == apimodels.RedactedValue {
        contactPoint.Settings.Set(secretKey, rawContactPoint.Settings.Get(secretKey).MustString())
```

## Reproduction Steps

1. Using an integration type that has a hypothetical non-V1 secret field (or wait for a schema update that adds new secret fields):
   - As Admin, `POST /api/v1/provisioning/contact-points` with the secret field in `settings` JSON
2. `RemoveSecretsForContactPoint` extracts only V1 secret fields; the non-V1 secret field remains in `settings`
3. The contact point is saved with the plaintext secret in `settings` in the database
4. As Viewer-role user, `GET /api/v1/provisioning/contact-points`
5. Observe: the `settings` JSON in the response contains the plaintext secret value
6. Observe: the `secureSettings` map shows `"<REDACTED>"` only for V1 secrets; the new field has plaintext in `settings`
7. For the alertmanager config path: As Admin, `GET /api/alertmanager/grafana/config/api/v1/alerts`; the raw Settings field contains any non-V1 plaintext secret
