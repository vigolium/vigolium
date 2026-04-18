Phase: 10
Sequence: 047
Slug: integration-v1-config-assignment-redact-bypass
Verdict: VALID
Rationale: PostableGrafanaReceiverToIntegration at legacy_storage/compat.go:157 hard-assigns schema.V1 as Integration.Config, which propagates to every Encrypt/Redact/SecureFields call on that integration, forming the read-path counterpart of the crypto.go:88 write-path root cause and completing the end-to-end plaintext exposure chain through the provisioning API.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-045-receiver-v1-schema-secret-leak.md
Origin-Pattern: AP-045

## Summary

`PostableGrafanaReceiverToIntegration` at `pkg/services/ngalert/notifier/legacy_storage/compat.go:157` calls `GetSchemaVersionForIntegration(integrationType, schema.V1)` and assigns the resulting V1 `IntegrationSchemaVersion` as the `Config` field of the returned `models.Integration`. This `Config` is later used by `Integration.Encrypt()` at `models/receivers.go:213`, `Integration.Redact()` at `models/receivers.go:322`, and `Integration.SecureFields()` at `models/receivers.go:360` to enumerate which fields are secret. All three methods call `integration.Config.GetSecretFieldsPaths()`, which returns only V1 secret paths. If an integration has any secret field not in V1 (for example, added in a later schema), that field is never moved from `Settings` to `SecureSettings` during encryption, never redacted during read, and never reported in the SecureFields map. This compat function is the central mechanism through which the write-path V1 gap (crypto.go:88) manifests as a read-path disclosure on the provisioning GET endpoint.

## Location

- `pkg/services/ngalert/notifier/legacy_storage/compat.go:157` — hardcoded `schema.V1` in `PostableGrafanaReceiverToIntegration`
- `pkg/services/ngalert/models/receivers.go:213-237` — `Integration.Encrypt()` uses `integration.Config.GetSecretFieldsPaths()`
- `pkg/services/ngalert/models/receivers.go:322-337` — `Integration.Redact()` uses `integration.Config.GetSecretFieldsPaths()`
- `pkg/services/ngalert/models/receivers.go:360-383` — `Integration.SecureFields()` uses `integration.Config.GetSecretFieldsPaths()`
- `pkg/services/ngalert/notifier/receiver_svc.go:244-255` — `GetReceivers` calls `rcv.Encrypt()/Redact()` relying on V1 Config

## Attacker Control

Any authenticated user with the Viewer role (which has `ActionAlertingReceiversRead` via `receiversReaderRole`) who calls `GET /api/v1/provisioning/contact-points` receives all contact points with their `settings` JSON. When a secret field is stored plaintext in `settings` (because both `EncryptReceiverConfigs` at crypto.go:88 and `Integration.Encrypt()` using V1 Config both missed it), that value is returned without redaction. The V1 Config assignment in `PostableGrafanaReceiverToIntegration` is the mechanism that ensures the read path does not redact what the write path did not encrypt.

## Trust Boundary Crossed

Viewer role -> notification integration credentials. This is the read-path completion of the p8-045 write-path root cause: the V1 Config assignment ensures that any secret that escaped encryption at write time also escapes redaction at read time.

## Impact

- Completes the exploit chain from p8-045: write-path misses encryption → read-path misses redaction → plaintext secret returned to Viewer
- `Integration.SecureFields()` returning incorrect results also affects the `secureFields` map in API responses (`GettableGrafanaReceiver.SecureFields`), which the frontend uses to decide which fields to render as redacted
- Any new integration type or schema update adding secret fields will immediately be visible plaintext to all Viewers through this propagating V1 assignment

## Evidence

```go
// pkg/services/ngalert/notifier/legacy_storage/compat.go:152-170
func PostableGrafanaReceiverToIntegration(p *apimodels.PostableGrafanaReceiver) (*models.Integration, error) {
    integrationType, err := alertingNotify.IntegrationTypeFromString(p.Type)
    // ...
    config, ok := alertingNotify.GetSchemaVersionForIntegration(integrationType, schema.V1)
    // ^-- hardcoded schema.V1; Integration.Config is permanently V1
    if !ok {
        return nil, fmt.Errorf("integration type [%s] does not have schema of version %s", integrationType, schema.V1)
    }
    integration := &models.Integration{
        // ...
        Config: config,  // V1 schema propagates to all Encrypt/Redact/SecureFields calls
        // ...
    }
```

```go
// pkg/services/ngalert/models/receivers.go:213-235
func (integration *Integration) Encrypt(encryptFn EncryptFn) error {
    secretFieldPaths := integration.Config.GetSecretFieldsPaths()
    // ^-- uses V1 schema assigned by PostableGrafanaReceiverToIntegration
    // Non-V1 secret fields are never moved to SecureSettings
```

```go
// pkg/services/ngalert/models/receivers.go:322-337
func (integration *Integration) Redact(redactFn RedactFn) {
    for _, path := range integration.Config.GetSecretFieldsPaths() {
        // ^-- V1 paths only; non-V1 secret field remains plaintext in Settings
    }
    for key, secureVal := range integration.SecureSettings {
        // Only redacts keys already in SecureSettings (which is empty for missed fields)
```

```go
// pkg/services/ngalert/notifier/receiver_svc.go:231-255
filterFn := rs.authz.FilterReadDecrypted
if !q.Decrypt {
    filterFn = rs.authz.FilterRead  // Suppresses SecureSettings only, not Settings
}
// ...
for _, rcv := range filtered {
    if q.Decrypt {
        err := rcv.Decrypt(rs.decryptor(ctx))
    } else {
        err := rcv.Encrypt(rs.encryptor(ctx))
        // Encrypt uses V1 Config; non-V1 plaintext secrets remain in Settings
```

## Reproduction Steps

1. Identify an integration type with a non-V1 secret field (or trigger via a schema update)
2. Configure the integration; the write path (EncryptReceiverConfigs at crypto.go:88) stores the secret plaintext in Settings because V1 schema doesn't recognize it
3. As Viewer-role user, `GET /api/v1/provisioning/contact-points`
4. The read path: `GetReceivers` → `PostableGrafanaReceiverToIntegration` (assigns V1 Config) → `rcv.Encrypt()` (only moves V1 fields to SecureSettings) → `Redact()` (only redacts V1 fields + existing SecureSettings)
5. The non-V1 secret field remains plaintext in Settings and is returned in the response `settings` JSON
6. Compare with V1 secrets: they appear in SecureSettings as `"<REDACTED>"`; the non-V1 secret appears plaintext in `settings`
