Phase: 8
Sequence: 045
Slug: receiver-v1-schema-secret-leak
Verdict: VALID
Rationale: V1 schema hardcoding at crypto.go:88 creates systematic secret exposure for V2+ integration fields, bypassing FilterRead/FilterReadDecrypted which only suppress SecureSettings, confirmed by CVE-2024-11741 and CVE-2025-3415 pattern recurrence.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-3/debate.md

## Summary

The `EncryptReceiverConfigs` function at `pkg/services/ngalert/notifier/crypto.go:88` hardcodes `schema.V1` when calling `GetSchemaVersionForIntegration()` to discover secret field paths. This means only secret fields defined in the V1 schema are recognized, encrypted, and moved to `SecureSettings`. Any secret field added in V2 or later schema versions remains as plaintext in the `Settings` JSON blob. The `FilterRead` and `FilterReadDecrypted` access control functions only suppress the `SecureSettings` map, not the `Settings` JSON body, so plaintext V2+ secrets are visible to any user with `ActionAlertingNotificationsRead` permission (Viewer role).

## Location

- `pkg/services/ngalert/notifier/crypto.go:88` — hardcoded `schema.V1`
- `pkg/services/ngalert/notifier/receiver_svc.go:231-235` — FilterRead suppresses SecureSettings only
- Viewer-accessible endpoints: `GET /api/v1/provisioning/contact-points`, `GET /api/alertmanager/grafana/config/api/v1/receivers`

## Attacker Control

Any authenticated user with Viewer role (which includes `ActionAlertingNotificationsRead` by default) can read the Settings JSON containing plaintext secrets for any notification integration whose secret fields were added after V1 schema.

## Trust Boundary Crossed

Viewer role -> notification integration credentials. The trust boundary is the access control on sensitive credentials (API keys, webhook tokens) stored in alerting notification integrations.

## Impact

- Exposure of plaintext credentials (webhook tokens, API keys, passwords) for alerting notification integrations
- Viewer-accessible endpoints return these credentials without encryption or suppression
- Systematic gap: affects all integration types that added secret fields in V2+ schema
- Matches confirmed CVE pattern: CVE-2024-11741 (VictorOps token) and CVE-2025-3415 (DingDing webhook token)

## Evidence

```go
// pkg/services/ngalert/notifier/crypto.go:88
typeSchema, ok := alertingNotify.GetSchemaVersionForIntegration(schema.IntegrationType(gr.Type), schema.V1)
// Only V1 secret paths are returned
secretPaths := typeSchema.GetSecretFieldsPaths()
// V2+ secrets remain plaintext in Settings JSON
```

```go
// pkg/services/ngalert/notifier/receiver_svc.go:231-235
filterFn := rs.authz.FilterReadDecrypted
if !q.Decrypt {
    filterFn = rs.authz.FilterRead  // Only suppresses SecureSettings map
}
```

## Reproduction Steps

1. Create a notification integration of a type that has V2+ schema secret fields
2. Configure the integration with a secret value in a V2+ field
3. As a Viewer-role user, call `GET /api/v1/provisioning/contact-points`
4. Observe: the `settings` JSON in the response contains the plaintext secret
5. Verify: the `secureSettings` map correctly shows `"<REDACTED>"` for V1 secrets, but V2+ secrets are in `settings` as plaintext
6. Confirm: the V1 schema's `GetSecretFieldsPaths()` does not include the V2+ field
