# Round 4 Hypotheses

## Focus: Contact point export decrypt auth bypass, VictorOps redaction completeness, SnapshotPublicModeOrCreate middleware gap

---

### PH-19: Contact Point Export Decrypt Bypass via Provisioning Read Permission
**Hypothesis**: The export endpoint allows `decrypt=true` query param. Authorization at authorization.go:311-321 requires ANY of several permissions including `ActionAlertingReceiversRead` (without ReadSecrets). A user with only `ActionAlertingReceiversRead` could access the export endpoint and pass `decrypt=true` to get decrypted secrets.
**Test**: Verify the auth evaluator is EvalAny (line 321), meaning any single permission is sufficient. Check if `decrypt=true` requires `ReadSecrets` permission specifically.

### PH-20: VictorOps URL Redaction Completeness
**Hypothesis**: VictorOps URL is typed as `Secret` in contact_points.go:299. The `Redact()` function at receivers.go:322 iterates `GetSecretFieldsPaths()`. If the VictorOps integration schema correctly marks the URL as a secret path, it should be redacted. Verify the schema marks it correctly.
**Test**: Check the alerting schema for VictorOps secret paths.

### PH-21: SnapshotPublicModeOrCreate Middleware Does Not Call RBAC Middleware
**Hypothesis**: The `SnapshotPublicModeOrCreate` middleware at auth.go:238-251 has a bug: when the user IS signed in and public mode is disabled, it constructs the RBAC middleware but doesn't actually invoke it against the request context.
**Test**: Read auth.go:238-251 carefully to check if the RBAC middleware is properly invoked.
