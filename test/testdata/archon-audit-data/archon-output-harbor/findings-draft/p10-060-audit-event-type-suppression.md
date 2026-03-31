Phase: 10
Sequence: 060
Slug: audit-event-type-suppression
Verdict: VALID
Rationale: A system administrator can suppress audit logging for any specific operation type (e.g., delete_user, create_user) by setting disabled_audit_log_event_types via PUT /api/v2.0/configurations, with no validation on which event types may be disabled and no audit record of the suppression itself.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-020-audit-evidence-destruction.md
Origin-Pattern: AP-020

## Summary

The `disabled_audit_log_event_types` configuration field (`AuditLogEventsDisabled` constant) allows a system administrator to selectively silence audit logging for specific operation types. By supplying a comma-separated list of `<operation>_<resource_type>` strings (e.g., `delete_user,create_artifact,push_artifact`), an attacker with system admin access can suppress audit records for the most forensically relevant operations. The suppression itself is not audited because the configuration update handler does not special-case this field. This is a more surgical audit-evasion path than p8-020, enabling targeted suppression without disabling the entire audit database trail (which is more detectable).

## Location

- `src/lib/config/metadata/metadatalist.go:195` -- `AuditLogEventsDisabled` defined as `UserScope`, `StringType`, no validation of allowable values
- `src/lib/config/userconfig.go:266-279` -- `AuditLogEventEnabled` does simple string comparison against comma-split list
- `src/controller/event/handler/auditlog/auditlog.go:65` -- `config.AuditLogEventEnabled(ctx, ...)` gate applied before every non-pull audit write

## Attacker Control

- System admin can set `disabled_audit_log_event_types` to any comma-separated string via `PUT /api/v2.0/configurations`
- No validation of allowed event type names
- Value is evaluated at event handler time; changes take effect immediately for all subsequent events

## Trust Boundary Crossed

- Admin API configuration -> audit event processing pipeline
- System admin privilege allows targeted suppression of specific forensic event categories

## Impact

- Targeted suppression of specific high-value audit categories (e.g., user deletion, robot creation, artifact push) without disabling full audit trail
- More difficult to detect than full `skip_audit_log_database=true` because other audit records continue to appear
- Combined with p8-020 pattern, an attacker can suppress specific operation traces before performing sensitive actions
- No current restriction on which event types can be disabled (including `delete_artifact`, `delete_project`, `create_user`)

## Evidence

- `metadatalist.go:195`: `ItemType: &StringType{}`, `Editable: false` (but still settable by admin via PUT)
- `userconfig.go:271-277`: No whitelist validation; any string matching `<op>_<resource>` disables the corresponding audit record
- `auditlog.go:65`: Gate runs for all CommonEvents and standard events before DB write

## Reproduction Steps

1. Authenticate as system administrator
2. Send: `PUT /api/v2.0/configurations` with body `{"disabled_audit_log_event_types": "delete_artifact,create_user,delete_user"}`
3. Perform user deletion and artifact deletion operations
4. Verify `audit_log_ext` table has no entries for these operations
5. Verify that the configuration change itself has no corresponding audit record for the `disabled_audit_log_event_types` field change
