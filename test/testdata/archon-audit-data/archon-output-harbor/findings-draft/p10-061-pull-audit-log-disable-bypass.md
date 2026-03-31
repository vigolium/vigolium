Phase: 10
Sequence: 061
Slug: pull-audit-log-disable-bypass
Verdict: VALID
Rationale: The pull_audit_log_disable flag is a separate admin-configurable boolean that silences all pull event audit entries, enabling an attacker with system admin privileges to hide artifact exfiltration by disabling pull audit logging before conducting a mass pull.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-020-audit-evidence-destruction.md
Origin-Pattern: AP-020

## Summary

The `pull_audit_log_disable` configuration flag (`PullAuditLogDisable`) is a separate boolean control that suppresses audit records for all artifact pull (download) events. A system administrator can enable this flag via `PUT /api/v2.0/configurations` before conducting unauthorized mass artifact pulls. Because pull events represent the primary data exfiltration vector in a container registry, disabling their audit trail is particularly high-impact. Like p8-020, the flag change itself is not reliably audited, and the change takes effect immediately.

## Location

- `src/lib/config/metadata/metadatalist.go:184` -- `PullAuditLogDisable` defined as `UserScope`, `BoolType`, `Editable: false`
- `src/lib/config/userconfig.go:242-243` -- `PullAuditLogDisable(ctx)` getter
- `src/controller/event/handler/auditlog/auditlog.go:52-53` -- `PullArtifactEvent` gate: `addAuditLog = !config.PullAuditLogDisable(ctx)`

## Attacker Control

- System admin sets `pull_audit_log_disable: true` via `PUT /api/v2.0/configurations`
- All subsequent `PullArtifactEvent` audit records are silently dropped at the handler
- Only pull events are affected; no user-visible side effects

## Trust Boundary Crossed

- Admin API configuration -> audit event pipeline for pull events

## Impact

- Complete suppression of artifact pull audit records (primary exfiltration vector)
- Attacker can pull all container images/artifacts without any audit trail
- Combined with skip_audit_log_database or disabled_audit_log_event_types, attacker achieves complete audit blackout
- Enables stealth data exfiltration from the registry

## Evidence

- `metadatalist.go:184`: `{Name: common.PullAuditLogDisable, ... ItemType: &BoolType{}, Editable: false}`
- `auditlog.go:52-53`: `case *event.PullArtifactEvent: addAuditLog = !config.PullAuditLogDisable(ctx)` -- when true, `addAuditLog` is false, so no DB write occurs

## Reproduction Steps

1. Authenticate as system administrator
2. Send: `PUT /api/v2.0/configurations` with body `{"pull_audit_log_disable": true}`
3. Pull several artifacts: `docker pull harbor.example.com/library/ubuntu:latest`
4. Query `audit_log_ext` table: `SELECT * FROM audit_log_ext WHERE operation='pull'`
5. Verify zero pull audit entries exist despite successful pulls
