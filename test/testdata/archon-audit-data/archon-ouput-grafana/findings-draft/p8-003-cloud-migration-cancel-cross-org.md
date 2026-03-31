---
id: p8-003
title: Cloud Migration CancelSnapshot Missing OrgID Enables Cross-Org Migration Disruption
severity: MEDIUM
status: VALID
verdict: VALID
cluster: Authentication & Authorization
---

Phase: 8
Sequence: 003
Slug: cloud-migration-cancel-cross-org
Verdict: VALID
Rationale: The CancelSnapshot service interface at cloudmigration.go:33 lacks an orgID parameter, and the SQL UPDATE at xorm_store.go:228 has no org_id WHERE constraint. An admin in Org-B can cancel an in-flight migration snapshot belonging to Org-A if they know the session_uid and snapshot_uid. The Advocate identified admin-only access, UUID non-guessability, and enterprise-only availability as mitigating factors that justify MEDIUM severity.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: check-4-ambiguous
Debate: security/chamber-workspace/chamber-1-p8/debate.md

## Summary

The `CancelSnapshot` method in the cloud migration service interface (`pkg/services/cloudmigration/cloudmigration.go:33`) accepts only `sessionUid` and `snapshotUid` parameters without an `orgID`. The API handler at `pkg/services/cloudmigration/api/api.go:615-641` extracts these UIDs from URL parameters but does not pass the requester's org ID to the service layer. The underlying SQL UPDATE at `pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go:228` executes:

```sql
UPDATE cloud_migration_snapshot SET status=? WHERE session_uid=? AND uid=?
```

This query has no `org_id` constraint, allowing an admin in one organization to cancel a migration snapshot belonging to a different organization. Additionally, the `cancelFunc()` at `cloudmigrationimpl/cloudmigration.go:812` is a process-global singleton that terminates any in-flight migration regardless of org.

## Location

- `pkg/services/cloudmigration/cloudmigration.go:33` -- Service interface: `CancelSnapshot(ctx, sessionUid, snapshotUid)` lacks orgID parameter
- `pkg/services/cloudmigration/api/api.go:615-641` -- API handler does not pass `c.OrgID` to service
- `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:796-830` -- Implementation calls global `s.cancelFunc()` and `updateSnapshotWithRetries` without org filter
- `pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go:228` -- SQL UPDATE has no `org_id` in WHERE clause
- Contrast with `GetSession` at `cloudmigration.go:25`: `GetSession(ctx, orgID int64, migUID string)` correctly includes orgID

## Attacker Control

The attacker controls the `session_uid` and `snapshot_uid` URL path parameters. These are UUID-like values with high entropy (122 bits each), so they cannot be brute-forced. The attacker would need to obtain them via:
- Information disclosure in logs or error messages
- Social engineering
- Other API information disclosure vulnerabilities

## Trust Boundary Crossed

TB-11 (Org Isolation). The cloud migration service is intended to operate within a single organization's context. The missing orgID parameter allows operations to cross organizational boundaries, violating the multi-tenant isolation model.

## Impact

- **Cross-org migration disruption**: Admin in Org-B can cancel Org-A's active migration snapshot
- **Global process cancellation**: The `s.cancelFunc()` is process-global, terminating any in-flight migration for the entire Grafana instance
- **Status corruption**: The SQL UPDATE marks the snapshot as "canceled" without org verification
- **Availability impact**: The migration must be restarted from scratch after cancellation, potentially delaying cloud onboarding

## Evidence

1. `cloudmigration.go:33`: `CancelSnapshot(ctx context.Context, sessionUid string, snapshotUid string) error` -- no orgID parameter
2. `api.go:619`: `sessUid, snapshotUid := web.Params(c.Req)[":uid"], web.Params(c.Req)[":snapshotUid"]` -- no `c.OrgID` usage
3. `api.go:633`: `cma.cloudMigrationService.CancelSnapshot(ctx, sessUid, snapshotUid)` -- orgID not passed
4. `xorm_store.go:228`: `UPDATE cloud_migration_snapshot SET status=? WHERE session_uid=? AND uid=?` -- no `AND org_id=?`
5. `cloudmigration.go:812`: `s.cancelFunc()` -- global cancel function, not org-scoped
6. Contrast: `GetSession(ctx, orgID int64, migUID string)` at line 25 correctly includes orgID

## Reproduction Steps

1. Set up multi-org Grafana with cloud migration feature enabled
2. In Org-A (admin), create a migration session and initiate a snapshot upload
3. Note the session_uid and snapshot_uid from the API response
4. In Org-B (admin), send `POST /api/cloudmigration/migration/{session_uid}/snapshot/{snapshot_uid}/cancel`
5. Expected: 403 or 404 (resources belong to different org)
6. Actual: 200 OK -- migration in Org-A is canceled

## Severity Justification

MEDIUM severity because:
- Requires admin-level access (elevated privilege prerequisite)
- Requires knowledge of cross-org UUIDs (not guessable, 122 bits of entropy each)
- Cloud migration is an enterprise/cloud feature (limited deployment surface)
- Impact is availability-only (DoS on migration, no data exfiltration or privilege escalation)
- The global cancelFunc makes the issue worse than just a SQL filter bypass
- Pattern matches CVE-2024-9476 (missing org_id in cloud migration operations)
