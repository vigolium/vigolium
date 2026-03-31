Phase: 10
Sequence: 015
Slug: cloud-migration-no-additional-orgid-variants
Verdict: FALSE_POSITIVE
Rationale: All other Cloud Migration service methods (GetSession, GetSessionList, GetSnapshot, GetSnapshotList, UploadSnapshot) correctly pass orgID through to the store layer, implementing the JOIN or WHERE org_id constraint; the missing-orgID pattern is isolated to CancelSnapshot.
Severity-Original: N/A
PoC-Status: N/A
Origin-Finding: security/findings-draft/p8-003-cloud-migration-cancel-cross-org.md
Origin-Pattern: AP-046

## Summary

A systematic review of all Cloud Migration service interface methods was performed to identify variants of the CancelSnapshot orgID omission pattern. Every candidate method was traced from the service interface signature through the implementation to the SQL store layer.

## Location

Candidates reviewed:

- `pkg/services/cloudmigration/cloudmigration.go:25` -- `GetSession(ctx, orgID int64, migUID)` -- PROTECTED
- `pkg/services/cloudmigration/cloudmigration.go:27` -- `GetSessionList(ctx, orgID int64)` -- PROTECTED
- `pkg/services/cloudmigration/cloudmigration.go:30` -- `GetSnapshot(ctx, GetSnapshotsQuery)` -- PROTECTED (OrgID field in struct)
- `pkg/services/cloudmigration/cloudmigration.go:31` -- `GetSnapshotList(ctx, ListSnapshotsQuery)` -- PROTECTED (OrgID field in struct)
- `pkg/services/cloudmigration/cloudmigration.go:32` -- `UploadSnapshot(ctx, orgID int64, ...)` -- PROTECTED

## Attacker Control

N/A — no vulnerable instances found.

## Trust Boundary Crossed

N/A

## Impact

N/A

## Evidence

1. `cloudmigrationimpl/xorm_store.go:85`: `GetCloudMigrationSessionList` uses `sess.Where("org_id=?", orgID)` — org-scoped.
2. `cloudmigrationimpl/xorm_store.go:106`: `DeleteMigrationSessionByUID` uses `sess.Where("org_id=? AND uid=?", orgID, uid)` — org-scoped.
3. `cloudmigrationimpl/xorm_store.go:364`: `GetSnapshotByUID` calls `GetMigrationSessionByUID(ctx, orgID, sessionUID)` first — session lookup enforces org_id before snapshot retrieval.
4. `cloudmigrationimpl/xorm_store.go:409-419`: `GetSnapshotList` uses INNER JOIN on `cloud_migration_session.org_id = ?` — org-scoped.
5. `cloudmigrationimpl/cloudmigration.go:725`: `UploadSnapshot` calls `s.store.GetMigrationSessionByUID(ctx, orgID, sessionUid)` as first action — enforces org boundary.

## Reproduction Steps

No reproduction — no valid variant found.
