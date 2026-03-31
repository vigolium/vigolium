Phase: 10
Sequence: 031
Slug: cloud-migration-gms-status-results-db-injection
Verdict: VALID
Rationale: The `GetSnapshotStatus` GMS response contains `results` items with attacker-controlled `error_code` and `error_string` fields that are written verbatim to the database without length, format, or content validation, allowing an attacker-controlled GMS server to inject arbitrary strings into the `cloud_migration_resource` table.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-020-cloud-migration-attacker-controlled-encryption-key.md
Origin-Pattern: AP-020

## Summary

After a snapshot is uploaded, Grafana polls the GMS `GetSnapshotStatus` endpoint until migration is complete. The response body is a `GetSnapshotStatusResponse` containing a `results` array of `CloudMigrationResource` items with fields `Status`, `Error` (string), and `ErrorCode` (string). These values are written directly to the `cloud_migration_resource` database table via `UpdateSnapshotResources` without any length validation, character filtering, or content sanitization.

```go
// cloudmigration.go:604,614-618 (in GetSnapshot/syncStatus)
resources := snapshotMeta.Results
if err := s.store.UpdateSnapshot(ctx, cloudmigration.UpdateSnapshotCmd{
    CloudResourcesToUpdate: resources,  // attacker-controlled fields flow directly to SQL UPDATE
}); err != nil { ... }
```

The SQL UPDATE at `xorm_store.go:546-547` writes the attacker-controlled `ErrorCode` and `Error` strings as-is:

```sql
UPDATE cloud_migration_resource SET status=?, error_code=?, error_string=? WHERE snapshot_uid=? AND resource_uid IN (...)
```

An attacker-controlled GMS server can write arbitrary strings into `error_code` and `error_string` columns for any snapshot resource. These values are then returned to the GrafanaAdmin via the `GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid` API and rendered in the frontend migration UI. If the frontend renders these error strings without sanitization, this is a stored XSS vector. Even without XSS, unbounded string injection can exhaust database storage (if no column length limits are enforced at the schema level) or produce misleading error messages that manipulate the admin's remediation decisions.

Additionally, the `State` field of the `GetSnapshotStatusResponse` controls the local snapshot status (`localStatus`) via the `gmsStateToLocalStatus` mapping. An attacker supplying an unrecognized state causes an error log entry and leaves the snapshot in its current status, while supplying known states like `FINISHED` or `ERROR` transitions the snapshot to terminal states, preventing further migration retries without manual intervention.

## Location

- **Attacker-controlled value source**: `pkg/services/cloudmigration/gmsclient/gms_client.go:180-184` -- `json.NewDecoder(resp.Body).Decode(&result)` deserializes GMS response including `result.Results[*].Error` and `result.Results[*].ErrorCode`
- **Response model**: `pkg/services/cloudmigration/model.go:320-323` -- `GetSnapshotStatusResponse.Results []CloudMigrationResource`
- **Values passed to store without validation**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:604,614-618` -- `resources := snapshotMeta.Results; s.store.UpdateSnapshot(ctx, ..., CloudResourcesToUpdate: resources)`
- **SQL sink**: `pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go:546-547` -- `UPDATE cloud_migration_resource SET status=?, error_code=?, error_string=? WHERE snapshot_uid=? AND resource_uid IN (?...)`
- **State transition**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:599,617` -- `localStatus` derived from `snapshotMeta.State` controls snapshot `Status` field written to DB
- **Returned to frontend**: `pkg/services/cloudmigration/api/api.go:565` -- `GetSnapshot` response includes resource results

## Attacker Control

- **Error strings**: Attacker's fake GMS server returns `results[*].error` with arbitrary string content. No length limit enforced in Go code before DB write.
- **Error codes**: Attacker's fake GMS server returns `results[*].error_code` matching any `ResourceErrorCode` constant or an entirely unknown value. No allowlist check before DB write.
- **RefID matching**: `UpdateSnapshotResources` matches resources by `resource_uid` (the `RefID` field). The attacker can target specific resources by supplying `RefID` values corresponding to resources they know exist (e.g., datasource UIDs that are publicly known or leaked).
- **State control**: Attacker can force snapshot into `FINISHED`, `ERROR`, or `CANCELED` states by returning matching state values, blocking future migration attempts.
- **Authentication required**: GrafanaAdmin + `cfg.CloudMigration.Enabled = true`. Triggered when `GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid` is called on a snapshot in `pending_processing` or `processing` status.

## Trust Boundary Crossed

TB-8 (Cloud Migration external control plane) to TB-3 (Grafana internal database). GMS response data crosses from external control plane into Grafana's internal database without validation.

## Impact

- **Stored XSS vector**: `error_string` values are rendered in the migration results UI. If the frontend renders these via `dangerouslySetInnerHTML` or equivalent without sanitization, attacker-injected HTML/JS executes in the GrafanaAdmin's browser session.
- **Database storage exhaustion**: No length limit on `error_string` in the Go code path. An attacker supplying multi-megabyte error strings per resource can exhaust database storage if the schema column lacks a hard limit.
- **Migration state manipulation**: Attacker can force snapshot into terminal error/finished states, requiring the admin to create a new snapshot from scratch. Combined with the p8-020 encryption key attack, this can force repeated credential-exposing snapshot cycles.
- **Misleading error messages**: Fabricated error codes (e.g., `DATASOURCE_ALREADY_MANAGED`, `RESOURCE_CONFLICT`) in the migration UI can mislead admins into taking incorrect remediation actions on their datasources.
- **Severity**: MEDIUM -- requires SSRF prerequisite (p7-021) to reach attacker-controlled GMS, limited to injection into migration UI display fields. Escalates to HIGH if frontend XSS is confirmed.

## Evidence

```go
// model.go:320-323 -- GetSnapshotStatusResponse, no field validation annotations
type GetSnapshotStatusResponse struct {
    State   SnapshotState            `json:"state"`    // controls status transition
    Results []CloudMigrationResource `json:"results"`  // attacker-controlled array
}

// CloudMigrationResource fields that flow to SQL
// model.go:87-100
type CloudMigrationResource struct {
    Error     string            `xorm:"error_string" json:"error"`      // unbounded
    ErrorCode ResourceErrorCode `xorm:"error_code" json:"error_code"`   // not allowlist-checked
    Status    ItemStatus        `xorm:"status" json:"status"`
    RefID     string            `xorm:"resource_uid" json:"refId"`
}

// xorm_store.go:546-547 -- error_code and error_string written from attacker input
sql: "UPDATE cloud_migration_resource SET status=?, error_code=?, error_string=? WHERE snapshot_uid=? AND resource_uid IN (?...)"
args: [ItemStatusError, k.errCode, k.errStr, snapshotUid, ...ids]
// k.errCode = attacker-supplied ResourceErrorCode
// k.errStr  = attacker-supplied Error string
```

## Reproduction Steps

1. Set up Grafana with `cfg.CloudMigration.Enabled = true` and configured datasources
2. Complete a snapshot cycle (CreateSnapshot + UploadSnapshot) using attacker's GMS server
3. When snapshot reaches `pending_processing` state, have attacker's GMS server respond to `GET /cloud-migrations/api/v1/snapshots/{gmsSnapshotUID}/status` with:
   ```json
   {
     "state": "ERROR",
     "results": [
       {
         "refId": "<known-datasource-uid>",
         "status": "ERROR",
         "error": "<script>alert(document.cookie)</script>",
         "error_code": "GENERIC_ERROR"
       }
     ]
   }
   ```
4. As GrafanaAdmin, call `GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid`
5. The status sync goroutine writes the injected error string to the database
6. The error string is returned in the API response and rendered in the migration UI
