Phase: 10
Sequence: 033
Slug: cloud-migration-max-items-per-partition-dos
Verdict: VALID
Rationale: The GMS-controlled `MaxItemsPerPartition` field from `StartSnapshot` is used directly in `slices.Chunk` to determine snapshot partition sizes, allowing an attacker-controlled GMS server to force Grafana to build a single monolithic partition containing all migration resources, causing unbounded memory allocation and potential OOM on the Grafana process.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-020-cloud-migration-attacker-controlled-encryption-key.md
Origin-Pattern: AP-020

## Summary

The `StartSnapshot` GMS response includes a `maxItemsPerPartition` field (`uint32`) that Grafana uses to control how many resources are bundled into each encrypted snapshot partition. This value is passed directly to `buildSnapshot` and then to `slices.Chunk`:

```go
// cloudmigration.go:545
err := s.buildSnapshot(asyncCtx, signedInUser, initResp.MaxItemsPerPartition, ...)

// snapshot_mgmt.go:647 (DB storage) / 664 (FS storage)
for chunk := range slices.Chunk(resourcesGroupedByType[resourceType], int(maxItemsPerPartition)) {
```

If `maxItemsPerPartition` is set to `math.MaxUint32` (4,294,967,295) or any very large value, `slices.Chunk` attempts to allocate a single slice containing all resources in one pass. With a large number of migration resources (dashboards, datasources, alert rules), this causes the `EncodePartition` or `snapshotWriter.Write` call to allocate and serialize the entire resource set in a single memory buffer, potentially causing OOM.

Conversely, if `maxItemsPerPartition` is set to `0` or `1`, Grafana creates an extremely large number of tiny partitions — one per resource. For instances with tens of thousands of resources, this means tens of thousands of database INSERT operations and S3 uploads, causing performance degradation and potential connection pool exhaustion.

The value `0` specifically causes `slices.Chunk(data, 0)` which in Go panics with "cannot be non-positive" or creates an infinite loop depending on the slice implementation. This would crash the snapshot goroutine.

## Location

- **Attacker-controlled value source**: `pkg/services/cloudmigration/gmsclient/gms_client.go:129-131` -- `json.NewDecoder(resp.Body).Decode(&result)` deserializes `result.MaxItemsPerPartition` as `uint32`
- **Value model**: `pkg/services/cloudmigration/model.go:313` -- `StartSnapshotResponse.MaxItemsPerPartition uint32`
- **Passed to builder**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:545` -- `buildSnapshot(asyncCtx, signedInUser, initResp.MaxItemsPerPartition, ...)`
- **Used in chunk loop (DB storage)**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:647` -- `slices.Chunk(resourcesGroupedByType[resourceType], int(maxItemsPerPartition))`
- **Used in chunk loop (FS storage)**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:664` -- `slices.Chunk(resourcesGroupedByType[resourceType], int(maxItemsPerPartition))`
- **No validation**: No minimum/maximum bounds check on `maxItemsPerPartition` anywhere in the code path

## Attacker Control

- **Value**: Attacker's GMS server returns `{"maxItemsPerPartition": 4294967295}` or `{"maxItemsPerPartition": 0}` or `{"maxItemsPerPartition": 1}`.
- **Effect of `0`**: `int(uint32(0)) = 0`; `slices.Chunk(slice, 0)` panics in Go standard library with "cannot chunk with size 0". The goroutine running `buildSnapshot` crashes, and the snapshot status is updated to `error`. An attacker can repeatedly trigger this to prevent successful migration.
- **Effect of `math.MaxUint32`**: Forces a single giant partition containing all resources. Memory allocation for `EncodePartition` is proportional to the total size of all migration data. For large Grafana instances, this can exhaust available heap memory.
- **Effect of `1`**: Forces one-resource-per-partition. For an instance with 10,000 resources, this means 10,000 DB INSERT operations and 10,000 presigned URL upload calls, each requiring a separate HTTP connection to the attacker's server — connection pool and rate limit exhaustion.
- **Authentication required**: GrafanaAdmin + `cfg.CloudMigration.Enabled = true`.

## Trust Boundary Crossed

TB-8 (Cloud Migration external control plane) to TB-2 (Grafana process memory/CPU). An attacker-supplied integer directly controls memory allocation patterns and I/O loop iteration counts in the Grafana server process.

## Impact

- **Process crash (value=0)**: `slices.Chunk` panics on chunk size 0. The snapshot goroutine crashes. While recovered at the snapshot level (status updated to error), repeated triggering creates a persistent migration DoS.
- **OOM (value=MaxUint32)**: Single-partition allocation of all migration data exceeds available memory on resource-constrained deployments.
- **I/O exhaustion (value=1)**: Creates N upload connections for N resources. For large instances, exhausts HTTP client connection pools and generates excessive load on the database.
- **Migration DoS**: All three variants prevent successful migration completion, requiring admin intervention. Combined with p8-020 (attacker controls encryption key), the attacker can perpetually prevent legitimate migration while also harvesting credentials from each attempted snapshot.
- **Severity**: MEDIUM -- requires SSRF prerequisite (p7-021), impact is availability (DoS on migration process) without direct data exfiltration beyond the p8-020 chain.

## Evidence

```go
// model.go:313 -- MaxItemsPerPartition is an unconstrained uint32
type StartSnapshotResponse struct {
    SnapshotID           string `json:"snapshotID"`
    MaxItemsPerPartition uint32 `json:"maxItemsPerPartition"` // no min/max check
    ...
}

// cloudmigration.go:545 -- passed directly to buildSnapshot
err := s.buildSnapshot(asyncCtx, signedInUser, initResp.MaxItemsPerPartition, ...)

// snapshot_mgmt.go:644-658 (DB storage) -- used directly in slices.Chunk
func (s *Service) buildSnapshotWithDBStorage(..., maxItemsPerPartition uint32) error {
    for _, resourceType := range currentMigrationTypes {
        i := 0
        for chunk := range slices.Chunk(resourcesGroupedByType[resourceType], int(maxItemsPerPartition)) {
            // int(0) would panic; int(MaxUint32) allocates entire dataset
            encoded, err := snapshotWriter.EncodePartition(chunk)
            ...
        }
    }
}

// snapshot_mgmt.go:662-682 (FS storage) -- same pattern
func (s *Service) buildSnapshotWithFSStorage(..., maxItemsPerPartition uint32) error {
    for _, resourceType := range currentMigrationTypes {
        for chunk := range slices.Chunk(resourcesGroupedByType[resourceType], int(maxItemsPerPartition)) {
            // same vulnerability
        }
    }
}
```

**No bounds check anywhere:**
- No `if maxItemsPerPartition == 0 { return error }` guard
- No `if maxItemsPerPartition > someReasonableMax { ... }` guard
- The only check on `initResp.Algo` (line 557) demonstrates that other fields are validated but `MaxItemsPerPartition` was overlooked

## Reproduction Steps

1. Set up Grafana with `cfg.CloudMigration.Enabled = true` and multiple datasources/dashboards
2. Create an attacker HTTPS server that on `POST /cloud-migrations/api/v1/start-snapshot` returns:
   ```json
   {"snapshotID":"test","maxItemsPerPartition":0,"algo":"nacl","encryptionKey":"<key>","metadata":"e30="}
   ```
3. As GrafanaAdmin, initiate a migration snapshot (`POST /api/cloudmigration/migration/:uid/snapshot`)
4. Observe: `buildSnapshot` goroutine panics due to `slices.Chunk(data, 0)`, snapshot status set to `error`
5. Repeat indefinitely -- migration is permanently broken until the attacker's GMS server is replaced
6. Alternatively, use `maxItemsPerPartition: 4294967295` to trigger OOM on instances with large resource sets
