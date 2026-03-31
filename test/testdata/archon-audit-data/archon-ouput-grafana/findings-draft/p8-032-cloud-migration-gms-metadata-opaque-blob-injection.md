Phase: 10
Sequence: 032
Slug: cloud-migration-gms-metadata-opaque-blob-injection
Verdict: VALID
Rationale: The `Metadata` field from the `StartSnapshot` GMS response is an opaque attacker-controlled byte blob that is stored in the database and later embedded verbatim into the snapshot index file, which is then uploaded to the attacker's presigned URL — completing a round-trip of unvalidated attacker-controlled data through Grafana's database and filesystem.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-020-cloud-migration-attacker-controlled-encryption-key.md
Origin-Pattern: AP-020

## Summary

The `StartSnapshot` GMS response includes a `metadata` field (`[]byte` JSON field `metadata`) that is stored opaquely in the Grafana database and later embedded in the snapshot index file. The code stores this field without any validation:

```go
// cloudmigration.go:500-510
snapshot := cloudmigration.CloudMigrationSnapshot{
    Metadata: initResp.Metadata,  // attacker-controlled opaque blob
    ...
}
s.store.CreateSnapshot(ctx, snapshot)
```

The metadata is passed to `buildSnapshot`:

```go
// cloudmigration.go:545
err := s.buildSnapshot(asyncCtx, signedInUser, initResp.MaxItemsPerPartition, initResp.Metadata, snapshot, ...)
```

In FS storage mode, the metadata is written into the snapshot index file via `snapshotWriter.Finish`:

```go
// snapshot_mgmt.go:674-679
snapshotWriter.Finish(snapshot.FinishInput{
    SenderPublicKey: publicKey[:],
    Metadata:        metadata,     // attacker-controlled blob written to index.json
})
```

In DB storage mode, the metadata is stored in the database `cloud_migration_snapshot.metadata` column (via the initial `CreateSnapshot` INSERT). When the snapshot is later uploaded, `GetIndex` retrieves this metadata and embeds it in the `snapshotIndex` structure that is uploaded to the attacker's presigned URL.

The `Metadata` field has no defined schema or maximum size. Since it is a `[]byte` field with no length validation in the Go code, an attacker can supply an arbitrarily large blob (e.g., hundreds of megabytes), which Grafana stores in its database and later uploads to the attacker's server. This creates two attack vectors: (1) database storage exhaustion and (2) a "metadata poisoning" attack where attacker-controlled content is embedded in the snapshot index alongside legitimate migration data.

## Location

- **Attacker-controlled value source**: `pkg/services/cloudmigration/gmsclient/gms_client.go:129-131` -- `json.NewDecoder(resp.Body).Decode(&result)` deserializes `result.Metadata` as `[]byte`
- **Stored to database**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:506` -- `Metadata: initResp.Metadata` in snapshot struct; `cloudmigrationimpl/xorm_store.go:187` -- `sess.InsertOne(&snapshot)` writes `metadata` column
- **Passed to snapshot builder**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:545` -- `buildSnapshot(..., initResp.Metadata, ...)`
- **Embedded in index file (FS storage)**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:674-679` -- `snapshotWriter.Finish(snapshot.FinishInput{Metadata: metadata})`
- **Retrieved and embedded in upload (DB storage)**: `pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go:303-308` -- `GetIndex` returns `Metadata: snap.Metadata`; then `snapshot_mgmt.go:734` -- `snapshotIndex := snapshot.Index{..., Metadata: index.Metadata, ...}`
- **Model**: `pkg/services/cloudmigration/model.go:315` -- `StartSnapshotResponse.Metadata []byte` (no size constraint)

## Attacker Control

- **Content**: The `metadata` JSON value is arbitrary bytes (base64-decoded from JSON). No schema validation, no content inspection, no size limit in Go code.
- **Size**: `[]byte` with no maximum length check. An attacker can supply an arbitrarily large payload.
- **Round-trip**: The blob is stored in DB, retrieved, and re-uploaded to the attacker's presigned URL, creating a complete attacker-controlled data round-trip through Grafana's persistence layer.
- **Authentication required**: GrafanaAdmin + `cfg.CloudMigration.Enabled = true`.

## Trust Boundary Crossed

TB-8 (Cloud Migration external control plane) to TB-3 (Grafana internal database) and TB-6 (snapshot filesystem). An unvalidated blob from an external server is persisted in Grafana's database and written to the filesystem.

## Impact

- **Database storage exhaustion**: An attacker supplying a 1 GB `metadata` blob causes Grafana to attempt writing 1 GB to the `cloud_migration_snapshot.metadata` database column. Repeated calls exhaust disk space or trigger OOM conditions depending on the database engine.
- **Snapshot index poisoning**: The metadata blob is embedded in the snapshot index file alongside legitimate resource data. Downstream GMS processing of the poisoned index may have unexpected behavior depending on how the real GMS parses the metadata field.
- **Memory exhaustion**: `json.NewDecoder(resp.Body).Decode(&result)` reads the entire response body into memory. A multi-gigabyte response causes heap allocation pressure on the Grafana process during snapshot creation.
- **Filesystem write of attacker data**: In FS storage mode, the metadata blob is written to the `index.json` file in the snapshot directory, creating a local file containing attacker-controlled content.
- **Severity**: MEDIUM -- requires SSRF prerequisite (p7-021), no direct data exfiltration of new credentials beyond the p8-020 chain, but enables availability attacks (DoS via storage exhaustion) without the cryptographic complexity of p8-020.

## Evidence

```go
// model.go:316
type StartSnapshotResponse struct {
    ...
    Metadata []byte `json:"metadata"`  // no size or content validation
}

// cloudmigration.go:506 -- stored without validation
snapshot := cloudmigration.CloudMigrationSnapshot{
    Metadata: initResp.Metadata,  // attacker-supplied []byte
}

// snapshot_mgmt.go:674-679 -- written to index file (FS mode)
if _, err := snapshotWriter.Finish(snapshot.FinishInput{
    SenderPublicKey: publicKey[:],
    Metadata:        metadata,       // attacker-supplied blob written to index.json
}); err != nil { ... }

// xorm_store.go:303-308 -- retrieved from DB and embedded in upload index (DB mode)
return cloudmigration.CloudMigrationSnapshotIndex{
    EncryptionAlgo: snap.EncryptionAlgo,
    PublicKey:      snap.PublicKey,
    Metadata:       snap.Metadata,  // attacker-supplied blob re-embedded
    Items:          partitionsByResourceType,
}, nil
```

## Reproduction Steps

1. Set up Grafana with `cfg.CloudMigration.Enabled = true`
2. Create an attacker HTTPS server that on `POST /cloud-migrations/api/v1/start-snapshot` returns:
   ```json
   {
     "snapshotID": "test-snapshot",
     "maxItemsPerPartition": 100,
     "algo": "nacl",
     "encryptionKey": "<base64-key>",
     "metadata": "<base64-of-100MB-random-data>"
   }
   ```
3. As GrafanaAdmin, initiate a migration snapshot
4. Observe: Grafana stores 100 MB in `cloud_migration_snapshot.metadata` column
5. Repeat until database storage is exhausted or the Grafana process OOMs during JSON decoding
