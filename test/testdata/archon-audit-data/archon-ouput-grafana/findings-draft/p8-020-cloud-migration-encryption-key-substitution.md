---
id: p8-020
title: Cloud Migration GMS-Controlled Encryption Key Substitution Enables Plaintext Credential Exfiltration
severity: HIGH
status: VALID
verdict: VALID
cluster: Proxy & SSRF
---

Phase: 8
Sequence: 020
Slug: cloud-migration-encryption-key-substitution
Verdict: VALID
Rationale: The GMSPublicKey returned by the GMS server in StartSnapshotResponse is stored and used to encrypt all decrypted datasource credentials without any key verification, trust anchor, or format validation. A compromised or MITM'd GMS can substitute an attacker-controlled key, enabling plaintext recovery of all exfiltrated datasource secrets. This is a distinct attack angle from p9-073 (which documented the SSRF + presigned URL exfiltration chain) that upgrades the impact from encrypted to fully decryptable credential theft.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-2/debate.md

## Summary

When a Grafana administrator initiates a cloud migration snapshot, the Grafana instance contacts the Grafana Migration Service (GMS) to start the snapshot process. The GMS response includes a `GMSPublicKey` (NaCl public key) that Grafana uses to encrypt all datasource credentials before uploading them. This key is accepted from the GMS response without any verification -- no trust anchor comparison, no certificate pinning, no format validation. If the GMS server is compromised or the connection is MITM'd (facilitated by an `http://` override option at `gms_client.go:314`), an attacker can substitute their own public key. Since the attacker knows the corresponding private key, they can decrypt all exfiltrated datasource credentials: database passwords, API keys, OAuth client secrets, and any other values stored in `SecureJsonData`.

This finding extends the prior p9-073 finding (Cloud Migration SSRF via presigned URL) by demonstrating that the encryption meant to protect the exfiltrated data provides no real protection when the GMS is compromised, because the encryption key itself comes from the same compromised source.

## Affected Code

### Primary: No key verification on GMS public key
- **File**: `pkg/services/cloudmigration/gmsclient/gms_client.go:129-134`
- **Function**: `StartSnapshot` -- decodes `GMSPublicKey` from GMS JSON response with no validation
- **Line 129-131**: `var result cloudmigration.StartSnapshotResponse; json.NewDecoder(resp.Body).Decode(&result)` -- key accepted as-is

### Storage without validation
- **File**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:504`
- **Line 504**: `GMSPublicKey: initResp.GMSPublicKey` -- stored in snapshot record directly

### Credential decryption and encryption with attacker key
- **File**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:305`
- **Line 305**: `DecryptJsonData(ctx, dataSource.SecureJsonData)` -- ALL datasource credentials decrypted
- **Lines 310-330**: Decrypted credentials assembled into `AddDataSourceCommand` structs

### Upload to attacker-controlled URL
- **File**: `pkg/services/cloudmigration/objectstorage/s3.go:27-88`
- **Function**: `PresignedURLUpload` -- uploads encrypted payload to GMS-provided presigned URL (also attacker-controlled)

### HTTP downgrade enabler
- **File**: `pkg/services/cloudmigration/gmsclient/gms_client.go:314`
- **Line 314**: `if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://")` -- allows `http://` prefix to bypass default HTTPS

### Key type definition
- **File**: `pkg/services/cloudmigration/model.go:315`
- **Line 315**: `GMSPublicKey []byte` -- raw byte slice with no type safety or validation

## Attacker Control

The attacker controls the `GMSPublicKey` field in the `StartSnapshotResponse` JSON payload returned by the GMS server. This control is achieved through:

1. **GMS server compromise**: If the GMS infrastructure is breached, the attacker controls all responses including the encryption key
2. **Network-level MITM**: If `GMSDomain` is configured with an `http://` prefix (for development/testing), any network-level attacker (same LAN, cloud VPC) can intercept and modify the GMS response
3. **DNS hijacking**: If the attacker can redirect `cms-{slug}.{domain}` DNS resolution, they can serve a malicious GMS endpoint

The attacker also controls the `presignedURL` (from `CreatePresignedUploadUrl`) where the encrypted payload is sent, completing the exfiltration chain.

## Trust Boundary Crossed

**TB-8 (Cloud Migration)**: Grafana trusts the GMS server to provide a legitimate encryption key, but the GMS is an external service whose responses should be treated as potentially compromised. The trust model assumes that TLS to GMS provides both authentication and integrity, but:
- TLS can be bypassed via the `http://` configuration override
- TLS only authenticates the server certificate, not the application-layer content (a compromised GMS with valid TLS cert still serves attacker keys)
- There is no out-of-band key verification mechanism

## Impact

**Complete credential dump**: All datasource credentials for the organization are decrypted from Grafana's secrets store (via `DecryptJsonData`) and encrypted with the attacker's key. The attacker can decrypt:
- Database passwords (PostgreSQL, MySQL, InfluxDB, etc.)
- API keys and tokens (Prometheus, Elasticsearch, CloudWatch, etc.)
- OAuth client secrets
- Any custom `SecureJsonData` values

This enables lateral movement to all monitored infrastructure via the stolen credentials.

**Scope**: All datasources in the organization. The `GetDataSources` call at `snapshot_mgmt.go:296` retrieves every datasource for the org.

## Evidence

### Code path trace

```
POST /api/cloudmigration/migration/:uid/snapshot
  -> api.go:CreateSnapshot
  -> cloudmigration.go:477 CreateSnapshot()
  -> cloudmigration.go:488 GetMigrationSessionByUID(ctx, orgID, cmd.SessionUID) [org-scoped]
  -> cloudmigration.go:494 gmsClient.StartSnapshot(ctx, session, algo)
     -> gms_client.go:86 StartSnapshot()
     -> gms_client.go:101 POST to GMS /api/v1/start-snapshot
     -> gms_client.go:129-131 Decode StartSnapshotResponse {GMSPublicKey: ATTACKER_KEY}
  -> cloudmigration.go:504 snapshot.GMSPublicKey = initResp.GMSPublicKey [NO VALIDATION]
  -> cloudmigration.go:526 [goroutine] buildSnapshot()
     -> snapshot_mgmt.go:296-309 [for each datasource]
        -> snapshot_mgmt.go:305 DecryptJsonData() [ALL credentials decrypted]
     -> [encryption with ATTACKER_KEY]
     -> snapshot_mgmt.go:756 PresignedURLUpload(ctx, uploadUrl, key, data)
        -> s3.go:82 POST encrypted data to ATTACKER_URL
```

### Verified source evidence

1. `GMSPublicKey` is a raw `[]byte` field with no type constraint (model.go:315)
2. No call to verify key against any trust anchor between gms_client.go:131 and cloudmigration.go:504
3. The in-memory client (inmemory_client.go:34) generates a fresh NaCl key pair, confirming the key is expected to come from GMS, not from local configuration
4. The `http://` override at gms_client.go:314 is a production code path (not behind a feature flag or developer mode check)

## Reproduction Steps

1. Set up a Grafana instance with cloud migration enabled and at least one datasource with stored credentials
2. Configure `GMSDomain` to point to an attacker-controlled server (or use `http://` prefix for MITM)
3. Create a migration session pointing to the attacker's GMS
4. The attacker's GMS responds to `POST /api/v1/start-snapshot` with a `StartSnapshotResponse` containing the attacker's NaCl public key as `encryptionKey`
5. The attacker's GMS responds to presigned URL requests with the attacker's upload endpoint
6. Trigger snapshot creation: `POST /api/cloudmigration/migration/{sessUid}/snapshot`
7. Grafana decrypts all datasource credentials and encrypts them with the attacker's key
8. Grafana uploads the encrypted payload to the attacker's endpoint
9. The attacker decrypts the payload using their corresponding NaCl private key
10. All datasource credentials are recovered in plaintext

## Defense Brief

- **RBAC**: `MigrationAssistantAccess` requires `migrationassistant:migrate`, granted only to `RoleGrafanaAdmin` (instance-level superuser)
- **TLS default**: GMS communication defaults to HTTPS (`gms_client.go:311`)
- **No blocking protection found**: No key pinning, no out-of-band verification, no key format validation

## Severity Justification

**HIGH** rather than CRITICAL because:
- Requires GrafanaAdmin access (high privilege requirement)
- Requires GMS compromise or MITM (external precondition)
- Default HTTPS provides transport-layer protection (but not against compromised GMS)

Upgrade factors:
- Impact is complete credential dump of ALL datasource secrets for the org
- Enables lateral movement to all monitored infrastructure
- The encryption that was supposed to protect the data is completely defeated
