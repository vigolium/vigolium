Phase: 9
Sequence: 072
Slug: cloud-migration-ssrf-post-creation-gms-ops
Verdict: VALID
Rationale: All four GMS API operations executed after session creation (StartSnapshot, GetSnapshotStatus, CreatePresignedUploadUrl, ReportEvent) load the stored CloudMigrationSession from the database and pass session.ClusterSlug directly to the same vulnerable buildURL() function, persisting the SSRF across the entire migration workflow.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-021-cloud-migration-ssrf.md
Origin-Pattern: AP-021

## Summary

The original p7-021 finding documented that ClusterSlug is used without validation in `buildURL()` during token validation (ValidateKey). The same vulnerable code path is exercised by every subsequent GMS API call in the cloud migration workflow. Once an attacker creates a migration session with a crafted ClusterSlug, the stored ClusterSlug is reloaded from the database and injected into `buildURL()` for every future GMS request: StartSnapshot, GetSnapshotStatus, CreatePresignedUploadUrl, and ReportEvent. These operations are triggered by separate authenticated API endpoints, each re-exploiting the SSRF independently and each sending `Authorization: Bearer <StackID>:<AuthToken>` to the attacker-controlled host.

## Location

- **buildURL sink** (shared): `pkg/services/cloudmigration/gmsclient/gms_client.go:309-323`
- **StartSnapshot**: `gms_client.go:87` — called by `cloudmigration.go:494` (CreateSnapshot handler)
- **GetSnapshotStatus**: `gms_client.go:141` — called by `cloudmigration.go:589` (GetSnapshot handler, async goroutine)
- **CreatePresignedUploadUrl**: `gms_client.go:190` — called by `cloudmigration.go:739` (UploadSnapshot handler)
- **ReportEvent**: `gms_client.go:245` — called by `cloudmigration.go:874` (report() helper, invoked from CreateSession, DeleteSession, CreateSnapshot, UploadSnapshot)
- **Session load (all paths)**: `cloudmigrationimpl/xorm_store.go:37-57` — `GetMigrationSessionByUID` returns stored ClusterSlug unchanged

- **Entry points**:
  - `POST /api/cloudmigration/migration/:uid/snapshot` → CreateSnapshot → StartSnapshot + ReportEvent
  - `GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid` → GetSnapshot → GetSnapshotStatus
  - `POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/upload` → UploadSnapshot → CreatePresignedUploadUrl + ReportEvent
  - `DELETE /api/cloudmigration/migration/:uid` → DeleteSession → ReportEvent

## Attacker Control

- **Input**: ClusterSlug originates from the base64-encoded token supplied during session creation (`POST /api/cloudmigration/migration`). After the session is created and stored, every subsequent workflow operation loads the session from the database using `GetMigrationSessionByUID()`, which returns the original (unvalidated) ClusterSlug.
- **Authentication required**: Same as original — GrafanaAdmin role via `cloudmigration.MigrationAssistantAccess` + cloud migration feature enabled.
- **Persistence**: The SSRF is not a one-shot attack. Any GrafanaAdmin can trigger additional SSRF callbacks against the stored attacker URL by simply calling the snapshot or upload endpoints with the session UID. Each call sends a fresh HTTP request to the attacker-controlled host with a live `Authorization` header.

## Trust Boundary Crossed

TB1 — Internet Edge (outbound). Grafana server makes HTTP requests from its internal network position to an attacker-controlled host. The ReportEvent path is particularly relevant as it fires asynchronously even on session deletion, making the SSRF difficult to time-bound.

## Impact

- **Persistent SSRF**: Unlike the original ValidateToken path (which fires before the session is stored), these paths fire from already-stored sessions. Any admin can unknowingly retrigger the SSRF.
- **Migration auth token leakage**: Each GMS operation sends `Authorization: Bearer <StackID>:<AuthToken>` to the attacker host.
- **Full migration credential exfiltration**: ReportEvent fires on every major migration lifecycle event (connect, disconnect, start build, done build, start upload, done upload) — multiple callbacks per migration.
- **Scope extension**: The GetSnapshotStatus path runs in an async polling loop (10-second tick, `cloudmigration.go:677`), meaning a single GetSnapshot API call can result in repeated SSRF requests until the snapshot reaches a terminal state.

## Evidence

**All four operations use the same buildURL() with session.ClusterSlug:**

```go
// gms_client.go:87
path, err := c.buildURL(session.ClusterSlug, "/api/v1/start-snapshot")

// gms_client.go:141
path, err := c.buildURL(session.ClusterSlug, fmt.Sprintf("/api/v1/snapshots/%s/status?offset=%d", snapshot.GMSSnapshotUID, offset))

// gms_client.go:190
path, err := c.buildURL(session.ClusterSlug, fmt.Sprintf("/api/v1/snapshots/%s/create-upload-url", snapshot.GMSSnapshotUID))

// gms_client.go:245
path, err := c.buildURL(session.ClusterSlug, "/api/v1/events")
```

**Session loaded from DB without re-validation:**
```go
// cloudmigration.go:488
session, err := s.store.GetMigrationSessionByUID(ctx, signedInUser.GetOrgID(), cmd.SessionUID)
// ...
initResp, err := s.gmsClient.StartSnapshot(ctx, *session, ...)
```

**No ClusterSlug validation in xorm_store.go:GetMigrationSessionByUID** — returns the stored value verbatim.

**ReportEvent polling loop (cloudmigration.go:677):**
```go
tick := time.NewTicker(10 * time.Second)
for snapshot.ShouldQueryGMS() {
    select {
    case <-tick.C:
        updatedSnapshot, err := syncStatus(ctx, session, snapshot)
        // session.ClusterSlug flows to gmsClient.GetSnapshotStatus → buildURL
    }
}
```

## Reproduction Steps

1. Create a migration session with a crafted ClusterSlug via the original p7-021 technique.
2. Note the returned session UID (e.g., `abc123`).
3. As the same GrafanaAdmin, call `POST /api/cloudmigration/migration/abc123/snapshot` with a valid resource types payload.
4. Observe: Grafana makes an outbound POST to `https://cms-ATTACKER.HOST/cloud-migrations/api/v1/start-snapshot` with `Authorization: Bearer <StackID>:<AuthToken>`.
5. Grafana then asynchronously calls `GET /api/cloudmigration/migration/abc123/snapshot/<snapshotUid>`.
6. Observe: Grafana makes repeated outbound GET requests to `https://cms-ATTACKER.HOST/cloud-migrations/api/v1/snapshots/<uid>/status?offset=N` every 10 seconds.
