# Variant Analysis: p7-021 (cloud-migration-ssrf)

**Origin Finding**: security/findings-draft/p7-021-cloud-migration-ssrf.md
**Attack Pattern**: AP-021 — SSRF via Unsanitized Subdomain Injection in URL Template
**Analysis Date**: 2026-03-20
**Variants Found**: 3 (p9-072, p9-073, p9-074)

---

## Search Strategy Summary

### 1. Registry-Driven Search
AP-021 detection signature (`Sprintf.*https://.*%s\.%s`) matched only `gms_client.go:311` — the original confirmed instance. A broader pattern was used to find structural equivalents.

### 2. AST-Level Structural Search (Manual)
Searched for all calls to `buildURL()` in `gms_client.go`. Found five callers beyond `ValidateKey`:
- `StartSnapshot` (line 87)
- `GetSnapshotStatus` (line 141)
- `CreatePresignedUploadUrl` (line 190)
- `ReportEvent` (line 245)
All pass `session.ClusterSlug` without any intervening validation.

Searched across `pkg/` for `routes[...].url +` and string concatenation into URL templates. Found `pkg/tsdb/cloud-monitoring/httpclient.go:75` as a structural match.

### 3. Flow Shape Search
Original flow shape: `user-controlled string` → stored/passed → `buildURL()` → `url.Parse()` → `http.Do()`.

Post-creation GMS operations (p9-072): `user-supplied ClusterSlug` → `DB store` → `GetMigrationSessionByUID` → `buildURL()` → `http.Do()`. Same shape, different trigger path.

Chained SSRF (p9-073): `buildURL() → attacker GMS server` → `presigned URL response` → `PresignedURLUpload()` → `http.Do()`. Extended flow shape with a second outbound request using attacker-returned URL.

Cloud-monitoring universeDomain (p9-074): `datasource jsonData.UniverseDomain` → `newInstanceSettings()` → `buildURL(route, universeDomain)` → `dsInfo.services[name].url` → `http.Do()`. Structurally identical — user-controlled string → URL template concatenation → HTTP sink.

### 4. Phase 7 Addendum Targets
The addendum entry "Cloud Migration SSRF: clusterSlug from user-supplied base64 token flows verbatim into buildURL" was the origin finding. No additional addendum targets for this pattern were noted for the proxy/SSRF chamber.

### 5. Chamber Variant Candidates
No `variant-candidates/` directories existed in the chamber workspaces.

---

## Variant Summary Table

| ID | Slug | Severity | Location | Key Difference from Origin |
|----|------|----------|----------|---------------------------|
| p9-072 | cloud-migration-ssrf-post-creation-gms-ops | MEDIUM | gms_client.go:87,141,190,245 | Same buildURL() sink, triggered from stored sessions via 4 separate API operations; GetSnapshotStatus runs in a polling loop |
| p9-073 | cloud-migration-ssrf-presigned-url-exfiltration | HIGH | objectstorage/s3.go:27-103 | Second-order SSRF: attacker GMS returns arbitrary presigned URL, Grafana POSTs full snapshot data (all exported resources) to attacker server |
| p9-074 | cloud-monitoring-universe-domain-ssrf | MEDIUM | tsdb/cloud-monitoring/httpclient.go:71-76 | Different service, `universeDomain` from datasource jsonData injected into URL template; requires only datasources:write; GCP OAuth tokens leaked |

---

## Variant Details

### p9-072: Post-Creation GMS Operations (MEDIUM)

**Root cause**: Identical to p7-021 — `session.ClusterSlug` is passed to `buildURL()` without validation. The distinction is that these operations fire from stored sessions rather than during initial token validation.

**Entry points**:
- `POST /api/cloudmigration/migration/:uid/snapshot` → StartSnapshot + ReportEvent
- `GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid` → GetSnapshotStatus (polls every 10s)
- `POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/upload` → CreatePresignedUploadUrl + ReportEvent
- `DELETE /api/cloudmigration/migration/:uid` → ReportEvent

**Why MEDIUM (not upgraded)**: Same preconditions as origin (GrafanaAdmin + feature enabled). The polling behavior increases the number of SSRF callbacks but doesn't change the trust boundary or impact category beyond p7-021.

**Blocking protection**: None beyond the session UID validation (which is a length/character check on the UID path parameter, not on ClusterSlug).

### p9-073: Presigned URL Exfiltration (HIGH)

**Root cause**: `CreatePresignedUploadUrl` returns an attacker-controlled URL (from the SSRF-reached GMS server), which is passed to `PresignedURLUpload` in `s3.go`. No URL validation exists in `s3.go` — `url.Parse()` accepts any valid URL and the HTTP client POSTs to whatever host is specified.

**Upgrade rationale**: Upgraded from MEDIUM to HIGH because:
1. The impact extends from SSRF/token-leakage to **full data exfiltration** of all migrated resources.
2. The chained nature of the attack (SSRF → exfiltration) represents a materially higher impact than network-position escalation alone.
3. The snapshot payload includes datasource credentials, alert contact point tokens (PagerDuty, Slack, etc.), and dashboard content.

**Blocking protection**: None. The datasource proxy `DataProxyWhiteList` does not apply to the object storage client. The `s3.go` HTTP client is separate from the GMS HTTP client.

### p9-074: Cloud Monitoring universeDomain SSRF (MEDIUM)

**Root cause**: `httpclient.go:buildURL()` performs `routes[route].url + universeDomain` — pure string concatenation of `universeDomain` from datasource `jsonData`. No `url.Parse()` call is made at the injection point; the result is stored and later used in `http.NewRequest()`.

**Structural difference from origin**: 
- Not in the cloud migration package — this is in the cloud-monitoring tsdb plugin.
- Input vector: datasource `jsonData` (admin-configured) rather than a user-supplied migration token.
- Lower privilege required: `datasources:write` vs. GrafanaAdmin.
- No feature flag gate (unlike cloud migration which is disabled by default).
- Credentials leaked: GCP OAuth access tokens (not migration auth tokens).

**Blocking protection**: `validateJSONData()` in `datasources.go:348-366` does not validate `universeDomain` or any URL-typed field. The datasource proxy whitelist (`DataProxyWhiteList`) does not apply to the cloud-monitoring plugin's own HTTP client.

---

## Candidates Examined and Rejected

### Cloud Monitoring `universeDomain` — route prefix injection
`routes[route].url` is a hardcoded map (`"https://monitoring."`, `"https://cloudresourcemanager."`). The route name comes from internal iteration over a hardcoded map, not from user input. Only `universeDomain` (the suffix) is user-controlled. **Accepted as p9-074.**

### Azure Blob Uploader (`azureblobuploader.go:97,135`)
`fmt.Sprintf("https://%s.blob.core.windows.net/...", az.account_name, ...)` where `account_name` comes from server-side configuration (not user-supplied at runtime). The storage account name is set in Grafana's server config file, not via an API. **Rejected — not attacker-controlled input.**

### AzureAD `tenantID` in Graph API URL (`azuread_oauth.go:647`)
`fmt.Sprintf("https://graph.microsoft.com/v1.0/%s/users/%s/getMemberObjects", tenantID, claims.ID)`. The `tenantID` comes from the authenticated OIDC token's `tid` claim, not from a user-supplied request body. The `claims.ID` is also from the verified token. **Rejected — trust level differs (token-derived, not user-supplied request body).**

### Datasource proxy URL (ds_proxy.go:ValidateURL)
`datasource.ValidateURL()` is called on `ds.URL` before it is used as `targetURL`. While `ValidateURL` does not perform IP-range blocking (no RFC 1918 check), an explicit allowlist (`DataProxyWhiteList`) is available. The pattern is different from AP-021 (no string templating, different URL construction). Documented as related to AP-022 (path parser differential). **Rejected — different attack pattern, not AP-021.**

---

## Notes on GMSSnapshotUID as Secondary Injection Point

In `GetSnapshotStatus` (line 141) and `CreatePresignedUploadUrl` (line 190), the path also includes `snapshot.GMSSnapshotUID`:
```go
fmt.Sprintf("/api/v1/snapshots/%s/status?offset=%d", snapshot.GMSSnapshotUID, offset)
```

The `GMSSnapshotUID` originates from the GMS `start-snapshot` response (`initResp.SnapshotID`), which the attacker controls if they have already won the ClusterSlug SSRF. This represents an additional injection point within the URL path, but it is only exploitable after the initial ClusterSlug SSRF has been achieved. It is captured as part of p9-072's impact scope rather than as a standalone finding.
