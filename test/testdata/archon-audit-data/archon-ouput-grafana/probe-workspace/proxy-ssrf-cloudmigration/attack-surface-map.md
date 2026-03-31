# Attack Surface Map: Datasource Proxy, Cloud Migration, and SSRF

## Entry Points

### Datasource Proxy
- `pkg/services/datasourceproxy/datasourceproxy.go:58` -- `ProxyDataSourceRequest` -- HTTP proxy via datasource ID from URL path `:id`
- `pkg/services/datasourceproxy/datasourceproxy.go:67` -- `ProxyDatasourceRequestWithUID` -- HTTP proxy via datasource UID from URL path `:uid`
- `pkg/services/datasourceproxy/datasourceproxy.go:87` -- `ProxyDatasourceRequestWithID` -- HTTP proxy via integer datasource ID
- `pkg/services/datasourceproxy/datasourceproxy.go:139` -- `extractProxyPath` -- Extracts attacker-controlled proxy path from URL (everything after `/api/datasources/proxy/<id>/`)
- `pkg/api/pluginproxy/ds_proxy.go:59` -- `NewDataSourceProxy` -- Builds reverse proxy with attacker-controlled proxyPath
- `pkg/api/pluginproxy/ds_proxy.go:173` -- `director` -- Sets outbound request URL using proxyPath + targetUrl

### Datasource CRUD API
- `pkg/api/datasources.go:44` -- `GetDataSources` -- List all datasources (returns URLs, JsonData)
- `pkg/api/datasources.go:108` -- `GetDataSourceById` -- Get datasource by ID (returns URL, credentials info)
- `pkg/api/datasources.go:152` -- `DeleteDataSourceById` -- Delete datasource by ID
- Lines ~200+ -- `GetDataSourceByUID`, `DeleteDataSourceByUID`, `AddDataSource`, `UpdateDataSource` -- CRUD with user-supplied URLs, JsonData, SecureJsonData

### Cloud Migration API
- `pkg/services/cloudmigration/api/api.go:53` -- `GetToken` -- GET /api/cloudmigration/token
- `pkg/services/cloudmigration/api/api.go:54` -- `CreateToken` -- POST /api/cloudmigration/token
- `pkg/services/cloudmigration/api/api.go:55` -- `DeleteToken` -- DELETE /api/cloudmigration/token/:uid
- `pkg/services/cloudmigration/api/api.go:58` -- `GetSessionList` -- GET /api/cloudmigration/migration
- `pkg/services/cloudmigration/api/api.go:59` -- `CreateSession` -- POST /api/cloudmigration/migration (body: AuthToken)
- `pkg/services/cloudmigration/api/api.go:60` -- `GetSession` -- GET /api/cloudmigration/migration/:uid
- `pkg/services/cloudmigration/api/api.go:61` -- `DeleteSession` -- DELETE /api/cloudmigration/migration/:uid
- `pkg/services/cloudmigration/api/api.go:64` -- `CreateSnapshot` -- POST /api/cloudmigration/migration/:uid/snapshot (body: ResourceTypes)
- `pkg/services/cloudmigration/api/api.go:65` -- `GetSnapshot` -- GET /api/cloudmigration/migration/:uid/snapshot/:snapshotUid
- `pkg/services/cloudmigration/api/api.go:66` -- `GetSnapshotList` -- GET /api/cloudmigration/migration/:uid/snapshots
- `pkg/services/cloudmigration/api/api.go:67` -- `UploadSnapshot` -- POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/upload
- `pkg/services/cloudmigration/api/api.go:68` -- `CancelSnapshot` -- POST /api/cloudmigration/migration/:uid/snapshot/:snapshotUid/cancel

## Trust Boundary Crossings

1. **Datasource Proxy -> External Datasource** (TB-5 -> TB-6): Grafana injects stored credentials (Basic Auth, OAuth, API keys) into outbound requests to external datasources. Attacker-controlled proxy path determines the destination URL path.
2. **Cloud Migration -> GMS** (TB-8): Grafana sends data to GMS using auth tokens. GMS returns presigned URLs that Grafana blindly follows for upload.
3. **Cloud Migration -> S3 (via presigned URL)**: The presigned URL from GMS is used without validation. A compromised/malicious GMS can return an arbitrary URL, causing Grafana to upload snapshot data (including decrypted datasource credentials) to an attacker-controlled server (SSRF/data exfiltration).
4. **Cloud Migration -> Internal Services**: The `getDataSourceCommands` method decrypts ALL datasource SecureJsonData and includes it in snapshot payloads. This data crosses the trust boundary to GMS/S3.
5. **OSS DataSourceRequestValidator is a NO-OP**: `pkg/services/validations/oss.go:11` -- `Validate` always returns nil, providing zero request validation in OSS builds.

## Parser / Serialization Functions

- `pkg/services/datasourceproxy/datasourceproxy.go:139-143` -- `extractProxyPath` -- Regex-based path extraction from URL
- `pkg/api/pluginproxy/ds_proxy.go:173-218` -- `director` -- URL construction from targetUrl + proxyPath; uses PathUnescape
- `pkg/api/pluginproxy/ds_proxy.go:280-348` -- `validateRequest` -- Route matching via `CleanRelativePath` + string prefix matching
- `pkg/api/datasource/validation.go:63-91` -- `ValidateURL` -- URL parsing with auto-prepend of `http://` for missing schemes
- `pkg/services/cloudmigration/objectstorage/s3.go:27-104` -- `PresignedURLUpload` -- Parses presigned URL and constructs multipart upload request
- `pkg/services/cloudmigration/gmsclient/gms_client.go:189-235` -- `CreatePresignedUploadUrl` -- Receives URL from GMS response without validation

## Auth / AuthZ Decision Points

- `pkg/services/cloudmigration/api/api.go:72` -- `authorize(cloudmigration.MigrationAssistantAccess)` -- All cloud migration endpoints protected by single RBAC permission
- `pkg/services/cloudmigration/cloudmigration.go:33` -- `CancelSnapshot(ctx, sessionUid, snapshotUid)` -- **NO orgID parameter** in service interface
- `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:796` -- `CancelSnapshot` impl -- Does NOT check orgID, does NOT call store.GetMigrationSessionByUID with orgID
- `pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go:228` -- `UpdateSnapshot` SQL -- `WHERE session_uid=? AND uid=?` **NO org_id check**
- `pkg/api/pluginproxy/ds_proxy.go:350-367` -- `hasAccessToRoute` -- Route-level RBAC or org role check for plugin proxy routes
- `pkg/services/validations/oss.go:11` -- `OSSDataSourceRequestValidator.Validate` -- **Always returns nil** (no validation)

## Validation / Sanitization Functions

- `pkg/api/datasource/validation.go:63` -- `ValidateURL` -- Validates datasource URL has scheme; auto-prepends `http://` if missing; no SSRF protection (no IP/hostname blocklist)
- `pkg/services/datasourceproxy/datasourceproxy.go:74` -- `util.IsValidShortUID(dsUID)` -- Validates UID format
- `pkg/api/pluginproxy/ds_proxy.go:305-324` -- `CleanRelativePath` route matching -- Path normalization for route ACL checking
- `pkg/services/cloudmigration/api/api.go:157,214,292,325,388,527,581,620` -- `util.ValidateUID` -- UID format validation on path params
- `pkg/services/cloudmigration/objectstorage/s3.go:32` -- `url.Parse(presignedURL)` -- **Only syntactic URL parse; no scheme/host/IP validation**

## KB Domain Research Highlights

### SSRF via Presigned URL (H4 - Prior Audit, EXECUTED)
- GMS returns a presigned URL that Grafana uses to upload snapshot data containing decrypted datasource credentials
- No validation of the presigned URL destination (scheme, host, IP range)
- A compromised GMS or MITM can redirect uploads to attacker-controlled servers
- `objectstorage/s3.go:80` constructs endpoint as `scheme://host/path` from parsed URL and sends HTTP POST

### Cross-Org Operations (CVE-2024-9476)
- `CancelSnapshot` service interface lacks orgID parameter
- `UpdateSnapshot` SQL uses `WHERE session_uid=? AND uid=?` without org_id
- Pattern may extend to other operations that call `UpdateSnapshot`

### Datasource Proxy Path Differential (CVE-2025-3454, M7)
- Route matching uses `CleanRelativePath` but path forwarding uses `PathUnescape`
- Parser differential between validation and forwarding creates bypass risk
- OSS validator is a no-op, providing no additional protection

### Data Exfiltration via Cloud Migration
- `getDataSourceCommands` decrypts ALL datasource SecureJsonData (passwords, API keys, tokens)
- This decrypted data is included in migration snapshots
- Combined with SSRF, enables full credential exfiltration
