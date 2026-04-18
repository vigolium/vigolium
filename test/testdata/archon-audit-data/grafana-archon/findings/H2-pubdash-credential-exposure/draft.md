Phase: 8
Sequence: 002
Slug: pubdash-credential-exposure
Verdict: VALID
Rationale: Unauthenticated credential disclosure via residual gap in CVE-2026-27877 patch. Decrypted passwords returned in JSON to any public dashboard visitor with a direct-mode datasource. Cold verification confirmed no blocking protection on credential extraction block.
Severity-Original: HIGH
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-1/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path from unauthenticated /bootdata/:accessToken endpoint through getFSDataSources deterministically includes decrypted BasicAuth and InfluxDB passwords in JSON response for direct-mode datasources, with no IsPublicDashboardView() guard on the credential extraction block (lines 541-577 of frontendsettings.go).
Severity-Final: HIGH
PoC-Status: theoretical

## Summary

Unauthenticated visitors to public dashboards that use direct-mode datasources (DS_ACCESS_DIRECT) receive decrypted datasource credentials in the `GET /bootdata/:accessToken` JSON response (and potentially `/api/frontend/settings`). The CVE-2026-27877 fix correctly filters WHICH datasources appear in the response but does NOT suppress credential fields for datasources that pass the filter. BasicAuth passwords (base64-encoded) and InfluxDB plaintext passwords are returned to unauthenticated callers.

## Cold Verification Notes

1. **Endpoint correction**: The primary exploitable endpoint is `GET /bootdata/:accessToken` (pkg/api/api.go:207-214), registered with `reqNoAuth`. This endpoint sets `PublicDashboardAccessToken` on the context via middleware and calls `setIndexViewData` -> `getFrontendSettings` -> `getFSDataSources`. The finding's stated endpoint `/api/frontend/settings` does not have the `SetPublicDashboardAccessToken` middleware, making it a secondary or incorrect vector.

2. **Code path confirmed**: `getFSDataSources` (pkg/api/frontendsettings.go:464-629) has a single `IsPublicDashboardView()` check at line 476, used only for datasource filtering. The credential extraction block at lines 541-577 has NO public dashboard guard and decrypts+exposes BasicAuth and InfluxDB passwords unconditionally for direct-mode datasources.

3. **No blocking protections**: No middleware, framework feature, or application logic strips credential fields from the DTO before serialization. The `DataSourceDTO` struct (pkg/plugins/models.go:282-312) serializes `BasicAuth`, `Password`, and `Username` fields directly to JSON.

4. **Existing test gap**: The test `TestIntegrationHTTPServer_GetFrontendSettings_publicDashboardDataSourceFiltering` (frontendsettings_test.go:803) only tests proxy-mode datasources and only verifies which datasource names appear. It does not test credential exposure for direct-mode datasources.

## Location

- **Primary**: `pkg/api/frontendsettings.go:541-577` -- credential extraction block inside `getFSDataSources`
- **Filter**: `pkg/api/frontendsettings.go:476-483` -- `publicDashFilterUsedDataSources` (filters DS list but not credential fields)
- **Endpoint**: `GET /bootdata/:accessToken` (pkg/api/api.go:207-214, with reqNoAuth)
- **Secondary endpoint**: `GET /api/frontend/settings` (if PublicDashboardAccessToken is set through other means)

## Attacker Control

The attacker needs only a valid public dashboard access token (visible in the public dashboard URL). No authentication is required.

## Trust Boundary Crossed

Unauthenticated internet user -> decrypted internal datasource credentials (BasicAuth passwords, InfluxDB passwords).

## Impact

- **Credential disclosure**: Decrypted BasicAuth username:password (base64 in `dsDTO.BasicAuth`) and plaintext InfluxDB passwords (`dsDTO.Password`) returned to unauthenticated callers
- **Direct datasource access**: Attacker can use the disclosed credentials to directly access the backend datasource API, bypassing Grafana entirely
- **Lateral movement**: Backend datasource credentials may grant access to production databases, monitoring infrastructure, or other sensitive systems

## Evidence

```go
// pkg/api/frontendsettings.go:541-577
// NO IsPublicDashboardView() guard around this block
if ds.Access == datasources.DS_ACCESS_DIRECT {
    if ds.BasicAuth {
        password, err := hs.DataSourcesService.DecryptedBasicAuthPassword(c.Req.Context(), ds)
        // ...
        dsDTO.BasicAuth = util.GetBasicAuthHeader(ds.BasicAuthUser, password)
    }
    // ...
    if ds.Type == datasources.DS_INFLUXDB {
        password, err := hs.DataSourcesService.DecryptedPassword(c.Req.Context(), ds)
        // ...
        dsDTO.Username = ds.User
        dsDTO.Password = password  // PLAINTEXT password in JSON response
    }
}
```

## Reproduction Steps

1. Create a datasource with `Access: direct` and `BasicAuth` enabled (e.g., InfluxDB with username/password)
2. Create a dashboard using this datasource and enable public sharing
3. Note the public dashboard access token from the share URL
4. As an unauthenticated user, request:
   ```
   GET /bootdata/<accessToken>
   ```
5. Observe the response JSON at `settings.datasources.<name>` contains `basicAuth` (base64 user:pass) and/or `password` (plaintext) fields for the direct-mode datasource
