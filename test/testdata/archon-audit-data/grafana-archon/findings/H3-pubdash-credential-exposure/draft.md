Phase: 8
Sequence: 002
Slug: pubdash-credential-exposure
Verdict: VALID
Rationale: Unauthenticated credential disclosure via residual gap in CVE-2026-27877 patch. Decrypted passwords returned in JSON to any public dashboard visitor with a direct-mode datasource. Advocate confirmed no blocking protection.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-1/debate.md

## Summary

Unauthenticated visitors to public dashboards that use direct-mode datasources (DS_ACCESS_DIRECT) receive decrypted datasource credentials in the `GET /bootdata/:accessToken` JSON response. The CVE-2026-27877 fix correctly filters WHICH datasources appear in the response but does NOT suppress credential fields for datasources that pass the filter. BasicAuth passwords (base64-encoded) and InfluxDB plaintext passwords are returned to unauthenticated callers.

## Location

- **Primary**: `pkg/api/frontendsettings.go:541-577` -- credential extraction block inside `getFSDataSources`
- **Filter**: `pkg/api/frontendsettings.go:476-483` -- `publicDashFilterUsedDataSources` (filters DS list but not credential fields)
- **Endpoint**: `GET /bootdata/:accessToken` (unauthenticated public dashboard viewer endpoint)

## Attacker Control

The attacker needs only a valid public dashboard access token (obtainable via the public dashboard URL or via H-06 token enumeration). No authentication is required.

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
   (no Authorization header, no session cookie)
5. Observe the response JSON contains `basicAuth` (base64 user:pass) and/or `password` (plaintext) fields for the direct-mode datasource
