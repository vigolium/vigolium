Phase: 10
Sequence: 001
Slug: pubdash-influxdb08-credential-exposure
Verdict: VALID
Rationale: InfluxDB v0.8 (DS_INFLUXDB_08) plaintext credential extraction follows the identical missing-guard pattern as p8-002 but for a distinct datasource type that was omitted from the original evidence.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-002-pubdash-credential-exposure.md
Origin-Pattern: AP-002

## Summary

Unauthenticated public dashboard viewers receive decrypted plaintext credentials for InfluxDB v0.8 (`influxdb_08`) datasources configured with direct mode (`DS_ACCESS_DIRECT`). The code block at `pkg/api/frontendsettings.go:557-565` calls `DecryptedPassword` and sets `dsDTO.Username` and `dsDTO.Password` (plaintext) without any `IsPublicDashboardView()` guard. The p8-002 finding evidence only covers the `DS_INFLUXDB` branch (lines 568-577); the structurally identical `DS_INFLUXDB_08` branch is a missed co-located variant.

## Location

- **Primary**: `pkg/api/frontendsettings.go:557-565` — `DS_INFLUXDB_08` credential extraction block inside `getFSDataSources`
- **Endpoint**: `GET /api/frontend/settings` (with public dashboard access token cookie/context)
- **Missing guard position**: Before the `if ds.Access == datasources.DS_ACCESS_DIRECT` block at line 541, no `IsPublicDashboardView()` check exists

## Attacker Control

The attacker needs only a valid public dashboard access token (accessible via the public dashboard URL). No additional authentication is required. The public dashboard must use a panel that queries a direct-mode InfluxDB 0.8 datasource (or the H-03/p8-003 bypass can force its inclusion via template variable UID injection).

## Trust Boundary Crossed

Unauthenticated internet user -> decrypted internal InfluxDB 0.8 datasource credentials (plaintext password and username).

## Impact

- **Credential disclosure**: `dsDTO.Username = ds.User` and `dsDTO.Password = plaintext_password` returned in JSON response to unauthenticated callers
- **Direct datasource access**: Attacker can authenticate directly against the InfluxDB 0.8 HTTP API using the disclosed credentials
- **Database name exposed**: `dsDTO.URL = url + "/db/" + ds.Database` additionally reveals the configured database name in the URL field
- **InfluxDB 0.8 deployments**: Though the protocol is deprecated, legacy InfluxDB 0.8 deployments remain in production environments; this credential would grant full time-series data read access

## Evidence

```go
// pkg/api/frontendsettings.go:557-565
// NO IsPublicDashboardView() guard around this block — identical omission to p8-002
if ds.Type == datasources.DS_INFLUXDB_08 {
    password, err := hs.DataSourcesService.DecryptedPassword(c.Req.Context(), ds)
    if err != nil {
        return nil, err
    }

    dsDTO.Username = ds.User
    dsDTO.Password = password           // PLAINTEXT password in JSON response
    dsDTO.URL = url + "/db/" + ds.Database  // raw backend URL + database name
}
```

Compare with the analogous `DS_INFLUXDB` block (p8-002's primary evidence) at lines 568-577 — structurally identical, same root cause, same missing guard.

## Reproduction Steps

1. Create an InfluxDB datasource with type `influxdb_08`, `Access: direct`, and a username/password configured
2. Create a dashboard using this datasource and enable public sharing
3. Note the public dashboard access token from the share URL
4. As an unauthenticated user, request:
   ```
   GET /api/frontend/settings
   Cookie: [public dashboard access token cookie]
   ```
5. Observe the response JSON contains `username` (plaintext) and `password` (plaintext) fields for the InfluxDB 0.8 datasource, along with the raw backend URL including the database name in the `url` field
