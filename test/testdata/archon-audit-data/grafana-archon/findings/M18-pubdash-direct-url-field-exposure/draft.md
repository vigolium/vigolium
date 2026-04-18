Phase: 10
Sequence: 002
Slug: pubdash-direct-url-field-exposure
Verdict: VALID
Rationale: The dsDTO.URL field is set to the raw backend URL for all direct-mode datasources and returned to unauthenticated public dashboard viewers without any IsPublicDashboardView() guard, exposing internal network topology beyond just Prometheus (covered by p8-004).
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-002-pubdash-credential-exposure.md
Origin-Pattern: AP-002

## Summary

For every datasource configured with `Access: direct`, the `getFSDataSources` function sets `dsDTO.URL` to the raw backend datasource URL (e.g., `http://graphite.internal:8080`, `http://opentsdb.prod:4242`). This raw URL is included in the `url` field of the DataSourceDTO returned in the `GET /api/frontend/settings` response to unauthenticated public dashboard viewers. No `IsPublicDashboardView()` guard surrounds this URL assignment. This is distinct from p8-004 (which is specifically about `directUrl` injected into `jsonData` for Prometheus/Amazon/Azure Prometheus via simplejson reference mutation); this variant affects the top-level `url` JSON field for ALL direct-mode datasource types.

## Location

- **Primary**: `pkg/api/frontendsettings.go:496-510` — URL selection and DataSourceDTO construction inside `getFSDataSources`
- **Root cause**: Line 496 (`url := ds.URL`) is unchanged for direct-mode; line 507 (`URL: url`) sets raw URL in DTO; no `IsPublicDashboardView()` guard anywhere in this flow before the DTO is returned
- **Endpoint**: `GET /api/frontend/settings` (with public dashboard access token cookie/context)

## Attacker Control

The attacker needs only a valid public dashboard access token (accessible via the public dashboard URL). The public dashboard must include a panel that references a direct-mode datasource — or leverage the p8-003 ByRef bypass to include any direct-mode datasource from the org regardless of panel reference.

## Trust Boundary Crossed

Unauthenticated internet user -> raw backend URL of internal datasources (internal hostnames, IP addresses, and ports for Graphite, OpenTSDB, and any other direct-mode datasource type).

## Impact

- **Internal network topology disclosure**: Raw backend URLs (e.g., `http://graphite.internal:8080/`, `http://opentsdb.mycompany.internal:4242`) returned in `url` field to unauthenticated callers for all direct-mode datasource types
- **Distinct from p8-004**: p8-004 is about Prometheus-specific `directUrl` injected into `jsonData` via simplejson reference; this variant is the `url` top-level field for ALL direct-mode types (Graphite, OpenTSDB, generic HTTP datasources, legacy datasources)
- **Reconnaissance**: Disclosed URLs enable targeted internal network scanning and SSRF exploitation pivot
- **Combined with credential exposure**: For InfluxDB direct-mode, the URL is additionally included in the credential exposure (p8-002/p10-001); for other types this may be the only sensitive field

## Evidence

```go
// pkg/api/frontendsettings.go:496-510
url := ds.URL  // For direct-mode: raw backend URL (e.g., "http://graphite.internal:8080")

if ds.Access == datasources.DS_ACCESS_PROXY {
    url = "/api/datasources/proxy/uid/" + ds.UID  // Only proxy-mode gets the safe proxied URL
}

dsDTO := plugins.DataSourceDTO{
    // ...
    URL: url,    // For direct-mode, this is the RAW backend URL — no IsPublicDashboardView() guard
    // ...
    Access: string(ds.Access),  // "direct" — confirms the access mode in response
}
```

The `IsPublicDashboardView()` check at line 476 only governs which datasources pass the filter; it does not suppress or redact the `URL` field for datasources that do pass the filter and are included in the public dashboard response.

## Reproduction Steps

1. Create a Graphite datasource (or any non-Prometheus direct-mode datasource) with `Access: direct` and URL `http://graphite.internal:8080`
2. Create a dashboard using this datasource and enable public sharing
3. Note the public dashboard access token from the share URL
4. As an unauthenticated user, request:
   ```
   GET /api/frontend/settings
   Cookie: [public dashboard access token cookie]
   ```
5. Observe the response JSON contains `"url": "http://graphite.internal:8080"` in the datasource entry — the raw internal backend URL is disclosed
6. Note that `"access": "direct"` is also present in the response, confirming this is a direct-mode datasource whose URL is the actual backend
