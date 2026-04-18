Phase: 10
Sequence: 003
Slug: panel-datasource-uid-filter-bypass
Verdict: VALID
Rationale: The same ByRef fallback that bypasses the CVE-2026-27877 datasource filter via template variables is also triggered by direct panel-level datasource fields — any dashboard editor can inject an arbitrary direct-mode datasource UID into panel.datasource to make it pass publicDashFilterUsedDataSources and receive its credentials.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-003-cve-2026-27877-bypass.md
Origin-Pattern: AP-002

## Summary

The public dashboard datasource filter (`publicDashFilterUsedDataSources`) calls `ReadDashboard` with an empty `DatasourceLookup`. When parsing panel-level `datasource` fields, `readpanelInfo` calls `targets.addDatasource()` which invokes `s.lookup.ByRef(ref)`. With an empty lookup, `ByRef` falls through to `ds_lookup.go:129` and returns the original ref unchanged, adding the arbitrary UID to `usedUIDs`. Any UID placed in a panel's `datasource` field by a dashboard editor will be included in the filter's output, allowing an attacker-controlled direct-mode datasource UID to bypass the CVE-2026-27877 filter and receive its decrypted credentials in the public dashboard frontend settings response.

This is a structural sibling of p8-003. That finding exploits the bypass via template variables; this finding exploits it via direct panel datasource fields. The exploiting dashboard JSON does not need any template variables at all.

## Location

- **Bypass entry**: `pkg/services/store/kind/dashboard/dashboard.go:614` — `case "datasource": targets.addDatasource(iter, ...)` in `readpanelInfo`
- **Bypass implementation**: `pkg/services/store/kind/dashboard/targets.go:41,56` — `s.lookup.ByRef(dsRef)` called with empty DsLookup
- **Fallback passthrough**: `pkg/services/store/kind/dashboard/ds_lookup.go:129` — `return ref` when UID not found in empty byUID map
- **Empty lookup creation**: `pkg/api/frontendsettings.go:851-853` — `CreateDatasourceLookup([]*DatasourceQueryResult{})` creates empty maps
- **Credential leak**: `pkg/api/frontendsettings.go:541-577` — same as p8-002

## Attacker Control

Dashboard editor (a standard Grafana role) controls the full dashboard JSON including `panels[].datasource`. The attacker sets `panel.datasource` to `{"uid": "target-direct-mode-ds", "type": "..."}` where `target-direct-mode-ds` is the UID of any direct-mode datasource in the org. No template variables, no `current.value`, just a plain panel datasource reference.

The panel need not actually execute queries successfully — the filter reads the dashboard JSON for UID collection, not for query validation.

## Trust Boundary Crossed

Dashboard editor privilege → unauthenticated credential disclosure. The editor saves the dashboard JSON with an arbitrary `panel.datasource.uid`; an unauthenticated viewer of the public dashboard receives the target datasource's decrypted credentials via `GET /api/frontend/settings` (with public dashboard context).

## Impact

- **CVE fix bypass**: Bypasses the CVE-2026-27877 fix via a simpler attack vector than p8-003 (no template variables required)
- **Credential disclosure**: Any direct-mode datasource in the org (BasicAuth password, InfluxDB plaintext password) exposed to unauthenticated viewers
- **Lower precondition**: Does not require understanding of template variable structure; a simple panel JSON modification suffices
- **Wider reach**: Affects both v1 dashboards (panels array) and v2 dashboards (elements structure), as `readV2PanelSpec` at `dashboard.go:733-791` also collects datasource UIDs without validation

## Evidence

```go
// pkg/services/store/kind/dashboard/dashboard.go:614
case "datasource":
    targets.addDatasource(iter, jsonPath+".datasource", lc)
```

```go
// pkg/services/store/kind/dashboard/targets.go:52-58
case jsoniter.ObjectValue:
    ref := &DataSourceRef{}
    iter.ReadVal(ref)

    if !isVariableRef(ref.UID) && !isSpecialDatasource(ref.UID) {
        s.addRef(s.lookup.ByRef(ref))  // empty lookup -> returns ref unchanged
    }
```

```go
// pkg/services/store/kind/dashboard/ds_lookup.go:99-129
func (d *DsLookup) ByRef(ref *DataSourceRef) *DataSourceRef {
    // ...all lookup attempts fail on empty maps...
    // With nothing was found (or configured), use the original reference
    return ref  // arbitrary UID returned as-is
}
```

```go
// pkg/api/frontendsettings.go:851-853
lookup := dashboardkind.CreateDatasourceLookup([]*dashboardkind.DatasourceQueryResult{
    // empty values (does not resolve anything)
})
```

The returned ref goes into `targets.uids` → `dash.Datasource` → `usedUIDs` in `publicDashFilterUsedDataSources`, causing the arbitrary UID to pass the filter and its datasource to be included in the frontend settings response (which then triggers credential extraction at lines 541-577).

## Reproduction Steps

1. Identify a direct-mode datasource UID in the org (e.g., `influxdb-prod-uid`)
2. Create or edit a dashboard with a panel using that datasource UID directly:
   ```json
   {
     "panels": [{
       "id": 1,
       "type": "timeseries",
       "title": "Test",
       "datasource": {"uid": "influxdb-prod-uid", "type": "influxdb"},
       "targets": []
     }]
   }
   ```
   Note: no template variables needed, no actual queries needed
3. Enable public sharing on this dashboard
4. As an unauthenticated user, fetch the public dashboard frontend settings:
   `GET /api/frontend/settings` (with public dashboard access token)
5. Observe `influxdb-prod-uid` datasource with decrypted credentials in the response
6. The editor does NOT need RBAC permission to read/query the datasource — only to save the dashboard JSON containing its UID
