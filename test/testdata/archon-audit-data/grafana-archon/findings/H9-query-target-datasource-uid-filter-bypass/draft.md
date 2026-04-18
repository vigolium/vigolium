Phase: 10
Sequence: 004
Slug: query-target-datasource-uid-filter-bypass
Verdict: VALID
Rationale: The ByRef fallback in DsLookup is also triggered by per-query-target datasource fields inside panel targets[], providing a third distinct injection point for the same CVE-2026-27877 filter bypass — a dashboard editor can inject an arbitrary direct-mode datasource UID via a query target's datasource field to expose its credentials to unauthenticated public dashboard viewers.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-003-cve-2026-27877-bypass.md
Origin-Pattern: AP-002

## Summary

`publicDashFilterUsedDataSources` uses `ReadDashboard` with an empty DatasourceLookup. When `readpanelInfo` processes the `targets[]` array in a panel, it calls `targets.addTarget()` for each element, which in turn calls `targets.addDatasource()` for the target-level `datasource` field. This `addDatasource` call invokes `s.lookup.ByRef(ref)` with the empty DsLookup, hitting the fallback at `ds_lookup.go:129` which returns the original ref unchanged. The arbitrary UID from the query target's `datasource` field is added to `usedUIDs`, bypassing the CVE-2026-27877 filter and exposing the target datasource's decrypted credentials in the public dashboard frontend settings.

This is the third structural variant of the same ByRef fallback bypass:
- p8-003: template variable `current.value` field
- p10-003: panel-level `datasource` field
- p10-004 (this finding): query target `targets[].datasource` field

All three use the same empty-lookup passthrough at `ds_lookup.go:129` but differ in which part of the dashboard JSON carries the attacker-controlled UID.

## Location

- **Bypass entry**: `pkg/services/store/kind/dashboard/dashboard.go:618,625` — `case "targets": targets.addTarget(iter, ...)` in `readpanelInfo`
- **Bypass propagation**: `pkg/services/store/kind/dashboard/targets.go:78-88` — `addTarget` reads each target object and calls `addDatasource` for target's `datasource` field
- **Bypass implementation**: `pkg/services/store/kind/dashboard/targets.go:41,56` — `s.lookup.ByRef(dsRef)` with empty DsLookup
- **Fallback passthrough**: `pkg/services/store/kind/dashboard/ds_lookup.go:129` — `return ref`
- **Empty lookup**: `pkg/api/frontendsettings.go:851-853`
- **Credential leak**: `pkg/api/frontendsettings.go:541-577`

## Attacker Control

Dashboard editor controls `panels[].targets[].datasource`. The attacker sets a query target's `datasource` field to `{"uid": "target-direct-mode-ds"}`. This is a different JSON location than p8-003 (templating.list) and p10-003 (panels[].datasource), providing an alternative injection point that may evade any future per-field sanitization that patches only one location.

## Trust Boundary Crossed

Dashboard editor privilege → unauthenticated credential disclosure. The editor controls the dashboard JSON's `targets[].datasource` field; an unauthenticated viewer receives the target datasource's decrypted credentials.

## Impact

- **CVE fix bypass**: Third distinct injection point for the same bypass, independent of template variables and panel-level datasource fields
- **Credential disclosure**: Same impact as p8-002 and p8-003 — decrypted BasicAuth/InfluxDB passwords for direct-mode datasources
- **Defense evasion**: If a future patch sanitizes only template variables (the original p8-003 finding) or only panel-level datasource fields (p10-003), this target-level variant remains exploitable
- **Cumulative severity**: The existence of three independent injection points for the same filter bypass makes a comprehensive fix harder — all three callsites to `ByRef` within the ReadDashboard flow must be addressed

## Evidence

```go
// pkg/services/store/kind/dashboard/dashboard.go:617-632
case "targets":
    if !checkAndSkipUnexpectedElement(iter, jsonPath+".targets", lc, jsoniter.ArrayValue, jsoniter.ObjectValue) {
        continue
    }
    switch iter.WhatIsNext() {
    case jsoniter.ArrayValue:
        for ix := 0; iter.ReadArray(); ix++ {
            targets.addTarget(iter, fmt.Sprintf("%s.targets[%d]", jsonPath, ix), lc)
        }
    // ...
```

```go
// pkg/services/store/kind/dashboard/targets.go:72-88
func (s *targetInfo) addTarget(iter *jsoniter.Iterator, jsonPath string, lc map[string]any) {
    // ...
    for f := iter.ReadObject(); f != ""; f = iter.ReadObject() {
        switch f {
        case "datasource":
            s.addDatasource(iter, jsonPath+".datasource", lc)  // -> ByRef with empty lookup
        // ...
    }
}
```

```go
// pkg/services/store/kind/dashboard/targets.go:52-58 (addDatasource, ObjectValue case)
case jsoniter.ObjectValue:
    ref := &DataSourceRef{}
    iter.ReadVal(ref)
    if !isVariableRef(ref.UID) && !isSpecialDatasource(ref.UID) {
        s.addRef(s.lookup.ByRef(ref))  // empty lookup returns ref unchanged (ds_lookup.go:129)
    }
```

The UID flows from `targets.uids` → `panel.Datasource` → `targets.addPanel(panel)` → `dash.Datasource` → `usedUIDs` → credential extraction at frontendsettings.go:541-577.

## Reproduction Steps

1. Identify a direct-mode datasource UID (e.g., `postgres-prod-uid`)
2. Create or edit a dashboard with a panel containing a query target with the target datasource:
   ```json
   {
     "panels": [{
       "id": 1,
       "type": "timeseries",
       "title": "Benign Panel",
       "datasource": {"uid": "legitimate-ds", "type": "prometheus"},
       "targets": [
         {
           "refId": "A",
           "datasource": {"uid": "postgres-prod-uid", "type": "postgres"},
           "rawSql": "SELECT 1"
         }
       ]
     }]
   }
   ```
   Note: The panel itself can have an allowed datasource; only the target needs the target UID
3. Enable public sharing on this dashboard
4. As an unauthenticated user, fetch the public dashboard frontend settings
5. Observe `postgres-prod-uid` datasource with decrypted credentials in the response
6. The target query may fail at query time (wrong datasource type, etc.) but the credential leak occurs at settings fetch time, independently of query execution
