# Bypass Analysis: CVE-2026-21722 -- Public Dashboard Timerange Bypass

**Patch Commit:** `e97fa5f587c`
**PR:** #117854
**Severity:** MEDIUM (5.3)
**Cluster ID:** PATCH-T1-02
**Component:** `pkg/services/publicdashboards/service/query.go`

---

## Patch Summary

**Vulnerability:** When `TimeSelectionEnabled = false` on a public dashboard, the annotation query endpoint (`GET /public/dashboards/{accessToken}/annotations?from=X&to=Y`) was passing client-supplied `from`/`to` query parameters directly to the annotation repository query. This allowed unauthenticated users to enumerate annotations outside the dashboard's intended time window.

**Fix:** The patch introduces `getAnnotationsTimeRange()`, which checks the `pub.TimeSelectionEnabled` flag:
- If `true`: uses the client-supplied `reqDTO.From` / `reqDTO.To` (existing behavior, by design).
- If `false`: parses the dashboard's stored time range (`time.from` / `time.to` for v1, `timeSettings.from` / `timeSettings.to` for v2) and uses those epoch-millisecond values instead, ignoring the request parameters entirely.

---

## Bypass Verdict: **sound**

The fix correctly addresses the vulnerability. No actionable bypass was identified. Below is the detailed analysis of each hypothesis.

---

## Hypothesis Analysis

### 1. Does the fix apply to ALL annotation query paths?

**Result: No bypass.** There is exactly one entry point for public dashboard annotations:

- `GET /public/dashboards/{accessToken}/annotations` -> `Api.GetPublicAnnotations()` (file: `pkg/services/publicdashboards/api/query.go:89`)
- This calls `PublicDashboardService.FindAnnotations()` which is the sole implementation in `pkg/services/publicdashboards/service/query.go:22`.

There is no WebSocket streaming path for public dashboard annotations. The fix covers the only code path.

### 2. Can `TimeSelectionEnabled` be overridden via URL parameters?

**Result: No bypass.** `TimeSelectionEnabled` is a `bool` field stored in the database (`xorm:"time_selection_enabled"`) on the `PublicDashboard` model (line 52 of `models.go`). It is loaded from the database via `FindByAccessToken` and is not read from request parameters. The API handler at `query.go:95-98` only reads `from` and `to` from the request query string -- there is no parameter that could override `TimeSelectionEnabled`.

The field can only be changed through the authenticated public dashboard management API (`POST/PUT /api/dashboards/uid/{dashboardUid}/public-dashboards`), which requires dashboard admin permissions.

### 3. Authenticated annotation endpoint bypass?

**Result: Not applicable (different threat model).** The authenticated `GET /api/annotations` endpoint (`pkg/api/annotations.go:36`) accepts arbitrary `from`/`to`/`dashboardId` parameters, but it:
- Requires authentication (signed-in user).
- Enforces standard Grafana RBAC authorization via `SignedInUser`.
- Is scoped to the user's organization.

This is a separate endpoint for authenticated users and is not part of the public dashboard attack surface. An unauthenticated attacker cannot use it. An authenticated user with annotation read permissions already has legitimate access to annotations within their org -- the CVE specifically concerns unauthenticated access via public dashboards.

### 4. Annotation query types that bypass the timerange check?

**Result: No bypass.** The `FindAnnotations` method iterates over `annoDto.Annotations.List` and only processes annotations with Grafana datasource UIDs (the `grafanads.DatasourceUID` / `grafanads.DatasourceName` check at line 45). All such annotations go through the same `annoQuery` construction that uses the fixed `from`/`to` values (lines 48-49). There are no separate code paths for alert state history or other annotation types within this function.

### 5. Relative time expressions handling?

**Result: Correctly handled.** The `getAnnotationsTimeRange()` function (line 643) parses the dashboard's time strings (which can be relative like `now-1h` or absolute like `2026-01-01T00:00:00.000Z`) using `gtime.NewTimeRange().ParseFrom()` / `ParseTo()`. These are the same parsing functions used by `buildTimeSettings()` for the data query path. The test suite (`TestGetAnnotationsTimeRange`) explicitly covers:
- Absolute timestamps (v1 and v2 dashboards)
- Relative time expressions (`now-1d/d`, `now-1h`, `now`)
- Timezone handling (Europe/Madrid, Europe/London, UTC, empty/invalid)

One minor observation: errors from `ParseFrom`/`ParseTo` are silently discarded (assigned to `_`). If parsing fails, the returned `time.Time` zero value would produce epoch 0 (Jan 1, 1970) as milliseconds, which would result in an overly broad query rather than a restricted one. However, this would require the dashboard owner to have stored an unparseable time string in the dashboard JSON, which is not attacker-controlled in the public dashboard context.

### 6. Consistency with data query timerange handling?

**Result: Consistent.** The data query path (`GetQueryDataResponse` -> `buildMetricRequest` -> `buildTimeSettings` / `buildTimeSettingsV2` -> `getTimeRangeValuesOrDefault`) already correctly enforced dashboard time ranges when `TimeSelectionEnabled = false`. The annotation path was the only gap, and this patch closes it.

---

## Additional Observations

- **Default value safety:** `TimeSelectionEnabled` defaults to `false` (Go zero value for bool). This means newly created public dashboards default to using the dashboard's locked timerange, which is the secure default. The `returnValueOrDefault` function in `service.go:580` also defaults to `false` when `nil` is provided.
- **Scope limitation:** The fix is scoped exclusively to `FindAnnotations`. The analogous data query path (`GetQueryDataResponse`) was already secure before this patch. This is not a relocated vulnerability -- it was an incomplete initial implementation where annotations were overlooked.

---

## Evidence

**Pre-patch vulnerable code** (from `git show e97fa5f587c~1`):
```go
annoQuery := &annotations.ItemQuery{
    From:         reqDTO.From,   // <-- directly from client request
    To:           reqDTO.To,     // <-- directly from client request
    ...
}
```

**Post-patch fixed code:**
```go
from, to := getAnnotationsTimeRange(dash, reqDTO, pub.TimeSelectionEnabled)
// ...
annoQuery := &annotations.ItemQuery{
    From:         from,  // <-- from dashboard config when TimeSelectionEnabled=false
    To:           to,    // <-- from dashboard config when TimeSelectionEnabled=false
    ...
}
```

**Single entry point confirmed:** `pkg/services/publicdashboards/api/api.go:73`:
```go
apiRoute.Get("/annotations", routing.Wrap(api.GetPublicAnnotations))
```
