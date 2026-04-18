# Bypass Analysis: Public Dashboard Annotation Time Range Fix

**Patch**: e97fa5f587c80fc3956faf56e29aa5c717f1bc43
**Component**: `pkg/services/publicdashboards/service/query.go`
**Advisory**: No CVE (MEDIUM, CVSS ~5.5)
**Cluster ID**: pubdash-annotation-timerange

## Patch Summary

**Vulnerability**: When `TimeSelectionEnabled` was `false` on a public dashboard, the `FindAnnotations` function still used the attacker-controlled `from`/`to` query parameters from the HTTP request (`reqDTO.From`, `reqDTO.To`) to query the annotation store. This allowed an unauthenticated user with a public dashboard access token to retrieve annotation data from arbitrary historical time ranges, even though the dashboard owner intended to lock the visible time window.

**Fix mechanism**: A new function `getAnnotationsTimeRange()` was introduced. When `TimeSelectionEnabled` is `false`, it parses the dashboard's saved time range (from the dashboard JSON data) and uses those values instead of the request parameters. The function handles both v1 dashboards (`data.time.from`/`data.time.to`) and v2 dashboards (`data.timeSettings.from`/`data.timeSettings.to`).

## Bypass Verdict: **sound** (with minor observations)

The core fix is correct -- the request time range is properly ignored when time selection is disabled, and the dashboard's own time range is enforced server-side.

## Evidence and Analysis

### 1. Alternate Entry Points -- No Bypass

There is only one annotation endpoint for public dashboards: `GET /api/public/dashboards/:accessToken/annotations` (registered in `api/api.go:73`). This routes to `GetPublicAnnotations` which is the sole caller of `FindAnnotations`. No other code path reaches the annotation query logic for public dashboards.

### 2. V2 Dashboard Detection Inconsistency -- Low Risk

The patch uses `d.Data.Get("elements").Interface() != nil` to detect v2 dashboards at line 674. However, elsewhere in the same file, `isDashboardV2()` (line 484) uses `dash.APIVersion` string prefix matching. These are two different detection mechanisms:

- `getAnnotationsTimeRange()` checks the JSON payload for an `elements` key
- `isDashboardV2()` checks `dash.APIVersion` field

If a v2 dashboard somehow has its `elements` key absent or null in the JSON data while still having `APIVersion` set to `v2`, the annotation function would fall through to the v1 path and read `data.time.from`/`data.time.to` instead of `data.timeSettings.*`. This would yield empty strings, resulting in `NewTimeRange("", "")` which would produce a default "now" based time range. This is a **fail-safe** behavior (empty/narrow range rather than wide open), so it does not constitute a bypass.

The same `elements`-based detection is used in `buildMetricRequest()` at line 166, so the annotation fix is at least consistent with the query data path.

### 3. Error Handling in Time Parsing -- Fail-Safe

`timeRange.ParseFrom()` and `timeRange.ParseTo()` errors are silently discarded (line 694-695). If the dashboard JSON contains malformed time strings, the parsed values would default to zero-value `time.Time`, producing Unix epoch milliseconds (negative or zero). This is fail-safe: an attacker cannot exploit malformed dashboard data to widen the query range because:
- The dashboard data is server-controlled, not user-supplied on the annotation request
- A zero/epoch time range would be narrower, not wider, than intended

### 4. Consistency with Metric Query Path -- Consistent

The `buildTimeSettings()` and `buildTimeSettingsV2()` functions (lines 493-534) already properly enforced `TimeSelectionEnabled` for metric/panel queries. The annotation path was the only one missing this check. The fix brings annotations in line with the metric query behavior.

### 5. Tag-Based Annotation Queries -- No Bypass

When an annotation target has `type == "tags"`, the query clears `DashboardID` and `DashboardUID` (lines 62-65), allowing cross-dashboard annotation lookups. However, the time range fix still applies to these queries since `from`/`to` are set before the loop. The tag query can only return annotations within the dashboard's time range when time selection is disabled. This is correct.

### 6. Request From/To When Time Selection Enabled -- By Design

When `TimeSelectionEnabled` is `true`, the request `from`/`to` are used directly. This is intentional -- the dashboard owner opted in to allowing time range selection.

## Minor Observations (Not Bypasses)

1. **Duplicated logic**: `getAnnotationsTimeRange()` partially duplicates `getTimeRangeValuesOrDefault()`/`getTimeRangeValuesOrDefaultV2()` but without panel-relative time range support. This is acceptable because annotations are dashboard-wide, not panel-specific.

2. **No timezone from request**: Unlike the metric query path which allows a user-supplied timezone when time selection is enabled, the annotation path does not accept a timezone parameter. This is a minor inconsistency but not a security issue.

3. **`NewTimeRange` is a mutable package variable** (line 490): `var NewTimeRange = gtime.NewTimeRange`. This is used by tests to stub time. Not a security concern but worth noting as a global mutable.

## Tags

- [undisclosed] -- This commit has no associated CVE or GHSA advisory.
- Cluster ID: `pubdash-annotation-timerange`
