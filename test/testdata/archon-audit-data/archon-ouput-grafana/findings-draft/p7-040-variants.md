# Variant Analysis Summary: p7-040 (Annotation Time-Range Guard Bypass)

**Origin Finding:** security/findings-draft/p7-040-public-dashboard-annotation-timerange-bypass.md
**Attack Pattern:** AP-040 (Annotation Time-Range Guard Bypass — from=0/to=0)
**Analysis Date:** 2026-03-20
**NNN Range Assigned:** p7-060 to p7-062
**Variants Found:** 1

---

## Search Strategies Executed

### 1. Registry-Driven Grep Search

Pattern searched: `query\.From > 0 && query\.To > 0`

Results:
- `pkg/services/annotations/annotationsimpl/xorm_store.go:389` — original sink (p7-040)
- `pkg/services/annotations/annotationsimpl/xorm_store.go:477` — metrics recording function `recordQueryMetrics`, not security-relevant (same guard, different purpose: skips Prometheus histogram recording when no time range provided)
- `security/real-env-evidence/public-dashboard-annotation-timerange-bypass/timerange_bypass_test.go:51` — test artifact, not production code

### 2. Entry Point Search

Searched all callers of `QueryInt64("from")` and `QueryInt64("to")` in the codebase:

- **`pkg/services/publicdashboards/api/query.go:96-97`** — original finding (p7-040), unauthenticated
- **`pkg/api/annotations.go:38-39`** — **VARIANT FOUND** → p7-060

No other files use `QueryInt64("from")` or `QueryInt64("to")` for annotation time range inputs.

### 3. Panel Query Path (Public Dashboard)

Examined `POST /api/public/dashboards/:accessToken/panels/:panelId/query`.

**Result: NOT VULNERABLE.** The panel query path uses string-based time range (`TimeRangeDTO.From`, `TimeRangeDTO.To` as "now-1h"/"now"). `ValidateQueryPublicDashboardRequest` at `pkg/services/publicdashboards/validation/validation.go:28-38` explicitly rejects blank or unparseable time range strings when `TimeSelectionEnabled=true`. When `TimeSelectionEnabled=false`, the function `getTimeRangeValuesOrDefault` falls back to the dashboard's stored time range strings, which always produce non-zero epoch values via `gtime.NewTimeRange().ParseFrom/ParseTo`. No zero-integer bypass path exists here.

### 4. Alternative Annotation Store (Loki)

Examined `pkg/services/annotations/annotationsimpl/loki/historian_store.go`.

**Result: NOT VULNERABLE.** The Loki historian store explicitly handles zero values at lines 124-129:
```go
if query.To == 0 {
    query.To = now.UnixMilli()
}
if query.From == 0 {
    query.From = now.Add(-defaultQueryRange).UnixMilli()
}
```
This defensive guard correctly substitutes safe defaults when `From` or `To` are zero, preventing the bypass. Only the xorm store (the default store for non-Loki deployments) is vulnerable.

### 5. Phase 7 Addendum Check

Reviewed the `## Phase 7 Addendum` in `security/knowledge-base-report.md`. Chamber 3 explicitly documented the annotation time-range bypass for the public dashboard path. No new attack surfaces in the addendum are relevant to AP-040 beyond those already examined.

### 6. Alerting State and Variable Endpoints

There are no alerting state or variable endpoints in the public dashboard API (no `GET .../alerts` or `GET .../variables` routes in `pkg/services/publicdashboards/api/api.go`). These were not present as potential variant surfaces.

---

## Confirmed Variants

### p7-060: Authenticated Annotation Time-Range Bypass

**File:** security/findings-draft/p7-060-authenticated-annotation-timerange-bypass.md

**Entry Point:** `GET /api/annotations`
**Handler:** `pkg/api/annotations.go:36-79` (`GetAnnotations`)
**Sink:** `pkg/services/annotations/annotationsimpl/xorm_store.go:389-392`
**Root Cause:** Same `if query.From > 0 && query.To > 0` guard — `c.QueryInt64("from")` and `c.QueryInt64("to")` return 0 for omitted or zero parameters, bypassing the time-range SQL WHERE clause.

**Key Differences from Original:**
- Requires authenticated session or API key (or anonymous access when `auth.anonymous.enabled=true`)
- No DashboardID zeroing; scope is bounded by the caller's RBAC permissions
- Does not require `TimeSelectionEnabled=true` (no such concept here; the guard is always bypassed)
- Lower severity (MEDIUM) because authentication is required in typical configurations

**Severity:** MEDIUM

---

## Rejected Candidates

| Candidate | Location | Reason for Rejection |
|-----------|----------|----------------------|
| Panel query time range bypass | POST /api/public/dashboards/:token/panels/:id/query | Uses string-based time range with explicit validation in ValidateQueryPublicDashboardRequest |
| Loki historian store bypass | annotationsimpl/loki/historian_store.go:124-129 | Has explicit zero-value default guard; produces safe non-zero values |
| recordQueryMetrics bypass | xorm_store.go:477 | Metrics only, no security impact |
| Public dashboard alerting state | (none) | No alerting state endpoint exists in public dashboard API |
| Public dashboard variables | (none) | No variable query endpoint exists in public dashboard API |

---

## Pattern Coverage Summary

The AP-040 pattern (`if From > 0 && To > 0` guard on time-range SQL filter) has exactly one vulnerable implementation: `xorm_store.go:389`. It is reached from two different entry points:

1. **Unauthenticated (original):** via public dashboard annotation endpoint with access token
2. **Authenticated (variant p7-060):** via standard annotations API with user session/API key

No other entry points flow to this guard. The Loki store has a parallel but safe guard. The panel query path uses a completely different time representation (string-based) with separate validation.

