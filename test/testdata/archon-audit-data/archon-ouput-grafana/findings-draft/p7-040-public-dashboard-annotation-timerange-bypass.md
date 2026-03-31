Phase: 7
Sequence: 040
Slug: public-dashboard-annotation-timerange-bypass
Verdict: VALID
Rationale: Unauthenticated annotation exfiltration across dashboard boundaries within an org when TimeSelectionEnabled=true. The from=0/to=0 guard bypass at xorm_store.go:389 is a confirmed logic bug (CVE-2026-21722). Tag-based DashboardID zeroing at query.go:61 amplifies impact to org-wide scope. Advocate's TimeSelectionEnabled defense acknowledged as precondition but rejected as blocking protection since it is commonly enabled in production.
Severity-Original: CRITICAL
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The public dashboard annotation endpoint (`GET /api/public/dashboards/:accessToken/annotations`) accepts `from` and `to` query parameters that are parsed via `c.QueryInt64()` with no range validation. When both values are 0, the time-range WHERE clause at `xorm_store.go:389` is skipped entirely (the guard `if query.From > 0 && query.To > 0` evaluates to false). Additionally, when the dashboard has tag-based annotation sources configured (`Target.Type == "tags"`), the annotation query sets `DashboardID=0` and `DashboardUID=""` at `query.go:60-63`, removing dashboard-level scoping. The combined effect is that all matching tag-based annotations in the entire org are returned to an unauthenticated user.

This requires `TimeSelectionEnabled=true` on the public dashboard (when false, the request's from/to values are ignored and the dashboard's own time range is used). TimeSelectionEnabled is commonly enabled in production to allow viewers to adjust time ranges.

## Location

- **Source:** `pkg/services/publicdashboards/api/query.go:95-98` -- `c.QueryInt64("from")` and `c.QueryInt64("to")` with no validation
- **Time range resolution:** `pkg/services/publicdashboards/service/query.go:643-647` -- `getAnnotationsTimeRange()` returns request from/to when TimeSelectionEnabled=true
- **Dashboard ID zeroing:** `pkg/services/publicdashboards/service/query.go:60-63` -- DashboardID=0 for tag-based queries
- **Sink:** `pkg/services/annotations/annotationsimpl/xorm_store.go:389-392` -- guard `if query.From > 0 && query.To > 0` skipped when both are 0

## Attacker Control

Unauthenticated internet user with a valid (or leaked) public dashboard access token. The access token is 32-char hex (128-bit entropy), not brute-forceable, but commonly shared via URL. The attacker directly controls `from` and `to` via URL query parameters.

## Trust Boundary Crossed

TB7 (Public Dashboard Gate) -- anonymous request crosses from internet into org-scoped annotation store. The time-range filter bypass allows access to annotations outside the dashboard's intended time window. The tag-based DashboardID zeroing allows access to annotations from other dashboards within the same org.

## Impact

Information disclosure: all tag-based annotations in the org matching the dashboard's configured tags are returned. This includes annotations from private dashboards, alert state annotations, incident annotations, and deployment markers. The exposure is within-org (org_id filter is maintained), not cross-org. In multi-org deployments, only the org associated with the public dashboard is affected.

## Evidence

1. `query.go:95-98`: `From: c.QueryInt64("from"), To: c.QueryInt64("to")` -- no validation
2. `query.go:643-647`: `if timeSelectionEnabled { return reqDTO.From, reqDTO.To }` -- attacker values used directly
3. `query.go:60-63`: `if anno.Target.Type == "tags" { annoQuery.DashboardID = 0; annoQuery.DashboardUID = "" }` -- dashboard scoping removed
4. `xorm_store.go:389-392`: `if query.From > 0 && query.To > 0 { sql.WriteString(...) }` -- time filter skipped when both are 0
5. CVE-2026-21722 pre-confirmed by CodeQL (SAST-001, SAST-002)

## Reproduction Steps

1. Identify or obtain a valid public dashboard access token (32-char hex string)
2. Verify the public dashboard has `TimeSelectionEnabled=true` and at least one tag-based annotation source configured
3. Send: `GET /api/public/dashboards/<accessToken>/annotations?from=0&to=0`
4. Observe response contains annotations from across the org, not limited to the specific dashboard or time range
5. Compare with a request using valid from/to values (e.g., last 1 hour) to confirm the bypass returns additional annotations

## Cold Verification

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Independent code trace confirms from=0/to=0 propagates to xorm_store.go:389 guard without validation when TimeSelectionEnabled=true, and tag-type DashboardID zeroing at query.go:61 enables org-wide scope. Service identity wildcard permissions bypass all access control. Code-level test proves the bypass.
Severity-Final: HIGH
PoC-Status: theoretical

### Claim-by-Claim Verification

**Claim 1: Public dashboard annotation endpoint accepts from=0 and to=0 without rejection**
CONFIRMED. At `pkg/services/publicdashboards/api/query.go:95-98`, the `AnnotationsQueryDTO` is constructed with `From: c.QueryInt64("from"), To: c.QueryInt64("to")`. The `QueryInt64` method returns 0 for missing or "0" parameters. No validation rejects zero values anywhere in the chain.

**Claim 2: The time range guard at xorm_store.go:389 is conditional on From>0 && To>0**
CONFIRMED. At `pkg/services/annotations/annotationsimpl/xorm_store.go:389-392`:
```go
if query.From > 0 && query.To > 0 {
    sql.WriteString(` AND a.epoch <= ? AND a.epoch_end >= ?`)
    params = append(params, query.To, query.From)
}
```
When both values are 0, the condition is false, and no time-range SQL clause is added.

**Claim 3: Tag-type annotations zero out DashboardID at query.go:60-64, making results org-wide**
CONFIRMED. At `pkg/services/publicdashboards/service/query.go:60-64`:
```go
if anno.Target.Type == "tags" {
    annoQuery.DashboardID = 0
    annoQuery.DashboardUID = ""
    annoQuery.Tags = anno.Target.Tags
}
```
This removes dashboard-level scoping. Combined with the service identity's wildcard permissions (verified at `pkg/apimachinery/identity/context.go:148-149`, which grants `annotations:read: ["*"]`), the access control layer at `annotationsimpl/annotations.go:86-98` allows org-wide queries, and the xorm store's `getAccessControlFilter` at line 494-521 permits access to all dashboards plus org annotations.

**Claim 4: This path is reachable without authentication (only public dashboard access token needed)**
CONFIRMED. Route registration at `pkg/services/publicdashboards/api/api.go:71-75` groups the annotations endpoint under `/api/public/dashboards/:accessToken` with only `api.Middleware.HandleApi` middleware, which is an empty no-op function (`middleware.go:80-81`). The anonymous route is also confirmed at `pkg/api/api.go:197`. No `reqSignedIn` middleware is applied.

**Claim 5: TimeSelectionEnabled=true is required for the bypass to work**
CONFIRMED. At `pkg/services/publicdashboards/service/query.go:643-647`:
```go
func getAnnotationsTimeRange(..., timeSelectionEnabled bool) (int64, int64) {
    if timeSelectionEnabled {
        return reqDTO.From, reqDTO.To
    }
    // ... parses dashboard time range, returns non-zero values ...
}
```
When `timeSelectionEnabled=false`, the dashboard's stored time range (e.g., "now-6h" to "now") is parsed into non-zero epoch milliseconds, which properly activates the xorm time filter. Verified by code-level test: disabled path returned `from=1773973951047, to=1773995551047`.

### Additional Finding: Service Identity Privilege Escalation

The service identity created at `query.go:41` via `identity.WithServiceIdentity(ctx, dash.OrgID)` has admin-level privileges (`OrgRole: RoleAdmin`, `IsGrafanaAdmin: true`) and wildcard permissions for `annotations:read`. This means the `Authorize` call in `RepositoryImpl.Find` always grants full org-wide annotation access. The access control layer provides no protection against this attack because the query executes under an elevated internal identity rather than the unauthenticated caller's identity.

### Severity Downgrade Rationale

Downgraded from CRITICAL to HIGH because:
- Three non-default configuration preconditions must all be true: `TimeSelectionEnabled=true`, `AnnotationsEnabled=true`, and tag-based annotation source configured
- Access token (128-bit entropy) must be known to attacker
- Impact is read-only information disclosure (no write/modify/RCE)
- Scope is within-org only (org_id filter always applies)
- No cross-org or cross-instance data exposure

Despite these preconditions, the finding reaches HIGH because:
- Remotely triggerable from the internet
- Crosses a meaningful trust boundary (anonymous -> org-internal data)
- Annotation text can contain operationally sensitive information
- The preconditions represent common production configurations for public dashboards

### Evidence Files

- Code-level proof test: `security/real-env-evidence/public-dashboard-annotation-timerange-bypass/timerange_bypass_test.go`
- Full adversarial review: `security/adversarial-reviews/public-dashboard-annotation-timerange-bypass-review.md`
