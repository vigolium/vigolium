Phase: 9
Sequence: 060
Slug: authenticated-annotation-timerange-bypass
Verdict: VALID
Rationale: The authenticated annotation list endpoint shares the same from=0/to=0 guard bypass at xorm_store.go:389 as the original public dashboard finding, allowing any user with annotations:read permission to retrieve all org annotations regardless of time range.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-040-public-dashboard-annotation-timerange-bypass.md
Origin-Pattern: AP-040

## Summary

The authenticated `GET /api/annotations` endpoint at `pkg/api/annotations.go:36-79` reads `from` and `to` as int64 query parameters via `c.QueryInt64()` with no range validation. When both values are 0 (either omitted or explicitly set to 0), the time-range WHERE clause at `pkg/services/annotations/annotationsimpl/xorm_store.go:389` is skipped entirely because the guard `if query.From > 0 && query.To > 0` evaluates to false.

This is the same root cause as p7-040. The difference is that this entry point requires an authenticated session or API key with `annotations:read` permission, whereas the original found an unauthenticated path through the public dashboard gateway.

Any user with `annotations:read` on their org (Grafana Viewer role or above) can retrieve all annotations from the dawn of the org's history — no time bounds are enforced. This includes alert state annotations, deployment markers, and incident annotations.

When Grafana anonymous access is enabled (`auth.anonymous.enabled = true`) and the anonymous org has `annotations:read` permission, this endpoint becomes exploitable without any credentials at all, making the threat model effectively identical to the original finding.

## Location

- **Source:** `pkg/api/annotations.go:38-39` — `From: c.QueryInt64("from"), To: c.QueryInt64("to")` with no validation
- **Flow:** `hs.GetAnnotations` → `hs.annotationsRepo.Find` → `RepositoryImpl.Find` → `xormRepositoryImpl.Get`
- **Sink:** `pkg/services/annotations/annotationsimpl/xorm_store.go:389-392` — guard `if query.From > 0 && query.To > 0` skipped when both are 0

Code at the source (`pkg/api/annotations.go:37-52`):
```go
query := &annotations.ItemQuery{
    From:         c.QueryInt64("from"),   // returns 0 for "0" or missing param
    To:           c.QueryInt64("to"),     // returns 0 for "0" or missing param
    OrgID:        c.GetOrgID(),
    ...
}
```

Code at the sink (`xorm_store.go:389-392`):
```go
if query.From > 0 && query.To > 0 {
    sql.WriteString(` AND a.epoch <= ? AND a.epoch_end >= ?`)
    params = append(params, query.To, query.From)
}
// When both are 0, no time clause is added — all annotations match
```

## Attacker Control

An authenticated user (or anonymous user when anonymous access is enabled) sends:

```
GET /api/annotations?from=0&to=0
```

or equivalently omits the from/to parameters entirely:

```
GET /api/annotations
```

The attacker directly controls the `from` and `to` query parameters. No other user-supplied values affect the time-range guard.

## Trust Boundary Crossed

TB3 (Authenticated API Gate): A user with standard Viewer-level permissions crosses into the full annotation history of the org. The intended behavior is that `from` and `to` constrain which time-window of annotations is returned. With the bypass, the time constraint is silently dropped and all annotations within the user's RBAC scope (which can be org-wide) are returned.

Additionally, when Grafana anonymous access is enabled (a supported deployment model), the trust boundary regresses to TB7 (Public Dashboard Gate) — no credentials required.

## Impact

Information disclosure: An authenticated user with `annotations:read` permission (Viewer role or above) can retrieve all annotations within the org from all time — not just the intended time window. This includes:

- Alert state transition annotations (recording when alerts fired or resolved)
- Deployment and incident annotations created by CI/CD pipelines or operators
- Text annotations containing sensitive operational context

The scope is within-org. The RBAC access control in `RepositoryImpl.Find` (via `authZ.Authorize`) still limits the caller to dashboards they have read access to. However, the time-range filter is entirely absent, so all historical annotations within their permission scope are returned.

In the anonymous-access case, the anonymous user's permission scope determines the data exposure. Default anonymous role is Viewer, which typically includes `annotations:read` on all org dashboards.

## Evidence

1. `pkg/api/annotations.go:38-39`: `From: c.QueryInt64("from"), To: c.QueryInt64("to")` — no validation, returns 0 for missing or zero values
2. `pkg/api/api.go:528`: Route registration under `r.Group("/api", ..., reqSignedIn)` — requires auth, but `reqSignedIn` allows anonymous users when `auth.anonymous.enabled=true`
3. `pkg/middleware/auth.go:216-218`: `requireLogin := !c.AllowAnonymous || forceLogin` — `AllowAnonymous=true` makes `requireLogin=false`, allowing unauthenticated requests through `reqSignedIn`
4. `pkg/middleware/auth_test.go:67-72`: Test case "ReqSignedIn should return 200 for anonymous user" confirms anonymous bypass of the `reqSignedIn` gate
5. `xorm_store.go:389-392`: Same guard as p7-040 — time filter is skipped when `query.From == 0 && query.To == 0`
6. `pkg/services/annotations/annotationsimpl/loki/historian_store.go:124-129`: Loki store correctly handles zero values by defaulting to `now-6h` / `now` — only the xorm store is vulnerable

## Reproduction Steps

**Scenario A (Authenticated user):**
1. Log in as any Viewer-level user with an existing session or API key
2. Send: `GET /api/annotations` (no from/to parameters)
3. Observe the response contains all annotations within the user's dashboard access scope, with no time bounding

**Scenario B (Anonymous access):**
1. Ensure Grafana is configured with `auth.anonymous.enabled = true` and `auth.anonymous.org_role = Viewer`
2. Without any authentication headers, send: `GET /api/annotations?from=0&to=0`
3. Observe annotations from all time in the anonymous org are returned

**Contrast test:** Same request with from/to set to a 1-hour window (e.g., `from=<now-3600000>&to=<now>`) returns only annotations within that window — confirming the difference is the guard bypass.

## Comparison to p7-040

| Attribute | p7-040 (Original) | p7-060 (This Variant) |
|-----------|-------------------|------------------------|
| Entry point | GET /api/public/dashboards/:accessToken/annotations | GET /api/annotations |
| Auth required | Access token only (unauthenticated) | Auth session/API key (or anon) |
| DashboardID zeroing | Yes (tag-based annotations) | No (user's normal RBAC scope) |
| Time guard bypassed | Yes (xorm_store.go:389) | Yes (same xorm_store.go:389) |
| Org-wide scope | Yes (via DashboardID=0) | Only if user has org-wide permissions |
| Severity | HIGH | MEDIUM |
