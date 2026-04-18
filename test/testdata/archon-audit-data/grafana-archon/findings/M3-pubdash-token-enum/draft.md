Phase: 8
Sequence: 006
Slug: pubdash-token-enum
Verdict: VALID
Rationale: Missing RBAC on ListPublicDashboards exposes all org access tokens to any authenticated member. Standalone impact is information disclosure; chain impact with H-02 enables credential theft.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-1/debate.md

## Summary

The `GET /api/dashboards/public-dashboards` endpoint (ListPublicDashboards) is protected only by `middleware.ReqSignedIn` and lacks RBAC permission checks. Any authenticated org member (including Viewers) can enumerate all public dashboard access tokens for their organization. Combined with the credential exposure vulnerabilities (H-02/H-03), this creates an attack chain where any Viewer can discover and exploit public dashboards with direct-mode datasource credential leaks.

## Location

- **Route**: `pkg/services/publicdashboards/api/api.go:82` -- `middleware.ReqSignedIn` only (no `accesscontrol.EvalPermission`)
- **Handler**: `pkg/services/publicdashboards/api/api.go:113` -- `ListPublicDashboards`
- **Model**: `pkg/services/publicdashboards/models/models.go:116-118` -- `PublicDashboardListResponse` includes `AccessToken` field

## Attacker Control

Any authenticated org member can call the endpoint. No special permissions required beyond org membership.

## Trust Boundary Crossed

Viewer role -> access to all org public dashboard access tokens. The tokens enable accessing public dashboards that the Viewer may not have RBAC permission to view directly.

## Impact

- **Token enumeration**: All public dashboard access tokens for the org are disclosed
- **RBAC bypass**: Viewer can access public dashboards for dashboards they don't have `dashboards:read` permission on
- **Attack chain enabler**: Tokens enable exploitation of H-02/H-03 credential leaks without needing to know dashboard URLs

## Evidence

```go
// pkg/services/publicdashboards/api/api.go:82
// Only ReqSignedIn -- no EvalPermission
api.routeRegister.Get("/api/dashboards/public-dashboards", middleware.ReqSignedIn, routing.Wrap(api.ListPublicDashboards))

// Compare with other endpoints that DO have RBAC:
// api.routeRegister.Get("/api/dashboards/uid/:dashboardUid/public-dashboards",
//     auth(accesscontrol.EvalPermission(dashboards.ActionDashboardsRead, uidScope)), ...)
```

```go
// pkg/services/publicdashboards/models/models.go:116-118
type PublicDashboardListResponse struct {
    Uid          string `json:"uid" xorm:"uid"`
    AccessToken  string `json:"accessToken" xorm:"access_token"`
    // ...
}
```

## Reproduction Steps

1. Authenticate to Grafana as a Viewer
2. Send request: `GET /api/dashboards/public-dashboards`
3. Observe the response includes `accessToken` for all public dashboards in the org
4. Use any access token to access the corresponding public dashboard's frontend settings
