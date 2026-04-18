Phase: 8
Sequence: 001
Slug: xds-auth-header-injection
Verdict: VALID
Rationale: Confirmed reachable code path where any Viewer can override backend datasource credentials via X-DS-Authorization header; no protection found after 5-layer defense search. Enables cross-tenant data access in multi-tenant backend deployments.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-1/debate.md

## Summary

Any authenticated user with `datasources:query` permission (Viewer role by default) can inject an arbitrary Authorization header value into outbound datasource proxy requests by setting the `X-DS-Authorization` HTTP header on their request. The datasource proxy director function reads this header and uses it to overwrite the stored datasource credentials (BasicAuth, Bearer token) on the outbound request to the backend datasource. This enables cross-tenant data access in deployments where namespace isolation is enforced at the backend datasource Authorization header level (e.g., shared Prometheus with multi-tenant auth).

## Location

- **Primary**: `pkg/api/pluginproxy/ds_proxy.go:230-234` -- `director` function
- **Missing strip**: `pkg/services/contexthandler/contexthandler.go:220-244` -- `GetAuthHTTPHeaders()` does NOT include `X-DS-Authorization`
- **Route entry**: `/api/datasources/proxy/uid/<uid>/*` and `/api/datasources/proxy/<id>/*`

## Attacker Control

The attacker fully controls the value of the `X-DS-Authorization` HTTP header sent in their request to the datasource proxy endpoint. This value is directly used as the `Authorization` header on the outbound request to the backend datasource, overwriting any stored credentials.

## Trust Boundary Crossed

Authenticated user (Viewer role) -> backend datasource credential override. The attacker operates as a standard authenticated Grafana user but can impersonate any identity at the backend datasource level by providing arbitrary credentials.

## Impact

- **Cross-tenant data access**: In multi-tenant deployments using shared backend datasources (Prometheus, Loki, Elasticsearch) with authorization-header-based namespace isolation, any Viewer can access data belonging to other tenants.
- **Credential override**: Backend datasource receives attacker-supplied credentials instead of the configured Grafana service account credentials, bypassing any data access restrictions enforced by those credentials.
- **Silent exploitation**: The `X-DS-Authorization` header is deleted from the request after being read, leaving no trace in the proxied request headers.

## Evidence

```go
// pkg/api/pluginproxy/ds_proxy.go:230-234
dsAuth := req.Header.Get("X-DS-Authorization")
if len(dsAuth) > 0 {
    req.Header.Del("X-DS-Authorization")
    req.Header.Set("Authorization", dsAuth)
}
```

```go
// pkg/services/contexthandler/contexthandler.go:220-244
// GetAuthHTTPHeaders returns headers to strip -- does NOT include X-DS-Authorization
func GetAuthHTTPHeaders(jwtAuth *setting.AuthJWTSettings, authProxy *setting.AuthProxySettings) []string {
    var items []string
    items = append(items, "Authorization")
    items = append(items, "X-Grafana-Device-Id")
    // ... JWT and proxy headers only
    return items
}
```

## Reproduction Steps

1. Authenticate to Grafana as a Viewer
2. Identify a datasource UID accessible via proxy (e.g., Prometheus)
3. Send a request to the datasource proxy with the injected header:
   ```
   GET /api/datasources/proxy/uid/<ds-uid>/api/v1/query?query=up
   X-DS-Authorization: Bearer <attacker-controlled-token>
   ```
4. Observe that the backend datasource receives `Authorization: Bearer <attacker-controlled-token>` instead of the configured Grafana credentials
5. In a multi-tenant Prometheus/Loki setup, the attacker-supplied token may grant access to other tenants' data
