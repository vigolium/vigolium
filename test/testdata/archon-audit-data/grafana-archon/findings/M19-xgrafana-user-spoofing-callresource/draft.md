Phase: 10
Sequence: 002
Slug: xgrafana-user-spoofing-callresource
Verdict: VALID
Rationale: When SendUserHeader is disabled, no middleware strips X-Grafana-User from inbound CallResource requests, allowing an authenticated user to inject an arbitrary username into the header that plugin backends forward to upstream datasource HTTP calls, spoofing identity on backends that use X-Grafana-User for access control or audit.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-001-xds-auth-header-injection.md
Origin-Pattern: AP-001

## Summary

The `X-Grafana-User` header is set by Grafana's `UserHeaderMiddleware` on outgoing plugin backend requests when `SendUserHeader=true`. However, this middleware is **conditionally inserted** into the plugin middleware chain — when `SendUserHeader=false`, `UserHeaderMiddleware` is absent. In that configuration, no middleware strips or validates a client-supplied `X-Grafana-User` header. Because `makePluginResourceRequest` copies all inbound HTTP headers verbatim into `crReq.Headers`, and `ClearAuthHeadersMiddleware` does not include `X-Grafana-User` in its strip list, an authenticated attacker can inject an arbitrary `X-Grafana-User` value that reaches plugin backend outgoing HTTP calls. This shares the same root cause as p8-001: the `GetAuthHTTPHeaders()` function does not enumerate `X-Grafana-User` as a security-sensitive header.

## Location

- **Entry point**: `pkg/api/plugin_resource.go:105-112` -- `Headers: req.Header` copies all client headers
- **Conditional middleware**: `pkg/services/pluginsintegration/pluginsintegration.go:212-213` -- `UserHeaderMiddleware` only added when `cfg.SendUserHeader == true`
- **Missing strip in ClearAuthHeaders**: `pkg/services/contexthandler/contexthandler.go:220-244` -- `GetAuthHTTPHeaders()` does not include `X-Grafana-User`/`proxyutil.UserHeaderName`
- **SDK forwarding**: plugin SDK `resource.go:75-85` -- `CallResourceRequest.GetHTTPHeaders()` returns ALL headers unfiltered

## Attacker Control

An authenticated Viewer sends `X-Grafana-User: admin` (or any username) in a request to a plugin resource endpoint (`/api/datasources/:id/resources/*` or `/api/plugins/:pluginId/resources/*`). When `SendUserHeader=false`, no middleware removes this header. The attacker's value propagates to plugin backend HTTP calls.

When `SendUserHeader=true`, the `UserHeaderMiddleware` deletes and resets `X-Grafana-User` to the actual authenticated user's login — so the attack is blocked. The vulnerability only manifests when `SendUserHeader=false` (which is the **default** Grafana configuration: `send_user_header = false`).

## Trust Boundary Crossed

Authenticated user (Viewer) → plugin backend outbound HTTP request with spoofed `X-Grafana-User`. In deployments where backends use `X-Grafana-User` for access control or audit, a Viewer can impersonate any user identity including `admin`.

## Impact

- **Identity spoofing at plugin backends**: Datasource backends that use `X-Grafana-User` for row-level security, tenant isolation, or audit logging will receive an attacker-controlled username instead of the actual Grafana user's identity.
- **Audit log poisoning**: Backend access logs keyed on `X-Grafana-User` will record incorrect identity, breaking audit trails.
- **Default configuration is vulnerable**: Since `send_user_header` defaults to `false`, the middleware is absent in most deployments, and no protection exists.
- **Affects all plugin resource endpoints**: Both datasource-scoped and app-scoped plugin resource calls are affected.

## Evidence

```go
// pkg/services/pluginsintegration/pluginsintegration.go:212-213
if cfg.SendUserHeader {
    middlewares = append(middlewares, clientmiddleware.NewUserHeaderMiddleware())
}
// When SendUserHeader=false: NO middleware strips X-Grafana-User
```

```go
// pkg/services/pluginsintegration/clientmiddleware/user_header_middleware.go:34-37
func (m *UserHeaderMiddleware) applyUserHeader(ctx context.Context, h backend.ForwardHTTPHeaders) {
    ...
    h.DeleteHTTPHeader(proxyutil.UserHeaderName)   // Removes attacker value
    if !reqCtx.IsIdentityType(claims.TypeAnonymous) {
        h.SetHTTPHeader(proxyutil.UserHeaderName, reqCtx.GetLogin())  // Sets real value
    }
}
// Only runs when SendUserHeader=true
```

```go
// pkg/services/contexthandler/contexthandler.go:220-244
func GetAuthHTTPHeaders(jwtAuth *setting.AuthJWTSettings, authProxy *setting.AuthProxySettings) []string {
    var items []string
    items = append(items, "Authorization")
    items = append(items, "X-Grafana-Device-Id")
    // ... JWT and proxy headers
    // "X-Grafana-User" is NOT included
    return items
}
```

```go
// pkg/api/plugin_resource.go:105-112
crReq := &backend.CallResourceRequest{
    ...
    Headers: req.Header,  // X-Grafana-User: admin passes through when SendUserHeader=false
    ...
}
```

## Reproduction Steps

1. Verify Grafana has `send_user_header = false` (the default) in `conf/custom.ini`
2. Authenticate as a Viewer (user: `viewer`, not `admin`)
3. Identify a datasource plugin resource endpoint
4. Send a resource call with spoofed user header:
   ```
   GET /api/datasources/:id/resources/some/path
   X-Grafana-User: admin
   ```
5. The plugin backend receives `CallResourceRequest.Headers["X-Grafana-User"] = ["admin"]`
6. Backends with `opts.ForwardHTTPHeaders=true` forward `X-Grafana-User: admin` to upstream datasource HTTP calls
7. Backends that trust `X-Grafana-User` for access control will grant admin-level access to the Viewer
