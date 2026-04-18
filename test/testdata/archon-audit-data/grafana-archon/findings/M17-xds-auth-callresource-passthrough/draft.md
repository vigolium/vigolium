Phase: 10
Sequence: 001
Slug: xds-auth-callresource-passthrough
Verdict: VALID
Rationale: X-DS-Authorization header injected by an authenticated user into a CallResource request passes through the entire plugin middleware chain unstripped and is forwarded to plugin backend HTTP calls, because ClearAuthHeadersMiddleware only strips standard auth headers and not X-DS-Authorization.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-001-xds-auth-header-injection.md
Origin-Pattern: AP-001

## Summary

The `X-DS-Authorization` header injection vulnerability (p8-001) has a structural variant in the plugin backend `CallResource` transport path. When an authenticated user calls `/api/datasources/:id/resources/*` or `/api/plugins/:pluginId/resources/*`, all inbound HTTP headers — including attacker-supplied `X-DS-Authorization` — are copied verbatim into the `backend.CallResourceRequest.Headers` map. The `ClearAuthHeadersMiddleware` only strips `Authorization`, `X-Grafana-Device-Id`, JWT headers, and auth proxy headers (via `GetAuthHTTPHeaders()`). Because `X-DS-Authorization` is absent from this list, it survives the full plugin middleware stack and is forwarded to the plugin backend's outgoing HTTP calls via the SDK's `headerMiddleware` (which calls `req.GetHTTPHeaders()` and copies all `CallResourceRequest.Headers` to outbound requests when `ForwardHTTPHeaders` is enabled).

## Location

- **Entry points**: `pkg/api/plugin_resource.go:97-116` -- `makePluginResourceRequest` copies `req.Header` → `crReq.Headers` verbatim
- **Missing strip**: `pkg/services/pluginsintegration/clientmiddleware/clear_auth_headers_middleware.go:38` -- `GetAuthHTTPHeaders()` does not include `X-DS-Authorization`
- **SDK forwarding**: `vendor/.../grafana-plugin-sdk-go/backend/http_headers.go:117-138` -- SDK `headerMiddleware.applyHeaders` forwards all `CallResourceRequest.GetHTTPHeaders()` to outgoing plugin HTTP requests
- **SDK GetHTTPHeaders**: plugin SDK `resource.go:75-85` -- `CallResourceRequest.GetHTTPHeaders()` returns ALL `req.Headers` with no filtering (unlike `QueryDataRequest` which filters by key prefix)
- **Routes affected**:
  - `/api/datasources/:id/resources` and `/api/datasources/:id/resources/*`
  - `/api/datasources/uid/:uid/resources` and `/api/datasources/uid/:uid/resources/*`
  - `/api/plugins/:pluginId/resources` and `/api/plugins/:pluginId/resources/*`

## Attacker Control

An authenticated Viewer with `datasources:query` permission sends `X-DS-Authorization: Bearer <attacker-token>` in any request to a plugin resource endpoint. The header value is fully attacker-controlled and travels unmodified through:
1. `makePluginResourceRequest` → `crReq.Headers`
2. `ClearAuthHeadersMiddleware.clearHeaders` (does not touch it)
3. SDK `CallResourceRequest.GetHTTPHeaders()` returns it in full
4. SDK `headerMiddleware` copies it to outgoing HTTP requests from the plugin backend

## Trust Boundary Crossed

Authenticated user (Viewer role) → plugin backend outbound HTTP request headers. The attacker can inject arbitrary headers into HTTP calls made by the plugin backend process to the upstream datasource service.

## Impact

- **Header injection into plugin backend HTTP calls**: Plugin backends that use `opts.ForwardHTTPHeaders=true` in their HTTP client configuration will forward `X-DS-Authorization` to the upstream datasource. If the upstream datasource or any intermediary interprets this header (as the datasource proxy itself does), arbitrary credentials can be injected.
- **Broader header injection surface**: Unlike the ds_proxy path (which serves as an HTTP reverse proxy), the CallResource path gives attacker-controlled headers to the plugin binary process itself, potentially reaching any HTTP call the plugin makes.
- **Affects both datasource plugins and app plugins**: Both `/api/datasources/*/resources/*` and `/api/plugins/*/resources/*` use the same `makePluginResourceRequest` → `pluginClient.CallResource` pipeline.

## Evidence

```go
// pkg/api/plugin_resource.go:105-112
crReq := &backend.CallResourceRequest{
    PluginContext: pCtx,
    Path:          req.URL.Path,
    Method:        req.Method,
    URL:           req.URL.String(),
    Headers:       req.Header,   // ALL client headers copied verbatim
    Body:          body,
}
```

```go
// pkg/services/pluginsintegration/clientmiddleware/clear_auth_headers_middleware.go:38-41
items := contexthandler.GetAuthHTTPHeaders(m.cfgJWTAuth, m.cfgAuthProxy)
for _, k := range items {
    h.DeleteHTTPHeader(k)  // Only strips: Authorization, X-Grafana-Device-Id, JWT, proxy headers
}
// X-DS-Authorization is NEVER in items
```

```go
// grafana-plugin-sdk-go/backend/resource.go:75-85
func (req *CallResourceRequest) GetHTTPHeaders() http.Header {
    httpHeaders := http.Header{}
    for k, v := range req.Headers {
        for _, strVal := range v {
            httpHeaders.Add(k, strVal)  // ALL headers returned, no filtering
        }
    }
    return httpHeaders
}
```

```go
// grafana-plugin-sdk-go/backend/http_headers.go:125-134
// SDK headerMiddleware forwards all GetHTTPHeaders() to outgoing HTTP calls
for k, v := range headers {
    if qreq.Header.Get(k) == "" {
        for _, vv := range v {
            qreq.Header.Add(k, vv)  // X-DS-Authorization added to plugin outbound request
        }
    }
}
```

**Contrast with QueryDataRequest**: The SDK's `getHTTPHeadersFromStringMap()` for `QueryDataRequest` only returns headers matching `Authorization`, `X-Id-Token`, `Cookie`, or `http_` prefix — effectively filtering out `X-DS-Authorization`. The `CallResourceRequest` has no such filter.

## Reproduction Steps

1. Authenticate to Grafana as a Viewer
2. Identify a datasource with a plugin that exposes resource endpoints (e.g., Prometheus, Loki, Elasticsearch)
3. Send a resource call with the injected header:
   ```
   GET /api/datasources/:id/resources/some/path
   X-DS-Authorization: Bearer <attacker-controlled-token>
   ```
4. The plugin backend receives the `CallResourceRequest` with `Headers["X-DS-Authorization"] = ["Bearer <attacker-token>"]`
5. If the plugin's HTTP client has `ForwardHTTPHeaders=true`, the header is forwarded to the upstream datasource HTTP call
6. Plugin backends that chain back to the datasource proxy (or backends where the upstream interprets `X-DS-Authorization`) would apply the attacker's credential override
