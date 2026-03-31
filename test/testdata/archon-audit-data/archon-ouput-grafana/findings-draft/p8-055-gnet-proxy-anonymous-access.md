Phase: 10
Sequence: 055
Slug: gnet-proxy-anonymous-access
Verdict: VALID
Rationale: The /api/gnet/* reverse proxy endpoint uses reqSignedIn instead of reqSignedInNoAnonymous; when anonymous auth is enabled, unauthenticated users can proxy arbitrary requests through Grafana to grafana.com with the instance's configured SSO API token attached, potentially leaking the token or enabling reconnaissance against the grafana.com API.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-043-avatar-anonymous-dos-bypass.md
Origin-Pattern: AP-043

## Summary

The grafana.com proxy endpoint at `r.Any("/api/gnet/*", ...)` (api.go:602) uses `reqSignedIn` middleware instead of `reqSignedInNoAnonymous`. When anonymous authentication is enabled (`[auth.anonymous] enabled=true`), unauthenticated users can reach the `ProxyGnetRequest` handler. This handler (`grafana_com_proxy.go:52-57`) acts as a reverse proxy to `hs.Cfg.GrafanaComAPIURL` and attaches `hs.Cfg.GrafanaComSSOAPIToken` as a Bearer token to every proxied request. An unauthenticated attacker can:
1. Use the Grafana instance as a proxy to enumerate the grafana.com API
2. Cause the GrafanaComSSOAPIToken (the instance's grafana.com credential) to be sent with attacker-specified paths
3. Consume the grafana.com API rate limit allocated to this Grafana instance

The `proxyPath` is taken directly from the wildcard URL parameter with no allowlist on the grafana.com path, allowing arbitrary API path traversal under the grafana.com host.

## Location

- **Primary**: `pkg/api/api.go:602` -- `r.Any("/api/gnet/*", requestmeta.SetSLOGroup(requestmeta.SLOGroupHighSlow), reqSignedIn, hs.ProxyGnetRequest)` -- uses `reqSignedIn`
- **Auth logic**: `pkg/middleware/auth.go:216` -- `requireLogin = !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- false when `AllowAnonymous=true`
- **Proxy handler**: `pkg/api/grafana_com_proxy.go:52-57` -- forwards request to GrafanaComAPIURL with SSO token
- **Token attachment**: `grafana_com_proxy.go:44-46` -- `req.Header.Set("Authorization", "Bearer "+grafanaComAPIToken)`

## Attacker Control

- **Input**: URL wildcard path `*` after `/api/gnet/` -- directly mapped to the proxied path on grafana.com
- **Minimum privilege**: Unauthenticated (when anonymous auth enabled)
- **Token exposure**: `GrafanaComSSOAPIToken` is sent to grafana.com for every proxied request, including attacker-crafted paths

## Trust Boundary Crossed

Internet (unauthenticated) -> Grafana server -> grafana.com API (with authenticated token). The authentication gate is bypassed via the reqSignedIn/anonymous auth interaction, allowing unauthenticated users to make authenticated requests to grafana.com on behalf of the Grafana instance.

## Impact

- **Token use**: Every request to `/api/gnet/*` causes Grafana's `GrafanaComSSOAPIToken` to be sent to grafana.com with attacker-specified path
- **API enumeration**: Unauthenticated attacker can enumerate grafana.com API endpoints using Grafana as a proxy
- **Rate limit exhaustion**: Grafana instance's grafana.com API quota can be consumed
- **Information disclosure**: Responses from grafana.com are returned to the attacker
- **Scope**: Impact depends on what the GrafanaComSSOAPIToken is authorized for on grafana.com

## Evidence

1. `api.go:602`: `r.Any("/api/gnet/*", ..., reqSignedIn, hs.ProxyGnetRequest)` -- uses reqSignedIn
2. `grafana_com_proxy.go:44-46`: `if grafanaComAPIToken != "" { req.Header.Set("Authorization", "Bearer "+grafanaComAPIToken) }` -- token attached unconditionally
3. `grafana_com_proxy.go:34`: `req.URL.Path = util.JoinURLFragments(url.Path, proxyPath)` -- proxyPath is attacker-controlled
4. `grafana_com_proxy.go:37-39`: Cookie and Authorization headers stripped from incoming request but the SSO token is then added -- authentication is replaced, not blocked

## Reproduction Steps

1. Enable anonymous auth in grafana.ini: `[auth.anonymous] enabled = true`
2. Configure a GrafanaComSSOAPIToken in grafana.ini (required for token leakage impact)
3. Without any authentication:
   ```bash
   curl -v "http://localhost:3000/api/gnet/plugins"
   ```
4. Expected (when anonymous auth disabled): 401 Unauthorized
5. Actual (when anonymous auth enabled): Proxied request reaches grafana.com with the instance's SSO token; response returned to unauthenticated attacker

Note: `[auth.anonymous] enabled=true` is disabled by default, and impact also requires GrafanaComSSOAPIToken to be configured. Fix: change `reqSignedIn` to `reqSignedInNoAnonymous` at api.go:602.
