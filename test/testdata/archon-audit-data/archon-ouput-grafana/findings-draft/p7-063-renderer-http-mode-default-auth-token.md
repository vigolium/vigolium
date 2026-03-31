Phase: 9
Sequence: 063
Slug: renderer-http-mode-default-auth-token
Verdict: VALID
Rationale: The same default renderer_token "-" used as the JWT signing key (p7-041) is also sent as the X-Auth-Token header in HTTP mode render requests to the external renderer service, allowing anyone who can reach the renderer directly to authenticate render requests with the publicly known default value.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-041-renderer-jwt-forgery-default-token.md
Origin-Pattern: AP-041

## Summary

The `renderer_token` configuration value (default `"-"`) serves a dual role in Grafana's renderer integration. In JWT mode (`renderAuthJWT` feature flag), it is the HMAC-HS512 signing key for JWT render tokens (confirmed in p7-041). In **HTTP mode** (the default rendering mode when `renderAuthJWT` is disabled), the same `RendererAuthToken` is sent as-is in the `X-Auth-Token` request header on every outbound HTTP request Grafana makes to the external renderer service (`http_mode.go:148`).

The external renderer service is documented to verify this header and reject requests that do not present a matching token. With the default value of `"-"`, any attacker who can reach the renderer's HTTP port directly (bypassing Grafana) can authenticate to the renderer by supplying `X-Auth-Token: -`. This grants the ability to make the renderer issue arbitrary HTTP requests (panel renders, CSV exports) back to the Grafana server, potentially leveraging any render-key-based session that the renderer holds.

Unlike p7-041 (which is a Grafana-side auth bypass), this variant targets the **renderer-side** auth check. The renderer trusts any caller presenting `X-Auth-Token: -`, meaning the Grafana-to-renderer trust boundary is defeated by the known default key.

## Location

- **Default token:** `conf/defaults.ini:1952` -- `renderer_token = -`
- **Token read:** `pkg/setting/setting.go:2070` -- `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")`
- **Token sent:** `pkg/services/rendering/http_mode.go:148` -- `req.Header.Set(authTokenHeader, rs.Cfg.RendererAuthToken)`
- **Header constant:** `pkg/services/rendering/http_mode.go:18` -- `const authTokenHeader = "X-Auth-Token"`
- **Send path:** `pkg/services/rendering/http_mode.go:140-158` -- `doRequest()` called for every render request

## Attacker Control

Any network client who can reach the renderer service's HTTP port directly. This is relevant in environments where:
- The renderer service is network-accessible beyond the Grafana server (e.g., exposed on a container network)
- The renderer service is hosted on a separate machine with a reachable URL
- Internal network access is possible (e.g., SSRF from another service reaches the renderer)

The attacker supplies `X-Auth-Token: -` in their HTTP request to the renderer and can trigger arbitrary render operations.

## Trust Boundary Crossed

TB6 (Renderer Boundary). The `X-Auth-Token` is the only mechanism protecting the renderer's HTTP interface from unauthorized callers. With the default value publicly known, this boundary is completely defeated for installations using the default `renderer_token`.

## Impact

An attacker who can reach the renderer HTTP service can:
1. Trigger render requests to arbitrary Grafana URLs, potentially causing the renderer to visit authenticated Grafana pages (if the renderer has a valid render key)
2. Consume renderer resources (CPU, network) by issuing unlimited render requests
3. Enumerate renderer capabilities and version information via `/version` endpoint (which also accepts the auth token)

This does not directly compromise Grafana's authentication system (unlike p7-041), but it compromises the renderer's own access control, enabling abuse of the renderer service.

## Evidence

1. `conf/defaults.ini:1952`: `renderer_token = -` (publicly known default)
2. `pkg/setting/setting.go:2070`: `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")` — default hardcoded as `"-"`
3. `pkg/services/rendering/http_mode.go:148`: `req.Header.Set(authTokenHeader, rs.Cfg.RendererAuthToken)` — sends the raw token value in every HTTP request to renderer
4. `pkg/services/rendering/http_mode.go:18`: `const authTokenHeader = "X-Auth-Token"` — the header name
5. Documentation at `conf/defaults.ini:1951`: "An auth token that will be sent to and verified by the renderer. The renderer will deny any request without an auth token matching the one configured on the renderer side." — confirms token is the sole renderer auth check
6. The same `RendererAuthToken` is used in both HTTP mode (this finding) and JWT mode (p7-041), confirming shared default root cause

## Reproduction Steps

1. Deploy Grafana with an external renderer (HTTP mode, `renderAuthJWT` not enabled)
2. Confirm default `renderer_token = -` is in effect (check `conf/grafana.ini [rendering]`)
3. From a host with network access to the renderer's HTTP port, send:
   `curl -H "X-Auth-Token: -" http://<renderer-host>:<port>/render?url=<target>&renderKey=<guess-or-obtain>&domain=<domain>&timezone=UTC&encoding=png&timeout=30&width=800&height=600`
4. Observe the renderer accepts the request (HTTP 200 or processes it)
5. Compare behavior with an invalid token (e.g., `X-Auth-Token: invalid`) to confirm auth bypass
