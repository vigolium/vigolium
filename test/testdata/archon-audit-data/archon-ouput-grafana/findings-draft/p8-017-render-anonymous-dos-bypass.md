Phase: 10
Sequence: 017
Slug: render-anonymous-dos-bypass
Verdict: VALID
Rationale: The /render/* endpoint uses reqSignedIn instead of reqSignedInNoAnonymous; when anonymous auth is enabled, unauthenticated attackers can trigger headless browser rendering jobs (CPU/memory-intensive) at full concurrency, enabling DoS with higher resource amplification than the avatar variant.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-043-avatar-anonymous-dos-bypass.md
Origin-Pattern: AP-043

## Summary

The render endpoint at `GET /render/*` (api.go:599) uses `reqSignedIn` middleware instead of `reqSignedInNoAnonymous`. When Grafana's anonymous authentication is enabled (`[auth.anonymous] enabled=true`), this allows unauthenticated requests to reach the rendering service handler. The rendering service spawns a headless Chromium browser process (via the plugin renderer) to capture screenshots of dashboards or panels. Each request triggers significant CPU, memory, and subprocess usage. Unlike the avatar endpoint (which only triggers outbound HTTP), rendering spawns a full browser process with a configurable timeout (default 60 seconds), making the DoS amplification substantially higher.

## Location

- **Primary**: `pkg/api/api.go:599` -- `r.Get("/render/*", requestmeta.SetSLOGroup(requestmeta.SLOGroupHighSlow), reqSignedIn, hs.RenderHandler)` -- uses `reqSignedIn`
- **Auth logic**: `pkg/middleware/auth.go:216` -- `requireLogin = !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- false when `AllowAnonymous=true`
- **Render handler**: `pkg/api/render.go:18` -- `RenderHandler` creates rendering request with timeout, dimensions, and theme
- **Rendering service**: `pkg/services/rendering/` -- spawns headless browser subprocess

## Attacker Control

- **Input**: URL path parameter `*` (arbitrary path after /render/) plus query parameters: `width`, `height`, `timeout` (up to configurable max), `scale`
- **Minimum privilege**: Unauthenticated (when anonymous auth enabled)
- **Amplification factor**: Each request launches a headless Chromium process consuming 50-200MB RAM and significant CPU for up to 60 seconds

## Trust Boundary Crossed

Internet (unauthenticated) -> Grafana server -> Subprocess execution (headless Chromium renderer). The authentication gate is bypassed via the reqSignedIn/anonymous auth interaction, allowing unauthenticated users to trigger resource-intensive server-side operations.

## Impact

- **Denial of Service**: Each render request spawns a headless browser; concurrent requests exhaust system memory and CPU
- **Higher amplification than avatar**: Rendering consumes orders of magnitude more resources than Gravatar HTTP requests
- **Configurable timeout**: Default 60-second timeout per request means connections remain resource-bound longer
- **Service disruption**: Memory/CPU exhaustion impacts all Grafana functionality, not just rendering
- **No data compromise**: This is a DoS vector only

## Evidence

1. `api.go:599`: `r.Get("/render/*", ..., reqSignedIn, hs.RenderHandler)` -- uses reqSignedIn (same pattern as p8-043)
2. `auth.go:216`: `requireLogin = !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- false when AllowAnonymous=true
3. `render.go:37`: `timeout, err := strconv.Atoi(queryReader.Get("timeout", "60"))` -- attacker-controllable timeout parameter
4. `render.go:28-34`: width and height parameters also attacker-controllable, affecting render resource usage

## Reproduction Steps

1. Enable anonymous auth in grafana.ini: `[auth.anonymous] enabled = true`
2. Ensure Grafana renderer plugin is installed
3. Without any authentication, send many concurrent render requests:
   ```bash
   for i in $(seq 1 50); do
     curl -s "http://localhost:3000/render/d/some-uid/dashboard?width=2000&height=2000&timeout=60" &
   done
   ```
4. Monitor Grafana process list: `ps aux | grep chromium | wc -l`
5. Expected: Each request spawns a headless Chromium process; 50 concurrent requests exhaust server resources
6. Server becomes unresponsive or OOM-kills Grafana

Note: `[auth.anonymous] enabled=true` is disabled by default. Fix: change `reqSignedIn` to `reqSignedInNoAnonymous` at api.go:599.
