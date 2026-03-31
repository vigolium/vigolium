Phase: 10
Sequence: 050
Slug: render-key-cookie-no-path-scoping-all-endpoints
Verdict: VALID
Rationale: The renderKey cookie is accepted by the Render authn client (priority 10, highest effective priority) on ALL Grafana HTTP endpoints with no Path, domain, or endpoint scoping; a render key legitimately issued for one rendering session can be replayed against any admin API endpoint, and there is no architectural check preventing this even when renderAuthJWT=false.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-041-renderer-jwt-forgery-admin-takeover.md
Origin-Pattern: AP-041

## Summary

The `Render` authn client (`pkg/services/authn/clients/render.go`) implements `Test()` by checking solely for the presence of the `renderKey` cookie on ANY HTTP request, with no restriction on which endpoints this applies to. This client is registered at priority 10 — the lowest numeric value among context-aware clients, meaning it fires before ExtJWT(15), JWT(20), APIKey(30), Basic(40), Proxy(50), and Session(60).

A render key is a short-lived (5 minutes by default) credential that grants either `TypeAnonymous` or `TypeRenderService` (Admin-equivalent) identity depending on the `OrgRole` field stored in the cache or JWT. Once issued, the same render key cookie is valid for ANY Grafana API request made within its lifetime. There is no endpoint path restriction on the cookie itself or in the `Test()` function.

This means any Grafana API request that arrives with `Cookie: renderKey=<valid_key>` will be authenticated as the render identity — even admin API endpoints such as `/api/admin/users`, `/api/admin/settings`, and `/api/datasources` — regardless of the original purpose the key was issued for.

The absence of a cookie `Path` attribute (which would restrict browser transmission to `/render*` paths) and the lack of server-side endpoint filtering in `Test()` means that any code path that can obtain a render key value can use it as a general authentication token.

## Location

- **Primary**: `pkg/services/authn/clients/render.go:73-78` — `Test()` returns `true` for any HTTP request bearing `renderKey` cookie; no endpoint path check
- **Primary**: `pkg/services/authn/clients/render.go:80-82` — `Priority() uint { return 10 }` — fires before all standard auth clients
- **Secondary**: `pkg/services/rendering/rendering.go:329-336` — render keys are generated per-request but the same key is passed to the renderer as a URL query parameter (`renderKey=<value>` in the render URL)
- **Secondary**: `pkg/services/rendering/auth.go:103-114` — `generateAndSetRenderKey` stores key with 5-minute TTL (configurable), valid for entire TTL duration regardless of render completion

## Attacker Control

**Scenario A — Render key interception from Grafana → Renderer HTTP request:**
- Attacker with SSRF on the Grafana host or network access between Grafana and renderer observes render request URLs
- Render key appears as `?renderKey=<value>` in the HTTP GET to the renderer (`http_mode.go:73`)
- Attacker extracts the key and presents it as `Cookie: renderKey=<value>` to any Grafana API endpoint within the 5-minute TTL

**Scenario B — Grafana Live WebSocket / public render endpoints:**
- Render key is transmitted from Grafana to the renderer over the network
- Any log aggregation, proxy, or network observer can intercept the key
- The key is then replayed against admin-level API endpoints

**Scenario C — renderAuthJWT=false (cache mode), existing session:**
- If an authenticated user triggers a dashboard render (e.g., scheduled alert image generation), the render key is stored in remote cache for 5 minutes
- Attacker who intercepts the render URL (e.g., from log files, proxy access logs, or the renderer's own access log) obtains the key
- Key is valid for full API access for its TTL, including admin endpoints

## Trust Boundary Crossed

Renderer authorization domain (TB6: Grafana ↔ Renderer communication) → Grafana HTTP API trust boundary (TB1: Internet → Grafana API). A credential designed for internal Grafana-to-Renderer communication is accepted by ALL Grafana API endpoints without path restriction, crossing from the internal rendering subsystem into the general API authorization domain.

## Impact

- Any Grafana API endpoint accessible using a valid render key, including: `GET /api/admin/settings`, `POST /api/admin/users`, `GET /api/datasources`, `PUT /api/org/users/:userId`
- Render keys issued with `OrgRole: "Admin"` (which is the case for dashboard screenshot jobs running as Admin context) grant full Admin API access
- TTL of 5 minutes (default `render_key_lifetime`) provides sufficient window for exploitation once a key is intercepted
- No feature flag required — this path is active in all Grafana deployments using image rendering

## Evidence

1. `render.go:73-78`: `Test()` checks only `getRenderKey(r) != ""` — no path, method, or endpoint filtering
2. `render.go:80-82`: `Priority() uint { return 10 }` — lower value = fires first in the priority queue (confirmed by `priority_queue_test.go:expectedOrder`)
3. `http_mode.go:73`: `queryParams.Add("renderKey", renderKey)` — render key appears in renderer request URL, logged by proxies/HTTP middleware
4. `rendering.go:329`: `renderKey, err := renderKeyProvider.get(ctx, opts.AuthOpts)` — key derived from the auth context of the requesting user (could be Admin)
5. `auth.go:103-114`: `GetRandomString(32)` key stored in remote cache — not bound to any specific Grafana endpoint or HTTP method
6. `render.go:43-57`: When `UserID<=0` and `OrgRole=="Admin"`, `Authenticate()` creates `TypeRenderService` identity with `SyncPermissions:true`

## Reproduction Steps

1. Configure Grafana with external image renderer (HTTP mode, no JWT flag required)
2. Set `renderer_token` to any value (default `-` or custom)
3. Trigger a dashboard alert or scheduled render as an Admin context
4. Capture the render request URL from the renderer's access log (contains `?renderKey=<32-char-value>`)
5. Within 5 minutes, replay the captured key:
   ```
   curl -H "Cookie: renderKey=<captured_key>" http://localhost:3000/api/admin/settings
   ```
6. Expected: Admin settings returned (200 OK) — render key accepted on admin endpoint

Note: This vulnerability does not require the `renderAuthJWT` feature flag. It affects all deployments with image rendering enabled.
