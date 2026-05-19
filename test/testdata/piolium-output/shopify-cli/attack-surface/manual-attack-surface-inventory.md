# Stage 08 Manual Attack Surface Inventory — Shopify CLI

Generated: 2026-05-01T07:26:59Z  
Mode: `/piolium-deep` P8 single-team manual probe  
Repo HEAD observed: `c3e54bea42`

## Source artifacts read

- `piolium/attack-surface/knowledge-base-report.md`
- `piolium/attack-surface/public-routes-authz-matrix.md`
- `piolium/attack-surface/source-sink-flows-all-severities.md`
- `piolium/attack-surface/spec-gap-summary.md`
- `piolium/attack-surface/state-concurrency-summary.md`
- `piolium/attack-surface/patch-bypass-summary.md`
- `piolium/attack-surface/agentic-actions-auditor.md`

## Highest-impact slices selected

| Slice | Boundary | Why selected | P8 action |
|---|---|---|---|
| DFD-2 extension dev server | Browser/tunnel visitor → local HTTP/WS extension control plane | Missing auth/Origin/key controls expose app/store/extension metadata and accept control messages. | Drafted `p8-001-extension-dev-websocket-cross-site-hijack.md` (spec-focused, overlaps p5-001). |
| DFD-7 template/init/generate | Custom GitHub template → Liquid renderer → generated filesystem/install | Custom templates are attacker-controlled GitHub repos; Liquid engine is created with default filesystem roots. | Drafted `p8-002-liquid-template-root-file-disclosure.md`. |
| DFD-1 GraphiQL local proxy | Browser/tunnel visitor → local GraphiQL → Admin GraphQL | Token-bearing proxy and public status/XSS issues already drafted in P4/P5. | Corroborated existing drafts; no duplicate P8 draft. |
| DFD-3 theme dev | Browser/tunnel visitor → theme server/proxy → Storefront renderer/CDN | Token-bearing proxy, SSE, CORS runtime behavior. | Reviewed controls; exact-origin CORS and host checks reduce new P8 findings. |
| DFD-4 include-assets/local asset serving | Project config/path/symlink/browser path → file read/copy | Prior P4 findings cover prefix/symlink traversal. | Not redrafted; noted for runtime regression coverage. |

## Public routes / URLs of interest

| Surface | Public URL / operation | Attacker source | Main sink(s) | Source files and line evidence | Notes |
|---|---|---|---|---|---|
| App GraphiQL status | `GET /graphiql/status` | Malicious browser origin, tunnel visitor | JSON response with dev-session status/store/app metadata; token refresh attempt | `packages/app/src/cli/services/dev/graphiql/server.ts:128-137` wildcard CORS; `:161-170` status route without key check | Existing `p4-002`/`p5-002`. |
| App GraphiQL UI | `GET /graphiql?key=...` | Browser request query/headers | HTML with embedded query/variables, API versions | `server.ts:174-229`; key check at `:181-184`; script insertion in `templates/graphiql.tsx:254-259` | Existing `p4-009`. |
| App GraphiQL proxy | `POST /graphiql/graphql.json?key=...&api_version=...` | Browser POST body/query/API version | Token-bearing Admin GraphQL request | `server.ts:232-265`; key check `:239-242`; `adminUrl(storeFqdn, query.api_version as string)` at `:244`; access token header at `:253-258` | Existing `p4-003`. |
| UI extension HTTP API | `GET /extensions`, `/extensions/:extensionId`, `/extensions/:extensionId/assets/**`, `/extensions/assets/:assetKey/**` | Browser/tunnel URL, route params | Extension/app/store JSON payloads; local build/assets file reads | Route registration `packages/app/src/cli/services/dev/extension/server.ts:21-44`; wildcard CORS `server/middlewares.ts:14-21`; raw payload response `:110-114`; extension payload `:209-225`; asset read via `fileServerMiddleware` `:34-72` | Existing `p5-001`; supports P8 WS exploit by disclosing `apiKey`/socket URL. |
| UI extension WebSocket | `WS /extensions` | Browser WebSocket handshake and messages, tunnel visitor | Connected payload, `payloadStore.update*`, broadcast to clients, terminal output | `websocket.ts:8-13` creates server/registers upgrade; `websocket/handlers.ts:19-24` upgrades only on URL; `:31-38` sends connected payload; `:99-134` processes messages; `:161-170` broadcasts | New P8 draft `p8-001`. |
| Theme dev CORS/proxy | `theme dev` catch-all and assets, usually `127.0.0.1:9292` | Browser/tunnel path/query/headers | Local theme asset responses; Storefront renderer/CDN requests with cookies/Bearer token | Exact CORS allowlist in `theme-environment.ts:126-145`; SSE/log endpoints `hot-reload/server.ts:181-228`; proxy URL/host check and Authorization header in `proxy.ts:297-344` | No new P8 draft; exact-origin CORS and hostname check are relevant mitigations. |
| Store auth callback | `GET /auth/callback?shop&state&code` on `127.0.0.1:13387` | OAuth redirect/browser/local process | OAuth code acceptance and persisted store session | `callback.ts:113-122` path parse; `:142-150` store/state checks; `:160-172` code handling | Reviewed; state/store checks present. |
| App reverse proxy | Dynamic HTTP/WS prefixes for app dev | Browser/tunnel path | Proxy to local app process; error response | `http-reverse-proxy.ts:49-61` WS; `:70-90` HTTP; `:94-103` prefix match | Existing `p4-008` covers reflected invalid-path response. |
| App init custom template | `shopify app init --template https://github.com/<user>/<repo>[subpath]#[branch]` | GitHub template URL/repo contents | Download, Liquid render, generated filesystem, package-manager install | Template flag accepts GitHub URL `app/init.ts:41-45`; validation only enforces GitHub origin `services/init/validate.ts:11-16`; download/render/install in `services/init/init.ts:72-101` and `:174-179` | New P8 draft `p8-002`. |

## Attacker sources

| Source | Control | Representative files |
|---|---|---|
| Malicious browser origin | Can open loopback/tunnel HTTP and WebSocket URLs, send headers/query/body/messages | GraphiQL server, extension server, theme dev server, app reverse proxy |
| Remote tunnel visitor | Can send direct HTTP/WS/SSE requests when dev server is exposed | Extension server, GraphiQL/theme/app proxy surfaces |
| Custom GitHub template repository | Controls template files, `.liquid` contents, output filenames, package manifest/scripts/dependencies | `packages/app/src/cli/services/init/init.ts`, `packages/cli-kit/src/public/node/liquid.ts` |
| Local project/theme files | Controls extension config/assets/globs/symlinks/theme assets | include-assets, extension asset server, theme package/dev |
| CLI flags/env | Controls paths, host/port/template/API version/tokens/binary paths | command classes, cli-kit environment/process helpers |

## High-value sinks

| Sink | Impact | File/line evidence |
|---|---|---|
| Admin GraphQL request with CLI token | Confused-deputy read/write to Shopify Admin API | `packages/app/src/cli/services/dev/graphiql/server.ts:244-265` |
| Extension connected/raw payload responses | Disclosure of app API key, store FQDN, app URLs, extension metadata | `payload/store.ts:41-60`, `:127-134`; `server/middlewares.ts:110-114`, `:209-225` |
| WebSocket state/log/broadcast handlers | Unauthorized dev payload mutation, client broadcast, terminal output | `websocket/handlers.ts:99-134`, `:161-170`, `:93-95` |
| File reads to local HTTP response | Local file/asset disclosure | `server/middlewares.ts:34-72`; theme local assets `local-assets.ts:18-60` |
| Liquid include/render/layout filesystem resolution | CWD/local file disclosure into generated scaffold | `packages/cli-kit/src/public/node/liquid.ts:24-26`, `:65-72`; Liquid docs in `piolium/tmp/specs/liquidjs-api-options.html` root/default section |
| Package-manager install after template render | Follow-on exfiltration/execution channel for generated secrets | `packages/app/src/cli/services/init/init.ts:174-179` |

## Exploit-relevant paths retained for P8

### P8-001 — Extension WebSocket cross-site hijack

`malicious website/tunnel` → `WS /extensions` → `websocketUpgradeHandler()` only checks `request.url` → `ws.send(getConnectedPayload())` → attacker obtains app/store/extensions → `getOnMessageHandler()` accepts `update`/`dispatch`/`log` messages → payload mutation/broadcast/terminal output.

Primary evidence: `packages/app/src/cli/services/dev/extension/websocket.ts:8-13`; `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:19-24`, `:31-38`, `:99-134`, `:161-170`; `packages/app/src/cli/services/dev/extension/payload/store.ts:41-60`, `:127-134`.

### P8-002 — Liquid template root file disclosure

`custom GitHub template` → `downloadGitRepository()` → `recursiveLiquidTemplateCopy()` → `.liquid` file contents rendered with `new Liquid()` default options → Liquid partial/include/layout lookup uses default root `['.']` / CWD instead of downloaded template root → included local file content written into scaffold → package-manager install can exfiltrate.

Primary evidence: `packages/app/src/cli/commands/app/init.ts:41-45`, `:140-148`; `packages/app/src/cli/services/init/validate.ts:11-16`; `packages/app/src/cli/services/init/init.ts:72-101`, `:174-179`; `packages/cli-kit/src/public/node/liquid.ts:24-26`, `:55`, `:65-72`; Liquid docs excerpts from `piolium/tmp/specs/liquidjs-options.html:107-110` and extracted `liquidjs-api-options.html` root/default section.

## Needs-deeper / not drafted in P8

| Candidate | Reason not drafted now | Follow-up |
|---|---|---|
| Dev-console static asset traversal via `/extensions/dev-console/assets/**:assetPath` | Code joins untrusted `assetPath` under generated bundle root without containment, but the source tree lacks generated `assets/dev-console` and H3 path normalization/runtime packaging were not proven in this pass. | Runtime built-package test against encoded `..` payloads; if reachable, draft as local file disclosure. |
| Theme hot-reload `hr-log` terminal injection | Route is unauthenticated but theme server exact-origin CORS limits browser readback, and impact appears terminal/log-only. | Dynamic malicious-origin/tunnel test if theme dev is intentionally tunnel-exposed. |
| Theme proxy token/header leak | Hostname is derived from selected store/CDN and checked before fetch; CORS exact allowlist present. | Keep under SSRF/proxy variant analysis with dynamic redirect/header tests. |
