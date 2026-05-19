# Stage 08 Manual Probe Hypotheses and Verification Notes

Generated: 2026-05-01T07:26:59Z

## Backward-reasoning hypotheses

### BW-01 — Extension dev WebSocket connected-payload disclosure implies missing handshake auth

- Target sink: `ws.send(JSON.stringify(connectedPayload))` at `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:37`.
- Backward path: connected payload comes from `options.payloadStore.getConnectedPayload()` at `handlers.ts:31-34`, which returns app/appId/store/extensions at `payload/store.ts:127-134`; upgrade is admitted by `request.url === '/extensions'` only at `handlers.ts:19-24`.
- Verification: `setupWebsocketConnection()` creates `new WebSocketServer({noServer: true, clientTracking: true})` at `websocket.ts:8-9` and registers the upgrade handler at `websocket.ts:12`; grep found no `Origin`, `verifyClient`, key, or auth check in the WebSocket path.
- Verdict: VALIDATED. Draft: `piolium/findings-draft/p8-001-extension-dev-websocket-cross-site-hijack.md`.

### BW-02 — Liquid render file disclosure from generated scaffold output

- Target sink: `writeFile(outputPathWithoutLiquid, contentOutput)` at `packages/cli-kit/src/public/node/liquid.ts:72`.
- Backward path: `.liquid` content is read from a downloaded template file at `liquid.ts:67`, rendered with `renderLiquidTemplate(content, data)` at `liquid.ts:68`; `renderLiquidTemplate()` constructs `new Liquid()` with no `root`, `partials`, `layouts`, or `templates` at `liquid.ts:24-26`.
- Source: `shopify app init` accepts a custom GitHub template URL (`app/init.ts:41-45`) and validation only enforces `https://github.com` (`services/init/validate.ts:11-16`); `init.ts:85-89` downloads it and `init.ts:96-101` renders it.
- Verification: LiquidJS docs state `root` resolves layout/include templates and defaults to `["."]`; `partials` and `layouts` default to `root`; `relativeReference` defaults to true and requires referenced paths to stay within root. Because the code never sets root to the downloaded template directory, root is process CWD.
- Verdict: VALIDATED. Draft: `piolium/findings-draft/p8-002-liquid-template-root-file-disclosure.md`.

### BW-03 — Dev-console asset path traversal through `assetPath`

- Target sink: `fileServerMiddleware(... joinPath(rootDirectory, assetPath))` at `packages/app/src/cli/services/dev/extension/server/middlewares.ts:135-151` (source line range from read; no containment check observed).
- Backward path: `assetPath` is from `getRouterParams(event)` and route is registered as `/extensions/dev-console/assets/**:assetPath` in `server.ts:37`.
- Counter-evidence/ambiguity: repo source tree does not contain generated `assets/dev-console/...`; need built package and H3 runtime normalization test for encoded traversal.
- Verdict: NEEDS-DEEPER. No P8 draft.

## Contradiction-reasoning hypotheses

### CR-01 — “Localhost-only means WebSocket Origin checks are unnecessary” is false

- Broken assumption: browser same-origin policy prevents a malicious site from using the local WebSocket.
- Contradiction evidence: RFC 6455 origin guidance in Stage 07; browser WebSockets include `Origin` but server must validate it. The implementation does not inspect `request.headers.origin` before `wss.handleUpgrade()` (`handlers.ts:19-24`).
- Verdict: VALIDATED and merged with BW-01.

### CR-02 — “The app API key check protects WebSocket updates” is incomplete

- Broken assumption: `payloadStoreApiKey !== eventAppApiKey` at `handlers.ts:111-118` blocks unauthorized changes.
- Contradiction evidence: connected/HTTP payloads disclose the app API key (`payload/store.ts:41-60`, `server/middlewares.ts:209-225`), and extension-only updates are accepted when `eventData.extensions` is present even if no `eventData.app` was supplied (`handlers.ts:111-128`).
- Verdict: VALIDATED and included in P8-001 consequence.

### CR-03 — “Liquid only renders variables, not files” is false for include/render/layout tags

- Broken assumption: `engine.render(engine.parse(templateContent), data)` only substitutes provided `data` and cannot read files.
- Contradiction evidence: LiquidJS docs say root/partials/layouts control lookup of included/layout templates and default to root/default `["."]`; `relativeReference` is enabled by default. The CLI renders attacker-controlled `.liquid` content with default engine options (`liquid.ts:24-26`, `:65-72`).
- Verdict: VALIDATED and merged with BW-02.

### CR-04 — “Theme dev wildcard CORS regression persists” is false at current HEAD

- Broken assumption: theme dev exposes wildcard CORS like GraphiQL/extension server.
- Counter-evidence: `theme-environment.ts:126-145` builds an exact allowlist of local origin and store origin and calls `handleCors` only when request `Origin` is present; Stage 02 also recorded this as sound.
- Verdict: INVALIDATED for new P8 drafting.

## Draft outcomes

| Hypothesis | Outcome | Draft |
|---|---|---|
| BW-01 + CR-01 + CR-02 | VALIDATED | `piolium/findings-draft/p8-001-extension-dev-websocket-cross-site-hijack.md` |
| BW-02 + CR-03 | VALIDATED | `piolium/findings-draft/p8-002-liquid-template-root-file-disclosure.md` |
| BW-03 | NEEDS-DEEPER | none |
| CR-04 | INVALIDATED for new P8 | none |
