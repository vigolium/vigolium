# [p10] UI extension dev server exposes an unauthenticated control plane

## Summary

The Shopify CLI UI-extension dev server used by `shopify app dev` exposes `/extensions` HTTP payload endpoints with wildcard CORS and upgrades `WS /extensions` connections after only checking the request URL. A malicious browser origin on the developer machine, or a remote client that can reach a tunnel exposing the dev server, can read app/store/extension metadata and use the WebSocket control channel without authentication to receive payloads and send update, dispatch, or log events.

## Details

The HTTP server installs the CORS middleware globally before registering the `/extensions` routes in [`packages/app/src/cli/services/dev/extension/server.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server.ts#L31-L43). The middleware in [`server/middlewares.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L14-L21) allows any origin to read these JSON responses:

```ts
export const corsMiddleware = defineEventHandler((event) => {
  setResponseHeader(event, 'Access-Control-Allow-Origin', '*')
  setResponseHeader(event, 'Access-Control-Allow-Methods', 'GET, OPTIONS')
  setResponseHeader(
    event,
    'Access-Control-Allow-Headers',
    'Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, ngrok-skip-browser-warning',
  )
})
```

Those routes return sensitive development payloads. The aggregate `/extensions` route returns the raw payload store in [`getExtensionsPayloadMiddleware`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L110-L113), and individual extension payloads include the app API key, WebSocket URL, store FQDN, and extension payload in [`getExtensionPayloadMiddleware`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/server/middlewares.ts#L209-L225):

```ts
setResponseHeader(event, 'content-type', 'application/json')
return {
  app: {
    apiKey: [REDACTED:secret],
  },
  version: devOptions.manifestVersion,
  root: {
    url: new URL('/extensions', devOptions.url).toString(),
  },
  socket: {
    url: getWebSocketUrl(devOptions.url),
  },
  devConsole: {
    url: new URL('/extensions/dev-console', devOptions.url).toString(),
  },
  store: devOptions.storeFqdn,
  extension: await getUIExtensionPayload(extension, bundlePath, devOptions),
}
```

The WebSocket side has the same trust-boundary issue. [`websocketUpgradeHandler`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/websocket/handlers.ts#L15-L24) accepts any upgrade whose URL is exactly `/extensions`; it does not validate `Origin`, `Host`, a per-session secret, or any authenticated client identity:

```ts
return (request, socket, head) => {
  if (request.url !== '/extensions') {
    return
  }
  outputDebug(`Upgrading HTTP request to a websocket connection`, options.stdout)
  wss.handleUpgrade(request, socket, head, getConnectionDoneHandler(wss, options))
}
```

After the upgrade, the server immediately sends `payloadStore.getConnectedPayload()` and attaches the message handler in [`getConnectionDoneHandler`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/websocket/handlers.ts#L28-L38). The handler then accepts control messages in [`getOnMessageHandler`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/dev/extension/websocket/handlers.ts#L99-L134): `Update` can mutate app or extension payload store state, `Dispatch` is broadcast to clients, and `Log` writes attacker-provided log data to the developer terminal path. The `Update` branch compares `eventData.app.apiKey` with the payload-store API key, but that value is exposed through the CORS-readable HTTP payload, so it is not an effective authorization boundary.

## Root Cause

The dev server treats a developer-local control plane as implicitly trusted by network location, but it exposes browser-reachable HTTP and WebSocket endpoints without a shared session secret or origin/host validation. Wildcard CORS makes the HTTP payload readable from arbitrary origins, and the WebSocket upgrade path relies only on `request.url === '/extensions'`, allowing untrusted browser or tunnel clients to join the same control channel as legitimate extension clients.

## Proof of Concept (PoC)

PoC status: **theoretical**. The runtime PoC was not executed in this audit workspace because no live `shopify app dev` session for a configured app/store with UI extensions was available. The provided script at `piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/poc.py` targets the real dev-server stack and records runtime observations under `evidence/` when run against a live server.

Shortest reproduction against a vulnerable live UI-extension dev server:

1. Start `shopify app dev` for an app with UI extensions and identify the extension dev-server base URL, for example `http://127.0.0.1:<extension-port>` or the tunnel URL that forwards to it.
2. Run the PoC from a separate shell with an attacker-controlled origin header:

```bash
BASE_URL="http://127.0.0.1:<extension-port>" \
ORIGIN="https://attacker.example" \
python3 piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/poc.py
```

3. The script sends `GET /extensions` with `Origin: https://attacker.example` and checks for `Access-Control-Allow-Origin: *` plus JSON containing `app.apiKey`, `store`, `socket.url`, and extension metadata.
4. It then opens `ws://<host>:<port>/extensions` with the same attacker origin and no credentials, verifies the server sends the `connected` payload, and sends an unauthenticated `update` event using the API key disclosed by the HTTP payload.

The audit evidence records the expected confirmation marker rather than an executed result:

```text
PoC-Status: theoretical
Runtime execution was not attempted because the audit workspace does not include a live `shopify app dev` UI-extension server/app/store session.
Expected confirmed evidence marker: "CORS-readable payload and unauthenticated websocket state mutation".
```

On a vulnerable live server, the PoC is expected to finish with a JSON status similar to:

```json
{"status":"confirmed","evidence":"CORS-readable payload and unauthenticated websocket state mutation","notes":"store=<store>; marker=piolium-poc-..."}
```

## Impact

An attacker who can cause a developer's browser to visit a malicious page while `shopify app dev` is running can attempt cross-origin requests to the local extension dev server; an attacker who can reach a tunnel exposing that server can do the same remotely. Successful exploitation discloses development metadata such as the store FQDN, app API key, socket URL, manifest version, and extension payloads. The same client can join the WebSocket control channel, receive connected payloads, send dispatch messages to other connected clients, mutate in-memory extension/app payload state via update events, and inject log output into the developer terminal path. The demonstrated impact is limited to the development server/control plane rather than direct production store compromise, but it can compromise local development previews and developer workflow integrity.

## Remediation

Require an unguessable per-session token or equivalent authentication on every `/extensions` HTTP response that exposes payload data and on the `/extensions` WebSocket upgrade. Replace wildcard CORS with an explicit allowlist of expected dev-console, preview, localhost, and tunnel origins, and reject WebSocket upgrades with unexpected `Origin` or `Host` headers before `handleUpgrade()`. Do not use the app API key disclosed in HTTP payloads as the authorization check for WebSocket updates; bind updates to the authenticated dev session instead. Consider restricting or sanitizing `Log` events, including stripping ANSI control sequences, so untrusted clients cannot write arbitrary terminal output even if another control-plane check fails.

## Confirmation (V4)
Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-05-01T09:00:22Z
Confirm-Evidence: piolium/findings/p10-extension-dev-server-unauthenticated-control-plane/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: CORS-readable payload and unauthenticated websocket state mutation; store=piolium-dev-store.myshopify.com; marker=piolium-poc-411abf83
Confirm-Queued-V5: no
