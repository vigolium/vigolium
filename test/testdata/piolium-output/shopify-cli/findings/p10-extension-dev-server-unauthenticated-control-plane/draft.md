---
Phase: 10
Sequence: 2
Slug: extension-dev-server-unauthenticated-control-plane
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: piolium/chamber-workspace/c03-ui-extension-dev-server/debate.md
Origin-Drafts: p5-001-ui-extension-dev-server-missing-auth.md; p8-001-extension-dev-websocket-cross-site-hijack.md
id: p10
slug: extension-dev-server-unauthenticated-control-plane
severity: info
Protocol: websocket
Auth-Required: no
Auth-Roles-Required: anonymous
---

# UI extension dev server exposes payloads and WebSocket control without authorization

## Summary
The app UI-extension dev server applies wildcard CORS to `/extensions*` and upgrades `WS /extensions` with only a URL equality check. A malicious browser origin on the developer machine, or a remote visitor to a tunnel exposing the dev server, can read extension/app/store payload metadata and send update/dispatch/log messages on the control channel.

## Location
- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:14-21` — wildcard CORS.
- `packages/app/src/cli/services/dev/extension/server/middlewares.ts:180-225` — extension payload response contains API key, socket URL, store, and extension payload.
- `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:19-24` — WebSocket upgrade checks only `request.url === '/extensions'`.
- `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:31-38` and `:99-134` — sends connected payload and accepts update/dispatch/log messages.

## Attacker Control
Browsers can initiate cross-origin HTTP and WebSocket requests to loopback services; tunnel visitors can reach the same routes remotely if the app dev server is exposed.

## Trust Boundary Crossed
An arbitrary browser/tunnel client crosses into a developer-only local dev control plane with no per-session key, Origin, Host, or session binding.

## Impact
Disclosure of app/store/extension dev metadata, unauthorized mutation or broadcast of extension dev payloads, and attacker-controlled terminal output through log messages (`stripAnsi: false`).

## Evidence
The HTTP middleware sets `Access-Control-Allow-Origin: *`; payload routes return app and store metadata. The WebSocket handler immediately calls `handleUpgrade()` and sends `payloadStore.getConnectedPayload()`, then processes `Update`, `Dispatch`, and `Log` events.

## Reproduction Steps
1. Start `shopify app dev` for an app with UI extensions.
2. From another web origin, fetch `http://localhost:<extension-port>/extensions/<extensionId>` and observe CORS-readable JSON metadata.
3. Open `ws://localhost:<extension-port>/extensions`; observe the connected payload.
4. Send `dispatch`, `update`, or `log` JSON messages and observe broadcast/state/terminal effects.
