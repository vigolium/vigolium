# Theoretical PoC chain

Runtime exploitation was not executed in this audit workspace because a live `shopify app dev` session for an app with UI extensions requires a configured Shopify app/store development session. The attached `poc.py` is designed to run against the real extension dev server when `{{BASE_URL}}` is substituted with that server's URL.

## Chain exercised by `poc.py`

1. Send an unauthenticated cross-origin HTTP request to `GET {{BASE_URL}}/extensions` with `Origin: https://attacker.example`.
2. Confirm the real middleware returns `Access-Control-Allow-Origin: *` and a JSON payload containing `app.apiKey`, `store`, `socket.url`, and extension metadata.
3. Open `ws(s)://{{HOST}}:{{PORT}}/extensions` with the same attacker `Origin` and no credentials.
4. Confirm the WebSocket upgrade succeeds and the server immediately sends the `connected` payload from `payloadStore.getConnectedPayload()`.
5. Use the CORS-readable `app.apiKey` to send an unauthenticated WebSocket `update` message that adds a benign `app.pioliumPocMarker` value.
6. Confirm the server broadcasts an `update` containing the marker and that a follow-up unauthenticated `GET /extensions` reads the mutated marker from server state.

## Expected confirmation marker

The final JSON line from `poc.py` reports:

```json
{"status":"confirmed","evidence":"CORS-readable payload and unauthenticated websocket state mutation","notes":"store=<store>; marker=piolium-poc-..."}
```

## Code evidence

See `evidence/code-path.log` for the relevant real-stack code paths: wildcard CORS, unauthenticated `/extensions` payload routes, WebSocket upgrade gated only by `request.url === '/extensions'`, and WebSocket `update`/`dispatch` handling.
