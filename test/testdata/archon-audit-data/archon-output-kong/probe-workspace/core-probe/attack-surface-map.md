# Attack Surface Map: core-probe

## Entry Points
- `kong/runloop/handler.lua:1211-1225` — `get_updated_router():exec(ctx)` — inbound HTTP/HTTPS request routing based on method/URI/host/scheme/headers.
- `kong/router/traditional.lua:1755-1788` — `exec(ctx)` — traditional router match on method/uri/host/headers; request path normalization via `strip_uri_args`.
- `kong/router/atc.lua:443-507` — `exec(ctx)` — expressions router matching; `strip_uri_args` normalization and cache keying.
- `kong/router/utils.lua:57-64` — `strip_uri_args(req_uri)` — normalizes URI (percent-decoding per `normalize(..., true)`) for route matching.
- `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade handling — accepts `Upgrade: websocket` and forwards Upgrade headers upstream.
- `kong/clustering/control_plane.lua:191-236` — `handle_cp_websocket` — CP accepts DP WebSocket, parses `node_id/node_version` args and initial `basic_info` payload.
- `kong/clustering/data_plane.lua:200-257` — `communicate()` — DP connects to CP WebSocket and sends `basic_info` payload (plugins, config, labels).
- `kong/clustering/rpc/manager.lua:507-562` — `handle_websocket()` — cluster RPC WebSocket handler with protocol negotiation + mTLS validation.
- `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — `Rpc:call()` — MsgPack RPC request/response framing with external plugin server.
- `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — `Rpc:call()` — ProtoBuf RPC framing with external plugin server.
- `kong/plugins/jwt/handler.lua:154-250` — `do_authentication()` — JWT token extraction + validation path.
- `kong/plugins/oauth2/access.lua:209-221` — `retrieve_parameters()` — OAuth2 parameters from query/body.
- `kong/plugins/oauth2/access.lua:533-812` — `issue_token()` — OAuth2 token issuance/refresh flows.
- `kong/resty/dns/client.lua:742-883` — `individualQuery/syncQuery` — DNS resolver query/response parsing.
- `kong/templates/nginx_kong.lua:97-519` — Nginx listener config — `http2 on;` for proxy/admin listeners.

## Trust Boundary Crossings
- Internet request -> Router/route selection in `kong/runloop/handler.lua` and `kong/router/*` (untrusted HTTP inputs driving routing/auth decisions).
- Proxy/WebSocket Upgrade -> Upstream service via `kong/runloop/handler.lua` (upgrade headers proxied without origin checks).
- Data Plane -> Control Plane WebSocket sync (`kong/clustering/control_plane.lua` + `data_plane.lua`) crossing CP/DP trust boundary.
- Cluster RPC WebSocket (`kong/clustering/rpc/manager.lua`) crossing node-to-node trust boundary with mTLS.
- Kong core -> External plugin server RPC (`kong/runloop/plugin_servers/rpc/*`) crossing process boundary and deserialization trust boundary.
- Kong -> DNS resolver (`kong/resty/dns/client.lua`) trusting DNS responses from external resolver(s).
- Kong -> OpenResty/Nginx HTTP/2 engine (templates enabling HTTP/2) trusting upstream core handling of HTTP/2 frames.

## Auth / AuthZ Decision Points
- `kong/plugins/jwt/handler.lua:154-250` — `do_authentication()` — validates JWT signature/claims, sets authenticated consumer.
- `kong/plugins/oauth2/access.lua:533-812` — `issue_token()` — OAuth2 grant validation and token issuance.
- `kong/plugins/oauth2/access.lua:934-1023` — `set_consumer()/retrieve_token()` — access-token validation for protected resources.
- `kong/clustering/rpc/manager.lua:527-533` — `handle_websocket()` — validates client cert before accepting cluster RPC.
- `kong/clustering/control_plane.lua:281-323` — `check_version_compatibility` / `check_configuration_compatibility` — CP decides whether DP is allowed to sync.

## Validation / Sanitization Functions
- `kong/router/utils.lua:57-64` — `strip_uri_args()` — normalizes request URI for routing.
- `kong/plugins/jwt/handler.lua:211-241` — JWT alg/claim validation (`verify_signature`, `verify_registered_claims`).
- `kong/plugins/oauth2/access.lua:224-248` — `retrieve_scope()` — scope allowlist enforcement.
- `kong/clustering/control_plane.lua:205-229` — `handle_cp_websocket()` — validates initial `basic_info` payload structure.
- `kong/clustering/rpc/manager.lua:510-525` — protocol allowlist for RPC (`Sec-WebSocket-Protocol` match).
- `kong/resty/dns/client.lua:686-733` — `parseAnswer()` — normalizes answer names and filters by qtype.

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| HTTP Listener | Router | Request URI normalized consistently | HTTP: YES | HTTP/2 via Nginx core: normalization before Lua? UNKNOWN |
| Router | Auth Plugins (JWT/OAuth2) | Matched route implies correct auth plugin chain | HTTP routes: YES | WebSocket upgrades: plugin chain still applies but Origin not checked in core |
| Auth Plugins | Upstream Proxy | AuthZ decision is final | YES | External plugin server can call PDK methods via RPC to modify behavior |
| Proxy | External Plugin RPC | RPC messages are well-formed and bounded | NO | MsgPack/ProtoBuf frames parsed without explicit size limits in Lua layer |
| DP | CP WebSocket Sync | mTLS + basic_info validation ensures only legitimate DP nodes | YES | Legacy sync v1 path: JSON-RPC fallback in DP communicate()
| Kong | DNS Resolver | DNS responses are well-formed and safe | NO | Custom resolver versions / upstream OpenResty patches may vary |
| Kong | Nginx/OpenResty HTTP/2 | HTTP/2 core enforces stream/HPACK limits | NO | h2c upgrade vs ALPN paths may differ in enforcement |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)
- Router normalization consistency vs HTTP/2 entry: possible path normalization differentials if HTTP/2/h2c paths bypass Lua-layer normalization assumptions.
- AuthZ decision finality can be influenced by external plugin RPC (PDK method abuse), which may bypass expected auth checks.
- External plugin RPC framing lacks explicit Lua-level size limits; malformed/oversized MsgPack/ProtoBuf frames could bypass assumptions.
- CP/DP sync has fallback/legacy paths (sync v1 JSON-RPC) that may not enforce identical validations.
- DNS resolver safety depends on OpenResty resolver version; Kong layer does not harden crafted DNS response handling.
- HTTP/2 limit enforcement depends on Nginx/OpenResty core; h2c upgrade vs ALPN may have inconsistent guards.
