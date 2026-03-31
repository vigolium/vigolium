# Code Anatomy: core-probe

## Scope
Router/route normalization, JWT/OAuth2 plugins, WebSocket upgrade handling, External plugin RPC (MsgPack/ProtoBuf), Clustering CP/DP WebSocket sync, DNS resolver integration, HTTP/2/OpenResty integration.

## Key Entry Points & Flows

### Router & Route Normalization
- `kong/runloop/handler.lua:1211-1225` → `router:exec(ctx)` is the primary request routing entry from OpenResty.
- Router flavor selection in `kong/router/init.lua:40-64` picks `traditional`, `expressions`, or `compat` router module.
- Path normalization is done via `kong/router/utils.lua:57-64` (`strip_uri_args` → `normalize(req_uri, true)`), used in:
  - `kong/router/traditional.lua:1755-1788` (traditional router exec)
  - `kong/router/atc.lua:443-507` (expressions router exec)
- Route match results feed upstream selection and headers in `kong/runloop/handler.lua:1340-1382`.

### WebSocket Upgrade Handling
- `kong/runloop/handler.lua:1357-1365` checks `Upgrade: websocket` and forwards `Connection: keep-alive, Upgrade` and `Upgrade: websocket` to upstream.
- No core Origin validation occurs at this layer; upgrade handling happens after routing.

### JWT Plugin
- `kong/plugins/jwt/handler.lua:154-260` (`do_authentication`) extracts tokens from URI params, cookies, or headers; validates JWT signature and registered claims; loads credential from DB; sets consumer context.
- Token retrieval logic is in `retrieve_tokens` (`kong/plugins/jwt/handler.lua:28-98`).
- Registered claims verification uses `jwt:verify_registered_claims(conf.claims_to_verify)` (claims list configured in schema).

### OAuth2 Plugin
- `kong/plugins/oauth2/access.lua:209-221` (`retrieve_parameters`) merges query + body for OAuth parameters depending on method.
- `issue_token` (approx `kong/plugins/oauth2/access.lua:533-812`) drives grant types, credential validation, and token issuance; uses `generate_token` to persist tokens.
- `parse_access_token` and `retrieve_token` read token from header or params and enforce service scoping.

### External Plugin RPC (MsgPack/ProtoBuf)
- `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — MsgPack RPC `call()` to external plugin server via Unix socket, uses MessagePack framing and responses.
- `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — ProtoBuf RPC `call()` uses length-prefixed framing and protobuf encoding.
- RPC layers call PDK methods (e.g., `call_pdk_method` in MsgPack, `call_pdk` in ProtoBuf) to access Kong internals.

### Clustering CP/DP WebSocket Sync
- Control plane accepts DP connections in `kong/clustering/control_plane.lua:191-439` (`handle_cp_websocket`):
  - reads `node_id`, `node_version` from query args
  - receives initial `basic_info` JSON frame
  - validates compatibility and sets up read/write threads.
- Data plane connects and sends `basic_info` in `kong/clustering/data_plane.lua:200-257` (`communicate`).
- Cluster RPC websocket handler is in `kong/clustering/rpc/manager.lua:507-562` (`handle_websocket`) with protocol negotiation and client cert validation.

### DNS Resolver Integration
- New DNS client uses `resty.dns.resolver` in `kong/resty/dns/client.lua`.
- DNS responses parsed and cached in `parseAnswer` (`kong/resty/dns/client.lua:686-733`); resolution through `individualQuery`, `asyncQuery`, `syncQuery`.

### HTTP/2 / OpenResty Integration
- HTTP/2 enabled in templates: `kong/templates/nginx_kong.lua` and defaults `kong/templates/kong_defaults.lua` (`http2 on;` and listener flags).
- Listener flags parsed in `kong/conf_loader/listeners.lua` with `http2` and `ssl` options.

## Trust Boundaries
- Internet -> Router/Proxy (OpenResty to Lua) via `kong/runloop/handler.lua`.
- CP/DP WebSocket boundary: `control_plane.lua` <-> `data_plane.lua` (mTLS + WebSocket frames).
- External plugin server RPC boundary: `kong/runloop/plugin_servers/rpc/*`.
- Kong -> DNS resolver boundary (`resty.dns.resolver`).
- Kong -> OpenResty/Nginx HTTP/2 core boundary (template-driven).

## Validation / Sanitization Points
- URI normalization via `normalize(req_uri, true)` in `strip_uri_args`.
- JWT signature and registered claims verification in `kong/plugins/jwt/handler.lua`.
- OAuth2 scope validation in `retrieve_scope` and client credential checks in `issue_token` flow.
- CP/DP WebSocket protocol negotiation and cert validation in `clustering/rpc/manager.lua`.
- DNS answer filtering and name normalization in `parseAnswer`.

## Sensitive Decisions
- Route selection is security-critical for auth plugin application.
- JWT/OAuth2 authentication decisions set authenticated consumer context for downstream proxying.
- External plugin RPC can invoke PDK methods that may impact request/response processing.
- CP/DP sync determines active configuration on data plane nodes.
