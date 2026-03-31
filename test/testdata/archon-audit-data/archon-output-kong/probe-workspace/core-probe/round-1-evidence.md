# Evidence — core-probe

## [HARVESTER] PH-01: HTTP/2 path normalization mismatch routes to unprotected service

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/runloop/handler.lua:1211-1212` — router exec on `ctx.request_uri` (`router:exec(ctx)`).
2. `kong/router/atc.lua:443-449` — `req_uri = ctx.request_uri` then `req_uri = strip_uri_args(req_uri)` for expressions router.
3. `kong/router/traditional.lua:1755-1778` — traditional router `exec` uses `req_uri = strip_uri_args(req_uri)`.
4. `kong/router/utils.lua:57-63` — `strip_uri_args` trims query string and calls `normalize(req_uri, true)`.
5. `kong/tools/uri.lua:78-166` — `normalize` percent-decodes unreserved characters, removes dot segments, merges slashes.

**Sanitizers on path**:
- `kong/router/utils.lua:57-63` — `strip_uri_args` → `normalize(req_uri, true)` — **Partial**: normalizes percent-encoding and dot segments, but does not establish how HTTP/2 `:path` is canonicalized before `var.request_uri`.

**Verdict rationale**: Router matching normalizes `var.request_uri` in Lua, but whether HTTP/2 `:path` is normalized upstream (and how it differs from `normalize`) is not shown in the code provided. Determining mismatch requires confirmation of OpenResty/Nginx HTTP/2 path handling relative to `normalize(req_uri, true)`.

**Deepening note** (NEEDS-DEEPER only): Confirm whether `ngx.var.request_uri` reflects raw HTTP/2 `:path` or an already-normalized path for h2c vs ALPN, and compare that normalization to `kong.tools.uri.normalize`.

---

## [HARVESTER] PH-02: Cross-site WebSocket upgrade allows cookie-authenticated action replay

**Verdict**: VALIDATED

**Code path**:
1. `kong/runloop/handler.lua:1357-1365` — on `Upgrade: websocket`, sets `var.upstream_connection = "keep-alive, Upgrade"` and `var.upstream_upgrade = "websocket"` before proxying.
2. `kong/templates/nginx_kong.lua:193-217` — `proxy_set_header Upgrade $upstream_upgrade` and `proxy_set_header Connection $upstream_connection`, then `proxy_pass` to upstream.

**Sanitizers on path**:
- None found in this path (no Origin validation before forwarding).

**Verdict rationale**: The upgrade headers are forwarded as-is and no Origin validation occurs in the runloop handler, so a cross-site WebSocket upgrade can reach the upstream without proxy-side blocking.

---

## [HARVESTER] PH-03: External plugin RPC can override auth context via PDK calls

**Verdict**: VALIDATED

**Code path**:
1. `kong/runloop/plugin_servers/rpc/mp_rpc.lua:301-307` — `Rpc:handle_event` invokes `bridge_loop(self, instance_id, phase)`.
2. `kong/runloop/plugin_servers/rpc/mp_rpc.lua:264-296` — `bridge_loop` reads `step_in.Data.Method` from plugin server and calls `call_pdk_method`.
3. `kong/runloop/plugin_servers/rpc/mp_rpc.lua:113-135` — `call_pdk_method` resolves method via `rpc_util.index_table` and invokes it on `plugin.exposed_api` without allowlist checks.
4. `kong/runloop/plugin_servers/rpc/util.lua:1-14` — `index_table` walks the dot-delimited method name to any reachable PDK method.

**Sanitizers on path**:
- None found in this path (no allowlist or phase gating on method names).

**Verdict rationale**: The RPC bridge executes arbitrary method names supplied by the plugin server against `plugin.exposed_api` with no filtering, allowing calls such as `kong.client.authenticate` or header mutation to execute post-authentication if the plugin server is compromised.

---

## [HARVESTER] PH-04: ProtoBuf RPC oversized frame exhausts worker memory

**Verdict**: VALIDATED

**Code path**:
1. `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-317` — `Rpc:call` uses `read_frame` to receive method names/args during the bridge loop.
2. `kong/runloop/plugin_servers/rpc/pb_rpc.lua:245-255` — `read_frame` reads 4-byte length, then `c:receive(msg_len)` with no Lua-level size cap.

**Sanitizers on path**:
- None found in this path (no max length check before `c:receive(msg_len)`).

**Verdict rationale**: The length prefix from the plugin server is trusted and directly used for `c:receive(msg_len)` without any cap or validation in Lua, allowing oversized frames to be requested and potentially exhaust resources.

---

## [HARVESTER] PH-05: Legacy CP/DP sync path leaks full cluster config to impersonator

**Verdict**: VALIDATED

**Code path**:
1. `kong/clustering/init.lua:65-72` — CP validates client cert via `validate_client_cert` and calls `control_plane:handle_cp_websocket(cert)`.
2. `kong/clustering/control_plane.lua:191-239` — CP receives DP `basic_info` frame and parses JSON.
3. `kong/clustering/control_plane.lua:281-289` — `check_version_compatibility` uses DP version and plugin map.
4. `kong/clustering/control_plane.lua:317-325` — `check_configuration_compatibility` then queues initial config.
5. `kong/clustering/control_plane.lua:457-479` — CP sends deflated config payload to DP via `wb:send_binary(deflated_payload)`.
6. `kong/clustering/data_plane.lua:200-244` — DP connects to `/v1/outlet` and sends `basic_info` (v1 sync path).

**Sanitizers on path**:
- `kong/clustering/init.lua:65-69` — `validate_client_cert` — **Bypassable**: if attacker has stolen/valid DP cert, validation succeeds and config is sent.

**Verdict rationale**: The v1 `/v1/outlet` sync path is active and, after client cert validation and compatibility checks, the CP sends the configuration bundle over WebSocket; a stolen DP cert allows the attacker to receive it.

---

## [HARVESTER] PH-06: Crafted DNS response poisons upstream resolution

**Verdict**: VALIDATED

**Code path**:
1. `kong/resty/dns/client.lua:742-763` — `individualQuery` calls resolver `r:query` and then `parseAnswer(qname, r_opts.qtype, result, try_list)`.
2. `kong/resty/dns/client.lua:686-717` — `parseAnswer` moves answers not matching `qname/qtype` into `others`.
3. `kong/resty/dns/client.lua:720-728` — `parseAnswer` caches `others` via `cacheinsert(lst)` and marks success with `cachesetsuccess`.

**Sanitizers on path**:
- None found in this path (no bailiwick or name/type restriction before caching `others`).

**Verdict rationale**: `parseAnswer` explicitly caches additional records for other names/types returned in a response, with no validation shown for bailiwick or relatedness, enabling cache poisoning via injected records.

---

## [HARVESTER] PH-07: HTTP/2 h2c upgrade bypasses stream/header limits

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/templates/kong_defaults.lua:27-29` — default listeners enable `http2` on proxy/admin TLS ports.
2. `kong/conf_loader/listeners.lua:150-167` — listener flags parsed; `http2` is tracked on entries.
3. `kong/templates/nginx_kong.lua:96-101` — if any listener has `http2`, emits `http2 on;` for the server block.

**Sanitizers on path**:
- None found in this path (no Lua-level HTTP/2 header/stream limits configured here).

**Verdict rationale**: The template enables HTTP/2 based on listener flags but does not set request/stream limits in the Lua layer; determining whether h2c upgrades bypass limits depends on OpenResty/Nginx http2 settings outside this code path.

**Deepening note** (NEEDS-DEEPER only): Verify Nginx/OpenResty http2 limit configuration for h2c vs ALPN listeners and whether defaults differ for upgrade vs TLS negotiation.

---

## [HARVESTER] PH-08: OAuth2 parameter merge allows scope escalation

**Verdict**: INVALIDATED

**Code path**:
1. `kong/plugins/oauth2/access.lua:209-218` — `retrieve_parameters` merges query and body via `kong.table.merge(uri_args, body_args)` for POST/PUT/PATCH.
2. `kong/pdk/table.lua:41-53` — `kong.table.merge` delegates to `kong.tools.table.table_merge`.
3. `kong/tools/table.lua:32-43` — `table_merge` copies `t1` then overwrites with `t2` on key conflicts (body overrides query).
4. `kong/plugins/oauth2/access.lua:224-247` — `retrieve_scope` uses merged parameters and validates scope values.

**Sanitizers on path**:
- `kong/tools/table.lua:32-43` — `table_merge` — **Blocks**: body parameters override query parameters, preventing query-supplied `scope` from taking precedence when body also sets `scope`.

**Verdict rationale**: The merge order in `retrieve_parameters` causes body values to override query values, so a query `scope=admin` is overwritten by the body `scope=read` rather than escalating privileges.

**Fragility Score** (INVALIDATED only): Fragile
- **Reason**: A single merge-order control prevents the override; if merge precedence changes or different parsing paths are introduced, the protection could be bypassed without defense-in-depth.

---

## [HARVESTER] PH-09: JWT in query string enables token leakage and replay

**Verdict**: VALIDATED

**Code path**:
1. `kong/plugins/jwt/handler.lua:28-45` — `retrieve_tokens` reads JWTs from query parameters defined in `conf.uri_param_names`.
2. `kong/plugins/jwt/schema.lua:12-17` — default `uri_param_names = { "jwt" }`, enabling query-parameter JWTs by default.
3. `kong/plugins/jwt/handler.lua:154-156` — `do_authentication` calls `retrieve_tokens(conf)` and accepts returned token.

**Sanitizers on path**:
- None found in this path (query-based JWT retrieval is enabled by default and not restricted).

**Verdict rationale**: The JWT plugin explicitly accepts JWTs from query parameters (default key `jwt`), so tokens in URLs are treated as valid authentication inputs without additional safeguards.

---
