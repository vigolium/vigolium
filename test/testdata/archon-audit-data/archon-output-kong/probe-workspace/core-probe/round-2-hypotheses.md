# Round 2 Hypotheses — core-probe

## PH-01: HTTP/2 path normalization differentials enable route misclassification

- **Reasoning-Model**: TRIZ
- **Target**: `kong/router/utils.lua:57-64` — `strip_uri_args`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: Send HTTP/2 request (ALPN or h2c upgrade) with crafted `:path` containing percent-encoded dot segments and mixed slash encodings (e.g., `/:path /secure%2f..%2fpublic%2f%2e%2e/health`) so Nginx/OpenResty normalizes differently from Lua `normalize(req_uri, true)`; compare routing vs upstream path handling across multiple attempts.
- **Tension / Game**: Compatibility tension between HTTP/1 Lua normalization and HTTP/2 core normalization paths; supporting multiple protocol entry paths risks inconsistent interpretation of request URI.
- **What was sacrificed / Information accumulated**: Consistent normalization across protocol paths; attacker can trigger the path where normalization diverges from Lua assumptions used for route matching.
- **Security consequence**: Route selection may map to a less protected route or bypass auth plugin application when HTTP/2 path interpretation differs from Lua normalization.
- **Severity estimate**: HIGH
- **Read needed**: `kong/router/utils.lua:57-64`
- **Deepening direction**: Inspect HTTP/2 request URI handling in Nginx/OpenResty, and confirm whether `var.request_uri` differs from raw `:path` for h2c vs ALPN; look for tests or compatibility notes around `normalize(..., true)`.

---

## PH-02: External plugin RPC can override auth decisions post-validation

- **Reasoning-Model**: TRIZ
- **Target**: `kong/runloop/plugin_servers/rpc/pb_rpc.lua:287-315` — `Rpc:call` (PDK bridge loop)
- **Attacker starting position**: authenticated plugin server / compromised external plugin
- **Attack input / strategy**: After JWT/OAuth2 has authenticated a consumer, malicious plugin server sends a PDK call frame with method name like `kong.service.request.set_header` or `kong.request.clear_header` to strip/replace Authorization or inject upstream headers; then continues normal response to hide the modification.
- **Tension / Game**: Convenience/extensibility vs finality of auth decisions; exposing PDK over RPC allows plugins to mutate request state after core auth plugins, sacrificing the assumption that auth decisions are final.
- **What was sacrificed / Information accumulated**: Integrity of authz pipeline; plugin RPC can observe and modify request/consumer context after authentication.
- **Security consequence**: AuthZ bypass or privilege escalation through post-auth request mutation.
- **Severity estimate**: HIGH
- **Read needed**: `kong/runloop/plugin_servers/rpc/pb_rpc.lua:287-315`
- **Deepening direction**: Enumerate exposed PDK methods callable via RPC and identify which ones can mutate headers, consumer, or routing after auth plugins run.

---

## PH-03: Unbounded RPC framing enables memory/CPU exhaustion via oversized frames

- **Reasoning-Model**: TRIZ
- **Target**: `kong/runloop/plugin_servers/rpc/pb_rpc.lua:245-265` — `read_frame`
- **Attacker starting position**: authenticated plugin server / compromised external plugin
- **Attack input / strategy**: Send a length-prefixed RPC frame with an extremely large `msg_len` (e.g., 2GB) or stream an enormous MsgPack object, causing Lua `receive(msg_len)` / unpacker loops to allocate or block excessively.
- **Tension / Game**: Performance/streaming convenience vs bounded input validation; RPC framing omits Lua-level size caps to keep the protocol generic.
- **What was sacrificed / Information accumulated**: Input size enforcement; attacker can force large allocations or prolonged reads by advertising oversized frames.
- **Security consequence**: Denial of service in worker process via memory exhaustion or event loop blocking.
- **Severity estimate**: HIGH
- **Read needed**: `kong/runloop/plugin_servers/rpc/pb_rpc.lua:245-265`
- **Deepening direction**: Verify whether socket-level `max_payload_len` or similar limits are configured; check MsgPack unpacker for size limits and failure behavior.

---

## PH-04: Legacy sync v1 fallback weakens CP/DP validation parity

- **Reasoning-Model**: TRIZ
- **Target**: `kong/clustering/data_plane.lua:110-136` — `worker_events.register` (sync v1 fallback)
- **Attacker starting position**: authenticated DP node / attacker with DP cert
- **Attack input / strategy**: Present an older DP version or omit `kong.sync.v2` capability during meta handshake to trigger v1 sync, then send `basic_info` and subsequent config frames via `/v1/outlet` with edge-case fields (oversized labels/filters/plugins) that may not be validated identically to v2.
- **Tension / Game**: Backwards compatibility vs consistent validation; enabling sync v1 for older DPs trades uniform validation and protocol guardrails for compatibility.
- **What was sacrificed / Information accumulated**: Parity of validation and limits across sync versions; attacker can choose the protocol path with weaker enforcement.
- **Security consequence**: Configuration poisoning or inconsistent config application across DP nodes, potentially enabling misrouting or bypassing plugin chains.
- **Severity estimate**: HIGH
- **Read needed**: `kong/clustering/data_plane.lua:110-136`
- **Deepening direction**: Compare validations and size limits between sync v1 (`/v1/outlet`) and sync v2 (`/v2/outlet`) in CP/DP implementations, especially around `basic_info` and config payload handling.

---

## PH-05: DNS additional records cached without strict validation enable cache poisoning

- **Reasoning-Model**: TRIZ
- **Target**: `kong/resty/dns/client.lua:686-733` — `parseAnswer`
- **Attacker starting position**: network attacker controlling resolver or response path
- **Attack input / strategy**: Respond to an A/AAAA query for `target.example` with extra records for attacker-chosen names/types (e.g., `CNAME` or `A` for `admin.internal`) and rely on `parseAnswer` caching “others” records even when not requested.
- **Tension / Game**: Performance (cache warmup) vs strictness; caching non-requested records improves resolution but sacrifices strict validation of response content.
- **What was sacrificed / Information accumulated**: Strict response filtering; attacker can prime cache entries for unrelated names/types via a single response.
- **Security consequence**: DNS cache poisoning leading to upstream misrouting or traffic interception.
- **Severity estimate**: HIGH
- **Read needed**: `kong/resty/dns/client.lua:686-733`
- **Deepening direction**: Check resolver configuration for DNSSEC, response validation, and whether additional record caching honors bailiwick or TTL bounds.

---

## PH-06: HTTP/2 enablement relies on core limits; h2c vs ALPN paths may diverge

- **Reasoning-Model**: TRIZ
- **Target**: `kong/templates/kong_defaults.lua:27-29` — default `http2 on` listeners
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: Use h2c upgrade or ALPN to negotiate HTTP/2 and send large header frames / excessive concurrent streams, probing for enforcement differences between upgrade and TLS ALPN paths.
- **Tension / Game**: Performance and modern protocol support vs consistent guardrails; enabling HTTP/2 delegates stream/HPACK limits to Nginx/OpenResty, sacrificing Kong-level enforcement parity.
- **What was sacrificed / Information accumulated**: Unified limit enforcement at the Lua layer; attacker can select the protocol path with weaker core guardrails.
- **Security consequence**: Resource exhaustion or request smuggling via inconsistent HTTP/2 limit enforcement.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/templates/kong_defaults.lua:27-29`
- **Deepening direction**: Audit Nginx/OpenResty http2 settings for stream/HPACK limits and verify if h2c upgrades are enabled with the same limits as ALPN.

---

## PH-07: Route/protocol oracle via differentiated error responses

- **Reasoning-Model**: Game-Theory
- **Target**: `kong/runloop/handler.lua:1211-1328` — router exec + protocol mismatch handling
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: Send a sequence of requests to a candidate path with varying protocols/content-types: (1) HTTP/1.1 request → observe 404 vs 426 vs 415; (2) HTTP/2 request with `content-type: application/grpc` → observe 426 vs 200 grpc-status; (3) repeat across hostnames and paths to map which routes exist and which protocols they require.
- **Tension / Game**: Usability (helpful protocol errors) vs information disclosure; distinct error responses reveal route existence and protocol expectations.
- **What was sacrificed / Information accumulated**: Route confidentiality; attacker learns which paths are registered, which are gRPC-only, and which enforce HTTPS.
- **Security consequence**: Accelerated route enumeration enabling targeted attacks on known services or auth bypass attempts.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/runloop/handler.lua:1211-1328`
- **Deepening direction**: Measure response timing and error body consistency across auth-protected vs unprotected routes to quantify oracle strength.

---

## PH-08: WebSocket upgrade forwarded without origin checks enables CSWSH

- **Reasoning-Model**: TRIZ
- **Target**: `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade handling
- **Attacker starting position**: unauthenticated (browser-based)
- **Attack input / strategy**: From a malicious web page, initiate a cross-site WebSocket to a Kong-proxied upstream that relies on cookie-based auth; Kong forwards `Upgrade: websocket` without Origin validation, allowing cross-site WebSocket hijacking if upstream trusts Origin implicitly.
- **Tension / Game**: Convenience and protocol passthrough vs origin enforcement; core upgrade handling forwards headers without origin checks.
- **What was sacrificed / Information accumulated**: Cross-origin protections at the proxy layer; attacker can exploit browser auth cookies over WS.
- **Security consequence**: Cross-site WebSocket hijacking leading to authenticated actions against upstream services.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/runloop/handler.lua:1357-1365`
- **Deepening direction**: Identify whether any default plugins enforce Origin checks on WS upgrades; confirm upstream app’s Origin validation requirements.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| `kong/runloop/handler.lua:1211-1225` — router exec | PH-01 / YES | PH-07 / YES |
| `kong/router/traditional.lua:1755-1788` — traditional router exec | PH-01 / YES | NO — routing oracle handled at handler level |
| `kong/router/atc.lua:443-507` — expressions router exec | PH-01 / YES | NO — routing oracle handled at handler level |
| `kong/router/utils.lua:57-64` — strip_uri_args | PH-01 / YES | NO — normalization is not interactive by itself |
| `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade | PH-08 / YES | NO — single-request impact, not iterative |
| `kong/clustering/control_plane.lua:191-236` — handle_cp_websocket | PH-04 / YES | NO — requires authenticated DP, no adaptive oracle identified |
| `kong/clustering/data_plane.lua:200-257` — communicate | PH-04 / YES | NO — stateful but attacker is authenticated DP only |
| `kong/clustering/rpc/manager.lua:507-562` — handle_websocket | PH-04 / NO — v2 path not the fallback being targeted | NO — no repeated-interaction oracle identified |
| `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — MsgPack RPC call | PH-02/PH-03 / YES | NO — attack is single-shot DoS or mutation |
| `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — ProtoBuf RPC call | PH-02/PH-03 / YES | NO — attack is single-shot DoS or mutation |
| `kong/plugins/jwt/handler.lua:154-250` — do_authentication | NO — no contradiction found in anatomy | NO — no repeated-interaction mechanism identified |
| `kong/plugins/oauth2/access.lua:209-221` — retrieve_parameters | NO — no contradiction found in anatomy | NO — no repeated-interaction mechanism identified |
| `kong/plugins/oauth2/access.lua:533-812` — issue_token | NO — no contradiction found in anatomy | NO — no repeated-interaction mechanism identified |
| `kong/resty/dns/client.lua:742-883` — individualQuery/syncQuery | PH-05 / YES | NO — poisoning is single-response, not adaptive |
| `kong/templates/nginx_kong.lua:97-519` — listener config | PH-06 / YES | NO — limit enforcement difference is not iterative |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| Router normalization consistency vs HTTP/2 entry | PH-01 / YES — protocol normalization tension |
| AuthZ decision finality can be influenced by external plugin RPC | PH-02 / YES — PDK mutation after auth |
| External plugin RPC framing lacks explicit Lua-level size limits | PH-03 / YES — unbounded frame size |
| CP/DP sync has fallback/legacy paths (sync v1 JSON-RPC) | PH-04 / YES — fallback validation parity |
| DNS resolver safety depends on OpenResty resolver version | PH-05 / YES — cache poisoning via additional records |
| HTTP/2 limit enforcement depends on Nginx/OpenResty core | PH-06 / YES — core limit reliance |

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| Response differentiation on route/protocol mismatch | PH-07 / YES — multi-step route/protocol oracle |
| CP/DP ping/status state accumulation | NO — requires authenticated DP; no attacker-learnable oracle identified |
