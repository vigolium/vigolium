# Round 1 Hypotheses — core-probe

## PH-01: HTTP/2 path normalization mismatch routes to unprotected service

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/router/utils.lua:57-64` — `strip_uri_args(req_uri)`
- **Attacker starting position**: unauthenticated
- **Attack input**: HTTP/2 request with `:path` set to `/%2e%2e/%2fadmin` (or `/%2Fadmin`) over h2c upgrade
- **Chain**: attacker sends crafted HTTP/2 path → Nginx/OpenResty core normalizes differently than Lua `normalize(..., true)` → router matches a less-protected route than intended → request bypasses auth plugins applied to the correct canonical path
- **Catastrophe / Dangerous fallback**: access to admin/internal upstreams without intended auth chain
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: compare normalization semantics between OpenResty HTTP/2 path handling and `normalize(req_uri, true)`; confirm route selection differences for `%2f`, `%2e`, and double-slash inputs

---

## PH-02: Cross-site WebSocket upgrade allows cookie-authenticated action replay

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade forwarding
- **Attacker starting position**: unauthenticated (browser-based)
- **Attack input**: browser JS opens `wss://gateway.example.com/admin/ws` with victim cookies and `Origin: https://evil.example.com`
- **Chain**: attacker-controlled page initiates WS to Kong → core forwards upgrade headers without Origin validation → upstream admin WS accepts cookie-authenticated session → attacker controls WS channel via victim browser
- **Catastrophe / Dangerous fallback**: cross-site WebSocket CSRF leading to admin actions or data exfiltration
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: check whether any core or default plugin enforces Origin for WS routes; identify admin APIs exposed over WS

---

## PH-03: External plugin RPC can override auth context via PDK calls

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — `Rpc:call()`
- **Attacker starting position**: compromised external plugin server
- **Attack input**: MsgPack frame invoking `call_pdk_method` to set `kong.client.authenticate` or to inject `X-Consumer-Username: admin` before proxying
- **Chain**: attacker-controlled plugin server responds with RPC directing PDK auth/context mutation → Kong accepts RPC response and applies PDK call → downstream sees authenticated admin consumer without real credentials
- **Catastrophe / Dangerous fallback**: full authz bypass and impersonation across protected routes
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: enumerate PDK methods callable via RPC and check whether auth context changes are allowed post-auth

---

## PH-04: ProtoBuf RPC oversized frame exhausts worker memory

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — `Rpc:call()`
- **Attacker starting position**: compromised external plugin server
- **Attack input**: length-prefixed ProtoBuf frame advertising a 2GB message size
- **Chain**: Kong reads length prefix without Lua-level max → attempts to allocate/read huge frame → worker OOM or stalls → proxy capacity collapses
- **Catastrophe / Dangerous fallback**: cluster-wide denial of service on all worker processes
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: check for any upstream socket read limits or OpenResty buffering caps; confirm failure mode under oversized prefix

---

## PH-05: Legacy CP/DP sync path leaks full cluster config to impersonator

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/clustering/control_plane.lua:191-236` — `handle_cp_websocket`
- **Attacker starting position**: network-adjacent with stolen DP certificate
- **Attack input**: WebSocket connect with `node_id=dp-evil&node_version=3.0` then JSON-RPC `{"jsonrpc":"2.0","method":"sync","params":{"capabilities":"v1"}}`
- **Chain**: attacker establishes CP WebSocket as fake DP → triggers legacy JSON-RPC sync path with weaker validation → CP streams full configuration bundle to attacker node
- **Catastrophe / Dangerous fallback**: exfiltration of all cluster routes, credentials, and secrets; attacker can mirror or replay config
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: validate whether legacy sync v1 path is still enabled and whether it bypasses compatibility or identity checks

---

## PH-06: Crafted DNS response poisons upstream resolution

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/resty/dns/client.lua:686-733` — `parseAnswer()`
- **Attacker starting position**: network-adjacent (DNS MITM or malicious resolver)
- **Attack input**: DNS response with CNAME chain and name-compression loop resolving `api.internal` to attacker IP
- **Chain**: attacker returns malformed-but-accepted DNS answer → Kong parses and caches poisoned record → proxy routes internal traffic to attacker host
- **Catastrophe / Dangerous fallback**: traffic hijack of upstream services leading to data theft or command injection
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: inspect parseAnswer handling for compression loops, qtype filtering, and TTL acceptance

---

## PH-07: HTTP/2 h2c upgrade bypasses stream/header limits

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/templates/nginx_kong.lua:97-519` — HTTP/2 listener configuration
- **Attacker starting position**: unauthenticated
- **Attack input**: h2c upgrade request with 10k HEADER frames and a large HPACK dynamic table
- **Chain**: h2c upgrade accepted → Nginx/OpenResty core enforces different limits than ALPN path → Lua layer never sees oversize headers → worker CPU/memory exhaustion
- **Catastrophe / Dangerous fallback**: proxy-wide DoS and request queue collapse
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify h2c vs ALPN limit parity in the deployed OpenResty/Nginx build

---

## PH-08: OAuth2 parameter merge allows scope escalation

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/plugins/oauth2/access.lua:209-221` — `retrieve_parameters()`
- **Attacker starting position**: authenticated OAuth2 client
- **Attack input**: `POST /oauth2/token?scope=admin` with body `grant_type=client_credentials&scope=read&client_id=legit&client_secret=valid`
- **Chain**: attacker supplies conflicting scope in query and body → parameter merge selects higher-privilege query value → `issue_token()` issues token with `admin` scope
- **Catastrophe / Dangerous fallback**: privilege escalation via OAuth2 token over-scoping
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm precedence rules in retrieve_parameters and how retrieve_scope consumes merged values

---

## PH-09: JWT in query string enables token leakage and replay

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/plugins/jwt/handler.lua:28-98` — `retrieve_tokens()`
- **Attacker starting position**: unauthenticated (phishing/URL sharing)
- **Attack input**: `GET /protected?jwt=eyJhbGciOi...` link shared with victim
- **Chain**: plugin accepts JWT from URI parameter → URL is logged by proxies/analytics/referrers → attacker obtains valid token from logs → reuses token to impersonate victim
- **Catastrophe / Dangerous fallback**: account takeover via token replay outside intended channel
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm default token_sources and whether URL token use is enabled by default

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| `kong/runloop/handler.lua:1211-1225` — router exec | PH-01 | NO — anatomy has no defensive pattern for this path |
| `kong/router/traditional.lua:1755-1788` — exec(ctx) | PH-01 | NO — not tied to a defensive pattern |
| `kong/router/atc.lua:443-507` — exec(ctx) | PH-01 | NO — not tied to a defensive pattern |
| `kong/router/utils.lua:57-64` — strip_uri_args | PH-01 | NO — not tied to a defensive pattern |
| `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade | PH-02 | NO — no defensive fallback described |
| `kong/clustering/control_plane.lua:191-236` — handle_cp_websocket | PH-05 | NO — no defensive pattern described |
| `kong/clustering/data_plane.lua:200-257` — communicate() | PH-05 | NO — no defensive pattern described |
| `kong/clustering/rpc/manager.lua:507-562` — handle_websocket() | PH-05 (shared CP/DP trust boundary) | NO — no defensive pattern described |
| `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — Rpc:call() | PH-03 | NO — no defensive pattern described |
| `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — Rpc:call() | PH-04 | NO — no defensive pattern described |
| `kong/plugins/jwt/handler.lua:154-250` — do_authentication() | PH-09 | NO — no defensive pattern described |
| `kong/plugins/oauth2/access.lua:209-221` — retrieve_parameters() | PH-08 | NO — no defensive pattern described |
| `kong/plugins/oauth2/access.lua:533-812` — issue_token() | PH-08 | NO — no defensive pattern described |
| `kong/resty/dns/client.lua:742-883` — individualQuery/syncQuery | PH-06 | NO — no defensive pattern described |
| `kong/templates/nginx_kong.lua:97-519` — HTTP/2 config | PH-07 | NO — no defensive pattern described |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| (No Defensive Patterns section in anatomy) | NO — not applicable |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| Router normalization consistency vs HTTP/2 entry | PH-01 |
| AuthZ decision finality influenced by external plugin RPC | PH-03 |
| External plugin RPC framing lacks size limits | PH-04 |
| CP/DP sync legacy path (sync v1 JSON-RPC) | PH-05 |
| DNS resolver safety depends on OpenResty resolver | PH-06 |
| HTTP/2 limit enforcement depends on Nginx/OpenResty core | PH-07 |
