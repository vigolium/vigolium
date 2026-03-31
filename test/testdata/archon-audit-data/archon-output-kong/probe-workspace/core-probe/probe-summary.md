# Deep Probe Summary: core-probe

Status: complete
Loops: 3
Total hypotheses: 23
Validated: 12
Needs-Deeper: 6
Stop reason: max loops

## Validated Hypotheses

### PH-02: WebSocket upgrade lacks Origin enforcement (CSWSH)
- Reasoning-Model: Pre-Mortem
- Target: `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade handling
- Attack input: Cross-origin WebSocket handshake with victim cookies
- Code path: `kong/runloop/handler.lua:1357-1365` → `kong/templates/nginx_kong.lua:193-217`
- Sanitizers on path: none
- Security consequence: Cross-site WebSocket hijacking against cookie-authenticated upstreams
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-03: External plugin RPC can mutate auth context via PDK calls
- Reasoning-Model: Pre-Mortem
- Target: `kong/runloop/plugin_servers/rpc/mp_rpc.lua:264-296` — bridge loop + `call_pdk_method`
- Attack input: MsgPack RPC frames calling PDK methods (e.g., `kong.client.authenticate`)
- Code path: `mp_rpc.lua:264-296` → `mp_rpc.lua:113-135` → `rpc/util.lua:1-14`
- Sanitizers on path: none
- Security consequence: AuthZ bypass / identity impersonation
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-04: ProtoBuf RPC oversized frame DoS
- Reasoning-Model: Pre-Mortem
- Target: `kong/runloop/plugin_servers/rpc/pb_rpc.lua:245-255`
- Attack input: Length-prefixed ProtoBuf frame with huge `msg_len`
- Code path: `pb_rpc.lua:245-255` → `pb_rpc.lua:268-317`
- Sanitizers on path: none
- Security consequence: Worker memory exhaustion / event loop blocking
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-05: CP/DP sync config exfiltration with stolen DP cert
- Reasoning-Model: Pre-Mortem
- Target: `kong/clustering/control_plane.lua:191-325` — `handle_cp_websocket`
- Attack input: WebSocket connection with valid (stolen) DP cert and `basic_info`
- Code path: `control_plane.lua:191-325` → `control_plane.lua:457-479` (config send)
- Sanitizers on path: cert validation only (bypassable with stolen cert)
- Security consequence: Cluster config/secret exfiltration
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-06: DNS cache poisoning via additional records
- Reasoning-Model: Pre-Mortem
- Target: `kong/resty/dns/client.lua:686-728` — `parseAnswer`
- Attack input: DNS response with extra unrelated records
- Code path: `client.lua:686-728` → `cacheinsert(lst)`
- Sanitizers on path: none
- Security consequence: Upstream traffic redirection
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-09: JWT tokens accepted from query string by default
- Reasoning-Model: Pre-Mortem
- Target: `kong/plugins/jwt/schema.lua:12-17` + `kong/plugins/jwt/handler.lua:28-45`
- Attack input: URL with `?jwt=<token>`
- Code path: `jwt/handler.lua:28-45` → `jwt/handler.lua:154-156`
- Sanitizers on path: none
- Security consequence: Token leakage via logs/referrers, replay risk
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-01 (Loop2): OAuth2 parameter source confusion via merge order
- Reasoning-Model: Pre-Mortem/TRIZ
- Target: `kong/plugins/oauth2/access.lua:209-218` — `retrieve_parameters`
- Attack input: Conflicting query/body parameters for `/oauth2/token`
- Code path: `access.lua:209-218` → `kong/tools/table.lua:32-44` → `issue_token()`
- Sanitizers on path: grant-type checks only (no source enforcement)
- Security consequence: Parameter smuggling across layers that inspect only query/body
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-02 (Loop2): Password grant impersonation with leaked provision key
- Reasoning-Model: Pre-Mortem
- Target: `kong/plugins/oauth2/access.lua:737-763` — password grant path
- Attack input: `grant_type=password` + `provision_key` + arbitrary `authenticated_userid`
- Code path: `issue_token()` → `generate_token(... authenticated_userid ...)`
- Sanitizers on path: provision key presence only
- Security consequence: Full user impersonation
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence-loop2.md

### PH-03 (Loop2): Cross-service refresh token reuse when global_credentials enabled
- Reasoning-Model: Pre-Mortem
- Target: `kong/plugins/oauth2/access.lua:767-809`
- Attack input: Refresh token from Service A used on Service B
- Code path: `issue_token()` → `generate_token` with current service
- Sanitizers on path: service_id check skipped when `global_credentials` true
- Security consequence: Lateral movement across services
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-04 (Loop2): Non-expiring JWT accepted when exp not enforced
- Reasoning-Model: Pre-Mortem
- Target: `kong/plugins/jwt/handler.lua:238-249`
- Attack input: JWT without `exp` when `claims_to_verify` unset
- Code path: `verify_registered_claims` + `check_maximum_expiration` (disabled by default)
- Sanitizers on path: configurable but disabled by default
- Security consequence: Indefinite token validity
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-05 (Loop2): HS256 uses misconfigured public key as HMAC secret
- Reasoning-Model: Pre-Mortem
- Target: `kong/plugins/jwt/handler.lua:209-236`
- Attack input: HS256 token signed with RSA public key as HMAC secret
- Code path: `jwt_secret.secret` used for HS* algorithms
- Sanitizers on path: none to validate secret type
- Security consequence: Token forgery if credentials misconfigured
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-06 (Loop2): Cluster RPC node_id impersonation with stolen cert
- Reasoning-Model: Pre-Mortem
- Target: `kong/clustering/rpc/manager.lua:230-335`
- Attack input: RPC hello payload with arbitrary `kong_node_id`
- Code path: `handle_websocket()` → `_handle_meta_call` → register node_id
- Sanitizers on path: cert validation only (node_id not bound to cert)
- Security consequence: Unauthorized cluster control actions
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence-loop2.md

### PH-03 (Loop3): Expressions router cache key omits scheme
- Reasoning-Model: Pre-Mortem/Abductive
- Target: `kong/router/atc.lua:443-487`
- Attack input: Same host/uri across HTTP and HTTPS
- Code path: `exec()` computes cache key without scheme, then returns cached match
- Sanitizers on path: none
- Security consequence: Protocol constraints bypass via cached match
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop3.md

## NEEDS-DEEPER

### PH-01/PH-02 (Loop3): Cache reuse across flavor transition
- Why unresolved: Requires reload/update handler to confirm cache reuse across flavor changes
- Suggested follow-up: Trace `get_updated_router()` and router reload flow to confirm cache persistence and invalidation policy

### PH-04 (Loop3): traditional_compatible drops expression-only routes
- Why unresolved: Depends on `transform.get_expression` behavior for expression-only routes
- Suggested follow-up: Inspect `kong/router/transform.lua` and compat behavior for expression-only definitions

### PH-05 (Loop3): Header predicate cache key inclusion across flavors
- Why unresolved: Requires `fields:get_cache_key` and reload flow details
- Suggested follow-up: Inspect `kong/router/fields.lua` and cache key composition for expressions flavor

### PH-01 (Round1): HTTP/2 normalization mismatch vs Lua normalize
- Why unresolved: Requires OpenResty/Nginx HTTP/2 `:path` normalization details
- Suggested follow-up: Trace OpenResty HTTP/2 handling or test `ngx.var.request_uri` under h2c/ALPN

### PH-07 (Round1): HTTP/2 h2c vs ALPN limits divergence
- Why unresolved: Requires OpenResty/Nginx http2 config limits
- Suggested follow-up: Inspect Nginx/OpenResty http2 settings and h2c upgrade behavior

### PH-07 (Loop2): Router flavor change enables route mismatch bypass
- Why unresolved: Requires cache/reload flow plus flavor behavior comparison
- Suggested follow-up: Correlate reload path with cache reuse and matching differences across flavors

## Coverage Summary
| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|------------|:-:|:-:|:-:|
| `kong/runloop/handler.lua:1211-1225` | PH-01 | PH-07 | PH-301 |
| `kong/router/traditional.lua:1755-1788` | PH-01 | PH-01 | PH-301 |
| `kong/router/atc.lua:443-507` | PH-01 | PH-01 | PH-301 |
| `kong/router/utils.lua:57-64` | PH-01 | PH-01 | PH-301 |
| `kong/runloop/handler.lua:1357-1365` | PH-02 | PH-08 | PH-307 |
| `kong/clustering/control_plane.lua:191-236` | PH-05 | PH-04 | PH-304 |
| `kong/clustering/data_plane.lua:200-257` | PH-05 | PH-04 | PH-304 |
| `kong/clustering/rpc/manager.lua:507-562` | PH-06 | PH-04 | PH-304 |
| `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` | PH-03 | PH-02 | PH-302 |
| `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` | PH-04 | PH-03 | PH-303 |
| `kong/plugins/jwt/handler.lua:154-250` | PH-09/PH-04/PH-05 | PH-03 | PH-302 |
| `kong/plugins/oauth2/access.lua:209-221` | PH-08/PH-01 | PH-01 | PH-302 |
| `kong/plugins/oauth2/access.lua:533-812` | PH-08/PH-02/PH-03 | PH-02 | PH-302 |
| `kong/resty/dns/client.lua:742-883` | PH-06 | PH-05 | PH-305 |
| `kong/templates/nginx_kong.lua:97-519` | PH-07 | PH-06 | PH-306 |
