# Review Chamber: ch1

Cluster: core gateway/auth/clustering/rpc/dns
DFD Slices: Internet->Proxy->Router/Plugins->Upstream, Admin API->DB->CP/DP Sync, CP/DP WebSocket, External Plugin RPC
NNN Range: p8-001 to p8-019
Started: 2026-03-30T00:00:00Z
Status: ACTIVE

## Pre-Seeded Hypotheses (Deep Probe)

- H-00a WebSocket upgrade lacks Origin enforcement (CSWSH)
- H-00b External plugin RPC can mutate auth context via PDK calls
- H-00c ProtoBuf RPC oversized frame DoS
- H-00d CP/DP sync config exfiltration with stolen DP cert
- H-00e DNS cache poisoning via additional records
- H-00f JWT tokens accepted from query string by default
- H-00g OAuth2 parameter source confusion via merge order
- H-00h Password grant impersonation with leaked provision key
- H-00i Cross-service refresh token reuse when global_credentials enabled
- H-00j Non-expiring JWT accepted when exp not enforced
- H-00k HS256 uses misconfigured public key as HMAC secret
- H-00l Cluster RPC node_id impersonation with stolen cert
- H-00m Expressions router cache key omits scheme

## Round 1 -- Ideation

**H-01: OAuth2 client_secret leakage via query + log plugins**
- Attack class: Vulnerability Chaining
- Cross-modes: Business Logic Abuse
- Chain: Client credentials accepted in URI → full URL logged/exported by http-log/tcp-log → attacker with access to log sink harvests client_secret → token issuance
- Preconditions: Attacker can induce a client to request /oauth2/token with query params and can read the external logging sink (compromised log endpoint or multi-tenant log access)
- Target asset: OAuth client credentials and resulting access tokens
- Entry point: `/oauth2/token` query parameters
- Sink: OAuth2 token issuance + log plugin request export to external system
- Creativity signal: Chains a spec-gap parameter source with plugin-driven data egress across the proxy→log-service trust boundary

**H-02: CP/DP version-downgrade handshake strips security config**
- Attack class: State Machine Attacks
- Cross-modes: Trust Boundary Confusion
- Chain: Attacker with stolen DP cert opens CP WebSocket → advertises older `node_version` → CP emits downgraded/compat config missing newer auth fields → DP applies weaker config → protected routes become effectively unauthenticated
- Preconditions: Stolen DP cert or compromised DP host; CP accepts compatibility mode based on `node_version`
- Target asset: Routing/auth integrity on data plane
- Entry point: CP/DP WebSocket query params and basic-info payload
- Sink: DP config apply path (compatibility transform)
- Creativity signal: Uses a legit compatibility state transition to weaken policy across the CP→DP trust boundary

**H-03: Route+plugin update race pins unauthenticated cache**
- Attack class: Race Conditions / TOCTOU
- Cross-modes: Business Logic Abuse
- Chain: Admin creates/updates route → DP receives route before auth plugin attachment → attacker floods route to populate router/plugin cache as unauth → cache persists briefly after auth attach, allowing access bypass window
- Preconditions: Admin performs multi-step config changes; router/plugin caching enabled; attacker can time high-rate requests during deploy
- Target asset: Protected upstream data via transient auth bypass
- Entry point: Internet proxy request to newly created/updated route
- Sink: Upstream proxying without auth plugin enforcement due to cached pipeline
- Creativity signal: Turns a short admin→CP→DP propagation gap into a longer-lived bypass via cache stickiness

**H-04: Upstream response cache poisoning across tenants**
- Attack class: Second-Order / Stored Attacks
- Cross-modes: Trust Boundary Confusion
- Chain: Compromised upstream returns sensitive response with cacheable headers → proxy-cache stores response under key missing auth/consumer context → different tenant requests same route and receives cached data
- Preconditions: Proxy-cache enabled; cache key excludes Authorization/consumer; attacker controls or influences upstream response
- Target asset: Confidential data from other tenants/users
- Entry point: Upstream response headers/body
- Sink: Cache store + cached response replay to other clients
- Creativity signal: Leverages low-trust upstream control to poison a shared cache boundary, not a direct request exploit

**H-05: OAuth2 auth code replay via redirect_uri normalization differential**
- Attack class: Parser / Protocol Differentials
- Cross-modes: State Machine Attacks
- Chain: Authorization request stores code without binding redirect_uri → attacker obtains code via referrer/log leakage → redeems token with a differently normalized/encoded redirect_uri that still passes allowlist but doesn’t match original → unauthorized token grant
- Preconditions: Ability to capture auth code (log/referrer/redirect chain); redirect_uri allowlist uses normalization that differs from client/original request
- Target asset: OAuth2 access tokens for victim client/user
- Entry point: `/oauth2/authorize` and `/oauth2/token`
- Sink: Token issuance in OAuth2 plugin
- Creativity signal: Combines a spec gap (missing redirect binding) with subtle URI parser differentials to widen replay viability across the client→auth-server boundary

## Round 2 -- Tracing

### [TRACER] Evidence for H-00a -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/runloop/handler.lua:1357-1365` -- In proxy access phase, reads `Upgrade` header and sets `var.upstream_connection`/`var.upstream_upgrade` for WebSocket requests.
2. `kong/templates/nginx_kong.lua:196-301` -- Nginx template forwards `Upgrade` header to upstream based on `upstream_upgrade` (no Origin check in Kong path).

Sanitizers on path:
- None in the upgrade path; no Origin allowlist or validation is applied before upgrade forwarding.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: WebSocket upgrades are accepted based solely on `Upgrade: websocket` and forwarded upstream without Origin validation, enabling CSWSH if upstream relies on cookies/session auth.

### [TRACER] Evidence for H-00b -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/runloop/plugin_servers/plugin.lua:42-140` -- Exposes PDK methods to external plugin servers via `exposed_api`, including request/response and ctx access.
2. `kong/runloop/plugin_servers/rpc/mp_rpc.lua:113-137` -- `call_pdk_method` resolves and invokes PDK methods by name received from plugin server.
3. `kong/runloop/plugin_servers/rpc/mp_rpc.lua:144-166` -- Maps `kong.client.authenticate` to StepCredential, enabling external plugins to set auth context via PDK.
4. `kong/pdk/client.lua:236-264` -- `kong.client.authenticate` sets `ngx.ctx.authenticated_consumer` and `ngx.ctx.authenticated_credential`.

Sanitizers on path:
- `kong/pdk/client.lua:251-259` -- Type checks ensure table/nil inputs, but do not restrict *which* consumer/credential may be set; bypassable by supplying arbitrary objects.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: External plugin servers can invoke `kong.client.authenticate` through the RPC bridge, directly mutating authentication context if the plugin server is compromised/malicious.

### [TRACER] Evidence for H-00c -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/runloop/plugin_servers/rpc/pb_rpc.lua:245-257` -- `read_frame` reads a 4-byte length and then calls `c:receive(msg_len)` without bounds checks.
2. `kong/runloop/plugin_servers/rpc/pb_rpc.lua:317-324` -- Decodes received frame as protobuf after reading full payload.

Sanitizers on path:
- None; no maximum frame length enforcement before `receive(msg_len)`.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: A malicious/compromised external plugin server can send oversized protobuf frames to the Unix socket, forcing large allocations or blocking reads (DoS).

### [TRACER] Evidence for H-00d -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/clustering/init.lua:65-73` -- Validates DP client cert and then accepts CP WebSocket.
2. `kong/clustering/control_plane.lua:191-200` -- Accepts DP connection using `arg_node_id`, `arg_node_version` from query parameters.
3. `kong/clustering/control_plane.lua:113-162` -- Exports full declarative config and deflates payload for sync.
4. `kong/clustering/control_plane.lua:457-488` -- Sends deflated config payload over WebSocket to connected DP.

Sanitizers on path:
- `kong/clustering/tls.lua:194-231` -- mTLS/OCSP validation of DP certificate; bypassable if DP cert is stolen/compromised.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Any party holding a valid DP certificate can connect and receive full config payloads via CP WebSocket sync.

### [TRACER] Evidence for H-00e -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/resty/dns/client.lua:1171-1182` -- `resolve` defaults `additional_section` to `true` when not provided.
2. `kong/resty/dns/client.lua:686-732` -- `parseAnswer` caches “other” records (non-requested types/names) from response into DNS cache via `cacheinsert`.

Sanitizers on path:
- None; no bailiwick/authority checks before caching non-requested records.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Additional-section records from DNS responses are cached without authority validation, enabling cache poisoning if a resolver response is malicious.

### [TRACER] Evidence for H-00f -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/plugins/jwt/schema.lua:12-17` -- Default `uri_param_names` includes `jwt`.
2. `kong/plugins/jwt/handler.lua:30-45` -- `retrieve_tokens` reads JWTs from query parameters before cookies/headers.

Sanitizers on path:
- None; query tokens are accepted by default without additional validation.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: JWTs are accepted from query parameters by default, enabling exposure in URLs/logs unless configuration is tightened.

### [TRACER] Evidence for H-00g -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/plugins/oauth2/access.lua:209-218` -- `retrieve_parameters()` merges query params with body params.
2. `kong/plugins/oauth2/access.lua:293-339` -- `/oauth2/authorize` consumes merged parameters including query values.
3. `kong/plugins/oauth2/access.lua:537-565` -- `/oauth2/token` consumes merged parameters including query values.

Sanitizers on path:
- None; no restriction to body-only parameters.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: OAuth2 parameters are accepted from query string and body, enabling parameter source confusion relative to RFC guidance.

### [TRACER] Evidence for H-00h -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/plugins/oauth2/access.lua:737-765` -- Password grant checks `provision_key` and accepts `authenticated_userid` from request parameters to issue tokens.
2. `kong/plugins/oauth2/access.lua:760-764` -- `generate_token` called with attacker-provided `authenticated_userid` after provision key check.

Sanitizers on path:
- `kong/plugins/oauth2/access.lua:739-743` -- `provision_key` check; bypassable if the key is leaked/compromised.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Password grant trusts `authenticated_userid` when `provision_key` is valid. With a leaked key, impersonation is possible.

### [TRACER] Evidence for H-00i -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/plugins/oauth2/access.lua:768-776` -- Refresh token lookup uses `select_by_refresh_token(refresh_token)`.
2. `kong/plugins/oauth2/access.lua:771-779` -- Service scoping enforced only when `global_credentials` is false.

Sanitizers on path:
- `kong/plugins/oauth2/access.lua:771-779` -- Service ID check when `global_credentials` is false; bypassable when `global_credentials=true`.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: With `global_credentials=true`, refresh tokens are not bound to a service, enabling cross-service reuse if a token is leaked.

### [TRACER] Evidence for H-00j -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/plugins/jwt/handler.lua:238-240` -- Registered claims are verified only if configured via `conf.claims_to_verify`.
2. `kong/plugins/jwt/jwt_parser.lua:415-446` -- Only `exp` and `nbf` are enforceable, and only if listed.
3. `kong/plugins/jwt/schema.lua:26-32` -- `claims_to_verify` is optional and defaults to empty.

Sanitizers on path:
- `kong/plugins/jwt/handler.lua:238-240` -- Optional claim verification; bypassable when `claims_to_verify` omits `exp`.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Expiration is not enforced unless explicitly configured; tokens without `exp` can be accepted in default configs.

### [TRACER] Evidence for H-00k -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/plugins/jwt/handler.lua:209-227` -- Chooses key material based on algorithm: HS* uses `jwt_secret.secret`, non-HS uses `jwt_secret.rsa_public_key`.
2. `kong/plugins/jwt/jwt_parser.lua:112-116` -- HS verification treats key as HMAC secret without key type validation.

Sanitizers on path:
- None; no enforcement that HS secrets are symmetric and not RSA public keys.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: If an operator misconfigures HS256 while storing an RSA public key in `secret`, the plugin will use it as an HMAC secret, enabling alg confusion-like misuse under misconfiguration.

### [TRACER] Evidence for H-00l -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/clustering/control_plane.lua:191-199` -- Accepts `arg_node_id`/`arg_node_version` from WebSocket query parameters.
2. `kong/clustering/control_plane.lua:262-274` -- Persists DP identity/status using provided `node_id`.
3. `kong/clustering/init.lua:65-73` -- Only validates client cert; no binding between cert and `node_id`.

Sanitizers on path:
- `kong/clustering/tls.lua:194-231` -- Cert validation only; does not tie certificate identity to `node_id` (bypassable if cert stolen).

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: A DP presenting a valid cert can claim an arbitrary `node_id` in the WebSocket URL; no binding between certificate identity and node ID is enforced.

### [TRACER] Evidence for H-00m -- 2026-03-30T12:00:00Z

**Reachability: REACHABLE**

Code path:
1. `kong/router/fields.lua:399-406` -- Cache key visitor explicitly ignores `net.protocol` (scheme) for expressions router cache key.
2. `kong/router/atc.lua:451-474` -- Cache key is computed before setting `CACHE_PARAMS.scheme`.
3. `kong/router/atc.lua:487-488` -- Route match is cached under scheme-agnostic key.

Sanitizers on path:
- None; scheme is intentionally excluded from cache key.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Expressions-router cache key omits scheme, so cached route matches can be reused across http/https, creating cross-scheme cache collisions.

### [TRACER] Evidence for H-01 -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/plugins/oauth2/access.lua:209-218` -- `retrieve_parameters()` merges query + body parameters, allowing `client_secret` in query.
2. `kong/plugins/oauth2/access.lua:462-494` -- `retrieve_client_credentials()` reads `client_id`/`client_secret` from merged parameters.
3. `kong/pdk/log.lua:867-906` -- `kong.log.serialize()` includes `request.url` and `request.querystring`.
4. `kong/plugins/http-log/handler.lua:191-196` -- `http-log` sends serialized request data to external log endpoint.

Sanitizers on path:
- `kong/pdk/log.lua:842-890` -- Redacts `authorization` and `proxy-authorization` headers only; querystring is not redacted, so secrets in query persist.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: OAuth2 client secrets are accepted from query parameters and included in log serialization; logging plugins can exfiltrate them when enabled.

### [TRACER] Evidence for H-02 -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/clustering/control_plane.lua:191-195` -- CP reads `node_version` from WebSocket query parameters.
2. `kong/clustering/compat/init.lua:102-146` -- Compatibility check allows older DP minor versions (same major).
3. `kong/clustering/compat/init.lua:378-409` -- `update_compatible_payload` rewrites config for older DP versions.
4. `kong/clustering/control_plane.lua:466-488` -- Sends compatible (possibly downgraded) payload to DP.

Sanitizers on path:
- `kong/clustering/compat/init.lua:38-75` -- Version compatibility restricts major version mismatch; still permits older minor versions (bypassable by declaring older minor within same major).

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: DP-controlled `node_version` drives compatibility downgrades; older minor versions are allowed, enabling reduced config fidelity when a DP presents an older version string.

### [TRACER] Evidence for H-03 -- 2026-03-30T12:00:00Z

**Reachability: UNREACHABLE**

Code path:
1. `kong/runloop/handler.lua:1210-1238` -- Router match occurs per-request; no auth decision is cached here.
2. `kong/runloop/plugins_iterator.lua:357-406` -- Plugin configs are collected per-request based on current route/service/consumer; no persistent “unauth” decision cache.
3. `kong/runloop/plugins_iterator.lua:523-587` -- Plugin iterator is rebuilt from DB config; cached route matches do not bypass plugin execution.

Sanitizers on path:
- Per-request plugin collection acts as a guard: auth plugins are evaluated every request (not cached as “unauth”).

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Router caching does not cache authentication decisions. Plugin execution remains per-request, so a stale unauthenticated cache pin (as hypothesized) is not supported by the code path.

### [TRACER] Evidence for H-04 -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/plugins/proxy-cache/handler.lua:232-286` -- Builds cache key from consumer/route/method/uri/query/headers and serves cache on hits.
2. `kong/plugins/proxy-cache/cache_key.lua:85-112` -- `consumer_id` and `route_id` are part of cache key; headers only included if `vary_headers` configured.
3. `kong/plugins/proxy-cache/handler.lua:99-106` -- Authorization header only disables caching when `cache_control=true`.

Sanitizers on path:
- `kong/plugins/proxy-cache/handler.lua:99-106` -- When `cache_control=true`, presence of `Authorization` prevents caching; bypassable if `cache_control=false`.
- `kong/plugins/proxy-cache/cache_key.lua:85-112` -- `consumer_id` partitioning mitigates cross-tenant leakage when auth sets consumer; bypassable for unauth/anonymous routes.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Cache poisoning across tenants is possible when `cache_control` is off and cache keys do not include auth context (e.g., unauthenticated/anonymous routes or missing `vary_headers`).

### [TRACER] Evidence for H-05 -- 2026-03-30T12:00:00Z

**Reachability: PARTIAL**

Code path:
1. `kong/plugins/oauth2/access.lua:391-399` -- Authorization code stored without `redirect_uri` binding.
2. `kong/plugins/oauth2/access.lua:564-579` -- Token exchange only validates `redirect_uri` against client allowlist, not against original request.
3. `kong/plugins/oauth2/access.lua:697-704` -- Successful token issuance deletes code; no redirect_uri comparison to stored value.

Sanitizers on path:
- `kong/plugins/oauth2/access.lua:663-669` -- PKCE verifier check applies when PKCE is required; bypassable when PKCE is not enforced for the client.

CodeQL slice: CodeQL: unavailable (Lua core not covered; call-graph-slices.json only fixtures)
On-demand query: none

**Assessment**: Authorization codes are not bound to the original `redirect_uri`, enabling code replay across alternate but allowlisted redirect URIs unless PKCE is enforced.
