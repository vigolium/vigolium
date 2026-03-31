# Round 1 Hypotheses — core-probe router flavor transition/cache mismatch

## PH-01: Stale positive cache survives router flavor switch, routing to old (unauthenticated) service

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/router/init.lua:40-64` — `new()` flavor selection + `old_router` handoff; `kong/router/traditional.lua:1618-1627` — cache key build and cache hit
- **Attacker starting position**: unauthenticated
- **Attack input**: HTTP/1.1 `GET /admin?x=1` with `Host: api.example.com` (no auth headers), sent repeatedly before and after a router flavor change.
- **Chain**: attacker primes `cache` with a route match under the old flavor → admin switches `router_flavor` (traditional → expressions/compat) and reloads config; old cache object persists via `old_router` handoff → new router returns cached match for the same key without re-evaluating the new flavor’s constraints → attacker reaches service that should now require auth.
- **Catastrophe / Dangerous fallback**: authenticated-only route effectively bypassed after flavor transition due to stale cache entry.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify whether `atc.new(..., old_router)` reuses `cache`/`cache_neg` from the old router and whether cache invalidation occurs on flavor change.

---

## PH-02: Negative cache entry masks new protected route after flavor change, falling through to a public catch-all

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/router/traditional.lua:1629-1633` — negative cache short-circuit; `kong/router/init.lua:40-64` — flavor selection + old_router handoff
- **Attacker starting position**: unauthenticated
- **Attack input**: HTTP/1.1 `GET /internal/reports` with `Host: api.example.com` (no auth), sent before a config reload that adds a protected route for `/internal`.
- **Chain**: attacker primes `cache_neg` for `/internal/reports` under old router state → admin enables expressions/compat flavor with a new protected route → new router reuses negative cache and returns `nil` early → request falls through to a less restrictive route (e.g., wildcard/public service) instead of the intended protected route.
- **Catastrophe / Dangerous fallback**: access to newly protected endpoints via fallback routing because the negative cache suppresses re-evaluation.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm how `get_updated_router()` handles negative cache on reload and whether a fallback route is selected when match returns nil.

---

## PH-03: Protocol-specific constraints in expressions flavor bypassed due to cache key lacking scheme

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `kong/router/expressions.lua:36-55` — protocol filter injection; `kong/router/traditional.lua:1618-1622` — cache key missing `req_scheme`
- **Attacker starting position**: unauthenticated
- **Attack input**: (1) HTTP `GET /billing` with `Host: pay.example.com` to prime cache; (2) HTTPS `GET /billing` with same host immediately after flavor switch to expressions.
- **Chain**: attacker primes cache under traditional flavor where scheme isn’t part of the key → operator switches to expressions flavor with `net.protocol` constraints per-route → HTTPS request reuses cached match from HTTP because cache key omits scheme → routing ignores the new protocol-specific constraint.
- **Catastrophe / Dangerous fallback**: HTTPS-only protected routes may be matched using cached HTTP-only decisions, exposing sensitive endpoints over unintended protocol paths.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether expressions router cache key includes scheme/protocol and whether caches are shared across flavors.

---

## PH-04: Misconfigured traditional_compatible flavor silently drops expression-only routes

- **Reasoning-Model**: Abductive
- **Target**: `kong/router/compat.lua:12-27` — `get_exp_and_priority()` logs but continues
- **Attacker starting position**: unauthenticated
- **Attack input**: HTTP/1.1 `GET /v2/admin` with `Host: api.example.com` after operator sets `router_flavor=traditional_compatible` while leaving expression-only routes defined.
- **Chain**: config mixes expression-only routes with `traditional_compatible` flavor → compat logs misconfiguration but still computes expression from traditional fields → expression-only route yields `nil`/empty expression and is omitted in router construction → attacker requests path that should be protected by that route → request routes to a broader, less restrictive route.
- **Catastrophe / Dangerous fallback**: protected expression routes silently disappear, enabling access through a permissive fallback route.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify `transform.get_expression()` behavior when traditional fields are missing and how `atc.new()` handles `nil` expressions.

---

## PH-05: Header-based routing differences across flavor transition allow cache-key collision

- **Reasoning-Model**: Pre-Mortem
- **Target**: `kong/router/traditional.lua:1575-1614` — headers_key built only from traditional header matches; `kong/router/init.lua:40-64` — flavor switch with old_router handoff
- **Attacker starting position**: unauthenticated
- **Attack input**: HTTP/1.1 `GET /payments` with `Host: api.example.com` and **no** `X-Tier: premium` header, sent before and after switch to expressions routes that match `X-Tier: premium`.
- **Chain**: attacker primes cache under traditional flavor where headers_key includes only headers used by traditional routes → operator switches to expressions flavor that uses header predicates not represented in traditional header indexes → cache key for requests with and without `X-Tier: premium` collides → cached public route used even when header should select a protected route.
- **Catastrophe / Dangerous fallback**: header-gated routes bypassed due to cache key mismatch across flavor transitions.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: inspect expressions router cache-key composition and confirm whether header predicates from expressions are included or excluded when reusing old caches.

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| `kong/runloop/handler.lua:1211-1225` — `get_updated_router():exec(ctx)` | PH-01 / PH-02 / PH-05 | NO — out of scope to read runloop details in this pass |
| `kong/router/traditional.lua:1755-1788` — `exec(ctx)` | PH-01 / PH-02 / PH-03 / PH-05 | NO — no defensive patterns here tied to flavor transition |
| `kong/router/atc.lua:443-507` — `exec(ctx)` | NO — not read; focus limited to flavor constructors | NO — not read; focus limited to flavor constructors |
| `kong/router/utils.lua:57-64` — `strip_uri_args(req_uri)` | NO — not specific to flavor transition/cache mismatch | NO — not specific to flavor transition/cache mismatch |
| `kong/runloop/handler.lua:1357-1365` — WebSocket upgrade handling | NO — out of scope (router flavor/cache mismatch) | NO — out of scope |
| `kong/clustering/control_plane.lua:191-236` — `handle_cp_websocket` | NO — out of scope | NO — out of scope |
| `kong/clustering/data_plane.lua:200-257` — `communicate()` | NO — out of scope | NO — out of scope |
| `kong/clustering/rpc/manager.lua:507-562` — `handle_websocket()` | NO — out of scope | NO — out of scope |
| `kong/runloop/plugin_servers/rpc/mp_rpc.lua:172-218` — `Rpc:call()` | NO — out of scope | NO — out of scope |
| `kong/runloop/plugin_servers/rpc/pb_rpc.lua:268-328` — `Rpc:call()` | NO — out of scope | NO — out of scope |
| `kong/plugins/jwt/handler.lua:154-250` — `do_authentication()` | NO — out of scope | NO — out of scope |
| `kong/plugins/oauth2/access.lua:209-221` — `retrieve_parameters()` | NO — out of scope | NO — out of scope |
| `kong/plugins/oauth2/access.lua:533-812` — `issue_token()` | NO — out of scope | NO — out of scope |
| `kong/resty/dns/client.lua:742-883` — DNS queries | NO — out of scope | NO — out of scope |
| `kong/templates/nginx_kong.lua:97-519` — HTTP/2 listeners | NO — out of scope | NO — out of scope |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| (No defensive patterns section present in anatomy) | NO — not applicable |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| Router normalization consistency vs HTTP/2 entry | NO — out of scope (flavor/cache mismatch focus) |
| AuthZ decision finality influenced by external plugin RPC | NO — out of scope |
| External plugin RPC framing lacks size limits | NO — out of scope |
| CP/DP sync legacy fallback path | NO — out of scope |
| DNS resolver safety depends on OpenResty version | NO — out of scope |
| HTTP/2 limit enforcement depends on OpenResty core | NO — out of scope |
