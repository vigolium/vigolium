# Round 2 Hypotheses — router flavor transition/cache mismatch

## PH-01: Stale cache survives incremental rebuild after reload

- **Reasoning-Model**: TRIZ + Game-Theory
- **Target**: `kong/router/atc.lua:209-289` — `new_from_previous()` and `kong/router/atc.lua:443-487` — `exec()`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: (1) Send `GET /public/resource` with `Host: api.example` to prime the router cache when it matches an unauthenticated route. (2) Admin reloads and tightens route policy (e.g., `GET /public/resource` now requires auth or maps to a protected service). (3) Immediately repeat `GET /public/resource` to hit `self.cache:get(cache_key)` and reuse the stale match without re-evaluating the updated route set.
- **Tension / Game**: Performance vs correctness during reload — incremental rebuild reuses `old_router` for speed, while cache lookups happen before re-matching. Attacker optimally primes cache right before a reload and repeatedly probes to keep using the stale entry.
- **What was sacrificed / Information accumulated**: Cache invalidation on rebuild is not evident; cached `match_t` persists across configuration changes, letting the attacker rely on previously learned matches until eviction.
- **Security consequence**: Route/auth bypass window after reload (stale route selection continues to route unauthenticated requests to a service that should now be protected).
- **Severity estimate**: HIGH
- **Read needed**: `kong/router/atc.lua:209-289`, `kong/router/atc.lua:443-487`
- **Deepening direction**: Evidence-harvester should verify whether caches are reused across reload and whether `match_t` carries stale route/service objects post-update (look for cache reuse in the reload/handler layer).

---

## PH-02: Router flavor transition reuses incompatible caches (route selection mismatch)

- **Reasoning-Model**: TRIZ
- **Target**: `kong/router/init.lua:40-63` — `new()` flavor selection + `kong/router/atc.lua:293-319` — `new()`
- **Attacker starting position**: unauthenticated
- **Attack input / strategy**: (1) Before a flavor transition, send `GET /v1/data` with `Host: api.example` to create a positive/negative cache entry under the prior flavor. (2) Admin reload switches `router_flavor` (e.g., traditional → expressions/compat). (3) Send the same `GET /v1/data` (or a different method on the same path) to force a cache hit that was computed under the old flavor’s matching/normalization rules.
- **Tension / Game**: Compatibility (support multiple router flavors + incremental rebuild) vs cache coherence. The constructor passes `old_router` into the expressions/compat router and reuses caches without guarding flavor mismatch, potentially carrying stale matches across flavor boundaries.
- **What was sacrificed / Information accumulated**: Consistent normalization/selection semantics across flavors during reload; attacker capitalizes on cache entries learned under a previous flavor to influence routing after the transition.
- **Security consequence**: Route mismatch after reload (misrouting to a less protected service or incorrect 404s), enabling targeted bypass or selective denial of protected endpoints during the transition window.
- **Severity estimate**: MEDIUM
- **Read needed**: `kong/router/init.lua:40-63`, `kong/router/atc.lua:293-319`
- **Deepening direction**: Verify whether `old_router` can be passed across flavor changes and whether `cache`/`cache_neg` are reused without clearing; confirm cache key format differences between flavors.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| `kong/router/init.lua:40-63` — router flavor selection | PH-02 / YES — compatibility vs cache coherence | PH-02 / NO — no repeated interaction mechanism beyond reload timing |
| `kong/router/atc.lua:443-507` — expressions router exec/cache | PH-01 / YES — performance vs correctness | PH-01 / YES — attacker primes cache pre-reload |
| `kong/router/traditional.lua:1755-1788` — traditional exec/normalize | NO — not in scope for reload cache mismatch | NO — not used for repeated-interaction exploit here |
| `kong/router/utils.lua:57-64` — strip_uri_args normalize | NO — normalization step is shared; no distinct tension observed | NO — no interactive mechanism |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| Router flavor transition/cache mismatch during reload & normalization differences across flavors | PH-01/PH-02 / YES — tension confirmed |

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| Route match cache reuse across reload | PH-01 / YES — attacker primes cache before reload |
