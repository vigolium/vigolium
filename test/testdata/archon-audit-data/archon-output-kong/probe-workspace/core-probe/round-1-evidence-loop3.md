# Evidence — kong/router

## [HARVESTER] PH-01 (Round1): Stale positive cache survives router flavor switch

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/init.lua:40-63` — `_M.new()` selects router flavor and passes `cache`, `cache_neg`, and `old_router` into the expressions/compat constructor.
2. `kong/router/expressions.lua:73-75` → `kong/router/atc.lua:293-319` — `atc.new()` uses `old_router` for incremental rebuild and sets `router.cache`/`router.cache_neg` from the provided parameters (no clearing).
3. `kong/router/atc.lua:443-487` — `exec()` computes `cache_key` and returns cached `match_t` on hit without re-matching (sink).

**Sanitizers on path**:
- None observed in this path.

**Verdict rationale**: The expressions/compat router can be rebuilt in-place with `old_router`, and `exec()` will return cached matches before re-evaluating routes. However, this code alone does not confirm whether the caller reuses the same cache across a flavor change; that behavior is outside these files.

**Deepening note** (NEEDS-DEEPER only): Confirm in the reload handler (`get_updated_router()` or equivalent) whether `cache`/`cache_neg` from the prior router are passed into `_M.new()` when `router_flavor` changes.

---

## [HARVESTER] PH-02 (Round1): Negative cache masks new protected route after flavor change

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/init.lua:40-63` — `_M.new()` passes `cache`/`cache_neg` and `old_router` into expressions/compat router constructor.
2. `kong/router/atc.lua:293-319` — `atc.new()` sets `router.cache_neg` from the provided parameter (no clearing).
3. `kong/router/atc.lua:466-484` — `exec()` returns early when `cache_neg` has a key (sink).

**Sanitizers on path**:
- None observed in this path.

**Verdict rationale**: `exec()` short-circuits on a negative-cache hit, which would suppress re-evaluation. Whether those negative entries survive a flavor transition depends on whether the caller reuses `cache_neg` across the rebuild.

**Deepening note** (NEEDS-DEEPER only): Verify whether `cache_neg` is reused across reloads/flavor changes by the caller (runloop handler) or is recreated per rebuild.

---

## [HARVESTER] PH-03 (Round1): Protocol constraints bypassed due to cache key lacking scheme

**Verdict**: VALIDATED

**Code path**:
1. `kong/router/expressions.lua:30-55` — `get_expression()` injects `net.protocol` constraints into expressions for routes with multiple protocols.
2. `kong/router/atc.lua:443-463` — `exec()` computes `cache_key` using only `uri` and `host` set in `CACHE_PARAMS` (no scheme set yet).
3. `kong/router/atc.lua:466-487` — cache hit returns `match_t` without re-matching; scheme is only added *after* miss at line 473 (sink).

**Sanitizers on path**:
- None observed in this path.

**Verdict rationale**: The expressions router adds protocol predicates, but the cache key in `exec()` is computed before `scheme` is populated, so cached matches are reused across schemes for the same `uri`/`host`.

---

## [HARVESTER] PH-04 (Round1): traditional_compatible drops expression-only routes

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/compat.lua:12-21` — `get_exp_and_priority()` logs when `route.expression` exists, then calls `transform.get_expression(route)` and returns whatever it produces.
2. `kong/router/atc.lua:136-153` — `add_atc_matcher()` rejects `nil` expressions and returns an error.
3. `kong/router/atc.lua:182-192` — on error, `new_from_scratch()` logs and removes the route from `routes_t`/`services_t` (sink: route omitted from router).

**Sanitizers on path**:
- None observed in this path.

**Verdict rationale**: The compat flavor will drop a route if `transform.get_expression(route)` returns `nil`, but the behavior of `transform.get_expression` for expression-only routes is outside these files.

**Deepening note** (NEEDS-DEEPER only): Inspect `kong/router/transform.lua:get_expression()` to confirm whether expression-only routes return `nil` under `traditional_compatible`.

---

## [HARVESTER] PH-05 (Round1): Header-based routing cache-key collision across flavor transition

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/traditional.lua:1575-1614` — `headers_key` only includes headers present in `plain_indexes.headers` (traditional header match set).
2. `kong/router/traditional.lua:1618-1622` — cache key uses `headers_key` and omits non-traditional header predicates (sink for traditional cache composition).
3. `kong/router/atc.lua:459-463` — expressions/compat cache key built via `fields:get_cache_key(CACHE_PARAMS)` using only `uri`/`host` populated here.

**Sanitizers on path**:
- None observed in this path.

**Verdict rationale**: Traditional cache keys only include headers that are indexed for traditional matching, while expressions/compat cache key composition is delegated to `fields:get_cache_key`. This file set does not show whether expressions cache keys incorporate header predicates or how cache reuse is handled across flavor transitions.

**Deepening note** (NEEDS-DEEPER only): Inspect `kong/router/fields.lua:get_cache_key()` and the reload handler to verify header predicate inclusion and cache reuse across flavors.

---

## [HARVESTER] PH-01 (Round2): Stale cache survives incremental rebuild after reload

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/atc.lua:209-289` — `new_from_previous()` incrementally updates matchers in-place without clearing any caches.
2. `kong/router/atc.lua:293-319` — `atc.new()` assigns `router.cache`/`router.cache_neg` from parameters (no invalidation).
3. `kong/router/atc.lua:466-487` — `exec()` returns cached matches before re-evaluating routes (sink).

**Sanitizers on path**:
- None observed in this path.

**Verdict rationale**: Incremental rebuild mutates route matchers without cache invalidation, but whether the old cache is reused across reload depends on the caller passing previous caches into `atc.new()`.

**Deepening note** (NEEDS-DEEPER only): Confirm via the reload/update path whether `cache`/`cache_neg` are reused when rebuilding the router.

---

## [HARVESTER] PH-02 (Round2): Router flavor transition reuses incompatible caches

**Verdict**: NEEDS-DEEPER

**Code path**:
1. `kong/router/init.lua:40-63` — `_M.new()` chooses router flavor and passes `cache`, `cache_neg`, `old_router` into expressions/compat router.
2. `kong/router/expressions.lua:73-75` → `kong/router/atc.lua:293-319` — `atc.new()` uses `old_router` for incremental rebuild and assigns caches from provided params.
3. `kong/router/atc.lua:466-487` — `exec()` uses cache entries before re-matching (sink).

**Sanitizers on path**:
- None observed in this path.

**Verdict rationale**: The flavor switch path does not include any explicit cache invalidation in these files, but confirming whether caches actually persist across flavor changes requires the caller’s reload logic.

**Deepening note** (NEEDS-DEEPER only): Check the router reload handler for whether caches and old_router are reused across flavor changes.

---
