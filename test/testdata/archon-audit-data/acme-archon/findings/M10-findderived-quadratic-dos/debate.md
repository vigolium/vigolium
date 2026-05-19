# Review Chamber: chamber-synth-02

Cluster: Spec Ingestion, $ref Resolution, SSRF, Parser DoS, Schema-Model Traversal
DFD Slices: loadAndBundleSpec / OpenAPIParser / standalone spec-url / demo CORS proxy
NNN Range: p10-020 through p10-039
Started: 2026-05-19T00:00:00Z
Status: ACTIVE

Methodology: ~/.config/archon-audit/skills/audit/SKILL.md Phase 10
KB: archon/attack-surface/knowledge-base-report.md
Registry: archon/attack-pattern-registry.json (Chamber 1 already registered PATT-001..006)
Cross-service edges: N/A (single-service project; skip cross-service taint reasoning)

---

## [PRE-SEEDED] Deep-Probe Hypotheses (DO NOT regenerate — chain or extend)

Source files:
- archon/probe-workspace/spec-ingest-parser/probe-summary.md
- archon/probe-workspace/options-standalone-theme/probe-summary.md
- archon/probe-workspace/url-security-search/probe-summary.md

### PH-01 — SSRF via unrestricted `$ref` fetch [HIGH]
- Location: `src/utils/loadAndBundleSpec.ts:22-24`
- Root cause: `customFetch = global.fetch` is wired with NO scheme allow-list and NO host allow-list. Any URL appearing in a `$ref` is fetched by the browser (or Node, in build-time/SSR usage) of whoever is rendering the spec.
- Attacker control: full URL string inside any `$ref` in attacker-supplied or attacker-influenced spec.
- Guard analysis: Browser CORS is the SOLE guard. Same-origin internal corporate endpoints and CORS-open endpoints are reachable. In a Node/SSR consumer, no guard at all.
- Action for Tracer: re-verify file:line for the current HEAD, confirm `customFetch` default, confirm no URL normalization or allow-list added since probe.

### PH-03a — DoS via allOf breadth (depth-only guard bypass) [HIGH]
- Location: `src/services/OpenAPIParser.ts:169-226` (`mergeAllOf` / `deref` interaction)
- Root cause: `MAX_DEREF_DEPTH=999` bounds recursion DEPTH but not the COUNT of allOf elements iterated per level. A spec with one allOf containing 10,000 inline schemas at depth 1 walks 10,000 merges with no guard.
- Action for Tracer: confirm the loop in `mergeAllOf` has no `length` cap; confirm there is no separate "total merge ops" counter.

### PH-04 — `hoistOneOfs` exponential schema multiplication [HIGH]
- Location: `src/services/OpenAPIParser.ts:360-387` (`hoistOneOfs`)
- Root cause: M oneOf variants nested at depth D produce M^D total expanded schemas; recursive `mergeAllOf` is invoked on each.
- Action for Tracer: confirm there is no memoization or fan-out cap; estimate worst-case for M=10, D=6 (1M expansions).

### PH-05 — `x-refsStack` injection [MEDIUM]
- Location: `src/services/OpenAPIParser.ts:93-94`
- Root cause: `obj?.['x-refsStack']` is read from attacker-controlled input. A spec with `x-refsStack: [998 strings]` pre-exhausts the dedup budget, causing legitimate subsequent `$ref`s to be flagged circular and skipped → silent rendering corruption.
- Severity floor: MEDIUM (integrity, not confidentiality/availability).

### PH-06 — `byRef()` returns `{}` for bad `$ref` [LOW-MEDIUM]
- Location: `src/services/OpenAPIParser.ts:67`
- Root cause: Unresolvable `$ref` silently yields `{}` (an "accepts anything" schema) instead of throwing/warning. Allows silent schema substitution.
- Likely verdict trajectory: DROP at LOW unless paired with a downstream sink that trusts the substituted schema for security decisions.

### PH-07 — `decodeURIComponent` before pointer resolution [MEDIUM]
- Location: `src/services/OpenAPIParser.ts:61`
- Root cause: `decodeURIComponent` runs on each pointer token, so `%2F` decodes to `/` BEFORE split on `/`, allowing cross-section traversal. `$ref:"#/info%2Fdescription"` resolves to `spec.info.description` (a string), which is then handed to schema code expecting an object.
- Impact: cross-section traversal → type confusion in downstream consumers; possibly XSS amplification if a string field is rendered as a schema example.

### PH-09 — `findDerived()` O(discriminator × schema_count) DoS [MEDIUM-HIGH]
- Location: `src/services/OpenAPIParser.ts:343-358`
- Root cause: For each discriminator value, `findDerived` does a full scan over ALL schemas with deref calls; no memoization. Combined with PH-03/PH-04 this multiplies the blow-up.

### PH-08 (renumbered from probe options/standalone) — `<acme spec-url="…">` triggers unauthenticated browser fetch [HIGH]
- Location: `src/standalone.tsx:107`
- Root cause: Web-component attribute `spec-url` is read and passed directly to `loadAndBundleSpec(specUrl)`. No scheme check, no origin check, no allow-list, no integrity check. In CMS embed scenarios where an editor controls the attribute but cannot control script, this is the SSRF entry point.
- Pairs with PH-01 (same sink).

### PH-10 — demo `?url=` proxied via `cors.acme.ly` [MEDIUM]
- Location: `demo/index.tsx:30`
- Root cause: `url` query param is prefixed with `https://cors.acme.ly/` and used as `proxiedUrl`. `cors.acme.ly` is a public CORS-proxy operated by the project; the proxy host (not the visitor's browser) makes the request, so RFC1918 / link-local / cloud-metadata endpoints reachable from `cors.acme.ly`'s network are exposed. This is a server-side SSRF against the project's own infrastructure plus an open-redirect-ish UX.
- Scope question: is `cors.acme.ly` in-scope for THIS repo's findings? It's referenced from this codebase, so yes — at least report the demo-side coupling.

### Pre-existing draft pointers in this cluster
- `archon/findings-draft/p2-051-overrides-not-propagated-to-consumers.md` — npm override scope. This is supply-chain; HAND OFF to Chamber 3, not in scope here.

---

## Round 1 -- Ideation

### [SYNTHESIZER] Brief for Ideator (attack-designer / ideator-02) -- 2026-05-19T00:00:00Z

**Hard cap**: 7 net-new hypotheses (H-01..H-07). The 10 PH-* above are PRE-SEEDED — do NOT regenerate them, but you MAY chain new attacks that compose with them.

**Do NOT generate**:
- Any restatement of PH-01..PH-10 above.
- Any supply-chain / dependency / npm-override / lockfile concern → that's Chamber 3.
- Same-origin XSS-via-spec-content unless it's a net-new sink not enumerated by Chamber 1.

**DO focus on**:

1. **Net-new SSRF surfaces beyond `$ref` and `spec-url`**:
   - `info.x-logo.url` / `logo.url` — does anything load this through `<img src>` or pre-fetch it? Confirm vs. just rendering an `<img>` tag (the latter is browser-driven and limited).
   - `openIdConnectUrl` (security scheme) — is the OIDC discovery document ever fetched by Acme itself?
   - `externalDocs.url`, `servers[].url`, `example.externalValue` — does the parser or renderer dereference any of these?
   - Schema `example` files loaded via `$ref` to non-JSON (e.g., `.txt`, `.bin`) — does customFetch handle non-JSON?

2. **Net-new DoS amplification (beyond allOf/oneOf/findDerived)**:
   - Search worker indexing of a giant spec (10k operations × 10k schema nodes) — single-threaded freeze of UI worker.
   - Menu builder traversal cost per operation (group/tag/operation tree).
   - React reconciler with 10k expanded operation/schema UI nodes — virtualization gaps.
   - `patternProperties` with attacker-supplied regex → ReDoS during validation/highlight.

3. **Combination attacks**:
   - SSRF + parser-DoS: malicious `$ref` URL returns a DoS payload spec; the fetch succeeds and tips the parser over.
   - SSRF + cycle: `$ref` URL serves a spec that itself $refs back to the original URL → infinite remote fetch loop (does customFetch dedupe by URL?).

4. **Parser differentials**:
   - YAML vs JSON: does Acme parse YAML? If so, does the YAML loader strip `__proto__` / `constructor` / `prototype` keys before they reach `mergeObjects`? Chamber 1 noted mergeObjects filters these — but parser-differential may re-introduce them post-filter.
   - YAML anchors / aliases that expand to billion-laughs-style blowup (`&a [&a, &a, ...]`).

5. **Cycle-detection gaps in less-common combinators**:
   - `not`, `dependentSchemas`, `if/then/else`, `patternProperties`, `propertyNames`, `unevaluatedProperties`, `contentSchema` (OpenAPI 3.1).
   - These were enumerated as JSON Schema 2020-12 — does Acme's deref walk them with the same x-refsStack guard, or skip the guard?

6. **Header / response injection**:
   - Spec-derived strings flowing into HTTP request headers (unlikely client-side, but check `securitySchemes` and any "Try it out" code generator).

7. **`$ref` URL normalization inconsistency**:
   - Fragment + query string + hash composition: `$ref: "https://evil/spec.yaml?x=1#/components/X"` — is the URL used for fetch identical to the URL used for cache key / dedup? If not, cache poisoning or fetch-loop bypass.

8. **OpenAPI 3.1 surface**:
   - `webhooks` field — same parsing pipeline as `paths`? If so, all the above bugs apply to webhooks. If a separate pipeline, may be MORE permissive.
   - `jsonSchemaDialect` — if the spec sets this to an attacker URL, does Acme fetch it?

9. **Spec recompilation race / stale-state**:
   - Switching `spec-url` at runtime via React state — is the old async parse cancelled? If not, a slow malicious spec keeps running while a benign one renders, then overwrites the benign state.

**Output format** to debate.md under `## Round 1 -- Ideation`:

```
### H-NN — <one-line title> [SEV-FLOOR]
- Hypothesis: <one-paragraph attack scenario>
- Attacker control: <what the attacker controls>
- Sink: <file:line of the dangerous operation>
- Source-to-sink sketch: <best-guess flow, Tracer will verify>
- Why net-new: <how it differs from PH-01..PH-10 and Chamber 1 findings>
- Severity floor: MEDIUM | HIGH | CRITICAL  (anything LOW is dropped; do not file)
```

Stop when you reach H-07 or run out of plausible net-new attacks. Quality over quantity — five solid hypotheses beat seven thin ones.

---

(Round 2 / Round 3 / Round 4 sections will be appended as the debate progresses.)

### [IDEATOR-02] Round 1 Ideation -- 2026-05-19

### H-01 — SSRF via `examples[].externalValue` unguarded fetch [HIGH]
- Hypothesis: When a spec contains `examples[X].externalValue: "http://169.254.169.254/latest/meta-data/iam/..."`, Acme constructs `ExampleModel.externalValueUrl = new URL(externalValue, parser.specUrl).href` (`src/services/models/Example.ts:24`) and, the first time the `<Example>` component renders that example, calls bare `fetch(this.externalValueUrl)` (`src/services/models/Example.ts:41`). There is NO scheme allow-list, NO host allow-list, and NO reuse of `customFetch` from `loadAndBundleSpec` (different fetch path entirely — `@acmely/openapi-core` is never consulted). The response body is then `res.text()`-decoded and either parsed JSON or rendered as text into the page — so this is not just blind SSRF, it leaks the response back into the DOM (read-out SSRF) bounded only by browser CORS.
- Attacker control: full `externalValue` URL string in any `OpenAPIExample` node anywhere in the spec.
- Sink: `src/services/models/Example.ts:41` (`fetch(this.externalValueUrl)`).
- Source-to-sink sketch: spec `examples.foo.externalValue` → `ExampleModel` constructor (`Example.ts:23-25`) → user expands the relevant operation → `Example.tsx:13` branches into `<ExternalExample>` → `useExternalExample` calls `getExternalValue()` → `Example.ts:41` `fetch`.
- Why net-new: PH-01/PH-08 cover `$ref` and `spec-url` SSRF through `loadAndBundleSpec`'s `customFetch`. This sink is in a completely different module, never touches `customFetch`, ships in EVERY Acme build (no opt-in), and its response is rendered to the DOM rather than only used as a schema fragment — i.e., directly exfiltratable via timing OR via the rendered body when CORS permits.
- Severity floor: HIGH

### H-02 — XSS via `javascript:` scheme in `info.contact.url` / `x-logo.href` (and any `externalDocs.url`) [HIGH]
- Hypothesis: `ApiLogo` builds `logoHref = logoInfo.href || (info.contact && info.contact.url)` (`src/components/ApiLogo/ApiLogo.tsx:15`) and passes it unfiltered to `<Link href={url}>` via `LinkWrap` (`src/components/ApiLogo/styled.elements.tsx:21`). A spec setting `info.contact.url: "javascript:alert(document.domain)"` (or `info["x-logo"].href: "javascript:..."`) yields an `<a href="javascript:...">` rendered in the page header. Activation requires one user click on the logo — minimal interaction, very plausible for embed scenarios where the spec author is untrusted but renders inside a trusted origin (e.g., docs portals embedding third-party API specs).
- Attacker control: spec strings `info.contact.url`, `info.x-logo.href`. Verify also `externalDocs.url` (rendered as a link in many components), `server.url`, `license.url`, security scheme `tokenUrl`/`authorizationUrl`.
- Sink: `src/components/ApiLogo/styled.elements.tsx:21` (`<Link href={url}>`).
- Source-to-sink sketch: spec → `OpenAPIInfo.contact.url` → `ApiLogo.render()` → `LinkWrap(logoHref)` → DOM `<a href="...">`.
- Why net-new: Chamber 1 covered markdown-XSS sinks; this is a different attribute path (React component `href` prop, no markdown pipeline involved). React does NOT block `javascript:` in `href` (only logs a dev-mode warning); production builds happily render it. Need Tracer to confirm whether Acme adds a custom URL sanitizer at the `<Link>` styled component layer.
- Severity floor: HIGH

### H-03 — `mergeObjects` prototype-pollution via `constructor.prototype` (filter bypass) [HIGH]
- Hypothesis: `mergeObjects` at `src/utils/helpers.ts:95` filters only the literal key `__proto__` but allows the key `constructor`. A source object `{"constructor": {"prototype": {"polluted": "yes"}}}` recurses into `target.constructor` (which is `Object`) and merges `prototype` onto it, polluting `Object.prototype.polluted`. The function is called from `AcmeNormalizedOptions.ts:297` over `raw.theme` (`mergeObjects({} as any, defaultTheme, { ...raw.theme, ... })`), so any consumer that passes user-controlled theme JSON (e.g., a CMS that lets editors paste a theme blob, or `<acme theme="...">` web-component attribute) triggers global prototype pollution at app start.
- Attacker control: `theme` option object — set as web-component attribute, query param in demo, or programmatic `init({theme: ...})`.
- Sink: `src/utils/helpers.ts:95-103` recursion into `target.constructor.prototype`.
- Source-to-sink sketch: `raw.theme.constructor.prototype.X = Y` → `AcmeNormalizedOptions.ts:297` → `mergeObjects` → `Object.prototype.X = Y` (global).
- Why net-new: existing test (`helpers.test.ts:74`) only covers literal `__proto__`. The well-known `constructor.prototype` bypass is NOT in the filter. Chain with any downstream code that does `if (obj.polluted)` to escalate to logic confusion (e.g., MobX/React internals checking arbitrary keys).
- Severity floor: HIGH

### H-04 — Spec-recompile race: stale `externalExamplesCache` cross-spec poisoning [MEDIUM]
- Hypothesis: `externalExamplesCache` at `src/services/models/Example.ts:5` is a **module-level** `{ [url: string]: Promise<any> }` keyed only by URL string. When a Acme page programmatically swaps `spec` / `spec-url` (supported via standalone `<acme>` attribute changes, or `init()` re-invocation), the cache survives the unmount because it lives outside any component/store. A first spec from `attacker.com` can prime `externalExamplesCache["https://internal/api"] = Promise.resolve({malicious: payload})`, and a subsequent legitimate spec that references the same URL receives the poisoned cached payload instead of fetching it. Combined with H-01, this turns transient SSRF into a persistent (within-tab) data-tampering primitive.
- Attacker control: first-loaded spec containing `examples[X].externalValue: "<URL the victim spec will use>"`.
- Sink: `src/services/models/Example.ts:37-38` cache hit returns attacker-prepared Promise.
- Source-to-sink sketch: attacker spec loaded → cache populated → user navigates to legitimate spec in same tab (e.g., docs portal with spec dropdown) → cache returns poisoned value → renders attacker-controlled "example".
- Why net-new: PH-03/04/05 are parser-internal; PH-10 is server-proxy. This is a cross-spec stateful primitive enabled by missing cache invalidation on spec switch.
- Severity floor: MEDIUM

### H-05 — Search worker index DoS: O(N) indexItems recursion has no node cap, plus unbounded `done()`-time index build [MEDIUM-HIGH]
- Hypothesis: `SearchStore.indexItems` (`src/services/SearchStore.ts:25-37`) walks the entire menu tree with naive recursion and pushes every node's `name + description + path` into the worker; `searchWorker.done()` then triggers the lunr-style index build (O(n log n) tokens). A malicious spec with 50k synthetic operations (cheap to author with `paths: {"/p0": {...}, ..., "/p49999": {...}}` or via `$ref` fan-out from PH-04 hoistOneOfs) freezes the worker thread for tens of seconds during which Search UI is unresponsive. The recursion in `indexItems` is also non-tail and can blow the JS stack at deep menu depth (deeply-nested tag groups produced by attacker-crafted `x-tagGroups`).
- Attacker control: spec `paths`/`webhooks` count and `x-tagGroups` nesting depth.
- Sink: `src/services/SearchStore.ts:36` (`searchWorker.done()`) and the recursive call at line 31.
- Source-to-sink sketch: huge spec → `MenuBuilder` produces giant tree → `MenuStore` calls `searchStore.indexItems(groups)` → recursion overflow OR `done()` blocks the worker.
- Why net-new: PH-03a/04/09 hit the parser; this is post-parse, in a separate worker. Even if the parser is hardened the menu+search build remains a second amplification stage. Tracer should confirm `MenuStore` actually calls `indexItems` synchronously and there is no item-count cap.
- Severity floor: MEDIUM-HIGH

### H-06 — Webhooks pipeline parity: every parser bug in PH-01..PH-10 reachable via `webhooks` / `x-webhooks` [MEDIUM (multiplier, not standalone)]
- Hypothesis: OpenAPI 3.1 `webhooks` (and legacy `x-webhooks`) are merged in `SpecStore.ts:33-34` and traversed by `MenuBuilder.ts:211-217` and `WebhookModel.ts:15-21` using the SAME `parser.deref` / `mergeAllOf` / `hoistOneOfs` pipeline — but they are processed as a SEPARATE root tree. Therefore PH-03a (allOf breadth), PH-04 (hoistOneOfs explosion), PH-05 (`x-refsStack` budget exhaustion), PH-07 (decoded pointer traversal) ALL re-apply with a fresh, independent budget. An attacker with a single malicious spec gets TWO concurrent DoS amplifications (one in `paths`, one in `webhooks`) plus a bypass for any future per-tree node-count caps that only count `paths`. Critically, the spread `...this.parser?.spec?.['x-webhooks']` at `SpecStore.ts:33` runs `Object.keys` on attacker input with NO size limit; combined with H-03's prototype-pollution this could surface `Object.prototype` keys as bogus webhook names.
- Attacker control: spec `webhooks` and `x-webhooks` objects.
- Sink: `src/services/SpecStore.ts:33-36`, `src/services/models/Webhook.ts:15`.
- Source-to-sink sketch: malicious spec sets both `paths` (PH-03a payload) and `webhooks` (independent PH-03a payload) → two parser DoS runs at separate roots → total cost doubled, any per-tree guard bypassed.
- Why net-new: every PH-* in this chamber is implicitly scoped to `paths`. Webhooks is a parallel root with the same vulnerabilities and likely no separate test fixture for malicious cases.
- Severity floor: MEDIUM

### H-07 — `$ref` URL fetch-vs-cache key desync via fragment / query / encoding aliases [MEDIUM]
- Hypothesis: `@acmely/openapi-core`'s `bundle` (called from `loadAndBundleSpec.ts:37`) and the in-Acme per-pointer cache in `OpenAPIParser` are likely keyed differently. The fetch layer drops the fragment per RFC 3986; the parser pointer cache likely keys on the full string. So `$ref: "https://attacker.com/spec.yaml#/A"` and `$ref: "https://attacker.com/spec.yaml?x=1#/A"` and `$ref: "https://attacker.com/spec.yaml/#/A"` (trailing slash) and `$ref: "https://Attacker.com/spec.yaml#/A"` (uppercased host) cause distinct cache entries that map to the same fetched document — a single victim spec with N such aliases triggers N independent fetches and N independent parse passes. This converts PH-01's single SSRF into a fetch-loop amplifier (N×) and combines with H-04 to defeat its cache. Also: a `$ref` whose URL serves a spec that itself `$ref`s back with a TRIVIALLY-DIFFERENT URL spelling will NOT be detected as circular → infinite remote-fetch loop until the browser tab dies.
- Attacker control: `$ref` URL string permutations in attacker-supplied spec.
- Sink: `customFetch` invocations from `@acmely/openapi-core` (called via `bundle` at `loadAndBundleSpec.ts:37`); Acme-side pointer cache in `OpenAPIParser`.
- Source-to-sink sketch: spec contains 1000 `$ref` aliases that normalize to the same URL → 1000 fetches OR fetch-loop OR cache-poisoning depending on how `bundle()` normalizes.
- Why net-new: PH-01 treats the SSRF as a single fetch. This hypothesis is about FETCH MULTIPLICATION and CIRCULAR-FETCH detection — orthogonal axes the probe didn't enumerate. Tracer should verify `bundle()`'s URL normalization (canonicalization of case, percent-encoding, trailing slash, query order) and confirm whether `customFetch` itself dedupes in-flight requests.
- Severity floor: MEDIUM

## Round 1 Ideator Complete

---

## Round 2 -- Tracing (Tracer)

CodeQL: unavailable (archon/codeql-artifacts/ not present). All tracing is manual via Grep, Glob, and direct source reading.

---

### [TRACER] Evidence for PH-01 -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/utils/loadAndBundleSpec.ts:22-24` -- `if (IS_BROWSER) { config.resolve.http.customFetch = global.fetch; }` assigns the bare browser `fetch` with no URL filtering.
2. `src/utils/loadAndBundleSpec.ts:37` -- `await bundle(bundleOpts)` passes `bundleOpts` containing the unguarded `customFetch` to `@acmely/openapi-core`'s bundler, which will call it for every external `$ref` URL in the spec.
3. `@acmely/openapi-core` (external) -- The bundler walks every `$ref` value in the parsed spec; for each absolute-URL `$ref`, it calls `config.resolve.http.customFetch(url)` — i.e., `global.fetch(url)` — with no scheme, host, or path allow-list.

Sanitizers on path:
- Browser CORS policy -- bypassable for: (a) same-origin internal endpoints (no CORS restriction), (b) any CORS-open endpoint including cloud metadata at providers that have CORS-open metadata APIs, (c) any non-HTTPS plain-HTTP internal service reachable from the browser. Not bypassable for cross-origin services that correctly enforce CORS (response not readable, but the request STILL reaches the server — blind SSRF side-channel persists even when response is unreadable).

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at HIGH. The assignment at `:22-24` is confirmed. The sole guard is browser CORS, which is not a security control for intranet targets or same-origin endpoints. In Node.js / SSR consumers (which call `loadAndBundleSpec` without the `IS_BROWSER` branch's assignment but with Node-native `fetch` or the openapi-core default resolver), there is no CORS guard at all. The probe summary is accurate. No additional sanitizers added since probe.

---

### [TRACER] Evidence for PH-03a -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/OpenAPIParser.ts:199-226` -- `const allOfSchemas = uniqByPropIncludeMissing(schema.allOf.map(...), '$ref')` iterates every element of `schema.allOf` array.
2. `src/services/OpenAPIParser.ts:202` -- `this.deref(subSchema, refsStack, true)` called for each `allOf` element.
3. `src/services/OpenAPIParser.ts:205` -- `this.mergeAllOf(resolved, subRef, subRefsStack)` called recursively for each dereffed sub-schema.
4. `src/services/OpenAPIParser.ts:393-400` -- `uniqByPropIncludeMissing`: inline sub-schemas have `$ref = undefined`, so `k = undefined`, which returns `true` unconditionally — all inline schemas pass the dedup filter.

Sanitizers on path:
- `MAX_DEREF_DEPTH=999` at `src/services/OpenAPIParser.ts:8,108` -- guards recursion DEPTH only. An `allOf` with 50,000 inline schemas at depth 1 bypasses this entirely: no recursive calls deeper than 2, but 50,000 iterations at level 1 each calling `deref` + `mergeAllOf`.
- `uniqByPropIncludeMissing` dedup -- bypassable by inline schemas (no `$ref` key). Only dedups `$ref`-bearing sub-schemas.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at HIGH. Loop at `:200` has no breadth guard (`allOf.length` check). 10,000 inline schemas × 100 properties each = 1,000,000 merge operations per single schema node. This confirms the probe finding exactly. No breadth guard has been added in the current HEAD.

---

### [TRACER] Evidence for PH-04 -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/OpenAPIParser.ts:178` -- `schema = this.hoistOneOfs(schema, refsStack)` is called at the start of every `mergeAllOf` invocation.
2. `src/services/OpenAPIParser.ts:360-387` -- `hoistOneOfs`: finds the first `allOf` element containing `oneOf`, then returns `{ oneOf: oneOf.map(part => ({ allOf: [...beforeAllOf, ...siblingValues, part, ...afterAllOf], 'x-refsStack': refsStack } )) }`.
3. The caller `mergeAllOf` at `:178` receives this new schema with a `oneOf` (no `allOf`), returns it at `:180-182` (`if (schema.allOf === undefined) return schema`). But callers that build `allOf` from sibling `oneOf` elements will themselves call `mergeAllOf` on each.
4. `src/services/models/Schema.ts` -- `initOneOf` calls `mergeAllOf` on each variant; if each variant itself contains `hoistOneOfs`-eligible sub-schemas, exponential expansion occurs.

Sanitizers on path:
- `x-circular-ref` check at `src/services/OpenAPIParser.ts:174` -- only fires if the schema was already marked circular; no fan-out cap.
- No memoization of `hoistOneOfs` results.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at HIGH. Exponential schema expansion confirmed: M oneOf variants at depth D produces M^D `allOf` schemas each passed to `mergeAllOf`. No memoization, no fan-out cap. With M=10, D=6: 1,000,000 schema merges. The probe finding is confirmed.

---

### [TRACER] Evidence for PH-05 -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/OpenAPIParser.ts:93` -- `const objRefsStack = obj?.['x-refsStack']` reads the `x-refsStack` property directly from the spec object `obj`, which is attacker-controlled spec content.
2. `src/services/OpenAPIParser.ts:94` -- `baseRefsStack = concatRefStacks(baseRefsStack, objRefsStack)` appends the attacker-supplied array to the internal cycle-detection stack via `concatRefStacks` (`:18-20`: `return stack ? base.concat(stack) : base`).
3. `src/services/OpenAPIParser.ts:108` -- `if (baseRefsStack.includes(obj.$ref) || baseRefsStack.length > MAX_DEREF_DEPTH)` -- with attacker-prefilled `x-refsStack` of 998 entries, `baseRefsStack.length` immediately exceeds 999, causing the next `$ref` resolution to produce `{ 'x-circular-ref': true }` regardless of actual cycle state.

Sanitizers on path:
- NONE. `x-refsStack` is read from the spec object without any origin validation, filtering, or type check. OpenAPI `x-*` extensions are a first-class namespace, so this field is structurally indistinguishable from any other valid extension.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at MEDIUM. Attacker places `x-refsStack: ["#/fake1", ..., "#/fake998"]` on any schema in a spec. That schema's `deref()` call sees `baseRefsStack.length = 998`; any subsequent `$ref` in that schema immediately hits the depth guard and is marked `x-circular-ref: true`, silencing that schema from rendering. The probe finding is confirmed exactly.

---

### [TRACER] Evidence for PH-06 -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/OpenAPIParser.ts:54-67` -- `byRef(ref)`: calls `JsonPointer.get(this.spec, ref)` for any `$ref` string.
2. `src/services/OpenAPIParser.ts:67` -- `return res || {}` — when `JsonPointer.get` returns `undefined` (non-existent path), `res` is `undefined`, and `undefined || {}` returns `{}`.
3. `src/services/OpenAPIParser.ts:103-105` -- `if (!resolved) throw` — `{}` is truthy, so this guard does NOT fire; processing continues with the empty schema `{}`.
4. Downstream schema consumers treat `{}` as "accepts anything" (an empty schema validates all JSON values per JSON Schema spec).

Sanitizers on path:
- `if (!resolved) throw` at `:103-105` -- bypassable because `{}` is truthy. This is the intended guard but it has a logic flaw: the `|| {}` fallback at `:67` converts the "missing" sentinel (`undefined`) into a truthy value that bypasses the guard.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at LOW-MEDIUM. The `return res || {}` at `:67` is confirmed to silently swallow unresolvable `$ref`s and produce empty schemas. As the probe notes, consequence is limited to schema confusion/misleading documentation rather than code execution. The finding stands at its probe severity.

---

### [TRACER] Evidence for PH-07 -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/OpenAPIParser.ts:61` -- `ref = decodeURIComponent(ref)` applied unconditionally to every `$ref` string before pointer resolution.
2. `$ref: "#/info%2Fdescription"` → after decode: `"#/info/description"` (two segments: `info` and `description`).
3. `src/services/OpenAPIParser.ts:63` -- `JsonPointer.get(this.spec, '#/info/description')` resolves to `spec.info.description` which is a string value (e.g., `"My API"`) — not a schema object.
4. `src/services/OpenAPIParser.ts:67` -- `return res || {}` — the string `"My API"` is truthy, so it is returned as-is.
5. `src/services/OpenAPIParser.ts:103` -- `if (!resolved)` — `"My API"` is truthy, guard not fired; string passed as a schema to `mergeAllOf()` which receives a non-object.

Sanitizers on path:
- NONE. RFC 6901 JSON Pointer requires `~1` for literal slashes; `decodeURIComponent` is applied unconditionally, breaking the pointer semantics. No validation that the decoded pointer segments form a valid schema path.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at MEDIUM. Confirmed: `%2F` in a fragment pointer decodes to `/`, creating spurious pointer segments. Attacker can point a `$ref` to any string field in the spec (`info.description`, `info.title`, `servers[0].url`, etc.) and have that string value returned as a "schema" — causing type confusion downstream in `mergeAllOf` and schema renderers.

---

### [TRACER] Evidence for PH-09 -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/OpenAPIParser.ts:343-358` -- `findDerived($refs)`: `const schemas = (this.spec.components && this.spec.components.schemas) || {}; for (const defName in schemas) { const { resolved: def } = this.deref(schemas[defName]); ... }`.
2. For every schema in `components.schemas`, `this.deref()` is called — this is O(schema_count) `deref()` calls per `findDerived` invocation.
3. `src/services/models/Schema.ts:292-294` -- `initDiscriminator` calls `parser.findDerived(...)` once per discriminator usage.
4. With 10,000 schemas in `components.schemas` and 100 discriminator usages: 1,000,000 `deref()` calls, each potentially triggering `mergeAllOf()`.

Sanitizers on path:
- No memoization of `findDerived` results.
- `MAX_DEREF_DEPTH` in each `deref()` call limits nested recursion but NOT the frequency of `findDerived` calls.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at MEDIUM-HIGH. The O(discriminator × schema_count) cost is confirmed. Combined with PH-03a and PH-04, these three DoS vectors are additive. The finding is confirmed exactly.

---

### [TRACER] Evidence for PH-08 -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/standalone.tsx:107` -- `const specUrl = element.getAttribute('spec-url')`.
2. `src/standalone.tsx:109` -- `init(specUrl, {}, element)` — no URL validation on `specUrl`.
3. `src/utils/loadAndBundleSpec.ts:15,32` -- `loadAndBundleSpec(specUrl)` → `bundleOpts['ref'] = specUrlOrObject` → `bundle(bundleOpts)` with `customFetch = global.fetch`.

Sanitizers on path:
- NONE in Acme. No scheme check, no origin check, no allow-list on the `spec-url` attribute value.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at HIGH. Confirmed at `standalone.tsx:107`. Any CMS allowing injection of HTML attributes on the `<acme>` element can set `spec-url` to an arbitrary URL, causing the visitor's browser to fetch that URL. This pairs with PH-01 (same sink, different entry point).

---

### [TRACER] Evidence for PH-10 (demo CORS proxy SSRF) -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `demo/index.tsx:30` -- `let parts = window.location.search.match(/url=([^&]+)/)` extracts `url` query parameter.
2. `demo/index.tsx:33` -- `url = decodeURIComponent(parts[1])` — no validation.
3. `demo/index.tsx:88-90` -- `proxiedUrl = cors ? 'https://cors.acme.ly/' + new URL(url, window.location.href).href : url` — unconditional URL concatenation.
4. `demo/index.tsx:124` -- `<AcmeStandalone specUrl={proxiedUrl} ...>` passes the proxied URL to Acme, which then calls `loadAndBundleSpec(proxiedUrl)` → `global.fetch(proxiedUrl)`.
5. The fetch goes to `cors.acme.ly/http://target/...` — the cors.acme.ly server makes the outbound request, constituting server-side SSRF on that service's infrastructure.

Sanitizers on path:
- `sanitize: true` is set at `demo/index.tsx:125` — but this only affects HTML sanitization in Markdown rendering, not the URL fetch behavior.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at MEDIUM. The `?url=` → cors.acme.ly flow is confirmed. This is a server-side SSRF on the cors.acme.ly proxy: any URL the proxy's network can reach (including cloud metadata endpoints, internal services) can be fetched by sending a crafted link. Importantly, `demo/index.tsx:125` shows `sanitize: true` in the demo options — so the demo itself has some XSS mitigation, but the SSRF via cors.acme.ly is independent of that flag.

---

### [TRACER] Evidence for H-01 (externalValue fetch) -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/models/Example.ts:5` -- `const externalExamplesCache: { [url: string]: Promise<any> } = {}` — module-level cache, never cleared.
2. `src/services/models/Example.ts:23-25` -- `if (example.externalValue) { this.externalValueUrl = new URL(example.externalValue, parser.specUrl).href; }` — attacker-controlled `externalValue` is resolved against `parser.specUrl` using `new URL()`. No scheme check, no host allow-list.
3. `src/services/models/Example.ts:41` -- `externalExamplesCache[this.externalValueUrl] = fetch(this.externalValueUrl).then(res => res.text().then(txt => { ... }))` — bare `fetch()` call. This is NOT through `loadAndBundleSpec`'s `customFetch`; it is a direct `fetch()` call in the model layer.
4. `[REDACTED].ts:20` -- `value.current = await example.getExternalValue(mimeType)` — the hook calls `getExternalValue()`, which triggers the fetch.
5. `src/components/PayloadSamples/Example.tsx:44` -- `return <ExampleValue value={value} mimeType={mimeType} />` — the fetched response value is rendered.
6. `[REDACTED].tsx:13-22` -- if `isJsonLike(mimeType)`: rendered via `<JsonViewer data={value} />` (JSON parsing path); else via `<SourceCodeWithCopy lang={...} source={value} />` which calls `highlight(source, lang)` → Prism.js → `dangerouslySetInnerHTML`.
7. `src/components/JsonViewer/JsonViewer.tsx:48-50` -- `dangerouslySetInnerHTML={{ __html: jsonToHTML(props.data, ...) }}` — `jsonToHTML` is used.
8. `src/utils/jsonToHtml.ts:14-22` -- `htmlEncode()` properly escapes `&`, `"`, `<`, `>` for JSON values — so JSON-path is SAFE from XSS.
9. `src/utils/highlight.ts:74-81` -- Prism.js `highlight()` returns HTML. For non-JSON MIME types (e.g., `text/plain`, `text/html`), the fetched raw text is passed to Prism which escapes it for display. Prism's output is then placed in `dangerouslySetInnerHTML` at `src/components/SourceCode/SourceCode.tsx:14`.

Sanitizers on path:
- Browser CORS policy -- same as PH-01. Blind SSRF persists even when CORS blocks the response. When CORS is open or same-origin, full response body is returned.
- `jsonToHTML` htmlEncode -- protects the JSON rendering path against XSS.
- Prism.js in the non-JSON path -- Prism escapes HTML characters in syntax highlighting, providing XSS protection for the rendered output of non-JSON content.
- No scheme allow-list on `externalValue`.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at HIGH (SSRF component), with PARTIAL XSS. The fetch at `Example.ts:41` is confirmed — bare `fetch()`, no URL filtering, no use of `customFetch`. The SSRF is read-out when CORS permits: the response body is returned via the Promise and rendered to the DOM. However, the XSS component is PARTIAL: for JSON MIME types, `jsonToHTML`'s `htmlEncode` prevents XSS; for non-JSON types, Prism.js's HTML escaping prevents direct XSS in the `SourceCode` path. The primary confirmed impact is read-out SSRF (exfiltration of reachable HTTP resources' content to the rendered page), not direct XSS. An HTML response fetched with `Content-Type: text/plain` would be displayed escaped. If `mimeType` were `text/html` and the server returned HTML with scripts, Prism would not execute it (it escapes). The attack surface is: (1) SSRF side-channel (always), (2) response content exposure to DOM (when CORS permits), (3) no XSS via the rendering pipeline unless a future change removes the Prism/jsonToHTML escaping.

Variant detection signature: `fetch(<spec-derived-externalValue-URL>)` without scheme/host allow-list, response rendered to DOM. Distinct from PH-01/PH-08 which use `customFetch` via `@acmely/openapi-core`.

---

### [TRACER] Evidence for H-02 (javascript: in ApiLogo + contact.url) -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/components/ApiLogo/ApiLogo.tsx:10` -- `const logoInfo = info['x-logo']`.
2. `src/components/ApiLogo/ApiLogo.tsx:15` -- `const logoHref = logoInfo.href || (info.contact && info.contact.url)` — `x-logo.href` takes priority; falls back to `info.contact.url`. Both are spec-controlled strings.
3. `src/components/ApiLogo/ApiLogo.tsx:23` -- `{logoHref ? LinkWrap(logoHref)(logo) : logo}`.
4. `src/components/ApiLogo/styled.elements.tsx:21` -- `export const LinkWrap = url => Component => <Link href={url}>{Component}</Link>` — `url` (attacker-controlled) placed directly in React `href` prop.
5. React renders `<a href="javascript:alert(1)">` in the DOM. React does NOT block `javascript:` URIs (only a dev-mode console warning, not a production-build guard).

Cross-reference with url-security-search probe-summary.md PH-05: that probe confirmed `x-logo.href → ApiLogo.tsx:23 → styled.elements.tsx:21` as VALID (HIGH). The Chamber 1 finding is PH-05 of url-security-search, filed as part of that cluster.

Sanitizers on path:
- NONE. No scheme check on `logoHref`. No `rel="noopener noreferrer"` on the logo link.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at HIGH. The `info.contact.url` fallback path at `ApiLogo.tsx:15` is confirmed. This is partially a DUPLICATE of url-security-search PH-05 (which covers `x-logo.href`) — but the `info.contact.url` fallback is a DISTINCT source that the url-security-search probe identified separately as PH-02 (`ApiInfo.tsx:48`). However, in `ApiLogo.tsx`, `info.contact.url` is used as the logo HREF — this is a different rendered element (the sidebar logo, not the contact URL in the API info panel). The ideator's hypothesis is confirmed for both `x-logo.href` and `info.contact.url → logo href` sinks. This is NOT a pure duplicate — the `info.contact.url → ApiLogo href` path is distinct from `info.contact.url → ApiInfo.tsx:48 href`. Both sinks are reachable from the same source field.

---

### [TRACER] Evidence for H-03 (mergeObjects constructor.prototype bypass) -- 2026-05-19T00:00:00Z

**Reachability: UNREACHABLE (operator-controlled input only)**

Code path:
1. `src/utils/helpers.ts:84-109` -- `mergeObjects`: filter at `:95` is `key !== '__proto__'` — the `constructor` key is NOT filtered.
2. `src/services/AcmeNormalizedOptions.ts:297` -- `this.theme = resolveTheme(mergeObjects({} as any, defaultTheme, { ...raw.theme, extensionsHook: undefined }))` — `raw.theme` is spread with object spread before passing to `mergeObjects`.
3. Key issue: `{ ...raw.theme, extensionsHook: undefined }` is a SPREAD operation. In JavaScript, `{ ...obj }` copies own enumerable properties but does NOT copy `constructor` as an own enumerable property (it is non-enumerable on the prototype). However, if `raw.theme` is a plain object parsed from JSON with a literal `"constructor"` key, then `{ ...raw.theme }` WILL include `"constructor"` as an own enumerable key in the spread result.
4. `mergeObjects` at `:94` checks `Object.prototype.hasOwnProperty.call(source, key)` — this IS true for a literal `"constructor"` key in a spread object.
5. At `:96-100`: `if (isMergebleObject(source[key])) { if (!target[key]) { target[key] = {}; } mergeObjects(target[key], source[key]); }`. If `source["constructor"]` is an object, and `target["constructor"]` already exists (it does: it's the `Object` constructor function), the code does `mergeObjects(target["constructor"], source["constructor"])` — i.e., recursing into `Object` itself.
6. If `source["constructor"]["prototype"]` is an object: `isMergebleObject(Object.prototype)` — Object.prototype is an object, not an array, so `isMergebleObject` returns `true`. The code would then do `mergeObjects(Object.prototype, source["constructor"]["prototype"])`, polluting `Object.prototype`.

Threat model analysis:
- The `theme` option is operator-controlled, not spec-controlled. A legitimate API spec author cannot set the `theme` option.
- EXCEPTION: `src/standalone.tsx:37` — `res[optionName] = attrName === 'theme' ? JSON.parse(optionValue) : optionValue` parses the `theme` HTML attribute as JSON. If an attacker can inject `<acme theme='{"constructor":{"prototype":{"polluted":true}}}'>`, the parsed object IS attacker-controlled theme content.
- This requires an attacker who can write HTML attributes on the `<acme>` element but cannot run scripts — a CMS scenario.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: PARTIAL at MEDIUM. The `constructor.prototype` bypass in `mergeObjects` is structurally VALID (the filter only blocks `__proto__`, not `constructor`). However, the call site (`AcmeNormalizedOptions.ts:297`) uses `{ ...raw.theme }` spread — whether the spread propagates the literal `"constructor"` key from JSON-parsed theme depends on the runtime. Empirically, a JSON-parsed `{"constructor":{"prototype":{}}}` object DOES have `"constructor"` as an own enumerable key in the spread result, making it reachable via `mergeObjects`. Threat model: reachable only if attacker controls the `theme` HTML attribute or the JS `options.theme` object — both require either CMS attribute injection (medium precondition) or operator-level trust (high precondition). Severity depends on threat model: MEDIUM if CMS attribute injection is the attack vector (realistic in multi-tenant docs portals), LOW if only operator-controlled.

---

### [TRACER] Evidence for H-04 (externalExamplesCache cross-spec poisoning) -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/models/Example.ts:5` -- `const externalExamplesCache: { [url: string]: Promise<any> } = {}` — module-level object, initialized once at module load, never reset.
2. `src/services/models/Example.ts:37-38` -- `if (this.externalValueUrl in externalExamplesCache) { return externalExamplesCache[this.externalValueUrl]; }` — cache hit returns attacker-populated Promise without re-fetching.
3. `src/services/models/Example.ts:41` -- cache miss path sets the cache entry via `fetch()`.
4. React component unmount / `AppStore.dispose()` at `src/services/AppStore.ts:93-102` -- `dispose()` terminates the search worker and unsubscribes, but never clears `externalExamplesCache` (which is module-level, not instance-level).
5. When a new `AppStore` is created (spec switch), `ExampleModel` instances are constructed for the new spec; if `this.externalValueUrl` matches a URL previously fetched by the malicious spec, the cached (potentially attacker-poisoned) Promise is returned.

Sanitizers on path:
- NONE for cache invalidation. The cache has no TTL, no version check, no spec-switch flush mechanism.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at MEDIUM. Module-level cache confirmed at `Example.ts:5`. `AppStore.dispose()` confirmed NOT to clear the cache (inspected `AppStore.ts:93-102`). The cross-spec poisoning scenario is structurally correct: first spec primes the cache, second spec gets poisoned cache hits. This upgrades H-01's SSRF to a persistent-within-tab data-tampering primitive.

---

### [TRACER] Evidence for H-05 (SearchStore.indexItems DoS) -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/AppStore.ts:78-80` -- `this.search = new SearchStore(); if (createSearchIndex) { this.search.indexItems(this.menu.items); }` — called synchronously in the `AppStore` constructor (after spec parse and menu build).
2. `src/services/SearchStore.ts:25-37` -- `indexItems(groups)`: inner `recurse` function calls itself recursively on `group.items` for every menu item. No item-count cap, no recursion-depth cap.
3. `src/services/SearchStore.ts:36` -- `this.searchWorker.done()` — triggers the lunr-style index build in the worker after ALL items have been pushed.
4. `src/services/SearchStore.ts:31` -- `recurse(group.items)` — recursive call with no depth/breadth guard. A spec with 50,000 paths produces ~50,000 `OperationModel` items in the menu tree → 50,000 `add()` calls to the search worker.

Analysis:
- The recursion in `indexItems` is unbounded in breadth/count but constrained by the menu tree depth (which is determined by `x-tagGroups` nesting depth, typically shallow).
- The main DoS is not stack overflow from recursion depth but from item COUNT: each item adds to the lunr index. With 50,000 operations, the `done()` call builds a lunr index over 50,000 documents — O(n log n) token insertion into the inverted index.
- The worker operates in a separate thread (workerize-loader), so this is NOT a main-thread freeze. However, the worker thread IS a real thread (or a Web Worker), and freezing it makes search non-functional for the duration.
- JavaScript call stack: `recurse` is called once per menu item. For a flat spec with 50,000 paths all under one tag, the recursion depth is ~3 (groups → tag → operations), so no stack overflow. For deeply nested `x-tagGroups`, stack overflow is possible.

Sanitizers on path:
- `disableSearch` option -- if set, `indexItems` is never called (`AppStore.ts:76`). Not a bypass concern; it's an operator opt-out.
- `workerize-loader` provides thread isolation -- the freeze is in the Worker thread, not the main thread.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at MEDIUM. The unbounded item-count recursion in `indexItems` is confirmed with no count cap. The DoS impact is Worker-thread freeze (search becomes non-responsive) rather than main-thread freeze (UI remains usable but search is dead). This is lower severity than a main-thread freeze but still a confirmed DoS vector. For deeply nested `x-tagGroups`, stack overflow in the main thread is possible (since `indexItems` runs in the `AppStore` constructor, which is main-thread). Severity: MEDIUM (worker DoS) to MEDIUM-HIGH (for stack-overflow path via deep `x-tagGroups`).

---

### [TRACER] Evidence for H-06 (webhooks pipeline parity) -- 2026-05-19T00:00:00Z

**Reachability: REACHABLE**

Code path:
1. `src/services/SpecStore.ts:32-36` -- `const webhookPath: Referenced<OpenAPIPath> = { ...this.parser?.spec?.['x-webhooks'], ...this.parser?.spec.webhooks }; this.webhooks = new WebhookModel(this.parser, options, webhookPath)`.
2. `src/services/models/Webhook.ts:15` -- `const { resolved: webhooks } = parser.deref<OpenAPIPath>(infoOrRef || {})` — `parser.deref()` is called on the merged webhook object, which uses the same `OpenAPIParser.deref()` / `mergeAllOf()` / `hoistOneOfs()` pipeline as paths.
3. `src/services/MenuBuilder.ts:210-212` -- `const webhooks = spec['x-webhooks'] || spec.webhooks; ... if (webhooks) { getTags(parser, webhooks, true); }` — webhooks traversal uses the same `getTags` function with the same `parser.deref()` calls.
4. `src/services/SpecStore.ts:33` -- `{ ...this.parser?.spec?.['x-webhooks'], ...this.parser?.spec.webhooks }` — `Object.keys` (implicit in spread) runs on attacker-controlled `x-webhooks` / `webhooks` objects with no size limit.

Specifically verified:
- PH-03a (allOf breadth DoS) applies to webhook schemas — same `mergeAllOf()` loop.
- PH-04 (hoistOneOfs exponential) applies — same `hoistOneOfs()` call in `mergeAllOf()`.
- PH-05 (x-refsStack injection) applies — same `deref()` reads `x-refsStack`.
- PH-07 (decodeURIComponent traversal) applies — same `byRef()` with `decodeURIComponent`.

Sanitizers on path:
- Same guards (and same bypasses) as for paths. No separate, more-restrictive processing for webhooks.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: VALID at MEDIUM (as a multiplier). All parser bugs from PH-03a, PH-04, PH-05, PH-07 are confirmed to apply to webhooks through the same parser pipeline. An attacker with a single spec can trigger both `paths`-rooted and `webhooks`-rooted DoS simultaneously with independent budgets. The `Object.prototype` pollution note from the ideator (via H-03 + spread on `x-webhooks`) is also structurally possible but requires the same preconditions as H-03.

---

### [TRACER] Evidence for H-07 ($ref URL normalization desync) -- 2026-05-19T00:00:00Z

**Reachability: NEEDS-DEEPER**

Code path:
1. `src/utils/loadAndBundleSpec.ts:37` -- `await bundle(bundleOpts)` — the `bundle()` call in `@acmely/openapi-core` is responsible for resolving and deduplicating external `$ref` URLs. The normalization behavior (case-folding of host, percent-encoding canonicalization, query-string ordering, trailing-slash handling) is implemented inside `@acmely/openapi-core`, which is an external dependency not in this repository.
2. `src/services/OpenAPIParser.ts:53-67` -- `byRef()` handles only LOCAL (fragment-only, `#/...`) refs after bundling. After `bundle()` completes, all external refs are already inlined into the bundled spec — so the Acme-side pointer cache in `OpenAPIParser` only ever sees local pointers, not remote URLs.
3. Therefore: the URL normalization question is entirely within `@acmely/openapi-core`'s bundler, not in Acme's own codebase.

What can be confirmed from THIS repo:
- There is no URL canonicalization code in `loadAndBundleSpec.ts` before passing to `bundle()`.
- `customFetch = global.fetch` is assigned at `:23` — `global.fetch` does NOT itself deduplicate in-flight requests (the Fetch API makes a new request per call).
- Whether `bundle()` deduplicates equivalent URLs (case-normalized, percent-decoded, query-canonicalized) is an `@acmely/openapi-core` implementation question.

Sanitizers on path:
- Cannot confirm or deny from this codebase alone.

CodeQL slice: none (unavailable)
On-demand query: none

**Assessment**: NEEDS-DEEPER. The fetch-multiplication hypothesis is plausible — if `bundle()` uses raw string comparison for `$ref` URL deduplication, URL aliases (`//Attacker.com/spec.yaml` vs `//attacker.com/spec.yaml`) would trigger separate fetches. However, confirming this requires auditing `@acmely/openapi-core/lib/bundle.js` or `resolve.js` (the external dependency). The circular-fetch loop component (two URL aliases that fetch each other) is also unverifiable without the external library source. This is not a VALID finding from THIS codebase alone; it is a VALID concern that requires external-library tracing.

---

## Round 2 Tracer Complete

**Summary:**

| Hypothesis | Verdict | Severity |
|---|---|---|
| PH-01 SSRF via $ref fetch | VALID | HIGH |
| PH-03a allOf breadth DoS | VALID | HIGH |
| PH-04 hoistOneOfs exponential | VALID | HIGH |
| PH-05 x-refsStack injection | VALID | MEDIUM |
| PH-06 byRef returns {} | VALID | LOW-MEDIUM |
| PH-07 decodeURIComponent traversal | VALID | MEDIUM |
| PH-09 findDerived DoS | VALID | MEDIUM-HIGH |
| PH-08 spec-url SSRF | VALID | HIGH |
| PH-10 demo cors.acme.ly SSRF | VALID | MEDIUM |
| H-01 externalValue fetch SSRF | VALID | HIGH |
| H-02 javascript: in ApiLogo | VALID | HIGH |
| H-03 mergeObjects constructor.prototype | PARTIAL | MEDIUM |
| H-04 externalExamplesCache poisoning | VALID | MEDIUM |
| H-05 SearchStore DoS | VALID | MEDIUM |
| H-06 webhooks parity | VALID | MEDIUM |
| H-07 $ref URL normalization desync | NEEDS-DEEPER | MEDIUM |

**Counts:** 14 VALID, 1 PARTIAL (treated as VALID for filing purposes), 1 NEEDS-DEEPER, 0 INVALID

**Variant drafts filed:** p10-020 through p10-028 (9 drafts)

**New patterns registered:** PATT-007, PATT-008, PATT-009

---

## Round 3 -- Adversarial Defense (Advocate)

Timestamp: 2026-05-19T00:00:00Z
Reviewer: advocate-02

### Cross-cutting framing — Spec-author trust model

No `SECURITY.md` exists in this repo (`Glob /SECURITY*` -> none) and `README.md` contains no `trusted`/`untrusted`/`threat model`/`security` strings. Acme therefore does NOT have an explicit "specs must come from a trusted source" doctrine that would convert spec-parser bugs into documented intended behavior. This collapses the strongest possible cross-cutting defense for the DoS / silent-corruption cluster — every "spec author is trusted" argument must instead be made as a deployment-pattern argument (curated internal docs), which is weaker because canonical Acme deployments include `cors.acme.ly`-backed demo and embedding scenarios where the spec URL is end-user-supplied.

### PH-01 SSRF via unrestricted `$ref` fetch
Tracer verdict: VALID (HIGH)
Advocate position: DEFENSIBLE (downward pressure on severity wording, not on verdict)
Defense argument: Browser-side fetch from a `$ref` is constrained by SOP. For cross-origin internal corporate APIs with default-deny CORS, the response is unreadable, leaving only blind SSRF (request delivery + timing/error side channel). The READ-side-channel only materialises against (a) same-origin endpoints, (b) cloud-metadata services that themselves expose CORS, or (c) misconfigured intranet CORS. "Blind SSRF from a browser" is industry-conventionally MEDIUM, not HIGH, unless concrete side-effecting GET endpoints (admin actions, port scan, DNS leak) are demonstrated. Furthermore, the realistic deployment pattern for Acme is curated internal API docs where the spec is authored by the same team that operates the docs site — meaning the percentage of deployments that ingest attacker-supplied specs is low (estimate 10-20%: Acmely demo + open-source docs portals accepting `?url=` query). Mitigating side: in Node/SSR consumers, no CORS at all — that path is correctly HIGH.
Citations: src/utils/loadAndBundleSpec.ts:22-24, src/utils/loadAndBundleSpec.ts:37; no SECURITY.md; README contains no trust statement.
Impact on severity: unchanged HIGH for SSR/Node path; document "browser path is HIGH only when (a) intranet CORS-open or (b) blind side-channel is sufficient for the deployment".
Impact on verdict: leave VALID with caveat that the SSRF severity assessment must annotate the CORS bounding.

### PH-03a allOf breadth DoS
Tracer verdict: VALID (HIGH)
Advocate position: DOWN-RANK to MEDIUM
Defense argument: Client-side parser DoS where the worst observable consequence is a tab freeze and the user refreshes. No service-impact: each visitor has their own browser instance; the docs server is unaffected. No data integrity issue. Industry norm for client-side parser DoS in a renderer that is opt-in invoked on a spec is MEDIUM. The threat model is identical to "a website renders a giant PDF and the browser freezes" — operationally low impact unless the spec is auto-loaded on a heavily trafficked page from an untrusted source.
Citations: src/services/OpenAPIParser.ts:199-226; no SECURITY.md trust statement to convert this to "intended".
Impact on severity: downgrade to MEDIUM.
Impact on verdict: unchanged VALID.

### PH-04 hoistOneOfs exponential schema multiplication
Tracer verdict: VALID (HIGH)
Advocate position: DOWN-RANK to MEDIUM
Defense argument: Same client-side DoS argument as PH-03a. M^D blowup is real but the impact ceiling is "user's tab freezes and they refresh". Multi-user availability is not affected. Severity HIGH is reserved for vectors with persistent/cross-user/server-resource impact. MEDIUM is the correct band.
Citations: src/services/OpenAPIParser.ts:360-387.
Impact on severity: downgrade to MEDIUM.
Impact on verdict: unchanged VALID.

### PH-05 x-refsStack injection
Tracer verdict: VALID (MEDIUM)
Advocate position: DEFENSIBLE (keep MEDIUM)
Defense argument: Integrity-only impact: specific $refs render as `{}` or get marked circular. The rendered docs are wrong, which is a documentation-quality bug, not a confidentiality/availability one. No mitigating doc but also no escalation path identified.
Citations: src/services/OpenAPIParser.ts:93-94, 108.
Impact on severity: unchanged MEDIUM.
Impact on verdict: unchanged VALID.

### PH-06 byRef returns `{}` for bad `$ref`
Tracer verdict: VALID (LOW-MEDIUM)
Advocate position: DOWN-RANK to LOW
Defense argument: This is robustness-in-face-of-broken-specs behavior, not a security boundary crossing. Returning `{}` for an unresolvable `$ref` means the affected portion of the documentation renders as "no constraints" — a graceful-degradation choice common in renderers. There is no downstream security decision keyed on the resolved schema in Acme itself; the schema is rendered for human consumption, not validated against. No "embedder thinks spec is OK but renderer is permissive" cross-trust scenario was demonstrated. Pure documentation-quality / UX bug at most.
Citations: src/services/OpenAPIParser.ts:67, :103-105.
Impact on severity: downgrade to LOW (consider dropping from filed findings).
Impact on verdict: unchanged VALID-but-LOW; recommend not filed unless paired with a concrete sink.

### PH-07 decodeURIComponent before pointer split
Tracer verdict: VALID (MEDIUM)
Advocate position: DEFENSIBLE (keep MEDIUM)
Defense argument: Type-confusion: a `$ref` can resolve to a string field. Downstream `mergeAllOf` will then iterate `Object.keys("My API")` which yields numeric indices for string characters — produces noisy but not exploitable rendering. No XSS amplification was demonstrated by the tracer; the "string-as-schema example" argument is speculative absent a concrete sink that renders raw schema strings as HTML. Best-case defense: this is also more accurately a spec-correctness bug than a security control failure. However, no documented intentional behavior, and the cross-section traversal primitive is real.
Citations: src/services/OpenAPIParser.ts:61.
Impact on severity: unchanged MEDIUM.
Impact on verdict: unchanged VALID with caveat that downstream sink impact must be demonstrated, not assumed.

### PH-08 `<acme spec-url="...">` triggers unauthenticated browser fetch
Tracer verdict: VALID (HIGH)
Advocate position: DOWN-RANK to MEDIUM
Defense argument: Reachability requires CMS-style scenario where an attacker can inject HTML attributes on the `<acme>` element but cannot execute scripts — this is a fairly narrow precondition. The standard documented usage pattern in `README.md` is JS-initialised (`Acme.init(specUrl, ...)`) where `specUrl` is operator-controlled. The HTML-attribute path is the standalone web-component build, primarily intended for `<script>`-driven embeds. An attacker who can write `<acme spec-url="...">` typically can also write `<script>`, in which case `spec-url` SSRF is irrelevant. The narrow scenario is CMSes that allow only a hardened HTML subset including `<acme>` but not `<script>` — a deployment pattern I cannot exhibit. Same CORS bounding as PH-01. MEDIUM more accurately reflects the deployment-precondition rarity.
Citations: src/standalone.tsx:107-109.
Impact on severity: downgrade to MEDIUM.
Impact on verdict: unchanged VALID.

### PH-09 findDerived O(discriminator × schema_count) DoS
Tracer verdict: VALID (MEDIUM-HIGH)
Advocate position: DOWN-RANK to MEDIUM
Defense argument: Same client-side parser DoS class as PH-03a/PH-04. Concrete impact is tab freeze, no service impact. Severity should match the cluster: MEDIUM.
Citations: src/services/OpenAPIParser.ts:343-358.
Impact on severity: downgrade to MEDIUM.
Impact on verdict: unchanged VALID.

### PH-10 demo `?url=` proxied via `cors.acme.ly`
Tracer verdict: VALID (MEDIUM)
Advocate position: DOWN-RANK / SCOPE-CHALLENGE
Defense argument: This is a finding against the `cors.acme.ly` *service* operated by Acmely, not against the open-source `acme` *library*. The library audit scope is the acme repo. `demo/index.tsx` is a development/demo asset and not part of the published npm package surface — `npm publish` ships `bundles/`, not `demo/`. Realistic copy-paste risk exists but Acmely likely operates cors.acme.ly with rate limits / IP allow-lists / metadata-IP blocklists; that is service-side hardening I cannot directly inspect from this repo. The remediation, if any, belongs on the cors.acme.ly service, not in this codebase. Recommend filing as OUT-OF-SCOPE or as an informational note rather than a finding against this library.
Citations: demo/index.tsx:30, 88-90, 124; package.json `files` field controls publish scope.
Impact on severity: downgrade to LOW or mark out-of-scope.
Impact on verdict: leave VALID but reclassify as informational / out-of-library-scope.

### H-01 externalValue fetch SSRF (Example.ts:41)
Tracer verdict: VALID (HIGH, partial XSS ruled out)
Advocate position: DEFENSIBLE (no good defense — keep HIGH)
Defense argument: I cannot disprove this. The defense angle worth noting: `fetch()` here uses bare global fetch instead of `customFetch`, which is WORSE than PH-01 from a defense-in-depth standpoint — even an operator who configures `customFetch` with a host allow-list at the openapi-core layer (a documented extension point) gets NO protection at Example.ts:41 because that sink never consults the custom resolver. CORS still bounds read-side-channel but the request is still issued. The strongest argument for downgrade is the same CORS bounding as PH-01, but since this is a customFetch-bypass it actually merits being at LEAST as severe as PH-01, and arguably more. No documented "examples are trusted" carve-out exists.
Citations: src/services/models/Example.ts:5, 23-25, 37-41; src/utils/loadAndBundleSpec.ts:22-24 (the customFetch hook this sink bypasses).
Impact on severity: unchanged HIGH.
Impact on verdict: unchanged VALID. Mark as "customFetch-bypass" variant in the finding writeup.

### H-02 javascript: in ApiLogo via contact.url / x-logo.href
Tracer verdict: VALID (HIGH)
Advocate position: DEFENSIBLE (potential FP-pattern-8 double-count)
Defense argument: Pattern 8 (double-count) MATCH against Chamber 1 url-security-search PH-05 (`x-logo.href → ApiLogo.tsx:23`). The tracer notes the `info.contact.url → ApiLogo` fallback is a *distinct source* — but it is the same sink and same XSS class. From a remediation standpoint, one fix (URL scheme allow-list in `LinkWrap`) closes both. Recommend filing as a single variant on the Chamber 1 finding rather than a net-new HIGH. Severity itself is correct for the class (`javascript:` XSS); no React/framework protection blocks `javascript:` in `href` (only dev-mode warning).
Citations: src/components/ApiLogo/ApiLogo.tsx:10, 15, 23; src/components/ApiLogo/styled.elements.tsx:21.
Impact on severity: unchanged HIGH.
Impact on verdict: leave VALID but mark as variant of Chamber-1 PH-05 to avoid double-counting in the final report.

### H-03 mergeObjects constructor.prototype bypass
Tracer verdict: PARTIAL (MEDIUM)
Advocate position: FLIP-TO-INVALID
Defense argument: `archon/bypass-analysis/153ec7a-mergeObjects-pollution.md` documents an empirical Node REPL test of EXACTLY this `constructor.prototype` payload against the patched code. Result: `({}).polluted === undefined` because recursion descends to `mergeObjects(target.constructor, {prototype: ...})`, then `target.constructor === Object` (a function), and `isMergebleObject` at `src/utils/helpers.ts:115-117` calls `isObject` which short-circuits on `typeof Object === 'function'` — the recursive call returns early, no assignment occurs. The patch-auditor's hands-on empirical verification of this exact payload is more authoritative than a static-trace hypothesis. FP Pattern 3 MATCH: framework/language protection (`typeof X === 'function'` rejection inside `isMergebleObject`) blocks the bypass.
Citations: archon/bypass-analysis/153ec7a-mergeObjects-pollution.md (rows 1-8 of hypothesis table, "Empirical methodology" section); src/utils/helpers.ts:115-117 (`isMergebleObject` -> `isObject` -> `typeof === 'object'` check rejects functions).
Impact on severity: N/A.
Impact on verdict: FLIP to INVALID. Do not file p10-022.

### H-04 externalExamplesCache cross-spec poisoning
Tracer verdict: VALID (MEDIUM)
Advocate position: DOWN-RANK to LOW
Defense argument: The cache crosses specs within the SAME tab — that's a single browsing context where the user already loaded an attacker spec. There is no cross-origin / cross-tab / cross-user trust boundary crossed. A user who chose to load attacker-spec-A and then victim-spec-B in the same tab has already lost — the attacker spec could have polluted MobX state, registered service workers, dropped IndexedDB entries, etc. The cache poisoning is a correctness/state-leak bug, not a security primitive crossing a trust boundary. To be MEDIUM it would need a cross-trust scenario (e.g., iframe-isolation that the cache breaches). No such scenario was demonstrated. FP Pattern 6-adjacent: closer to "stale state in a same-trust context" than a vulnerability.
Citations: src/services/models/Example.ts:5; src/services/AppStore.ts:93-102 (`dispose()` correctly tears down per-instance state but cache is module-level).
Impact on severity: downgrade to LOW.
Impact on verdict: unchanged VALID-but-LOW; recommend deprioritising filing.

### H-05 SearchStore indexItems DoS
Tracer verdict: VALID (MEDIUM-HIGH)
Advocate position: DEFENSIBLE (keep MEDIUM, downgrade upper bound)
Defense argument: Worker thread isolation is real — `workerize-loader` puts the lunr indexing off the main thread. Worker freeze means search is unresponsive, not that the page is unresponsive. The stack-overflow path requires deeply nested `x-tagGroups` which is bounded by typical spec authorship; even pathological nesting hits V8 stack limits at ~10k-15k frames, surviving most realistic abuse. The `disableSearch` option provides operator opt-out. Same client-side DoS bounding as the parser cluster.
Citations: src/services/AppStore.ts:76 (disableSearch opt-out), :78-80; src/services/SearchStore.ts:25-37.
Impact on severity: downgrade to MEDIUM (not MEDIUM-HIGH).
Impact on verdict: unchanged VALID.

### H-06 webhooks pipeline parity
Tracer verdict: VALID (MEDIUM, multiplier)
Advocate position: DEFENSIBLE (multiplier framing is correct)
Defense argument: This is a multiplier on PH-03a/04/05/07, not a standalone vulnerability. From a filing standpoint, this should be noted as scope-expansion on each of the parent findings ("also applies to webhooks pipeline") rather than a separate finding. Severity inherits from the multiplied parent. No independent defense — confirmed valid as a structural observation.
Citations: src/services/SpecStore.ts:32-36; src/services/models/Webhook.ts:15; src/services/MenuBuilder.ts:210-212.
Impact on severity: unchanged MEDIUM (as multiplier annotation).
Impact on verdict: unchanged VALID; recommend merging into PH-03a/04/05/07 finding writeups rather than filing as standalone p10-NN.

### Summary tallies

- Started Round 3 with 15 VALID + 1 PARTIAL.
- FLIP-TO-INVALID: 1 (H-03, citing patch-auditor empirical SOUND verdict).
- DOWN-RANK on severity: 7 (PH-03a, PH-04, PH-08, PH-09, PH-10, H-04, H-05) plus PH-06 to LOW.
- DEFENSIBLE-as-filed: 6 (PH-01 with CORS caveat, PH-05, PH-07, H-01, H-02 [merge with Chamber 1], H-06 [merge as multiplier]).
- UNDEFENDED (no credible defense): H-01 stands out — the customFetch-bypass dimension actively strengthens the finding above PH-01.

Net post-defense recommendation: 14 VALID (PH-06 borderline-drop), 1 INVALID (H-03), with 7 severities lowered and 2 findings (H-02, H-06) recommended for merger to avoid double-counting.
