---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/services/OpenAPIParser.ts:199-219 maps allOf with no breadth cap; depth guard at :108 only counts baseRefsStack.length so inline schemas bypass it; uniqByPropIncludeMissing at :393-400 returns true for missing $ref.
FP-Reasoning: `mergeAllOf` iterates `schema.allOf` of attacker-chosen length with no size limit, MAX_DEREF_DEPTH only checks ref-stack length (not breadth), and the dedup helper waives the seen-set check whenever `$ref` is undefined — all three mechanisms confirmed in current source, so the attacker-controlled inline-schema breadth blow-up is real (client-side severity per advocate stands).
Severity-Original: MEDIUM
Severity-Tracer: HIGH
Severity-Advocate: MEDIUM
Class: Parser DoS / Algorithmic Complexity
Origin-Finding: PH-03a
Origin-Pattern: PATT-008
File: src/services/OpenAPIParser.ts:199
Chamber: chamber-02
Synthesizer-Note: Advocate downgraded HIGH → MEDIUM. Client-side parser DoS — per-visitor tab freeze, no service-side impact, no cross-user availability degradation. Industry norm for client-side renderer DoS.
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: Client-side only tab freeze via crafted spec; requires victim to load attacker spec; no server-side or cross-user impact; MEDIUM severity + moderate exploitability = P2.
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
PoC-Notes: 10 schemas x 200,000 inline allOf children = 2,000,000 unconstrained mergeAllOf iterations; measured 586ms in Node.js v25.9.0 (baseline <1ms). Depth guard (MAX_DEREF_DEPTH=999) confirmed bypassed — x-circular-ref=false throughout. uniqByPropIncludeMissing dedup also bypassed (k=undefined for all inline schemas). Browser tab freeze estimated 1-3s for same payload. PoC runner: poc_m4_runner.ts at repo root; canonical copy at evidence/poc.ts.
---

# DoS via Unbounded `allOf` Breadth in `mergeAllOf` (Depth Guard Bypass)

## Summary

`mergeAllOf` at `src/services/OpenAPIParser.ts:199-226` iterates all elements of `schema.allOf` without any breadth limit. The existing `MAX_DEREF_DEPTH=999` guard only bounds recursion depth. A spec with a single `allOf` containing 50,000 inline schemas at depth 1 bypasses the depth guard entirely and forces 50,000 merge operations with no protection.

## Attack Scenario

```yaml
components:
  schemas:
    BombSchema:
      allOf:
        - { type: string, maxLength: 1 }
        - { type: string, maxLength: 2 }
        # ... repeat 49,998 more times ...
        - { type: string, maxLength: 50000 }
```

Parsing this spec causes:
1. `mergeAllOf()` → `schema.allOf.map(...)` at `:200-219` iterates 50,000 elements.
2. For each: `this.deref(subSchema, refsStack, true)` + `this.mergeAllOf(resolved, subRef, subRefsStack)`.
3. `uniqByPropIncludeMissing` dedup at `:199`: inline schemas have `$ref = undefined`, key `k = undefined`, always passes filter — no dedup.
4. Total: ~50,000 × (deref + mergeAllOf) operations per schema node. With 10 such schemas in `components.schemas`: 500,000 operations before even rendering.

## Bypass of Depth Guard

`MAX_DEREF_DEPTH` check at `:108`: `baseRefsStack.length > 999`. Inline schemas have no `$ref` to push onto the stack; `refsStack.length` never grows. The guard cannot fire at breadth-1 depth.

## Dedup Bypass

`uniqByPropIncludeMissing` at `:393-400`: inline schemas have `item['$ref'] = undefined`, so `k = undefined`, and `if (!k) return true` — all inline schemas pass regardless of how many times they appear.

## Code Evidence

- `src/services/OpenAPIParser.ts:8` — `MAX_DEREF_DEPTH = 999`
- `src/services/OpenAPIParser.ts:108` — depth check (bypassable via inline schemas)
- `src/services/OpenAPIParser.ts:199-226` — unbounded `allOf.map()` loop
- `src/services/OpenAPIParser.ts:393-400` — `uniqByPropIncludeMissing` with inline-schema bypass
