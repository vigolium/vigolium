---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/services/OpenAPIParser.ts:343-357 iterates every entry of `components.schemas` and calls `this.deref(...)` on each, with no per-call cache; Schema.ts:293-296 invokes findDerived once per discriminator-bearing SchemaModel.
FP-Reasoning: `findDerived` performs a full O(N) walk of `components.schemas` (including a `deref` per entry) and is invoked once per discriminator schema build, with zero memoization on the parser instance and no shared reverse-index. With attacker-chosen N (schemas) × D (discriminator usages) growing together, the quadratic factor is real and additive with the other parser-DoS findings in this cluster.
Severity-Original: MEDIUM
Severity-Tracer: MEDIUM-HIGH
Severity-Advocate: MEDIUM
Class: Parser DoS / Algorithmic Complexity
Origin-Finding: PH-09
Origin-Pattern: PATT-008
File: src/services/OpenAPIParser.ts:343-358
Chamber: chamber-02
Source: spec with large `components.schemas` × many discriminator usages
Sink: `findDerived()` full-scan over all schemas per discriminator call, no memoization
Pre-FP-Flag: none
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: Client-side browser tab freeze only; attacker must serve crafted spec; no server-side or data-exfil impact; MEDIUM severity aligns to P2.
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Debate: archon/chamber-workspace/chamber-02/debate.md
Synthesizer-Note: Advocate aligned this with the parser-DoS cluster at MEDIUM. Client-side DoS — per-visitor tab freeze, no service impact.
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
PoC-Script: archon/findings/M10-findderived-quadratic-dos/evidence/poc.js
PoC-Notes: Node.js timing PoC. deref() call count confirmed at exactly N×D=600000 (no memoization). Scaling grows 16.6× when N×D grows 4× (quadratic confirmed). At N=20000 D=1000 Node.js shows 1.6s; browser main-thread equivalent estimated 5-16s freeze. Status=confirmed by structural proof (call count = N×D) plus super-linear timing ratio.
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
---

# `findDerived()` O(discriminator × schema_count) Full-Scan DoS — No Memoization

## Summary

`src/services/OpenAPIParser.ts:343-358` (`findDerived`) iterates EVERY schema in `components.schemas` and calls `this.deref()` on each, for EACH discriminator usage in the spec. With N schemas and D discriminator usages, this is N×D `deref()` calls — quadratic in spec size when both grow together. Combined with PH-03a (allOf breadth) and PH-04 (hoistOneOfs exponential), the three parser-DoS vectors are additive.

## Location

- `src/services/OpenAPIParser.ts:343-358` — `findDerived($refs)` body
- `src/services/models/Schema.ts:292-294` — `initDiscriminator` calls `parser.findDerived(...)` once per discriminator usage

## Attacker Control

Spec author controls both the count of schemas in `components.schemas` and the count of discriminator usages across the spec.

## Trust Boundary Crossed

Attacker spec → visitor's main-thread CPU.

## Impact

Per-visitor tab freeze. No service-side impact (each visitor's browser is independent). Combines with PH-03a/PH-04 for multiplicative DoS.

## Defense Search Results (Advocate)

- No memoization layer for `findDerived` results.
- `MAX_DEREF_DEPTH` guards individual `deref()` calls' recursion depth but not the FREQUENCY of `findDerived` invocations.
- No budget/cap on total `findDerived` calls per spec render.
- Same client-side-DoS bounding as the rest of the parser DoS cluster — operationally MEDIUM.

## Evidence

```typescript
// src/services/OpenAPIParser.ts:343-358
findDerived($refs: string[]): Dict<string[] | string> {
  const res: Dict<string[] | string> = {};
  const schemas = (this.spec.components && this.spec.components.schemas) || {};
  for (const defName in schemas) {
    const { resolved: def } = this.deref(schemas[defName]);  // <-- O(N) deref per call
    if (def.allOf !== undefined &&
        def.allOf.find(obj => obj.$ref !== undefined && $refs.indexOf(obj.$ref) > -1)) {
      res['#/components/schemas/' + defName] =
        (def['x-discriminator-value'] as string) || defName;
    }
  }
  return res;
}
```

```typescript
// src/services/models/Schema.ts:292-294
this.derived = parser.findDerived([
  ...(this.rawSchema && this.rawSchema.parentRefs) || [],
  this.pointer,
]);
```

## Reproduction Steps

1. Author a spec with 10,000 schemas in `components.schemas` and 100 schemas using `discriminator`.
2. Load the spec.
3. `findDerived` is called 100 times; each call iterates 10,000 schemas and derefs each → 1,000,000 `deref()` calls.
4. Browser main thread becomes unresponsive during schema model construction.

## Pairs With

- p10-023 (PH-03a allOf breadth) and p10-024 (PH-04 hoistOneOfs exponential): all three are additive parser-DoS vectors in `OpenAPIParser`.
- p10-027 (H-06 webhooks parity): `findDerived` is called from `WebhookModel` traversal too, doubling the budget per spec.

## Recommendation

- Cache `findDerived` results keyed by `$refs` set.
- Build a reverse-discriminator index once at parse time (`Dict<parentRef, derivedRefs[]>`) rather than re-scanning per call.
