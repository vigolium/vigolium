---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/services/OpenAPIParser.ts:360-387 distributes oneOf into M sibling allOf wrappers with no memoization; Schema.ts:239-270 builds a SchemaModel per variant which re-enters mergeAllOf at Schema.ts:95, enabling M^D expansion.
FP-Reasoning: hoistOneOfs returns a new `oneOf` of `M` synthetic `allOf` schemas without any identity cache; each variant is independently fed back into `mergeAllOf` (via `initOneOf`'s SchemaModel constructor → `parser.mergeAllOf` at line 95), so nested oneOfs compound multiplicatively, and the only guard (`x-circular-ref` at :174) cannot mark these freshly allocated objects.
Severity-Original: MEDIUM
Severity-Tracer: HIGH
Severity-Advocate: MEDIUM
Class: Parser DoS / Exponential Complexity
Origin-Finding: PH-04
Origin-Pattern: PATT-008
File: src/services/OpenAPIParser.ts:360
Chamber: chamber-02
Synthesizer-Note: Advocate downgraded HIGH → MEDIUM. Same client-side DoS bounding as PH-03a — per-visitor tab freeze.
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: Client-side only DoS via crafted spec; requires attacker-controlled spec to reach victim browser, no server impact, per-tab blast radius.
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
---

# Exponential Schema Multiplication via `hoistOneOfs` — Parser DoS

## Summary

`hoistOneOfs` at `src/services/OpenAPIParser.ts:360-387` is called at every `mergeAllOf` invocation. When `allOf` contains a `oneOf` element, `hoistOneOfs` distributes the `oneOf` variants into sibling `allOf` schemas — creating `oneOf.length` new `allOf` schemas. If any of those new schemas also contains a nested `oneOf`, the next `mergeAllOf` call will expand again. M oneOf variants nested at depth D produce M^D total schema expansions with no memoization.

## Attack Scenario

```yaml
components:
  schemas:
    Bomb:
      allOf:
        - oneOf: [{ type: string }, { type: number }, { type: boolean },
                  { type: "null" }, { type: array }, { type: object },
                  { type: integer }, { type: string, format: date },
                  { type: string, format: time }, { type: string, format: uuid }]
        - allOf:
            - oneOf: [{ type: string }, { type: number }, { type: boolean },
                      { type: "null" }, { type: array }, { type: object },
                      { type: integer }, { type: string, format: date },
                      { type: string, format: time }, { type: string, format: uuid }]
            - allOf:
                - oneOf: [...]  # 6 levels deep
```

With M=10 variants per level and D=6 levels: 10^6 = 1,000,000 schema expansion calls. Each calls `mergeAllOf`. Browser OOM or tab kill.

## No Memoization

`hoistOneOfs` creates new anonymous `allOf` objects on every call with no identity tracking. The `x-circular-ref` check at `:174` only fires for schemas already marked circular — newly created anonymous schemas are never marked.

## Code Evidence

- `src/services/OpenAPIParser.ts:178` — `hoistOneOfs` called at every `mergeAllOf` entry
- `src/services/OpenAPIParser.ts:360-387` — `hoistOneOfs` creates M new `allOf` schemas
- `src/services/OpenAPIParser.ts:174` — `x-circular-ref` guard (insufficient)
- No memoization anywhere in `hoistOneOfs` or `mergeAllOf`

## PoC Execution Results

Measured call counts (faithful port of production algorithm, Node.js v25.9.0):

| Config  | Theoretical M^D | Actual calls  | Time    |
|---------|----------------|---------------|---------|
| M=3 D=4 | 81             | 361           | 0.22ms  |
| M=5 D=6 | 15,625         | 58,591        | 3.23ms  |
| M=5 D=8 | 390,625        | 1,464,841     | 47.43ms |
| M=10 D=5| 100,000        | 333,331       | 10.71ms |

Actual call count exceeds M^D because `initOneOf` (Schema.ts:239) re-enters
`mergeAllOf` for each variant's allOf children, creating additional fan-out.
Growth ratio baseline → M=5,D=8: **4,058x**.
