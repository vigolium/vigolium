# [M4] Allof Breadth Dos No Limit

## Summary

`mergeAllOf` at `src/services/OpenAPIParser.ts:199-226` iterates all elements of `schema.allOf` without any breadth limit. The existing `MAX_DEREF_DEPTH=999` guard only bounds recursion depth. A spec with a single `allOf` containing 50,000 inline schemas at depth 1 bypasses the depth guard entirely and forces 50,000 merge operations with no protection.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Parser DoS / Algorithmic Complexity
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Triage-Priority**: P2

## Impact

From `evidence/impact.log`:

```
=== M4 allOf breadth DoS — Impact Evidence ===

Exploit target : src/services/OpenAPIParser.ts:199-226 (mergeAllOf)
Guard bypassed : MAX_DEREF_DEPTH=999 at :108 (baseRefsStack.length check only)
Dedup bypassed : uniqByPropIncludeMissing at :393 ("if (!k) return true" when $ref=undefined)

--- Timing results (Node.js v25.9.0) ---
Baseline  (10 schemas × 1 child)           :   <1 ms
Malicious (10 schemas × 200,000 children)  :  586 ms

Total unconstrained iterations: 2,000,000

--- Guard verification ---
attack spec x-circular-ref flag : false  (guard DID NOT fire — bypassed)
Depth of inline allOf children  : 1      (refsStack never grows past [] for inline schemas)

--- Browser projection ---
V8 in Node.js is ~2-5x faster than V8 in a browser tab (no GC pressure, no DOM).
Estimated browser tab freeze for same spec: 1–3 seconds.
With 50 schemas × 500k children (still valid JSON): 25,000,000 ops → ~5-15s browser freeze.

--- Attacker capability ---
Single crafted OpenAPI YAML/JSON served from attacker-controlled URL.
Victim navigates to a Acme-powered documentation page loading attacker spec.
No authentication required, no server-side component needed.

```

## Affected Component

- **File**: `src/services/OpenAPIParser.ts:199`
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/services/OpenAPIParser.ts:199`. See draft.md for the full trace.

## Vulnerable Code

- `src/services/OpenAPIParser.ts:8` — `MAX_DEREF_DEPTH = 999`
- `src/services/OpenAPIParser.ts:108` — depth check (bypassable via inline schemas)
- `src/services/OpenAPIParser.ts:199-226` — unbounded `allOf.map()` loop
- `src/services/OpenAPIParser.ts:393-400` — `uniqByPropIncludeMissing` with inline-schema bypass

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.ts`
- `evidence/poc_root.ts`
- `evidence/run_poc.sh`

Decisive output from `evidence/exploit.log`:
```
[*] Baseline : 10 schemas × 1 allOf child
    => 0 ms  (depth guard fired: false)
[*] Malicious: 10 schemas × 200,000 inline allOf children
    => 586 ms  (depth guard fired: false)
[*] Total mergeAllOf iterations (attack): 2,000,000
[*] Depth guard bypassed: true — inline schemas never push onto refsStack
[*] uniqByPropIncludeMissing bypass: k=undefined ("if (!k) return true") — all 200,000 children pass dedup
[*] Slowdown: 586ms absolute (baseline < 1ms — sub-millisecond)
{"status":"confirmed","evidence":"10 schemas × 200000 inline allOf children took 586ms (baseline 0ms); depth guard x-circular-ref=false — bypassed","notes":"total_ops=2000000 slowdown=586ms absolute (baseline < 1ms — sub-millisecond)"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/services/OpenAPIParser.ts:199`.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/M4-allof-breadth-dos-no-limit/confirm-test.ts
Confirm-Test-Output: archon/findings/M4-allof-breadth-dos-no-limit/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:19:55Z
Confirm-Notes: Generated Jest reproducer counted 20,000 deref/merge iterations for attacker-controlled inline allOf children and observed 20,000 merged properties with no breadth limit or circular-depth guard firing; existing OpenAPIParser tests cover functional merge behavior only and would not detect this DoS path.
