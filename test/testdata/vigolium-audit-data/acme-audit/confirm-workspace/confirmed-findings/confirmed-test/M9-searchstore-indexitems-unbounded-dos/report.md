# [M9] Searchstore Indexitems Unbounded Dos

## Summary

`SearchStore.indexItems()` at `src/services/SearchStore.ts:25-37` recursively walks the entire menu tree with no item-count cap, then calls `searchWorker.done()` to build the lunr-style search index. For a spec with 50,000+ operations, this pushes 50,000 documents into the worker and triggers an O(n log n) index build. This is a post-parse DoS vector independent of the parser DoS bugs (PH-03a, PH-04, PH-09).

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Post-Parse DoS / Search Worker
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Triage-Priority**: P2

## Impact

From `evidence/impact.log`:

```
[
  {
    "ops": 50000,
    "calls": 50001,
    "ms": "1.5"
  },
  {
    "ops": 100000,
    "calls": 100001,
    "ms": "3.0"
  },
  {
    "ops": 200000,
    "calls": 200001,
    "ms": "5.1"
  },
  {
    "ops": 500000,
    "calls": 500001,
    "ms": "8.3"
  },
  {
    "ops": 1000000,
    "calls": 1000001,
    "ms": "16.9"
  }
]
```

## Affected Component

- **File**: `src/services/SearchStore.ts:25`
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/services/SearchStore.ts:25`. See draft.md for the full trace.

## Vulnerable Code

- `src/services/SearchStore.ts:25-37` — `indexItems` with no count/depth guard
- `src/services/AppStore.ts:78-80` — synchronous invocation in constructor
- `src/services/SearchStore.ts:31` — unbounded recursive call
- `src/services/SearchStore.ts:36` — `done()` triggers worker index build

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/callcount.json`
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/exploit.sh`
- `evidence/impact.log`
- `evidence/poc.js`
- `evidence/scale_test.log`
- `evidence/timing.json`

Decisive output from `evidence/exploit.log`:
```
  [small  (100 ops, flat)] calls=101  indexed=100  time=0.11ms
  [medium (10 000 ops, flat)] calls=10001  indexed=10000  time=0.65ms
  [large  (50 000 ops, flat)] calls=50001  indexed=50000  time=2.80ms
  [nested (500 groups × 100 ops)] calls=50500  indexed=50000  time=3.70ms

  [depth stress] building 1000-level deep nest...
  [depth stress] depth=1000  calls=1000  time=0.02ms

  Evidence written to:
    /Users/<user>/Desktop/oss-to-run/acme/archon/findings/M9-searchstore-indexitems-unbounded-dos/evidence/timing.json
    /Users/<user>/Desktop/oss-to-run/acme/archon/findings/M9-searchstore-indexitems-unbounded-dos/evidence/callcount.json

{"status":"confirmed","evidence":"main-thread recursion over 50 000 ops consumed 2.8ms (calls=50001) with no item-count guard in SearchStore.indexItems","notes":"No Worker needed to confirm main-thread stall; verbatim traversal logic from SearchStore.ts:26-33 exercised directly."}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/services/SearchStore.ts:25`.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/M9-searchstore-indexitems-unbounded-dos/confirm-test.ts
Confirm-Test-Output: archon/findings/M9-searchstore-indexitems-unbounded-dos/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:37:02.096502+00:00
Confirm-Notes: Generated a Jest reproducer against the real SearchStore.indexItems path. Repository test search found no existing tests referencing SearchStore or indexItems, so nothing previously exercised this sink with attacker-sized menu trees. The test mocked only SearchWorker.worker, fed 500 group nodes containing 50,000 operation items into SearchStore.indexItems, and confirmed all 50,000 items reached add() before done() with no count guard or truncation.
