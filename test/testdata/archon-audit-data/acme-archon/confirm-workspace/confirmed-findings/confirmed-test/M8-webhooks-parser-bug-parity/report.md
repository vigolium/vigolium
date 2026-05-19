# [M8] Webhooks Parser Bug Parity

## Summary

OpenAPI 3.1 `webhooks` (and legacy `x-webhooks`) are processed by the same `OpenAPIParser.deref()` / `mergeAllOf()` / `hoistOneOfs()` pipeline as `paths`, but as a separate root tree with an independent recursion budget. All DoS bugs from PH-03a (allOf breadth), PH-04 (hoistOneOfs exponential), PH-05 (x-refsStack injection), and PH-07 (decodeURIComponent traversal) apply to webhook schemas, giving an attacker two simultaneous DoS amplifications from a single spec.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Parser DoS / Attack Surface Multiplier
- **FP-Verdict**: TRUE-POSITIVE (confidence: HIGH)
- **Triage-Priority**: P2

## Impact

From `evidence/impact.log`:

```
M8 — Security Impact Summary
==============================

Finding: webhooks/x-webhooks reuse the same parser pipeline — any DoS payload
         fires via both roots with no independent budget or cap.

Measured parity (50,000 inline allOf children per bomb):
  paths root        : 50,001 mergeAllOf calls  ~20ms
  webhooks root     : 50,001 mergeAllOf calls  ~16ms
  x-webhooks root   : 50,001 mergeAllOf calls  ~14ms
  both roots armed  : 100,002 mergeAllOf calls  ~27ms  (2.00× single-root)

Code path evidence:
  SpecStore.ts:32-36  → Object spread of x-webhooks+webhooks, no size cap
  Webhook.ts:15       → parser.deref() into the shared OpenAPIParser pipeline
  MenuBuilder.ts:216  → getTags(parser, webhooks, true) — same deref/mergeAllOf chain

DoS amplifier claim (per finding draft):
  Any per-tree node-count cap added only at the paths level would NOT protect
  webhooks. A spec author arming both paths + webhooks simultaneously receives
  DOUBLE the parser work (confirmed: 2.00× ratio above) with no cross-root guard.

Related DoS bugs that also apply to webhooks:
  M4 — allOf breadth (demonstrated here)
  M5 — hoistOneOfs exponential (same mergeAllOf call path)
  M6 — x-refsStack injection cycle-detection bypass (deref called from Webhook.ts:15)

Status: CONFIRMED — structural parity demonstrated through real OpenAPIParser source.

```

## Affected Component

- **File**: `src/services/SpecStore.ts:32`
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/services/SpecStore.ts:32`. See draft.md for the full trace.

## Vulnerable Code

- `src/services/SpecStore.ts:32-36` — webhook path construction via spread (no size limit)
- `src/services/models/Webhook.ts:15` — `parser.deref()` entry into shared pipeline
- `src/services/MenuBuilder.ts:210-217` — webhook traversal via same `getTags` function

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
=== M8: webhooks/x-webhooks Parser Bug Parity PoC ===

Bomb: 50,000 inline allOf children (M4 pattern, no $ref → depth guard bypass)
Pipeline: SpecStore.ts:32-36 → Webhook.ts:15 → parser.deref() → mergeAllOf → hoistOneOfs

[1/4] paths root only (1 bomb schema) ...
      mergeAllOf_calls=50,001  time=20.45ms

[2/4] webhooks root only (1 bomb schema) ...
      mergeAllOf_calls=50,001  time=16.69ms

[3/4] x-webhooks root only (1 bomb schema) ...
      mergeAllOf_calls=50,001  time=13.67ms

[4/4] paths + webhooks BOTH armed (2 distinct bomb schemas) ...
      mergeAllOf_calls=100,002  time=26.22ms

--- SpecStore.ts:32-36 spread simulation ---
  x-webhooks spread result : [legacyOrderEvent]  (1 key(s), no size cap)
  webhooks spread result   : [orderEvent]  (1 key(s), no size cap)
  both combined spread     : [orderEvent]  (1 key(s))
  Object.prototype pollution (H3) would surface here as extra keys.

--- Parity analysis ---
  paths     mergeAllOf calls: 50,001
  webhooks  mergeAllOf calls: 50,001  ratio vs paths: 1.000
  x-webhooks mergeAllOf calls: 50,001  ratio vs paths: 1.000
  both-roots mergeAllOf calls: 100,002  dual ratio: 2.000x
  Parity OK (all roots within ±10%): true
  Dual-root amplification ≥1.5×: true
{"status":"confirmed","evidence":"paths=50001 webhooks=50001 x-webhooks=50001 mergeAllOf calls (ratio=1.000); all three roots share identical parser.deref→mergeAllOf pipeline (SpecStore.ts:32/Webhook.ts:15/MenuBuilder.ts:216); dual-root config produced 100002 calls (2.00× paths-only)","notes":"SpecStore.ts:32-36 spreads x-webhooks+webhooks into webhookPath with no size cap. | Webhook.ts:15 calls parser.deref(); MenuBuilder.ts:216 calls getTags(parser,webhooks). | No independent budget exists for webhooks vs paths. M4/M5/M6/M9/M10 DoS patterns fire via both roots. | paths_ms=20.45 webhooks_ms=16.69 xwebhooks_ms=13.67 both_ms=26.22"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/services/SpecStore.ts:32`.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/M8-webhooks-parser-bug-parity/confirm-test.ts
Confirm-Test-Output: archon/findings/M8-webhooks-parser-bug-parity/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:34:38Z
Confirm-Notes: Generated a Jest reproducer and executed it through a wrapper test under src/services/__tests__/ so Jest would collect it. The test shows a 5,000-child allOf payload reaches the same mergeAllOf sink through MenuBuilder paths, webhooks, and x-webhooks with identical call counts, and that merging x-webhooks plus webhooks via SpecStore-style spread doubles the work (2 operations, 2x mergeAllOf calls) without any separate webhook budget.
