# [M6] X Refsstack Injection Cycle Detection Bypass

## Summary

`OpenAPIParser.deref()` at `src/services/OpenAPIParser.ts:93-94` reads the `x-refsStack` property directly from spec objects — an internal tracking array used for cycle detection — and merges it into the live tracking stack. An attacker can place `x-refsStack: ["#/fake1", ..., "#/fake998"]` on any schema in their spec to pre-exhaust the depth budget, causing any subsequent legitimate `$ref` in that schema to be flagged as circular and silently skipped.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Integrity / Cycle Detection Bypass
- **FP-Verdict**: TRUE-POSITIVE (confidence: MEDIUM)
- **Triage-Priority**: P2

## Impact

An attacker can suppress any schema's rendering from the documentation — hiding required fields, authentication requirements, or error response schemas. This is a documentation integrity attack: users see incomplete or misleading API documentation.

## Affected Component

- **File**: `src/services/OpenAPIParser.ts:93`
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/services/OpenAPIParser.ts:93`. See draft.md for the full trace.

## Vulnerable Code

- `src/services/OpenAPIParser.ts:18-20` — `concatRefStacks` concatenates spec-supplied stack onto tracking stack
- `src/services/OpenAPIParser.ts:93-94` — `x-refsStack` read from spec object without validation
- `src/services/OpenAPIParser.ts:108` — depth check, bypassable via pre-filled stack
- `src/services/OpenAPIParser.ts:109` — `x-circular-ref: true` set, causing downstream silent skip

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
--- BASELINE: deref VictimSchema directly (empty stack) ---
  x-circular-ref  : false
  properties found: true
  stack depth out : 1

--- ATTACK: deref AttackSchema with injected x-refsStack[1000] ---
  baseRefsStack.length after concat : 1000 (> 999? true )
  x-circular-ref   : true
  properties found : true

--- Schema.init() simulation (Schema.ts:118 + :157-158) ---
  this.isCircular = true  →  init() returns at Schema.ts:158
  EFFECT: apiKey and role silently suppressed from rendered documentation

{"status":"confirmed","evidence":"VictimSchema resolved with x-circular-ref:true via spec-supplied x-refsStack[1000]; Schema.init() returns early at line 157-158 suppressing all properties (apiKey, role)","notes":"Baseline: x-circular-ref=false properties=true. Attack: x-circular-ref=true properties=true stackDepth=1000>999=true."}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/services/OpenAPIParser.ts:93`.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/M6-x-refsstack-injection-cycle-detection-bypass/confirm-test.ts
Confirm-Test-Output: archon/findings/M6-x-refsstack-injection-cycle-detection-bypass/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:28:14.374217+00:00
Confirm-Notes: Existing OpenAPIParser/Schema circular tests cover normal recursion cases but not attacker-controlled x-refsStack input. Generated Jest test proved spec-supplied x-refsStack (>999 entries) makes OpenAPIParser.deref() set x-circular-ref=true and SchemaModel.init() stop before building fields, confirming documentation suppression. Executed via Jest wrapper src/services/__tests__/confirm.x-refsstack-injection-cycle-detection-bypass.00000000.test.ts.