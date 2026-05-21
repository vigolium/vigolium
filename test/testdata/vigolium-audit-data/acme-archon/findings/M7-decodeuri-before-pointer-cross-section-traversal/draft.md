---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: MEDIUM
FP-Evidence: src/services/OpenAPIParser.ts:61 unconditionally decodes the full ref before JsonPointer.get at :63; the `res || {}` return at :67 lets a truthy non-object string pass `if (!resolved)` at :103.
FP-Reasoning: `decodeURIComponent` is applied to the whole ref string before tokenization, so `%2F` decodes into a real `/` segment and the pointer walks into arbitrary sections (e.g. `#/info%2Fdescription` → `spec.info.description` string). `byRef` returns the string truthy, `deref` accepts it, and `mergeAllOf`/Schema.ts then operate on a string primitive instead of a schema. Confidence is MEDIUM because real-world impact is mostly silent type-confusion (string has no `.allOf`/`.properties`); the type-confusion + RFC 6901 violation are demonstrably present in current source.
Severity-Original: MEDIUM
Class: Pointer Injection / Type Confusion
Origin-Finding: PH-07
Origin-Pattern: PATT-009
File: src/services/OpenAPIParser.ts:61
Chamber: chamber-02
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: Requires attacker-controlled spec with %2F-encoded ref; impact is type confusion/rendering anomaly, XSS path is speculative; MEDIUM severity moderate exploitability maps to P2.
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

# `decodeURIComponent` Before JSON Pointer Resolution Enables Cross-Section Traversal

## Summary

`OpenAPIParser.byRef()` at `src/services/OpenAPIParser.ts:61` applies `decodeURIComponent` to the entire `$ref` string before splitting it into JSON Pointer segments. This allows `%2F`-encoded slashes to decode into literal `/`, adding spurious pointer segments. An attacker using `$ref: "#/info%2Fdescription"` resolves to `spec.info.description` (a string), not a schema object — causing type confusion in all downstream schema consumers.

## Attack Scenario

```yaml
components:
  schemas:
    Confused:
      $ref: "#/info%2Fdescription"
```

Processing:
1. `byRef("#/info%2Fdescription")` at `:54`.
2. `:61` — `ref = decodeURIComponent("#/info%2Fdescription")` → `"#/info/description"`.
3. `:63` — `JsonPointer.get(spec, "#/info/description")` → resolves to `spec.info.description`, which is a plain string (e.g., `"My API description"`).
4. `:67` — `return "My API description" || {}` → returns the string (truthy).
5. `:103` — `if (!resolved)` — string is truthy, no error thrown.
6. String passed to `mergeAllOf()` which expects an object → undefined behavior / type errors.

## RFC 6901 Violation

RFC 6901 (JSON Pointer) section 3 requires that literal `/` characters in reference tokens be escaped as `~1`. `%2F` (URL percent-encoding) is NOT the JSON Pointer escape mechanism. Applying `decodeURIComponent` before pointer parsing violates the RFC and creates this ambiguity.

## Potential Impact

- **Type confusion**: downstream schema code receives a string where it expects an object.
- **Schema substitution**: any string-valued spec field can be injected as a "schema" — `spec.info.version` (a version string) would be returned as a schema, appearing as an object with no properties (empty schema behavior for strings treated as schemas).
- **XSS amplification**: if a string from `spec.info.description` containing user-controlled content is rendered as a schema's "example" value, it may bypass schema-level sanitization expectations.

## Code Evidence

- `src/services/OpenAPIParser.ts:61` — unconditional `decodeURIComponent` application
- `src/services/OpenAPIParser.ts:63` — `JsonPointer.get` receives decoded string
- `src/services/OpenAPIParser.ts:67` — truthy string passes through as resolved schema
- `src/services/OpenAPIParser.ts:103` — guard bypassed (string is truthy)
