---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: MEDIUM
FP-Evidence: src/services/OpenAPIParser.ts:93-94 unconditionally concatenates `obj['x-refsStack']` into the live tracking stack; :108 then trips on length>999 and stamps `x-circular-ref` which Schema.ts:118/157-159 honors as a hard render-skip.
FP-Reasoning: `deref` reads the spec-author-controllable `x-refsStack` of any input object and merges it into the cycle-tracking stack with no provenance check, so an attacker placing `x-refsStack: [...998 fakes...]` on an allOf sub-schema (the realistic injection point — `hoistOneOfs` already writes `x-refsStack` onto allOf members at :379) causes the very next $ref to be marked circular, and Schema.ts then short-circuits init() at line 158 silently dropping fields. Confidence is MEDIUM because the draft's top-level-schema scenario is slightly off (x-refsStack must be on the deref'd input, e.g. an allOf member or oneOf variant), but the underlying primitive is exploitable.
Severity-Original: MEDIUM
Class: Integrity / Cycle Detection Bypass
Origin-Finding: PH-05
Origin-Pattern: PATT-009
File: src/services/OpenAPIParser.ts:93
Chamber: chamber-02
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: Spec-author-controlled input required; impact is documentation integrity only (silent schema suppression), no data exfiltration or auth bypass.
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

# `x-refsStack` Injection Bypasses Cycle Detection — Silent Schema Suppression

## Summary

`OpenAPIParser.deref()` at `src/services/OpenAPIParser.ts:93-94` reads the `x-refsStack` property directly from spec objects — an internal tracking array used for cycle detection — and merges it into the live tracking stack. An attacker can place `x-refsStack: ["#/fake1", ..., "#/fake998"]` on any schema in their spec to pre-exhaust the depth budget, causing any subsequent legitimate `$ref` in that schema to be flagged as circular and silently skipped.

## Attack Scenario

```yaml
components:
  schemas:
    AttackSchema:
      x-refsStack:
        - "#/fake1"
        - "#/fake2"
        # ... 998 entries ...
        - "#/fake998"
      allOf:
        - $ref: "#/[REDACTED]"
```

When `deref(AttackSchema)` is called:
1. `:93` — `objRefsStack = ["#/fake1", ..., "#/fake998"]` (998 entries).
2. `:94` — `baseRefsStack = [].concat(objRefsStack)` → length 998.
3. `:108` — `baseRefsStack.length > MAX_DEREF_DEPTH` (998 > 999) — FALSE. But the `$ref` to `RequiredSecuritySchema` is then processed: `pushRef(baseRefsStack, "$ref")` makes length 999. Next recursive `deref` call starts with length 999. Any new `$ref` encountered makes length > 999 → marked circular.
4. `RequiredSecuritySchema` is marked `x-circular-ref: true`, which causes `Schema.ts` to return early without rendering that schema's properties.

**PoC correction (from execution):** The depth check is strictly `> 999`, so the injection must supply exactly 1000 entries (not 999) to trip the guard in a single `deref()` call without a recursive hop.

## Impact

An attacker can suppress any schema's rendering from the documentation — hiding required fields, authentication requirements, or error response schemas. This is a documentation integrity attack: users see incomplete or misleading API documentation.

## Why `x-*` Is a Valid OpenAPI Namespace

OpenAPI 3.x explicitly supports `x-*` extension fields on all schema objects. `x-refsStack` is an internal Acme field that happens to use this namespace. Spec authors can legitimately set any `x-*` field without violating the OpenAPI specification. There is no mechanism to distinguish Acme-internal `x-*` fields from spec-author `x-*` fields.

## Code Evidence

- `src/services/OpenAPIParser.ts:18-20` — `concatRefStacks` concatenates spec-supplied stack onto tracking stack
- `src/services/OpenAPIParser.ts:93-94` — `x-refsStack` read from spec object without validation
- `src/services/OpenAPIParser.ts:108` — depth check, bypassable via pre-filled stack
- `src/services/OpenAPIParser.ts:109` — `x-circular-ref: true` set, causing downstream silent skip
