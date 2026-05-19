# [M2] Component Regexp Cross Line Redos

## Summary

1. `src/services/AppStore.ts:149-170` — `DEFAULT_OPTIONS.allowedMdComponents` populated with three entries (`security-definitions`, `security-definition`, `schema-definition`).
2. `src/services/AppStore.ts:67` — `new AcmeNormalizedOptions(options, DEFAULT_OPTIONS)` — every AppStore instantiation inherits these defaults.
3. Spec field `*.description` → `AdvancedMarkdown` → `MarkdownRenderer.renderMdWithComponents()`.
4. `src/services/MarkdownRenderer.ts:163` — `const componentsRegexp = new RegExp(COMPONENT_REGEXP.replace(/{component}/g, names), 'mig')` — `COMPONENT_REGEXP` includes `[\\s\\S]*?` lazy quantifier (lines 19-22).
5. `src/services/MarkdownRenderer.ts:168` — `let match = componentsRegexp.exec(rawText)` in a synchronous `while(match)` loop.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: ReDoS
- **FP-Verdict**: TRUE-POSITIVE (confidence: MEDIUM)
- **Triage-Priority**: P2

## Impact

From `evidence/impact.log`:

```
Impact: extrapolated freeze durations
(Typical API spec description field — 5000 chars is already valid)

5000 chars: 3ms (0.00s) 
10000 chars: 8ms (0.01s) 
20000 chars: 33ms (0.03s) 
50000 chars: 197ms (0.20s) #
100000 chars: 784ms (0.78s) #######
200000 chars: 3148ms (3.15s) ###############################

```

## Affected Component

- **File**: `src/services/MarkdownRenderer.ts:163`
- **Source**: spec description text containing an MDX-component-name prefix (e.g. <security-definitions, <security-definition, <schema-definition) without a matching closing tag and a long [\s\S] body
- **Sink**: src/services/MarkdownRenderer.ts:168 — componentsRegexp.exec(rawText) in while loop (COMPONENT_REGEXP with [\s\S]*? lazy quantifier)
- **Chamber**: chamber-01

## Source to Sink Flow

1. `src/services/AppStore.ts:149-170` — `DEFAULT_OPTIONS.allowedMdComponents` populated with three entries (`security-definitions`, `security-definition`, `schema-definition`).
2. `src/services/AppStore.ts:67` — `new AcmeNormalizedOptions(options, DEFAULT_OPTIONS)` — every AppStore instantiation inherits these defaults.
3. Spec field `*.description` → `AdvancedMarkdown` → `MarkdownRenderer.renderMdWithComponents()`.
4. `src/services/MarkdownRenderer.ts:163` — `const componentsRegexp = new RegExp(COMPONENT_REGEXP.replace(/{component}/g, names), 'mig')` — `COMPONENT_REGEXP` includes `[\\s\\S]*?` lazy quantifier (lines 19-22).
5. `src/services/MarkdownRenderer.ts:168` — `let match = componentsRegexp.exec(rawText)` in a synchronous `while(match)` loop.

## Vulnerable Code

See `src/services/MarkdownRenderer.ts:163` and draft.md for code excerpts.

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
M2 COMPONENT_REGEXP ReDoS — timing PoC
Vulnerable file : src/services/MarkdownRenderer.ts:163,168
Trigger         : unclosed <security-definitions ...>a>a... in spec description
Pattern (head)  : (?:^ {0,3}<!-- Acme-Inject:\s+?<(security-definitions|security-definition|schema-definition).*?/?>\...

Payload (chars)     Elapsed (ms)    Growth flag
--------------------------------------------------------
1000                0.8             ok
7000                4.0             O(n^2) growth ^
15000               17.9            O(n^2) growth ^
30000               70.7            O(n^2) growth ^
60000               278.6           O(n^2) growth ^
100000              769.7           * >500ms slow *
150000              1729.8          * >500ms slow *

CONFIRMED: O(n^2) backtracking observed. 150000-char payload blocked event loop for 1730 ms.
Growth: 1000-char baseline 0.8ms → 150000-char payload 1729.8ms (ratio 2277x empirical vs 22500x expected for n^2)
{"status":"confirmed","evidence":"event-loop blocked 1730ms for 150000-char unclosed-tag payload; O(n^2) growth across size ladder","notes":"pure-JS timing against exact COMPONENT_REGEXP from MarkdownRenderer.ts; no live server required"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

Apply a length cap to `rawText` before `componentsRegexp.exec()` (e.g., refuse to scan inputs > 50 KiB for component tags, or chunk per paragraph). Alternatively rewrite `COMPONENT_REGEXP` to use a possessive/atomic body or a hand-written state machine that does not backtrack.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/M2-component-regexp-cross-line-redos/confirm-test.test.ts
Confirm-Test-Output: archon/findings/M2-component-regexp-cross-line-redos/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-18T18:03:38Z

Confirm-Notes: Existing src/services/__tests__/MarkdownRenderer.test.ts covered happy-path component parsing only; generated Jest timing test exercised renderMdWithComponents() with an unclosed <security-definitions payload and confirmed super-linear slowdown locally.
