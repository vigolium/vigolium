# [M1] Parseprops Redos

## Summary

`parseProps()` in `src/services/MarkdownRenderer.ts` (lines 204-229) contains a regular expression
`/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim` applied to the MDX-component props string
extracted from spec Markdown content. The regex is empirically confirmed to exhibit polynomial
(O(n²)) time complexity on adversarial input.

## Severity, Confidence, Vulnerability Type

- **Severity**: Medium
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: ReDoS
- **Triage-Priority**: P2

## Impact

- **Effect**: Main-thread freeze of the rendering tab for the duration of the match
- **Attacker**: Any spec author who injects a crafted `props` string in an MDX-component tag
  in a spec description field, when the embedding app uses `allowedMdComponents`
- **Same-user**: Yes (tab freeze, no cross-origin effect), but in a documentation site serving
  multiple users, every page load would freeze the rendering thread

## Affected Component

- **File**: `src/services/MarkdownRenderer.ts:213`
- **Source**: spec description text containing an MDX-component tag with an oversized props attribute string (e.g. 50k+ consecutive dash chars)
- **Sink**: src/services/MarkdownRenderer.ts:213 — regex /([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim in parseProps()
- **Chamber**: chamber-01

## Source to Sink Flow

Primary site: `src/services/MarkdownRenderer.ts:213`. See draft.md for the full trace.

## Vulnerable Code

See `src/services/MarkdownRenderer.ts:213` and draft.md for code excerpts.

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
[benign]  input length=19  time=0.23 ms
[redos]   dashes=1000  time=3.3 ms
[redos]   dashes=5000  time=73.7 ms
[redos]   dashes=10000  time=206.3 ms
[redos]   dashes=25000  time=1021.4 ms
[redos]   dashes=50000  time=4189.1 ms
{"status":"confirmed","evidence":"parseProps regex stalled for 4189 ms on 50000-char adversarial props string (expected <1 ms for benign input of 19 chars)","notes":"benign=0.23ms worst_adversarial=4189ms at n=50000"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

Replace the backtracking regex with a non-backtracking alternative or apply a length limit:
```typescript
function parseProps(props: string): object {
  if (!props || props.length > 4096) return {}; // length guard
  // Use possessive quantifiers or atomic groups if available, or rewrite as state machine
  const regex = /([a-zA-Z_][\w-]*)\s*=\s*(?:\{([^}]*)\}|"([^"]*)")/gim;
  ...
}
```
Or impose a hard limit: `props = props.slice(0, 4096)` before regex application.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/M1-parseprops-redos/confirm-test.ts
Confirm-Test-Output: archon/findings/M1-parseprops-redos/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:15:28Z
Confirm-Notes: Generated a Jest/ts-jest reproducer that drives MarkdownRenderer.renderMdWithComponents through parseProps with malformed oversized props input. Existing tests in src/services/__tests__/MarkdownRenderer.test.ts cover only happy-path attribute parsing and would not catch this ReDoS. The generated test passed, showing adversarial input caused materially slower execution than benign input.
