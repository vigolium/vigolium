---
ID: H-00-E
Verdict: VALID
Severity-Original: MEDIUM
Class: ReDoS
File: src/services/MarkdownRenderer.ts:213
Source: spec description text containing an MDX-component tag with an oversized props attribute string (e.g. 50k+ consecutive dash chars)
Sink: src/services/MarkdownRenderer.ts:213 — regex /([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim in parseProps()
Chamber: chamber-01
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: Client-side tab DoS only; requires spec authorship and allowedMdComponents config; no cross-user persistence or data exposure.
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Pre-FP-Flag: gate (options.allowedMdComponents non-empty) is satisfied by AppStore DEFAULT_OPTIONS (3 entries: security-definitions, security-definition, schema-definition) — Tracer notes the pre-seed "requires non-default config" claim is incorrect, this path is default-on. Advocate kept severity at MEDIUM (client-side per-tab DoS, browser unresponsive-page UX provides manual recovery, no cross-user/persistence impact) rather than upgrading to HIGH.
Debate: archon/chamber-workspace/chamber-01/debate.md
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
PoC-Notes: Executed against verbatim regex extracted from src/services/MarkdownRenderer.ts:209 in Node.js v25.9.0. Adversarial payload "aaaa=" + 50000 dashes stalled the JS event loop for 4189 ms vs 0.23 ms for a benign 19-char input. Quadratic growth confirmed: n=25k->1021ms, n=50k->4189ms (~4x for 2x input, consistent with O(n^2)). No HTTP server required — vulnerability is in client-side rendering logic.
---

# p5-004 — Polynomial ReDoS in parseProps() via spec description content

**Severity**: Medium
**CWE**: CWE-1333 (Inefficient Regular Expression Complexity)
**CVSS estimate**: 5.3 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H) — requires allowedMdComponents
**DFD Slice**: spec-components-redos-parseProps
**Phase**: D5 — Code Scan (CodeQL: js/polynomial-redos; Semgrep: acme-new-regexp-user-input)

## Finding Summary

`parseProps()` in `src/services/MarkdownRenderer.ts` (lines 204-229) contains a regular expression
`/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim` applied to the MDX-component props string
extracted from spec Markdown content. The regex is empirically confirmed to exhibit polynomial
(O(n²)) time complexity on adversarial input.

**Empirically confirmed**: A 50,000-character string of dashes as `props` input causes approximately
**4.2 seconds** of single-threaded JavaScript execution in Node.js v25.9.0 (measured directly
against the verbatim regex from the source file).

## Trigger Condition

`parseProps()` is only reached when the embedding app has configured `options.allowedMdComponents`
with at least one entry. This is NOT the default. The call path:

```
spec.*.description → AdvancedMarkdown → renderMdWithComponents()
  → [only if allowedMdComponents is set]
  → COMPONENT_REGEXP match → props capture group (match[3] || match[6])
  → parseProps(props) → polynomial ReDoS
```

## ReDoS Mechanism

The regex `/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim` on input `aaaa=--------...`:

1. `[\w-]+` matches `aaaa` (or tries lengths 1..n-1)
2. `\s*=\s*` requires literal `=` — finds it
3. `(?:{([^}]+?)}|"([^"]+?)")` requires `{...}` or `"..."` — fails on `-` characters
4. Engine backtracks, retries `[\w-]+` at next position
5. Since `[\w-]+` can absorb `-` too, the alternation `{...}|"..."` fails at every position,
   and the engine tries all starting positions × all prefix lengths → O(n²)

## Impact

- **Effect**: Main-thread freeze of the rendering tab for the duration of the match
- **Attacker**: Any spec author who injects a crafted `props` string in an MDX-component tag
  in a spec description field, when the embedding app uses `allowedMdComponents`
- **Same-user**: Yes (tab freeze, no cross-origin effect), but in a documentation site serving
  multiple users, every page load would freeze the rendering thread

## CodeQL Evidence

Rule `js/polynomial-redos` at `src/services/MarkdownRenderer.ts:213` (the `regex` variable in
`parseProps`). CodeQL message: "strings with many repetitions of '-={{'" — consistent with the
`[\w-]+` pattern absorbing repeated `-` followed by `={{`.

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
