---
ID: H-00-F
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: MEDIUM
FP-Evidence: MarkdownRenderer.ts:19-22 COMPONENT_REGEXP contains two `[\s\S]*?` quantifiers plus a `\2` backreference (children variant); MarkdownRenderer.ts:163-186 runs `componentsRegexp.exec(rawText)` synchronously in a while loop. AppStore.ts:149-170 DEFAULT_OPTIONS.allowedMdComponents always registers three names, so the regex is built and applied on every spec.
FP-Reasoning: Verified — regex with cross-line lazy quantifiers + backreference applied synchronously to attacker-controlled description text with default-on registry. Probe PH-06 in markdown-sanitization workspace reports 18s empirical hang at 50k chars (CodeQL polynomial-redos). Confidence MEDIUM rather than HIGH because the exact backtracking shape (polynomial vs catastrophic) depends on engine details, but the synchronous DoS reachability against an attacker-controlled description in a default Acme deployment is sound.
Severity-Original: MEDIUM
Class: ReDoS
Origin-Finding: H-00-F
Origin-Pattern: component-regexp-default-on-redos
File: src/services/MarkdownRenderer.ts:163
Source: spec description text containing an MDX-component-name prefix (e.g. <security-definitions, <security-definition, <schema-definition) without a matching closing tag and a long [\s\S] body
Sink: src/services/MarkdownRenderer.ts:168 — componentsRegexp.exec(rawText) in while loop (COMPONENT_REGEXP with [\s\S]*? lazy quantifier)
Chamber: chamber-01
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: low
Triage-Reasoning: MEDIUM ReDoS, client-side only, single-tab browser freeze with user-recoverable UX; no cross-user, no data loss, no persistence.
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Pre-FP-Flag: severity downgraded HIGH → MEDIUM on Advocate review (single-tab, client-side, recoverable via browser unresponsive-page UX; no cross-user, no persistence, no privilege impact). Default-on via AppStore DEFAULT_OPTIONS allowedMdComponents (3 entries) — runs for every Acme deployment processing a spec with description fields. Distinct regex from H-00-E (parseProps).
Debate: archon/chamber-workspace/chamber-01/debate.md
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
PoC-Notes: O(n^2) backtracking confirmed in Node.js v25.9.0 on arm64. Trigger: unclosed <security-definitions tag with interleaved '>' chars (payload "<security-definitions >a>a..."). With-children branch [\s\S]*? (group 3) grows lazily finding each '>'; inner [\s\S]*? (group 4) then scans full remainder for absent </security-definitions>. Timing ladder: 7k chars=4ms, 15k=18ms, 30k=71ms, 60k=279ms, 100k=770ms, 150k=1730ms. Event loop blocked >1.7s at 150k chars; extrapolated >3s at 200k chars. Evidence in archon/findings/M2-component-regexp-cross-line-redos/evidence/.
---

# Polynomial ReDoS in COMPONENT_REGEXP (default-on path)

## Source → Sink Path

1. `src/services/AppStore.ts:149-170` — `DEFAULT_OPTIONS.allowedMdComponents` populated with three entries (`security-definitions`, `security-definition`, `schema-definition`).
2. `src/services/AppStore.ts:67` — `new AcmeNormalizedOptions(options, DEFAULT_OPTIONS)` — every AppStore instantiation inherits these defaults.
3. Spec field `*.description` → `AdvancedMarkdown` → `MarkdownRenderer.renderMdWithComponents()`.
4. `src/services/MarkdownRenderer.ts:163` — `const componentsRegexp = new RegExp(COMPONENT_REGEXP.replace(/{component}/g, names), 'mig')` — `COMPONENT_REGEXP` includes `[\\s\\S]*?` lazy quantifier (lines 19-22).
5. `src/services/MarkdownRenderer.ts:168` — `let match = componentsRegexp.exec(rawText)` in a synchronous `while(match)` loop.

## ReDoS Mechanism

Payload `<security-definitions ` followed by 50,000+ chars without a closing tag forces the engine to backtrack the lazy `[\s\S]*?` body across the entire tail at every starting position. Probe PH-06 in `archon/probe-workspace/markdown-sanitization/probe-summary.md` empirically measured an 18+ second tab freeze for a 50k-char payload.

## Attack Mechanic

```yaml
info:
  description: "<security-definitions ---------------------- ... (50,000 dashes, no closing tag)"
```

Effect: main-thread renderer freeze ~18s on a typical x86 laptop. Repeats every time the page is loaded with this spec.

## Why Protection Does Not Apply

- The `allowedMdComponents` gate is satisfied by AppStore DEFAULT_OPTIONS — no user opt-in is required. No documented API to disable component scanning short of explicitly setting `allowedMdComponents: {}`.
- The synchronous `while(componentsRegexp.exec(rawText))` loop holds the main thread for the full backtracking duration.
- Distinct regex from H-00-E (parseProps regex `/([\w-]+)\s*=\s*(?:{...}|"...")/`).

## Why MEDIUM Not HIGH

Per Advocate: single-tab, client-side, browser-recoverable DoS. No cross-user effect, no persistence, no privilege escalation. Browser unresponsive-page UX (Chrome ~5s warning, "Wait / Kill") gives the user a manual recovery path. The "default-on" reachability raises probability of trigger but does not raise impact ceiling above availability-only on a self-loaded page.

## Remediation

Apply a length cap to `rawText` before `componentsRegexp.exec()` (e.g., refuse to scan inputs > 50 KiB for component tags, or chunk per paragraph). Alternatively rewrite `COMPONENT_REGEXP` to use a possessive/atomic body or a hand-written state machine that does not backtrack.
