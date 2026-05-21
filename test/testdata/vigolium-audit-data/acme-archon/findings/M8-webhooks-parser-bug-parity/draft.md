---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/services/SpecStore.ts:32-36 spreads `x-webhooks`/`webhooks` into a WebhookModel; Webhook.ts:15 calls `parser.deref` and MenuBuilder.ts:216-217 traverses the same paths via `getTags`, all sharing the same parser pipeline.
FP-Reasoning: Both webhook roots flow through the exact same `parser.deref` / `mergeAllOf` / `hoistOneOfs` functions used for `paths`, with no separate budget, cap, or traversal guard. Any DoS payload accepted in `paths` is accepted in `webhooks` as a second independent root, so the parity claim is structurally true in current source.
Severity-Original: MEDIUM
Class: Parser DoS / Attack Surface Multiplier
Origin-Finding: H-06
Origin-Pattern: PATT-008
File: src/services/SpecStore.ts:32
Chamber: chamber-02
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: MEDIUM DoS amplifier requiring attacker-controlled spec; no auth bypass or data exfiltration; doubles existing parser DoS surface only
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

# All Parser DoS Bugs Apply to `webhooks` / `x-webhooks` — Independent Budget Bypass

## Summary

OpenAPI 3.1 `webhooks` (and legacy `x-webhooks`) are processed by the same `OpenAPIParser.deref()` / `mergeAllOf()` / `hoistOneOfs()` pipeline as `paths`, but as a separate root tree with an independent recursion budget. All DoS bugs from PH-03a (allOf breadth), PH-04 (hoistOneOfs exponential), PH-05 (x-refsStack injection), and PH-07 (decodeURIComponent traversal) apply to webhook schemas, giving an attacker two simultaneous DoS amplifications from a single spec.

## Evidence

`src/services/SpecStore.ts:32-36`:
```typescript
const webhookPath: Referenced<OpenAPIPath> = {
  ...this.parser?.spec?.['x-webhooks'],
  ...this.parser?.spec.webhooks,
};
this.webhooks = new WebhookModel(this.parser, options, webhookPath);
```

`src/services/models/Webhook.ts:15`:
```typescript
const { resolved: webhooks } = parser.deref<OpenAPIPath>(infoOrRef || {});
```

`src/services/MenuBuilder.ts:210-217`:
```typescript
const webhooks = spec['x-webhooks'] || spec.webhooks;
if (webhooks) { getTags(parser, webhooks, true); }
```

All three entry points call the same `parser.deref()` → `mergeAllOf()` chain.

## DoS Budget Bypass

Any per-tree node-count cap added to harden `paths` processing would NOT protect webhooks if the cap is implemented at the `paths` root level only. An attacker placing DoS payloads in BOTH `paths` and `webhooks` would receive double the DoS impact and bypass any single-tree guard.

## Additional Risk

`{ ...this.parser?.spec?.['x-webhooks'], ...this.parser?.spec.webhooks }` at `SpecStore.ts:33` performs `Object.keys()` (implicit in spread) on attacker-controlled spec objects with no size limit. Combined with H-03's prototype pollution, `Object.prototype` keys could appear as bogus webhook names.

## Code Evidence

- `src/services/SpecStore.ts:32-36` — webhook path construction via spread (no size limit)
- `src/services/models/Webhook.ts:15` — `parser.deref()` entry into shared pipeline
- `src/services/MenuBuilder.ts:210-217` — webhook traversal via same `getTags` function
