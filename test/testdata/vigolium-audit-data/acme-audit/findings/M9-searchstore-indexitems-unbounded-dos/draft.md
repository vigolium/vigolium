---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/services/SearchStore.ts:25-37 recurses menu items with no depth/count cap and queues every node to the worker; AppStore.ts:76-80 invokes it synchronously in the constructor when search is enabled.
FP-Reasoning: `indexItems` does an unbounded `forEach`+`recurse` over the full menu tree and pushes every non-group node into the search worker, then triggers `done()` for the index build. Nothing in `SearchStore` or its sole caller `AppStore` enforces a cap on depth, item count, or string length, so a spec with very many menu items (paths × operations × tag groups) causes the documented main-thread/worker stall.
Severity-Original: MEDIUM
Class: Post-Parse DoS / Search Worker
Origin-Finding: H-05
Origin-Pattern: PATT-008
File: src/services/SearchStore.ts:25
Chamber: chamber-02
Triage-Priority: P2
Triage-Exploitability: moderate
Triage-Impact: medium
Triage-Reasoning: MEDIUM DoS requiring attacker-controlled spec with 50k+ ops; impacts search UI/main thread only, no data exfiltration or auth bypass.
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

# `SearchStore.indexItems` Unbounded Recursion / Search Worker DoS

## Summary

`SearchStore.indexItems()` at `src/services/SearchStore.ts:25-37` recursively walks the entire menu tree with no item-count cap, then calls `searchWorker.done()` to build the lunr-style search index. For a spec with 50,000+ operations, this pushes 50,000 documents into the worker and triggers an O(n log n) index build. This is a post-parse DoS vector independent of the parser DoS bugs (PH-03a, PH-04, PH-09).

## Invocation

`src/services/AppStore.ts:78-80`:
```typescript
this.search = new SearchStore();
if (createSearchIndex) {
  this.search.indexItems(this.menu.items);
}
```

Called synchronously in the `AppStore` constructor after menu build. `indexItems` itself calls `recurse(groups)` synchronously — the recursive traversal happens on the main thread. Only the `done()` call is sent to the Worker.

## No Count Guard

`src/services/SearchStore.ts:25-37`:
```typescript
indexItems(groups: Array<IMenuItem | OperationModel>) {
  const recurse = items => {
    items.forEach(group => {
      if (group.type !== 'group') {
        this.add(group.name, (group.description || '').concat(' ', group.path || ''), group.id);
      }
      recurse(group.items);  // no depth/count check
    });
  };
  recurse(groups);
  this.searchWorker.done();
}
```

No limit on: (a) recursion depth, (b) total item count, (c) string length added per item.

## Two-Stage DoS

1. **Main-thread**: for deeply nested `x-tagGroups`, JavaScript call stack overflow (stack depth = tag group nesting depth × operations per group).
2. **Worker-thread**: for flat specs with 50,000+ operations, the lunr index build freezes the Search Worker — search UI becomes non-responsive while the worker processes.

## Amplification with Parser DoS

PH-04 (`hoistOneOfs` exponential) can produce hundreds of thousands of synthetic schemas in `components.schemas`. If a `schemaDefinitionsTagName` is configured, `MenuBuilder` adds these as menu items — feeding them all into `indexItems`.

## Code Evidence

- `src/services/SearchStore.ts:25-37` — `indexItems` with no count/depth guard
- `src/services/AppStore.ts:78-80` — synchronous invocation in constructor
- `src/services/SearchStore.ts:31` — unbounded recursive call
- `src/services/SearchStore.ts:36` — `done()` triggers worker index build
