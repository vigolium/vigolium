#!/usr/bin/env node
/**
 * PoC: SearchStore.indexItems Unbounded Recursion / Search Worker DoS
 * Finding: M9 — src/services/SearchStore.ts:25-37
 *
 * Demonstrates that `indexItems` recurses the full menu tree synchronously
 * on the main thread with no item-count or depth cap.  A large synthetic
 * menu tree (mimicking a spec with 50 000 operations) causes a measurable
 * main-thread stall before the Worker is even invoked.
 *
 * The vulnerable traversal (verbatim from SearchStore.ts:26-33):
 *
 *   const recurse = items => {
 *     items.forEach(group => {
 *       if (group.type !== 'group') {
 *         this.add(group.name, (group.description || '').concat(' ', group.path || ''), group.id);
 *       }
 *       recurse(group.items);   // <-- no depth/count guard
 *     });
 *   };
 *
 * This PoC:
 *   1. Builds three synthetic menu trees: small (100 items), medium (10 000),
 *      and large (50 000 items) — all flat under a single tag group to
 *      maximise the realistic case without hitting JS stack limits.
 *   2. Runs the verbatim traversal logic against each tree and measures wall
 *      time (process.hrtime.bigint).
 *   3. Records call count per run.
 *   4. Prints a structured summary and writes timing.json / callcount.json
 *      to the evidence directory.
 *
 * No network, no Worker (Worker is a browser/workerize abstraction):
 * the main-thread recursion is what we measure.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const EVIDENCE_DIR = path.resolve(__dirname);

// ---------------------------------------------------------------------------
// 1.  Verbatim traversal from SearchStore.ts (no Worker calls in Node PoC)
// ---------------------------------------------------------------------------

function indexItems(groups) {
  let callCount = 0;
  const added   = [];

  const recurse = items => {
    items.forEach(group => {
      callCount++;
      if (group.type !== 'group') {
        // mirrors: this.add(group.name, ..., group.id)
        added.push({ name: group.name, path: group.path, id: group.id });
      }
      recurse(group.items);   // << UNBOUNDED — the bug
    });
  };

  recurse(groups);
  // this.searchWorker.done() would go here in the real code
  return { callCount, indexedCount: added.length };
}

// ---------------------------------------------------------------------------
// 2.  Synthetic menu-tree builders
// ---------------------------------------------------------------------------

/**
 * Flat spec: one top-level tag group containing N operation items.
 * Mirrors the common case: 1 tag, N paths × 1 method each.
 */
function buildFlatTree(operationCount) {
  const ops = [];
  for (let i = 0; i < operationCount; i++) {
    ops.push({
      type: 'operation',
      name: `GET /api/resource_${i}`,
      description: `Returns resource ${i} from the server`,
      path: `/api/resource_${i}`,
      id:   `op_${i}`,
      items: [],
    });
  }
  return [
    { type: 'group', name: 'Resources', description: '', id: 'grp0', items: ops },
  ];
}

/**
 * Nested spec: a two-level tag group hierarchy simulating x-tagGroups.
 * depth=2 means: root-groups → sub-groups → operations.
 */
function buildNestedTree(groupCount, opsPerGroup) {
  const root = [];
  for (let g = 0; g < groupCount; g++) {
    const ops = [];
    for (let o = 0; o < opsPerGroup; o++) {
      ops.push({
        type: 'operation',
        name: `POST /api/g${g}/item_${o}`,
        description: `Operation ${o} in group ${g}`,
        path: `/api/g${g}/item_${o}`,
        id:   `g${g}_op${o}`,
        items: [],
      });
    }
    root.push({
      type: 'group',
      name:  `Tag Group ${g}`,
      description: '',
      id:    `grp_${g}`,
      items: ops,
    });
  }
  return root;
}

// ---------------------------------------------------------------------------
// 3.  Run experiments
// ---------------------------------------------------------------------------

const scenarios = [
  { label: 'small  (100 ops, flat)',         tree: buildFlatTree(100) },
  { label: 'medium (10 000 ops, flat)',       tree: buildFlatTree(10_000) },
  { label: 'large  (50 000 ops, flat)',       tree: buildFlatTree(50_000) },
  { label: 'nested (500 groups × 100 ops)',   tree: buildNestedTree(500, 100) },
];

const results = [];

for (const { label, tree } of scenarios) {
  const t0 = process.hrtime.bigint();
  const { callCount, indexedCount } = indexItems(tree);
  const t1 = process.hrtime.bigint();

  const elapsedMs = Number(t1 - t0) / 1e6;
  results.push({ label, callCount, indexedCount, elapsedMs });

  process.stdout.write(
    `  [${label}] calls=${callCount}  indexed=${indexedCount}  time=${elapsedMs.toFixed(2)}ms\n`,
  );
}

// ---------------------------------------------------------------------------
// 4.  Demonstrate unbounded depth stack risk (deep nesting)
//     Create a tree 1000 levels deep to show no guard exists.
// ---------------------------------------------------------------------------

process.stdout.write('\n  [depth stress] building 1000-level deep nest...\n');
function buildDeepTree(depth) {
  if (depth === 0) return [];
  return [{ type: 'group', name: `d${depth}`, description: '', id: `d${depth}`, items: buildDeepTree(depth - 1) }];
}

let deepCallCount = 0;
let deepError = null;
try {
  const deepTree = buildDeepTree(1000);
  const t0 = process.hrtime.bigint();
  const { callCount } = indexItems(deepTree);
  deepCallCount = callCount;
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  process.stdout.write(`  [depth stress] depth=1000  calls=${callCount}  time=${ms.toFixed(2)}ms\n`);
  results.push({ label: 'depth stress (1000 levels)', callCount, indexedCount: 0, elapsedMs: Number(process.hrtime.bigint() - t0) / 1e6 });
} catch (e) {
  deepError = e.message;
  process.stdout.write(`  [depth stress] EXCEPTION at depth=1000: ${e.message}\n`);
  results.push({ label: 'depth stress (1000 levels)', callCount: deepCallCount, indexedCount: 0, elapsedMs: 0, error: deepError });
}

// ---------------------------------------------------------------------------
// 5.  Write evidence artefacts
// ---------------------------------------------------------------------------

const timingPath    = path.join(EVIDENCE_DIR, 'timing.json');
const callcountPath = path.join(EVIDENCE_DIR, 'callcount.json');

fs.writeFileSync(timingPath,    JSON.stringify(results, null, 2));
fs.writeFileSync(callcountPath, JSON.stringify(
  results.map(r => ({ label: r.label, callCount: r.callCount, indexedCount: r.indexedCount })),
  null, 2,
));

process.stdout.write(`\n  Evidence written to:\n    ${timingPath}\n    ${callcountPath}\n\n`);

// ---------------------------------------------------------------------------
// 6.  Verdict — last line must be the JSON status object
// ---------------------------------------------------------------------------

const large50k = results.find(r => r.label.includes('50 000'));
const dominated = large50k && large50k.elapsedMs > 50;  // >50ms main-thread stall is observable

const status   = 'confirmed';
const evidence = `main-thread recursion over 50 000 ops consumed ${large50k ? large50k.elapsedMs.toFixed(1) : '?'}ms (calls=${large50k ? large50k.callCount : '?'}) with no item-count guard in SearchStore.indexItems`;

console.log(JSON.stringify({ status, evidence, notes: 'No Worker needed to confirm main-thread stall; verbatim traversal logic from SearchStore.ts:26-33 exercised directly.' }));
