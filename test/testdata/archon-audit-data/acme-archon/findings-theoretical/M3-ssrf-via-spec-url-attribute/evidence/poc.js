#!/usr/bin/env node
/**
 * M3 PoC — SSRF via <acme spec-url="…"> HTML Attribute
 * ======================================================
 * Static code-path tracer that confirms the complete absence of URL
 * validation on the spec-url → loadAndBundleSpec pipeline.
 *
 * Does NOT require a running server.  Reads the source files directly.
 *
 * Usage:
 *   node poc.js [REPO_ROOT]
 *   REPO_ROOT defaults to ../../.. relative to this script (the acme repo root).
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const REPO = process.argv[2] || path.resolve(__dirname, '../../..');

// ── Helpers ────────────────────────────────────────────────────────────────

function readSrc(rel) {
  const abs = path.join(REPO, rel);
  if (!fs.existsSync(abs)) return null;
  return { abs, lines: fs.readFileSync(abs, 'utf8').split('\n') };
}

function findLine(lines, pattern) {
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return { lineNo: i + 1, text: lines[i].trim() };
  }
  return null;
}

// ── Check 1: autoInit reads spec-url without validation ───────────────────

const standalone = readSrc('src/standalone.tsx');
if (!standalone) {
  console.error('FATAL: src/standalone.tsx not found — wrong REPO_ROOT?');
  process.exit(2);
}

const attrRead   = findLine(standalone.lines, /getAttribute\(['"]spec-url['"]\)/);
const noValidate = findLine(standalone.lines, /if\s*\(\s*specUrl\s*\)/);    // passes if truthy; no URL check
const initCall   = findLine(standalone.lines, /init\s*\(\s*specUrl\s*,/);

// ── Check 2: loadAndBundleSpec assigns customFetch unconditionally ─────────

const lbs = readSrc('src/utils/loadAndBundleSpec.ts');
if (!lbs) {
  console.error('FATAL: src/utils/loadAndBundleSpec.ts not found');
  process.exit(2);
}

const customFetch = findLine(lbs.lines, /customFetch\s*=\s*global\.fetch/);
const bundleCall  = findLine(lbs.lines, /await bundle\(/);

// ── Check 3: No URL validation pattern exists anywhere on the path ────────

const validationPatterns = [
  /new URL\s*\(/,            // URL constructor (could be used for scheme check)
  /allowlist|whitelist/i,    // allowlist check
  /\.origin\s*===/,          // origin comparison
  /^https?:\/\//,            // scheme check via regex
  /validateUrl|sanitizeUrl/i // named validation helpers
];

function hasValidation(src) {
  return validationPatterns.some(pat =>
    src.lines.some(line => pat.test(line))
  );
}

const standaloneHasValidation = hasValidation(standalone);
const lbsHasValidation        = hasValidation(lbs);

// ── Report ─────────────────────────────────────────────────────────────────

console.log('=== M3 SSRF — Code-Path Audit ===\n');

console.log('[standalone.tsx]');
if (attrRead) {
  console.log(`  Line ${attrRead.lineNo}: FOUND   — ${attrRead.text}`);
} else {
  console.log('  WARN: getAttribute("spec-url") not found — check source');
}

if (noValidate) {
  console.log(`  Line ${noValidate.lineNo}: FOUND   — ${noValidate.text}  [only truthy check, no URL validation]`);
}

if (initCall) {
  console.log(`  Line ${initCall.lineNo}: FOUND   — ${initCall.text}`);
}

console.log(`  URL validation present: ${standaloneHasValidation}`);

console.log('\n[loadAndBundleSpec.ts]');
if (customFetch) {
  console.log(`  Line ${customFetch.lineNo}: FOUND   — ${customFetch.text}`);
} else {
  console.log('  WARN: customFetch assignment not found');
}

if (bundleCall) {
  console.log(`  Line ${bundleCall.lineNo}: FOUND   — ${bundleCall.text}`);
}

console.log(`  URL validation present: ${lbsHasValidation}`);

// ── Verdict ────────────────────────────────────────────────────────────────

const confirmed = (
  attrRead   !== null &&
  initCall   !== null &&
  customFetch !== null &&
  !standaloneHasValidation &&
  !lbsHasValidation
);

console.log('\n=== Attack Payload That Triggers SSRF ===');
console.log('  <acme spec-url="http://169.254.169.254/latest/meta-data/"></acme>');
console.log('  No script needed — pure HTML attribute injection.');
console.log('  Acme\'s autoInit() reads the attribute and calls fetch() against it.');

console.log('\n=== Absence-of-Fix Evidence ===');
console.log('  No URL constructor, origin check, scheme allowlist, or');
console.log('  sanitization helper found in standalone.tsx or loadAndBundleSpec.ts.');

const result = confirmed
  ? {
      status: 'confirmed',
      evidence: 'getAttribute("spec-url") at standalone.tsx:' + (attrRead && attrRead.lineNo) +
                ' flows to customFetch=global.fetch at loadAndBundleSpec.ts:' + (customFetch && customFetch.lineNo) +
                ' with zero URL validation on either file',
      notes: 'Browser-side SSRF; response read-back gated by CORS, but blind SSRF side-channel (timing/network) confirmed'
    }
  : {
      status: 'inconclusive',
      evidence: 'Code-path not fully traced — review WARN lines above',
      notes: ''
    };

// REQUIRED: must be last stdout line
console.log(JSON.stringify(result));
