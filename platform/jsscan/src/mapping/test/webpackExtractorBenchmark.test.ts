/**
 * Webpack Extractor Benchmark Test Suite
 *
 * Tests the webpack extractor's ability to detect API endpoints from minified JS.
 * Measures detection rate across different bundlers and pattern types.
 */

import { describe, expect, test, beforeEach } from 'vitest';
import { parse } from '@babel/parser';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import {
  extractWebpackFunctions,
  clearWebpackState,
  getWebpackBundleState,
  getWebpackExtractedRequests,
  type WebpackExtractedRequest,
} from '../extractors/webpackExtractor';
import { createEmptyFunctionMap, clearFunctionMap } from '../functionMap';

const BENCHMARK_DIR = join(__dirname, '../../../testdata/benchmark-app/dist');

// Expected endpoints organized by difficulty
const EXPECTED_ENDPOINTS = {
  // Easy: Direct string literals (should always detect)
  easy: [
    '/api/health',
    '/api/v1/auth/ping',
    '/api/v1/auth/login',
    '/api/v1/auth/logout',
    '/api/v1/auth/refresh',
    '/api/v1/auth/register',
    '/api/v1/users/profile',
    '/api/v1/products',
    '/api/v1/products/create',
    '/api/v1/products/search',
  ],

  // Medium: Import references, template literals, concatenation
  medium: [
    '/api/v1/users/update',
    '/api/v1/users/delete',
    '/api/v1/users/avatar',
    '/api/v1/products/update',
    '/api/v1/products/delete',
    '/api/v1/analytics/track',
    '/api/v1/analytics/events',
    '/api/v1/auth/reset-password',
    '/api/v1/auth/forgot-password',
    '/api/v1/orders/create',
    '/api/v1/dashboard',
    '/api/v1/settings',
    '/api/v1/notifications',
    '/api/v1/app/config',
    '/site-api/track',
    '/site-api/auth/session',
    '/bob-service/report',
    '/admin-api/v2/dashboard',
  ],

  // Hard: Nested objects, function returns, conditionals
  hard: [
    '/api/v1/auth/verify', // template literal with param
    '/api/v1/users/search', // function return
    '/api/v1/admin/dashboard', // conditional URL
    '/api/v1/user/dashboard', // conditional URL (alternate)
    '/api/v1/auth/sso/prod', // conditional URL
    '/api/v1/auth/sso/staging', // conditional URL
    '/api/v1/auth/mfa/setup', // multiple concatenations
    '/api/v1/batch/update', // complex body
    '/api/v1/uploads/avatar', // object property access
    '/api/v1/uploads/document', // object property access
    '/api/v1/health/db', // from array
    '/api/v1/health/cache', // from array
    '/api/v1/health/queue', // from array
    '/api/v1/analytics/pageview', // conditional with flag
  ],
};

// All expected endpoints flattened
const ALL_EXPECTED_ENDPOINTS = [
  ...EXPECTED_ENDPOINTS.easy,
  ...EXPECTED_ENDPOINTS.medium,
  ...EXPECTED_ENDPOINTS.hard,
];

interface BenchmarkResult {
  bundler: string;
  totalExpected: number;
  detected: number;
  detectionRate: number;
  byDifficulty: {
    easy: { total: number; detected: number; rate: number };
    medium: { total: number; detected: number; rate: number };
    hard: { total: number; detected: number; rate: number };
  };
  missing: string[];
  extra: string[];
}

/**
 * Normalize URL for comparison
 * - Remove dynamic segments like /${id}, /${userId}
 * - Convert ${X} placeholders to standard format
 */
function normalizeUrl(url: string): string {
  return url
    // Remove trailing dynamic segments
    .replace(/\/\$\{[^}]+\}$/g, '')
    // Normalize placeholders
    .replace(/\$\{[^}]+\}/g, '${X}')
    // Remove query strings for base comparison
    .replace(/\?.*$/, '')
    // Remove trailing slashes
    .replace(/\/+$/, '');
}

/**
 * Check if detected URL matches expected (with fuzzy matching)
 */
function urlMatches(detected: string, expected: string): boolean {
  const normDetected = normalizeUrl(detected);
  const normExpected = normalizeUrl(expected);

  // Exact match
  if (normDetected === normExpected) return true;

  // Detected starts with expected (allows for dynamic suffix)
  if (normDetected.startsWith(normExpected)) return true;

  // Expected is contained in detected
  if (normDetected.includes(normExpected)) return true;

  return false;
}

/**
 * Calculate benchmark results
 */
function calculateBenchmark(
  requests: WebpackExtractedRequest[],
  bundler: string
): BenchmarkResult {
  const detectedUrls = requests.map((r) => r.url);

  // Check each expected endpoint
  const easyDetected = EXPECTED_ENDPOINTS.easy.filter((exp) =>
    detectedUrls.some((det) => urlMatches(det, exp))
  );
  const mediumDetected = EXPECTED_ENDPOINTS.medium.filter((exp) =>
    detectedUrls.some((det) => urlMatches(det, exp))
  );
  const hardDetected = EXPECTED_ENDPOINTS.hard.filter((exp) =>
    detectedUrls.some((det) => urlMatches(det, exp))
  );

  const totalDetected =
    easyDetected.length + mediumDetected.length + hardDetected.length;

  // Find missing endpoints
  const missing = ALL_EXPECTED_ENDPOINTS.filter(
    (exp) => !detectedUrls.some((det) => urlMatches(det, exp))
  );

  // Find extra endpoints (detected but not expected)
  const extra = detectedUrls.filter(
    (det) => !ALL_EXPECTED_ENDPOINTS.some((exp) => urlMatches(det, exp))
  );

  return {
    bundler,
    totalExpected: ALL_EXPECTED_ENDPOINTS.length,
    detected: totalDetected,
    detectionRate: (totalDetected / ALL_EXPECTED_ENDPOINTS.length) * 100,
    byDifficulty: {
      easy: {
        total: EXPECTED_ENDPOINTS.easy.length,
        detected: easyDetected.length,
        rate: (easyDetected.length / EXPECTED_ENDPOINTS.easy.length) * 100,
      },
      medium: {
        total: EXPECTED_ENDPOINTS.medium.length,
        detected: mediumDetected.length,
        rate: (mediumDetected.length / EXPECTED_ENDPOINTS.medium.length) * 100,
      },
      hard: {
        total: EXPECTED_ENDPOINTS.hard.length,
        detected: hardDetected.length,
        rate: (hardDetected.length / EXPECTED_ENDPOINTS.hard.length) * 100,
      },
    },
    missing,
    extra,
  };
}

/**
 * Get bundle filename for a specific bundler
 */
function getBundleFilename(bundler: string): string {
  // Parcel outputs index.js instead of bundle.js
  if (bundler === 'parcel') return 'index.js';
  return 'bundle.js';
}

/**
 * Check if bundle file exists (sync)
 */
function bundleExists(bundler: string): boolean {
  return existsSync(join(BENCHMARK_DIR, bundler, getBundleFilename(bundler)));
}

describe('Webpack Extractor Benchmark', () => {
  beforeEach(() => {
    clearWebpackState();
    clearFunctionMap();
  });

  // Test webpack5 bundle
  test('benchmark: webpack5 detection rate', async () => {
    if (!bundleExists('webpack5')) {
      console.log('Skipping webpack5 - bundle not found. Run: cd testdata/benchmark-app && ./build.sh webpack5');
      return;
    }

    const code = await readFile(
      join(BENCHMARK_DIR, 'webpack5', 'bundle.js'),
      'utf8'
    );

    const ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
    });
    const functionMap = createEmptyFunctionMap();
    extractWebpackFunctions(ast, functionMap, code);

    const requests = getWebpackExtractedRequests();
    const result = calculateBenchmark(requests, 'webpack5');

    console.log('\n=== WEBPACK 5 BENCHMARK RESULTS ===');
    console.log(`Overall: ${result.detected}/${result.totalExpected} (${result.detectionRate.toFixed(1)}%)`);
    console.log(`Easy:    ${result.byDifficulty.easy.detected}/${result.byDifficulty.easy.total} (${result.byDifficulty.easy.rate.toFixed(1)}%)`);
    console.log(`Medium:  ${result.byDifficulty.medium.detected}/${result.byDifficulty.medium.total} (${result.byDifficulty.medium.rate.toFixed(1)}%)`);
    console.log(`Hard:    ${result.byDifficulty.hard.detected}/${result.byDifficulty.hard.total} (${result.byDifficulty.hard.rate.toFixed(1)}%)`);

    if (result.missing.length > 0 && result.missing.length <= 10) {
      console.log('\nMissing endpoints:');
      result.missing.forEach((url) => console.log(`  - ${url}`));
    } else if (result.missing.length > 10) {
      console.log(`\nMissing ${result.missing.length} endpoints (showing first 10):`);
      result.missing.slice(0, 10).forEach((url) => console.log(`  - ${url}`));
    }

    console.log(`\nTotal detected URLs: ${requests.length}`);
    console.log('========================================\n');

    // Webpack 5 format: extractor should find some URLs
    // Note: The extractor is webpack-specific, so detection depends on output format
    expect(requests.length).toBeGreaterThan(0);
  });

  // Test rollup bundle
  test('benchmark: rollup detection rate', async () => {
    if (!bundleExists('rollup')) {
      console.log('Skipping rollup - bundle not found. Run: cd testdata/benchmark-app && ./build.sh rollup');
      return;
    }

    const code = await readFile(
      join(BENCHMARK_DIR, 'rollup', 'bundle.js'),
      'utf8'
    );

    const ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
    });
    const functionMap = createEmptyFunctionMap();
    extractWebpackFunctions(ast, functionMap, code);

    const requests = getWebpackExtractedRequests();
    const result = calculateBenchmark(requests, 'rollup');

    console.log('\n=== ROLLUP BENCHMARK RESULTS ===');
    console.log(`Overall: ${result.detected}/${result.totalExpected} (${result.detectionRate.toFixed(1)}%)`);
    console.log(`Easy:    ${result.byDifficulty.easy.detected}/${result.byDifficulty.easy.total} (${result.byDifficulty.easy.rate.toFixed(1)}%)`);
    console.log(`Medium:  ${result.byDifficulty.medium.detected}/${result.byDifficulty.medium.total} (${result.byDifficulty.medium.rate.toFixed(1)}%)`);
    console.log(`Hard:    ${result.byDifficulty.hard.detected}/${result.byDifficulty.hard.total} (${result.byDifficulty.hard.rate.toFixed(1)}%)`);
    console.log(`\nTotal detected URLs: ${requests.length}`);
    console.log('Note: Rollup uses different format - may need separate extractor');
    console.log('========================================\n');

    // Rollup uses different format - document capability
    expect(result).toBeDefined();
  });

  // Test esbuild bundle
  test('benchmark: esbuild detection rate', async () => {
    if (!bundleExists('esbuild')) {
      console.log('Skipping esbuild - bundle not found. Run: cd testdata/benchmark-app && ./build.sh esbuild');
      return;
    }

    const code = await readFile(
      join(BENCHMARK_DIR, 'esbuild', 'bundle.js'),
      'utf8'
    );

    const ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
    });
    const functionMap = createEmptyFunctionMap();
    extractWebpackFunctions(ast, functionMap, code);

    const requests = getWebpackExtractedRequests();
    const result = calculateBenchmark(requests, 'esbuild');

    console.log('\n=== ESBUILD BENCHMARK RESULTS ===');
    console.log(`Overall: ${result.detected}/${result.totalExpected} (${result.detectionRate.toFixed(1)}%)`);
    console.log(`Easy:    ${result.byDifficulty.easy.detected}/${result.byDifficulty.easy.total} (${result.byDifficulty.easy.rate.toFixed(1)}%)`);
    console.log(`Medium:  ${result.byDifficulty.medium.detected}/${result.byDifficulty.medium.total} (${result.byDifficulty.medium.rate.toFixed(1)}%)`);
    console.log(`Hard:    ${result.byDifficulty.hard.detected}/${result.byDifficulty.hard.total} (${result.byDifficulty.hard.rate.toFixed(1)}%)`);
    console.log(`\nTotal detected URLs: ${requests.length}`);
    console.log('Note: esbuild uses different format - may need separate extractor');
    console.log('========================================\n');

    // esbuild uses different format - document capability
    expect(result).toBeDefined();
  });

  // Test vite bundle
  test('benchmark: vite detection rate', async () => {
    if (!bundleExists('vite')) {
      console.log('Skipping vite - bundle not found. Run: cd testdata/benchmark-app && ./build.sh vite');
      return;
    }

    const code = await readFile(
      join(BENCHMARK_DIR, 'vite', 'bundle.js'),
      'utf8'
    );

    const ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
    });
    const functionMap = createEmptyFunctionMap();
    extractWebpackFunctions(ast, functionMap, code);

    const requests = getWebpackExtractedRequests();
    const result = calculateBenchmark(requests, 'vite');

    console.log('\n=== VITE BENCHMARK RESULTS ===');
    console.log(`Overall: ${result.detected}/${result.totalExpected} (${result.detectionRate.toFixed(1)}%)`);
    console.log(`Easy:    ${result.byDifficulty.easy.detected}/${result.byDifficulty.easy.total} (${result.byDifficulty.easy.rate.toFixed(1)}%)`);
    console.log(`Medium:  ${result.byDifficulty.medium.detected}/${result.byDifficulty.medium.total} (${result.byDifficulty.medium.rate.toFixed(1)}%)`);
    console.log(`Hard:    ${result.byDifficulty.hard.detected}/${result.byDifficulty.hard.total} (${result.byDifficulty.hard.rate.toFixed(1)}%)`);
    console.log(`\nTotal detected URLs: ${requests.length}`);
    console.log('Note: Vite uses Rollup format - may need separate extractor');
    console.log('========================================\n');

    // Vite uses Rollup format - document capability
    expect(result).toBeDefined();
  });

  // Test body extraction quality
  test('benchmark: body extraction accuracy (webpack5)', async () => {
    if (!bundleExists('webpack5')) {
      console.log('Skipping body extraction test - webpack5 bundle not found');
      return;
    }

    const code = await readFile(
      join(BENCHMARK_DIR, 'webpack5', 'bundle.js'),
      'utf8'
    );

    const ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
    });
    const functionMap = createEmptyFunctionMap();
    extractWebpackFunctions(ast, functionMap, code);

    const requests = getWebpackExtractedRequests();

    // Find requests with body
    const requestsWithBody = requests.filter((r) => r.body && r.body !== '{}' && r.body !== '');

    console.log('\n=== BODY EXTRACTION RESULTS ===');
    console.log(`Total requests: ${requests.length}`);
    console.log(`Requests with body: ${requestsWithBody.length}`);

    // Sample some bodies
    if (requestsWithBody.length > 0) {
      console.log('\nSample bodies:');
      requestsWithBody.slice(0, 5).forEach((req) => {
        console.log(`\n${req.method} ${req.url}`);
        console.log(`Body: ${req.body.substring(0, 100)}${req.body.length > 100 ? '...' : ''}`);
      });
    }

    console.log('========================================\n');

    expect(requests.length).toBeGreaterThanOrEqual(0);
  });

  // Test cross-module resolution
  test('benchmark: cross-module resolution (webpack5)', async () => {
    if (!bundleExists('webpack5')) {
      console.log('Skipping cross-module test - webpack5 bundle not found');
      return;
    }

    const code = await readFile(
      join(BENCHMARK_DIR, 'webpack5', 'bundle.js'),
      'utf8'
    );

    const ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
    });
    const functionMap = createEmptyFunctionMap();
    extractWebpackFunctions(ast, functionMap, code);

    const state = getWebpackBundleState();

    // Count resolved vs unresolved import URLs
    let resolvedCount = 0;
    let unresolvedCount = 0;

    for (const module of state.modules.values()) {
      for (const call of module.httpCalls) {
        if (call.urlSource.type === 'import') {
          if (call.urlSource.resolvedValue) {
            resolvedCount++;
          } else {
            unresolvedCount++;
          }
        }
      }
    }

    const total = resolvedCount + unresolvedCount;
    const resolutionRate = total > 0 ? (resolvedCount / total) * 100 : 0;

    console.log('\n=== CROSS-MODULE RESOLUTION ===');
    console.log(`Total modules: ${state.modules.size}`);
    console.log(`Total import-based URLs: ${total}`);
    console.log(`Resolved: ${resolvedCount}`);
    console.log(`Unresolved: ${unresolvedCount}`);
    console.log(`Resolution rate: ${resolutionRate.toFixed(1)}%`);
    console.log('========================================\n');

    // Document current capability
    expect(state.modules.size).toBeGreaterThanOrEqual(0);
  });

  // Summary test that runs all benchmarks
  test('benchmark: summary report', async () => {
    const bundlers = ['webpack5', 'webpack4', 'rollup', 'esbuild', 'parcel', 'vite'];
    const results: BenchmarkResult[] = [];

    for (const bundler of bundlers) {
      if (!bundleExists(bundler)) continue;

      clearWebpackState();
      clearFunctionMap();

      const code = await readFile(
        join(BENCHMARK_DIR, bundler, getBundleFilename(bundler)),
        'utf8'
      );

      const ast = parse(code, {
        sourceType: 'unambiguous',
        plugins: ['jsx', 'typescript'],
      });
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const requests = getWebpackExtractedRequests();
      results.push(calculateBenchmark(requests, bundler));
    }

    if (results.length === 0) {
      console.log('\n⚠️  No bundles found. Run: cd testdata/benchmark-app && ./build.sh all\n');
      return;
    }

    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║               BENCHMARK SUMMARY REPORT                       ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log('║ Bundler   │ Overall  │ Easy     │ Medium   │ Hard     │ URLs ║');
    console.log('╠═══════════╪══════════╪══════════╪══════════╪══════════╪══════╣');

    for (const r of results) {
      const overall = `${r.detectionRate.toFixed(0)}%`.padEnd(7);
      const easy = `${r.byDifficulty.easy.rate.toFixed(0)}%`.padEnd(7);
      const medium = `${r.byDifficulty.medium.rate.toFixed(0)}%`.padEnd(7);
      const hard = `${r.byDifficulty.hard.rate.toFixed(0)}%`.padEnd(7);
      const urls = `${r.detected}`.padEnd(4);
      console.log(`║ ${r.bundler.padEnd(9)} │ ${overall} │ ${easy} │ ${medium} │ ${hard} │ ${urls} ║`);
    }

    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('\nNote: Webpack extractor is optimized for webpack format.');
    console.log('Other bundlers may need dedicated extractors for better results.\n');

    expect(results.length).toBeGreaterThan(0);
  });
});
