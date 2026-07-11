/**
 * Framework Detection
 *
 * Detects which JavaScript framework is being used based on code patterns.
 */

import type { Framework } from './types';

/**
 * Framework signature patterns
 *
 * Note: Only frameworks with dedicated extractors are detected here.
 *
 * React/Vue patterns are NOT included because:
 * - Production bundles are minified, function names (handleSubmit, useApi) become single letters
 * - String-based patterns (imports, hooks) are often removed or transformed by bundlers
 * - fetchRequest.ts already detects fetch() calls directly without needing framework context
 * - Angular is different: its DI system uses strings (.factory('ServiceName')) that survive minification
 */
const FRAMEWORK_SIGNATURES: Record<Framework, RegExp[]> = {
  angular: [
    /angular\.module\s*\(/,
    /\.factory\s*\(/,
    /\.service\s*\(/,
    /\.controller\s*\(/,
    /\.directive\s*\(/,
    /\$http/,
    /\$resource/,
    /\$scope/,
    /ng-app/,
    /ng-controller/,
  ],
  webpack: [
    /__webpack_require__/,
    /webpackJsonp/,
    /\/\*\!\s*\*\*\*/,  // Webpack bundle marker
  ],
  unknown: [],
};

/**
 * Minimum number of signature matches required to identify a framework
 */
const MIN_SIGNATURE_MATCHES = 2;

/**
 * Detect the framework used in the source code
 *
 * @param sourceCode - The source code to analyze
 * @returns The detected framework
 */
export function detectFramework(sourceCode: string): Framework {
  const scores: Record<Framework, number> = {
    angular: 0,
    webpack: 0,
    unknown: 0,
  };

  // Count matches for each framework
  for (const [framework, patterns] of Object.entries(FRAMEWORK_SIGNATURES)) {
    if (framework === 'unknown') continue;

    for (const pattern of patterns) {
      if (pattern.test(sourceCode)) {
        scores[framework as Framework]++;
      }
    }
  }

  // Find the framework with the highest score
  let bestFramework: Framework = 'unknown';
  let bestScore = 0;

  for (const [framework, score] of Object.entries(scores)) {
    if (framework === 'unknown') continue;

    if (score > bestScore && score >= MIN_SIGNATURE_MATCHES) {
      bestScore = score;
      bestFramework = framework as Framework;
    }
  }

  return bestFramework;
}

/**
 * Check if the code is likely Angular
 */
export function isAngular(sourceCode: string): boolean {
  return detectFramework(sourceCode) === 'angular';
}

/**
 * Check if the code is a Webpack bundle
 */
export function isWebpack(sourceCode: string): boolean {
  return detectFramework(sourceCode) === 'webpack';
}

/** Cheap gate for the much heavier module-graph traversal. */
export function hasWebpackStructureSignal(sourceCode: string): boolean {
  return /(?:__webpack_require__|webpackJsonp|webpackChunk|\.push\s*\(\s*\[\s*\[)/.test(sourceCode) ||
    /\b(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*\{\s*["']?\d+["']?\s*:\s*(?:function|\(?[\w$,.\s]+\)?\s*=>)/.test(sourceCode) ||
    /\[\s*function\s*\([^)]*\)\s*\{/.test(sourceCode);
}

/**
 * Get all framework scores for debugging
 */
export function getFrameworkScores(sourceCode: string): Record<Framework, number> {
  const scores: Record<Framework, number> = {
    angular: 0,
    webpack: 0,
    unknown: 0,
  };

  for (const [framework, patterns] of Object.entries(FRAMEWORK_SIGNATURES)) {
    if (framework === 'unknown') continue;

    for (const pattern of patterns) {
      if (pattern.test(sourceCode)) {
        scores[framework as Framework]++;
      }
    }
  }

  return scores;
}
