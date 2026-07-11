/**
 * Framework-Aware Function Mapping
 *
 * This module provides functionality to build a function map BEFORE
 * request pattern extraction, enabling resolution of function parameters
 * from their call sites.
 */

export * from './types';
export {
  buildFunctionMap,
  getFunctionMap,
  clearFunctionMap,
  resolveFromFunctionMap,
  resolveMethodCall,
  getCallSites,
  getCallSiteCount,
  getEffectiveIterations,
  hasFunction,
  getFunction,
  debugPrintFunctionMap,
  setMaxResolutionDepth,
  getMaxResolutionDepth,
  type EffectiveIteration,
} from './functionMap';
export { detectFramework, isAngular, isWebpack } from './frameworkDetector';
export {
  resolveWebpackReference,
  getWebpackModuleMap,
  getWebpackBundleState,
  getWebpackExtractedRequests,
  debugPrintWebpackModules,
  type WebpackModule,
  type WebpackExport,
  type WebpackImport,
  type WebpackHttpCall,
  type WebpackBundleState,
  type WebpackExtractedRequest,
  type ResolvedExportValue,
  type UrlSource,
  type BodySource,
} from './extractors/webpackExtractor';
