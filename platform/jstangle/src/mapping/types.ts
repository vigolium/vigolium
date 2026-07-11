/**
 * Framework-Aware Function Mapping Types
 *
 * These types support building a function map BEFORE capturing HTTP requests,
 * allowing us to resolve function parameters from their call sites.
 */

/**
 * A registered function/method definition
 */
export interface FunctionDefinition {
  /** Full qualified name: "CommentsService.getComments" or "downloadFile" */
  fullName: string;

  /** Service name (if method): "CommentsService" */
  serviceName?: string;

  /** Method/function name: "getComments" */
  name: string;

  /** Parameter names in order: ["params"] */
  params: string[];

  /** Start line in source */
  startLine: number;

  /** End line in source */
  endLine: number;

  /**
   * Returned object template (for functions that return objects).
   * Keys are property names, values are either:
   * - "${paramName}" for direct parameter references
   * - literal strings for static values
   * - nested objects for complex structures
   */
  returnedObject?: Record<string, string | Record<string, unknown>>;
}

/**
 * A call site - where a function is called
 */
export interface CallSite {
  /** Function being called: "CommentsService.getComments" */
  targetFunction: string;

  /** Line number of the call */
  line: number;

  /** Arguments passed (resolved values) */
  arguments: ResolvedArgument[];

  /** The function that contains this call site (for nested resolution) */
  containingFunction?: string;
}

/**
 * A resolved argument value
 */
export interface ResolvedArgument {
  /** Index in params list: 0 */
  index: number;

  /** Corresponding param name: "params" */
  paramName: string;

  /** Resolved value (can be object literal or string) */
  value: string | Record<string, string>;

  /** Raw code for deeper resolution if needed */
  rawCode: string;
}

/**
 * Supported frameworks for function mapping
 *
 * Note: Only frameworks with dedicated extractors are included here.
 * - Angular: Uses string-based DI that survives minification (.factory('ServiceName'))
 * - Webpack: Has module system patterns (__webpack_require__, webpackJsonp)
 *
 * React/Vue are NOT included because:
 * - Production bundles are minified (handleSubmit → t, useApi → e)
 * - Function names are lost, making mapping impossible
 * - fetchRequest.ts already detects fetch() calls directly in bundled code
 */
export type Framework = 'angular' | 'webpack' | 'unknown';

/**
 * Global function map containing all function definitions and their call sites
 */
export interface FunctionMap {
  /** Detected framework */
  framework: Framework;

  /** All function definitions: fullName -> FunctionDefinition */
  functions: Map<string, FunctionDefinition>;

  /** All call sites grouped by target function */
  callSites: Map<string, CallSite[]>;
}

/**
 * Context passed when resolving values during request extraction
 */
export interface ResolutionContext {
  /** Current function we're in: "CommentsService.getComments" */
  currentFunction: string;

  /** Line number where the HTTP call is made */
  line: number;
}

/**
 * Method info extracted from a service/class
 */
export interface ExtractedMethod {
  /** Method name */
  name: string;

  /** Parameter names */
  params: string[];

  /** Start line */
  startLine: number;

  /** End line */
  endLine: number;

  /** Returned object template (if function returns an object) */
  returnedObject?: Record<string, string | Record<string, unknown>>;
}
