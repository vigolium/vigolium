/**
 * Webpack Function Extractor
 *
 * Extracts full module mapping from webpack bundles for API endpoint discovery.
 * Supports Webpack 4 and 5 bundle formats.
 *
 * Key capabilities:
 * - Module parsing (IIFE and push patterns)
 * - Export extraction with value resolution
 * - Import tracking with usage analysis
 * - HTTP call detection (axios, fetch, $http)
 * - Cross-module reference resolution
 */

import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import { traverse } from '../../ast-utils/babel';
import type { NodePath } from '../../ast-utils/babel';
import type { FunctionMap, FunctionDefinition } from '../types';

// =============================================================================
// Types
// =============================================================================

/**
 * Resolved export value types
 */
export type ResolvedExportValue =
  | { type: 'string'; value: string }
  | { type: 'object'; value: Record<string, unknown> }
  | { type: 'array'; value: unknown[] }
  | { type: 'function'; params: string[] }
  | { type: 'unresolved'; placeholder: string };

/**
 * Webpack export definition
 */
export interface WebpackExport {
  name: string;
  localName?: string;
  valueNode: t.Node | null;
  resolvedValue?: ResolvedExportValue;
  exportType: 'named' | 'default' | 'reexport';
}

/**
 * Import usage tracking
 */
export interface ImportUsage {
  accessPath: string[];
  line: number;
  context: string;
}

/**
 * Webpack import reference
 */
export interface WebpackImport {
  moduleId: string | number;
  localVar: string;
  usages: ImportUsage[];
}

/**
 * URL source in HTTP call
 */
export interface UrlSource {
  type: 'literal' | 'import' | 'variable' | 'template' | 'concatenation' | 'conditional';
  value: string;
  importPath?: string[];
  resolvedValue?: string;
  alternatives?: string[]; // For conditional URLs (e.g., cond ? url1 : url2)
}

/**
 * Body source in HTTP call
 */
export interface BodySource {
  type: 'literal' | 'object' | 'variable';
  value: string | Record<string, unknown>;
}

/**
 * HTTP call detected within a webpack module
 */
export interface WebpackHttpCall {
  moduleId: string | number;
  clientVar: string;
  clientAccessPath: string[];
  method: string;
  urlSource: UrlSource;
  bodySource?: BodySource;
  line: number;
}

/**
 * Webpack module representation
 */
export interface WebpackModule {
  id: string | number;
  chunkId?: number;
  exportsVar: string;
  moduleVar: string;
  requireVar: string;
  body: t.BlockStatement | t.Expression;
  exports: WebpackExport[];
  imports: WebpackImport[];
  httpCalls: WebpackHttpCall[];
  localVars: Map<string, t.Node>;
}

/**
 * Import resolution entry
 */
export interface ImportResolutionEntry {
  moduleId: string | number;
  contextModuleId: string | number;
  localVar: string;
}

/**
 * Full webpack bundle state
 */
export interface WebpackBundleState {
  modules: Map<string | number, WebpackModule>;
  importResolution: Map<string, ImportResolutionEntry>;
  publicPath?: string;
}

// =============================================================================
// Global State
// =============================================================================

let bundleState: WebpackBundleState = createEmptyBundleState();

function createEmptyBundleState(): WebpackBundleState {
  return {
    modules: new Map(),
    importResolution: new Map(),
  };
}

/**
 * Clear webpack state
 */
export function clearWebpackState(): void {
  bundleState = createEmptyBundleState();
  endpointDictionary = new Map();
}

/**
 * Get webpack module map (for compatibility)
 */
export function getWebpackModuleMap(): Map<string | number, WebpackModule> {
  return bundleState.modules;
}

/**
 * Get full webpack bundle state
 */
export function getWebpackBundleState(): WebpackBundleState {
  return bundleState;
}

/**
 * Get endpoint dictionary (for debugging)
 */
export function getEndpointDictionary(): Map<string, string> {
  return endpointDictionary;
}

// =============================================================================
// Main Entry Point
// =============================================================================

/**
 * Extract webpack function definitions from AST
 *
 * Supports both webpack bundles and generic bundles (rollup, esbuild, vite, parcel).
 * For webpack bundles, uses module-based extraction.
 * For non-webpack bundles, falls back to generic AST traversal.
 */
export function extractWebpackFunctions(
  ast: ParseResult<t.File>,
  functionMap: FunctionMap,
  _sourceCode: string
): void {
  clearWebpackState();

  // Step 1: Parse webpack bundle structure
  parseWebpackBundle(ast);

  // Step 2: Extract HTTP calls
  if (bundleState.modules.size === 0) {
    // No webpack modules found - check if this is a bundled code (rollup, esbuild, vite, parcel)
    // Only use generic extraction for actual bundled code, not simple scripts
    // This prevents duplicate extraction when requestpattern module already handles simple fetch calls
    if (looksLikeBundledCode(ast)) {
      extractHttpCallsGeneric(ast);
    }
  } else {
    // Webpack bundle - extract from each module
    for (const module of bundleState.modules.values()) {
      extractHttpCalls(module);
    }
  }

  // Step 3: Build import resolution map
  buildImportResolutionMap();

  // Step 4: Resolve cross-module references
  resolveImportChains();

  // Step 5: Register in function map
  registerWebpackFunctions(functionMap);
}

// =============================================================================
// Bundle Parsing
// =============================================================================

/**
 * Check if the code looks like bundled code.
 *
 * Detects these bundled code patterns:
 * 1. IIFE wrapper: (function(){...})() or (()=>{...})()
 * 2. UMD pattern: !function(t,e){...}(this, function(){...})
 * 3. Parcel bundle: var $hash$export, function $parcel$...(), require("...")
 *
 * Does NOT trigger for:
 * - Simple fetch() calls without bundle wrapping
 * - Regular scripts with a few function declarations
 */
function looksLikeBundledCode(ast: ParseResult<t.File>): boolean {
  const body = ast.program.body;
  if (body.length === 0) return false;

  // Check for Parcel bundle patterns FIRST (before IIFE check)
  // Parcel bundles have many top-level statements but distinctive naming
  if (isParcelBundle(body)) {
    return true;
  }

  // For IIFE/UMD patterns, we need fewer top-level statements
  if (body.length > 5) return false;

  for (const stmt of body) {
    if (t.isExpressionStatement(stmt)) {
      const expr = stmt.expression;

      // Pattern 1: Direct IIFE call - (function(){...})() or (()=>{...})()
      if (t.isCallExpression(expr)) {
        const callee = expr.callee;
        if (t.isFunctionExpression(callee) || t.isArrowFunctionExpression(callee)) {
          const fnBody = callee.body;
          if (t.isBlockStatement(fnBody) && fnBody.body.length > 10) {
            return true;
          }
        }
      }

      // Pattern 2: UMD pattern - !function(t,e){...}(...)
      if (t.isUnaryExpression(expr) && expr.operator === '!' && t.isCallExpression(expr.argument)) {
        const call = expr.argument;
        if (t.isFunctionExpression(call.callee) || t.isArrowFunctionExpression(call.callee)) {
          return true;
        }
      }
    }

    // Pattern 3: var X = (function(){...})() or var X = (()=>{...})()
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isCallExpression(decl.init)) {
          const callee = decl.init.callee;
          if (t.isFunctionExpression(callee) || t.isArrowFunctionExpression(callee)) {
            const fnBody = callee.body;
            if (t.isBlockStatement(fnBody) && fnBody.body.length > 10) {
              return true;
            }
          }
        }
      }
    }
  }

  return false;
}

/**
 * Check if the code is a Parcel bundle.
 *
 * Parcel bundles have distinctive patterns:
 * - var $hash$varname = require("module")
 * - function $parcel$defineInteropFlag(a) {...}
 * - function $parcel$export(e, n, v, s) {...}
 * - $parcel$export(module.exports, "name", () => ...)
 * - Variable names with $hash$export$ pattern
 */
function isParcelBundle(body: t.Statement[]): boolean {
  let parcelPatternCount = 0;

  for (const stmt of body) {
    // Check for $parcel$ function declarations
    if (t.isFunctionDeclaration(stmt) && t.isIdentifier(stmt.id)) {
      if (stmt.id.name.startsWith('$parcel$')) {
        parcelPatternCount++;
      }
    }

    // Check for var $hash$name = require(...) or var $hash$name = ...
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isIdentifier(decl.id)) {
          // Pattern: $xxxxx$yyy where xxxxx is a hash
          if (/^\$[a-zA-Z0-9]+\$/.test(decl.id.name)) {
            parcelPatternCount++;
          }
        }
      }
    }

    // Check for $parcel$export(...) or $parcel$defineInteropFlag(...) calls
    if (t.isExpressionStatement(stmt) && t.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.callee;
      if (t.isIdentifier(callee) && callee.name.startsWith('$parcel$')) {
        parcelPatternCount++;
      }
    }

    // Early exit if we've found enough evidence
    if (parcelPatternCount >= 3) {
      return true;
    }
  }

  return false;
}

/**
 * Parse webpack bundle with improved pattern detection
 */
function parseWebpackBundle(ast: ParseResult<t.File>): void {
  traverse(ast, {
    CallExpression(path) {
      const node = path.node;

      // Pattern 1: Webpack 5 push pattern
      // (self.webpackChunk...||[]).push([[178],{7917:(e,l,t)=>{...}}])
      if (isWebpack5PushPattern(node)) {
        extractFromPushPattern(node);
        return;
      }

      // Pattern 2: Webpack IIFE pattern
      // (()=>{var e={4850:(e,t,n)=>{...},...}})()
      if (isWebpackIIFE(node)) {
        extractFromIIFE(node);
        return;
      }

      // Pattern 3: Webpack 4 jsonp pattern
      // (window.webpackJsonp=window.webpackJsonp||[]).push([[],{...}])
      if (isWebpack4JsonpPattern(node)) {
        extractFromPushPattern(node);
        return;
      }
    },

    // Pattern 4: UnaryExpression IIFE - !function(e){...}({...})
    UnaryExpression(path) {
      const node = path.node;
      if (node.operator === '!' && t.isCallExpression(node.argument)) {
        const call = node.argument;
        if (t.isFunctionExpression(call.callee)) {
          // Check if argument is modules object or array
          if (call.arguments.length >= 1) {
            const arg = call.arguments[0];
            if (t.isObjectExpression(arg) && looksLikeWebpackModulesObject(arg)) {
              extractModulesFromObject(arg);
            } else if (t.isArrayExpression(arg) && looksLikeWebpackModulesArray(arg)) {
              extractModulesFromArray(arg);
            }
          }

          // Pattern 4b: UMD wrapper - !function(t,e){...}(this, ()=>( (()=>{...})() ))
          // The second argument is an arrow function returning an inner IIFE
          if (call.arguments.length >= 2) {
            const secondArg = call.arguments[1];
            if (t.isArrowFunctionExpression(secondArg)) {
              // Check if arrow body is a CallExpression (inner IIFE invocation)
              if (t.isCallExpression(secondArg.body)) {
                const innerCall = secondArg.body;
                // Check if the inner callee is also an arrow function (the actual IIFE)
                if (t.isArrowFunctionExpression(innerCall.callee)) {
                  const innerIIFE = innerCall.callee;
                  if (t.isBlockStatement(innerIIFE.body)) {
                    extractModulesFromBlockStatement(innerIIFE.body);
                  }
                }
              }
            }
          }
        }
      }
    },

    // Pattern 5: Webpack 4 UMD return pattern
    // return (function(modules) { ... })([/* 0 */..., /* 1 */...])
    ReturnStatement(path) {
      const node = path.node;
      if (!node.argument || !t.isCallExpression(node.argument)) return;

      const call = node.argument;
      // Check if callee is a FunctionExpression (the webpack bootstrap)
      if (!t.isFunctionExpression(call.callee)) return;

      // Check if first param is named 'modules'
      const fn = call.callee;
      if (fn.params.length === 0) return;
      const firstParam = fn.params[0];
      if (!t.isIdentifier(firstParam)) return;

      // Accept common webpack module param names: modules, e, n, etc.
      const paramName = firstParam.name;
      const isWebpackBootstrap = paramName === 'modules' || /^[a-z]$/.test(paramName);

      if (isWebpackBootstrap && call.arguments.length >= 1) {
        const arg = call.arguments[0];
        if (t.isArrayExpression(arg) && looksLikeWebpackModulesArray(arg)) {
          extractModulesFromArray(arg);
        } else if (t.isObjectExpression(arg) && looksLikeWebpackModulesObject(arg)) {
          extractModulesFromObject(arg);
        }
      }
    },

    noScope: true,
  });
}

/**
 * Check if node is Webpack 5 push pattern
 */
function isWebpack5PushPattern(node: t.CallExpression): boolean {
  if (!t.isMemberExpression(node.callee)) return false;
  if (!t.isIdentifier(node.callee.property)) return false;
  if (node.callee.property.name !== 'push') return false;

  // Check for webpackChunk pattern in the object
  const obj = node.callee.object;

  // Pattern 1: (self.webpackChunk=self.webpackChunk||[]).push(...)
  if (t.isAssignmentExpression(obj)) {
    const left = obj.left;
    if (t.isMemberExpression(left) && t.isIdentifier(left.property)) {
      return left.property.name.startsWith('webpackChunk');
    }
  }

  // Pattern 2: ((self.webpackChunk=self.webpackChunk||[])||[]).push(...)
  if (t.isLogicalExpression(obj)) {
    const left = obj.left;
    // Check if left side is assignment
    if (t.isAssignmentExpression(left)) {
      const assignLeft = left.left;
      if (t.isMemberExpression(assignLeft) && t.isIdentifier(assignLeft.property)) {
        return assignLeft.property.name.startsWith('webpackChunk');
      }
    }
    // Check if left side is member expression directly: (self.webpackChunk||[]).push(...)
    if (t.isMemberExpression(left) && t.isIdentifier(left.property)) {
      return left.property.name.startsWith('webpackChunk');
    }
  }

  // Pattern 3: self.webpackChunk.push(...) - direct access without fallback
  if (t.isMemberExpression(obj) && t.isIdentifier(obj.property)) {
    return obj.property.name.startsWith('webpackChunk');
  }

  return false;
}

/**
 * Check if node is Webpack 4 jsonp pattern
 */
function isWebpack4JsonpPattern(node: t.CallExpression): boolean {
  if (!t.isMemberExpression(node.callee)) return false;
  if (!t.isIdentifier(node.callee.property)) return false;
  if (node.callee.property.name !== 'push') return false;

  const obj = node.callee.object;
  // Check for webpackJsonp pattern
  if (t.isAssignmentExpression(obj)) {
    const left = obj.left;
    if (t.isMemberExpression(left) && t.isIdentifier(left.property)) {
      return left.property.name === 'webpackJsonp' || left.property.name.includes('webpackJsonp');
    }
  }
  if (t.isIdentifier(obj)) {
    return obj.name === 'webpackJsonp' || obj.name.includes('webpackJsonp');
  }

  return false;
}

/**
 * Check if node is Webpack IIFE pattern
 */
function isWebpackIIFE(node: t.CallExpression): boolean {
  if (!t.isArrowFunctionExpression(node.callee) && !t.isFunctionExpression(node.callee)) {
    return false;
  }

  const fn = node.callee;
  if (!t.isBlockStatement(fn.body)) return false;

  // Pattern 1: Arrow/Function IIFE with variable declaration containing modules
  // (()=>{ var e = { 4850:(e,t,n)=>{...} }; })()
  for (const stmt of fn.body.body) {
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isObjectExpression(decl.init)) {
          // Check if it looks like webpack modules
          if (looksLikeWebpackModulesObject(decl.init)) {
            return true;
          }
        }
      }
    }
  }

  // Pattern 2: Webpack 4 IIFE with modules passed as argument
  // (function(e){...})({0:function(e,t,a){...},...})
  if (node.arguments.length >= 1 && t.isObjectExpression(node.arguments[0])) {
    if (looksLikeWebpackModulesObject(node.arguments[0])) {
      return true;
    }
  }

  return false;
}

/**
 * Check if object looks like webpack modules
 */
function looksLikeWebpackModulesObject(obj: t.ObjectExpression): boolean {
  if (obj.properties.length === 0) return false;

  let moduleLikeCount = 0;
  for (const prop of obj.properties) {
    // Handle ObjectProperty: { 287: function(t,e){...} } or { 287: (t,e)=>{...} }
    if (t.isObjectProperty(prop)) {
      // Check if key is numeric or string that looks like module ID
      const key = prop.key;
      const isNumericKey =
        t.isNumericLiteral(key) ||
        (t.isStringLiteral(key) && /^\d+$/.test(key.value)) ||
        (t.isIdentifier(key) && /^\d+$/.test(key.name));

      // Check if value is a function
      const isFunction =
        t.isFunctionExpression(prop.value) || t.isArrowFunctionExpression(prop.value);

      if (isNumericKey && isFunction) {
        moduleLikeCount++;
      }
    }
    // Handle ObjectMethod (shorthand): { 287(t,e){...} }
    else if (t.isObjectMethod(prop)) {
      const key = prop.key;
      const isNumericKey =
        t.isNumericLiteral(key) ||
        (t.isStringLiteral(key) && /^\d+$/.test(key.value)) ||
        (t.isIdentifier(key) && /^\d+$/.test(key.name));

      if (isNumericKey) {
        moduleLikeCount++;
      }
    }
  }

  // If at least 1 module-like property, consider it webpack
  return moduleLikeCount >= 1;
}

/**
 * Check if array looks like webpack modules (array-based format)
 * Pattern: [function(e,t,a){...}, function(e,t,a){...}, ...]
 */
function looksLikeWebpackModulesArray(arr: t.ArrayExpression): boolean {
  if (arr.elements.length === 0) return false;

  let moduleLikeCount = 0;
  for (const elem of arr.elements) {
    if (!elem) continue; // Skip holes

    // Check if element is a function with 2-3 params (module, exports, require)
    if (t.isFunctionExpression(elem) || t.isArrowFunctionExpression(elem)) {
      if (elem.params.length >= 2 && elem.params.length <= 3) {
        moduleLikeCount++;
      }
    }
  }

  return moduleLikeCount >= 1;
}

/**
 * Extract modules from array format (Webpack 3/4 style)
 * Modules are indexed by array position
 */
function extractModulesFromArray(arr: t.ArrayExpression, chunkId?: number): void {
  arr.elements.forEach((elem, index) => {
    if (!elem) return; // Skip holes

    let moduleFn: t.Function | null = null;
    if (t.isFunctionExpression(elem) || t.isArrowFunctionExpression(elem)) {
      moduleFn = elem;
    }

    if (!moduleFn) return;

    // Extract parameter names
    const params = moduleFn.params;
    let moduleVar = 'module';
    let exportsVar = 'exports';
    let requireVar = '__webpack_require__';

    if (params.length >= 1 && t.isIdentifier(params[0])) {
      moduleVar = params[0].name;
    }
    if (params.length >= 2 && t.isIdentifier(params[1])) {
      exportsVar = params[1].name;
    }
    if (params.length >= 3 && t.isIdentifier(params[2])) {
      requireVar = params[2].name;
    }

    const module: WebpackModule = {
      id: index, // Array index is the module ID
      chunkId,
      moduleVar,
      exportsVar,
      requireVar,
      body: moduleFn.body,
      exports: [],
      imports: [],
      httpCalls: [],
      localVars: new Map(),
    };

    // Extract module content
    if (t.isBlockStatement(moduleFn.body)) {
      extractModuleContent(module, moduleFn.body);
    }

    bundleState.modules.set(index, module);
  });
}

/**
 * Extract modules from a BlockStatement (e.g., from UMD inner IIFE)
 * Looks for variable declarations containing webpack modules object
 * Also extracts HTTP calls from the main chunk (inline code)
 */
function extractModulesFromBlockStatement(body: t.BlockStatement): void {
  // First, extract webpack modules from modules object
  for (const stmt of body.body) {
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isObjectExpression(decl.init)) {
          if (looksLikeWebpackModulesObject(decl.init)) {
            extractModulesFromObject(decl.init);
          }
        }
      }
    }
  }

  // Second, create a synthetic module for the main chunk (inline code)
  // This captures HTTP calls that are NOT inside webpack modules
  const mainChunkModule: WebpackModule = {
    id: '__main_chunk__',
    moduleVar: '__main__',
    exportsVar: '__exports__',
    requireVar: '__require__',
    body: body,
    exports: [],
    imports: [],
    httpCalls: [],
    localVars: new Map(),
  };

  // Collect local variables from main chunk
  extractLocalVarsFromBlock(body, mainChunkModule.localVars);

  // Extract HTTP calls from main chunk
  extractHttpCalls(mainChunkModule);

  // Only add if there are HTTP calls
  if (mainChunkModule.httpCalls.length > 0) {
    bundleState.modules.set('__main_chunk__', mainChunkModule);
  }
}

/**
 * Global endpoint dictionary - maps property names to URL values
 * This is used for resolving endpoints when direct variable lookup fails
 * (e.g., when minifier reassigns the same variable name)
 */
let endpointDictionary: Map<string, string> = new Map();

/**
 * Extract local variables from a block statement
 */
function extractLocalVarsFromBlock(body: t.BlockStatement, localVars: Map<string, t.Node>): void {
  // Create a mini-AST for traversal
  const program: t.Program = {
    type: 'Program',
    body: body.body,
    directives: [],
    sourceType: 'module',
  };

  traverse(
    { type: 'File', program } as t.File,
    {
      VariableDeclarator(path) {
        const node = path.node;
        if (t.isIdentifier(node.id) && node.init) {
          // Store the variable
          localVars.set(node.id.name, node.init);

          // Also extract endpoints from ObjectExpression to build endpoint dictionary
          if (t.isObjectExpression(node.init)) {
            extractEndpointDictionary(node.init);
          }
        }
      },
      noScope: true,
    },
    undefined,
    {}
  );
}

/**
 * Extract URL-like string values from an ObjectExpression and add to endpoint dictionary
 * This helps resolve endpoints even when variable names are reassigned by minifier
 */
function extractEndpointDictionary(obj: t.ObjectExpression): void {
  for (const prop of obj.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = getPropertyKeyName(prop.key);
    if (!keyName) continue;

    // Check if value is a URL-like string
    if (t.isStringLiteral(prop.value)) {
      const value = prop.value.value;
      // Store if it looks like an API endpoint or a URL prefix
      // Include patterns: /api/..., /..., http..., and common config keys like API_URL, BOB_URL
      if (value.startsWith('/') || value.startsWith('http') || value.startsWith('ws')) {
        endpointDictionary.set(keyName, value);
      }
    }
  }
}

/**
 * Extract modules from push pattern
 */
function extractFromPushPattern(node: t.CallExpression): void {
  if (node.arguments.length === 0) return;

  const arg = node.arguments[0];
  if (!t.isArrayExpression(arg)) return;

  // Find chunk ID if present
  let chunkId: number | undefined;
  if (arg.elements.length >= 1 && t.isArrayExpression(arg.elements[0])) {
    const chunkIds = arg.elements[0];
    if (chunkIds.elements.length > 0 && t.isNumericLiteral(chunkIds.elements[0])) {
      chunkId = chunkIds.elements[0].value;
    }
  }

  // Find modules object
  for (const element of arg.elements) {
    if (t.isObjectExpression(element)) {
      extractModulesFromObject(element, chunkId);
    }
  }
}

/**
 * Extract modules from IIFE pattern
 */
function extractFromIIFE(node: t.CallExpression): void {
  const fn = node.callee as t.ArrowFunctionExpression | t.FunctionExpression;
  if (!t.isBlockStatement(fn.body)) return;

  // Pattern 1: Variable declaration with modules object
  for (const stmt of fn.body.body) {
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isObjectExpression(decl.init)) {
          if (looksLikeWebpackModulesObject(decl.init)) {
            extractModulesFromObject(decl.init);
          }
        }
      }
    }
  }

  // Pattern 2: Webpack 4 - modules passed as argument to IIFE
  // (function(e){...})({0:function(e,t,a){...},...})
  if (node.arguments.length >= 1 && t.isObjectExpression(node.arguments[0])) {
    if (looksLikeWebpackModulesObject(node.arguments[0])) {
      extractModulesFromObject(node.arguments[0]);
    }
  }
}

/**
 * Extract modules from a webpack modules object
 */
function extractModulesFromObject(obj: t.ObjectExpression, chunkId?: number): void {
  for (const prop of obj.properties) {
    if (!t.isObjectProperty(prop) && !t.isObjectMethod(prop)) continue;

    // Get module ID from key
    const moduleId = getPropertyKeyValue(prop.key);
    if (moduleId === null) continue;

    // Get module function
    let moduleFn: t.Function | null = null;
    if (t.isObjectProperty(prop)) {
      if (t.isFunctionExpression(prop.value) || t.isArrowFunctionExpression(prop.value)) {
        moduleFn = prop.value;
      }
    } else if (t.isObjectMethod(prop)) {
      moduleFn = prop;
    }

    if (!moduleFn) continue;

    // Extract parameter names
    const params = moduleFn.params;
    let moduleVar = 'module';
    let exportsVar = 'exports';
    let requireVar = '__webpack_require__';

    if (params.length >= 1 && t.isIdentifier(params[0])) {
      moduleVar = params[0].name;
    }
    if (params.length >= 2 && t.isIdentifier(params[1])) {
      exportsVar = params[1].name;
    }
    if (params.length >= 3 && t.isIdentifier(params[2])) {
      requireVar = params[2].name;
    }

    const module: WebpackModule = {
      id: moduleId,
      chunkId,
      moduleVar,
      exportsVar,
      requireVar,
      body: moduleFn.body,
      exports: [],
      imports: [],
      httpCalls: [],
      localVars: new Map(),
    };

    // Extract module content
    if (t.isBlockStatement(moduleFn.body)) {
      extractModuleContent(module, moduleFn.body);
    }

    bundleState.modules.set(moduleId, module);
  }
}

/**
 * Extract exports, imports, and local variables from module body
 *
 * Uses a two-pass approach:
 * 1. First pass: collect all local variables and imports (they may appear AFTER export calls)
 * 2. Second pass: process export calls (now we have all local vars available for resolution)
 */
function extractModuleContent(module: WebpackModule, body: t.BlockStatement): void {
  // Store export calls to process after collecting all local vars
  const exportCalls: t.CallExpression[] = [];

  // First pass: collect all local variables and imports
  for (const stmt of body.body) {
    // Track variable declarations
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isIdentifier(decl.id) && decl.init) {
          module.localVars.set(decl.id.name, decl.init);

          // Extract endpoint dictionary from objects containing URL strings
          if (t.isObjectExpression(decl.init)) {
            extractEndpointDictionary(decl.init);
          }

          // Check for imports: var a = t(8947)
          if (t.isCallExpression(decl.init)) {
            const call = decl.init;
            if (
              t.isIdentifier(call.callee) &&
              call.callee.name === module.requireVar &&
              call.arguments.length === 1
            ) {
              const arg = call.arguments[0];
              const importedModuleId = getNodeValue(arg);

              if (importedModuleId !== null) {
                module.imports.push({
                  moduleId: importedModuleId,
                  localVar: decl.id.name,
                  usages: [],
                });
              }
            }
          }
        }
      }
    }

    // Collect export calls for second pass
    if (t.isExpressionStatement(stmt) && t.isCallExpression(stmt.expression)) {
      exportCalls.push(stmt.expression);
    }
  }

  // Second pass: process exports now that we have all local vars
  for (const call of exportCalls) {
    extractExportsFromDefineCall(call, module);
  }
}

/**
 * Extract exports from t.d(l, {...}) pattern
 */
function extractExportsFromDefineCall(call: t.CallExpression, module: WebpackModule): void {
  if (!t.isMemberExpression(call.callee)) return;

  const callee = call.callee;
  if (!t.isIdentifier(callee.object) || !t.isIdentifier(callee.property)) return;
  if (callee.object.name !== module.requireVar || callee.property.name !== 'd') return;
  if (call.arguments.length < 2) return;

  const exportsArg = call.arguments[1];
  if (!t.isObjectExpression(exportsArg)) return;

  for (const prop of exportsArg.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const exportName = getPropertyKeyName(prop.key);
    if (!exportName) continue;

    const exportEntry: WebpackExport = {
      name: exportName,
      valueNode: null,
      exportType: exportName === 'default' ? 'default' : 'named',
    };

    // Handle: {O: () => endpoints} - arrow function returning identifier
    if (t.isArrowFunctionExpression(prop.value)) {
      const arrowBody = prop.value.body;
      if (t.isIdentifier(arrowBody)) {
        exportEntry.localName = arrowBody.name;
        const localValue = module.localVars.get(arrowBody.name);
        if (localValue) {
          exportEntry.valueNode = localValue;
          exportEntry.resolvedValue = resolveNodeToValue(localValue, module.localVars);
        }
      } else {
        exportEntry.valueNode = arrowBody;
        exportEntry.resolvedValue = resolveNodeToValue(arrowBody, module.localVars);
      }
    }
    // Handle: {O: function() { return endpoints; }}
    else if (t.isFunctionExpression(prop.value)) {
      if (t.isBlockStatement(prop.value.body)) {
        for (const bodyStmt of prop.value.body.body) {
          if (t.isReturnStatement(bodyStmt) && bodyStmt.argument) {
            if (t.isIdentifier(bodyStmt.argument)) {
              exportEntry.localName = bodyStmt.argument.name;
              const localValue = module.localVars.get(bodyStmt.argument.name);
              if (localValue) {
                exportEntry.valueNode = localValue;
                exportEntry.resolvedValue = resolveNodeToValue(localValue, module.localVars);
              }
            } else {
              exportEntry.valueNode = bodyStmt.argument;
              exportEntry.resolvedValue = resolveNodeToValue(bodyStmt.argument, module.localVars);
            }
            break;
          }
        }
      }
    }
    // Handle direct value
    else {
      exportEntry.valueNode = prop.value;
      exportEntry.resolvedValue = resolveNodeToValue(prop.value, module.localVars);
    }

    module.exports.push(exportEntry);
  }
}

// =============================================================================
// HTTP Call Detection
// =============================================================================

const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'request', 'head', 'options'];

/**
 * Extract HTTP calls from module
 */
function extractHttpCalls(module: WebpackModule): void {
  if (!t.isBlockStatement(module.body)) return;

  // Wrap module body in a File for full traversal with proper scope tracking
  const file: t.File = {
    type: 'File',
    program: {
      type: 'Program',
      body: module.body.body,
      directives: [],
      sourceType: 'module',
    },
  };

  traverse(file, {
    CallExpression(path) {
      const call = path.node;

      // Collect scope-local variables by walking up parent chain
      const scopeVars = collectScopeVariablesFromPath(path, module.localVars);

      // Pattern: importedVar.property.httpMethod(url, body)
      // e.g., s.S.post(a.O.accountLogin, {phone_number: e})
      if (t.isMemberExpression(call.callee)) {
        const httpCall = extractHttpCallFromMemberExpression(call, module, scopeVars);
        if (httpCall) {
          module.httpCalls.push(httpCall);
        }
      }

      // Pattern: fetch(url, options)
      if (t.isIdentifier(call.callee) && call.callee.name === 'fetch') {
        const httpCall = extractFetchCall(call, module, scopeVars);
        if (httpCall) {
          module.httpCalls.push(httpCall);
        }
      }
    },
  });
}

/**
 * Extract HTTP calls from non-webpack bundles (rollup, esbuild, vite, parcel).
 *
 * This function traverses the entire AST looking for fetch() and HTTP client calls
 * without relying on webpack-specific module patterns.
 */
function extractHttpCallsGeneric(ast: ParseResult<t.File>): void {
  // Create a synthetic "global module" to store results
  const globalModule: WebpackModule = {
    id: '__global__',
    moduleVar: '__global__',
    exportsVar: '__exports__',
    requireVar: '__require__',
    body: ast.program as unknown as t.BlockStatement,
    exports: [],
    imports: [],
    httpCalls: [],
    localVars: new Map(),
  };

  // First pass: Collect ALL variable declarations (for endpoint dictionaries and URL resolution)
  traverse(ast, {
    VariableDeclarator(path) {
      const node = path.node;
      if (t.isIdentifier(node.id) && node.init) {
        globalModule.localVars.set(node.id.name, node.init);
        // Also extract endpoint dictionary entries
        if (t.isObjectExpression(node.init)) {
          extractEndpointDictionary(node.init);
        }
      }
    },
    noScope: true,
  });

  // Second pass: Find HTTP calls with scope-aware variable resolution
  traverse(ast, {
    CallExpression(path) {
      const call = path.node;

      // Collect scope-local variables by walking up parent chain
      const scopeVars = collectScopeVariablesFromPath(path, globalModule.localVars);

      // Pattern: fetch(url, options)
      if (t.isIdentifier(call.callee) && call.callee.name === 'fetch') {
        const httpCall = extractFetchCall(call, globalModule, scopeVars);
        if (httpCall) {
          globalModule.httpCalls.push(httpCall);
        }
      }

      // Pattern: obj.method(url) where method is HTTP verb
      // e.g., axios.get(url), http.post(url), client.request('GET', url)
      if (t.isMemberExpression(call.callee)) {
        const httpCall = extractHttpCallFromMemberExpression(call, globalModule, scopeVars);
        if (httpCall) {
          globalModule.httpCalls.push(httpCall);
        }
      }
    },
  });

  // Only register if we found HTTP calls
  if (globalModule.httpCalls.length > 0) {
    bundleState.modules.set('__global__', globalModule);
  }
}

/**
 * Collect local variables from parent scopes by walking up the path
 * This properly handles nested functions with same-named variables
 */
function collectScopeVariablesFromPath(
  path: NodePath<t.Node>,
  moduleVars: Map<string, t.Node>
): Map<string, t.Node> {
  const scopeVars = new Map(moduleVars);
  const seenVarNames = new Set<string>();

  // Walk up the parent chain to find enclosing function bodies
  let current: NodePath | null = path;

  while (current) {
    // If we're in a block statement, collect variable declarations
    if (t.isBlockStatement(current.node)) {
      // Collect variables from this block
      // Earlier declarations in the same block take precedence
      for (const stmt of current.node.body) {
        if (t.isVariableDeclaration(stmt)) {
          for (const decl of stmt.declarations) {
            if (t.isIdentifier(decl.id) && decl.init) {
              // Only set if not already seen (inner scope takes precedence)
              if (!seenVarNames.has(decl.id.name)) {
                scopeVars.set(decl.id.name, decl.init);
                seenVarNames.add(decl.id.name);
              }
            }
          }
        }
      }
    }

    // Check if this is a function with its own scope
    if (
      t.isArrowFunctionExpression(current.node) ||
      t.isFunctionExpression(current.node) ||
      t.isFunctionDeclaration(current.node)
    ) {
      // If the function has a block body, we've already processed it above
      // But we need to mark that we've entered a new scope boundary
      // Variables from outer function shouldn't override inner function's vars
    }

    current = current.parentPath;
  }

  return scopeVars;
}

/**
 * Extract HTTP call from member expression like s.S.post(...)
 */
function extractHttpCallFromMemberExpression(
  call: t.CallExpression,
  module: WebpackModule,
  scopeVars?: Map<string, t.Node>
): WebpackHttpCall | null {
  const callee = call.callee;
  if (!t.isMemberExpression(callee)) return null;

  // Get the method name (last property)
  const methodProp = callee.property;
  if (!t.isIdentifier(methodProp)) return null;

  const methodName = methodProp.name.toLowerCase();
  if (!HTTP_METHODS.includes(methodName)) return null;

  // Get the client access path (e.g., s.S for s.S.post)
  const clientPath = getMemberExpressionPath(callee.object);
  if (clientPath.length === 0) return null;

  // Get URL from first argument
  const urlArg = call.arguments[0];
  if (!urlArg) return null;

  // Use scope variables if provided, otherwise fall back to module local vars
  const localVars = scopeVars ?? module.localVars;

  const urlSource = extractUrlSource(urlArg, module, localVars);
  if (!urlSource) return null;

  // Get body from second argument if present
  let bodySource: BodySource | undefined;
  if (call.arguments.length >= 2) {
    bodySource = extractBodySource(call.arguments[1], module, localVars);
  }

  return {
    moduleId: module.id,
    clientVar: clientPath[0],
    clientAccessPath: clientPath,
    method: methodName,
    urlSource,
    bodySource,
    line: call.loc?.start.line ?? 0,
  };
}

/**
 * Extract fetch() call
 */
function extractFetchCall(
  call: t.CallExpression,
  module: WebpackModule,
  scopeVars?: Map<string, t.Node>
): WebpackHttpCall | null {
  if (call.arguments.length === 0) return null;

  const localVars = scopeVars ?? module.localVars;

  const urlArg = call.arguments[0];
  const urlSource = extractUrlSource(urlArg, module, localVars);
  if (!urlSource) return null;

  let method = 'get';
  let bodySource: BodySource | undefined;

  // Check options object for method and body
  if (call.arguments.length >= 2 && t.isObjectExpression(call.arguments[1])) {
    const options = call.arguments[1];
    for (const prop of options.properties) {
      if (!t.isObjectProperty(prop)) continue;
      const key = getPropertyKeyName(prop.key);

      if (key === 'method' && t.isStringLiteral(prop.value)) {
        method = prop.value.value.toLowerCase();
      }
      if (key === 'body') {
        bodySource = extractBodySource(prop.value, module, localVars);
      }
    }
  }

  return {
    moduleId: module.id,
    clientVar: 'fetch',
    clientAccessPath: ['fetch'],
    method,
    urlSource,
    bodySource,
    line: call.loc?.start.line ?? 0,
  };
}

/**
 * Extract URL source from node
 */
function extractUrlSource(
  node: t.Node,
  module: WebpackModule,
  localVars?: Map<string, t.Node>
): UrlSource | null {
  const vars = localVars ?? module.localVars;

  // String literal
  if (t.isStringLiteral(node)) {
    return {
      type: 'literal',
      value: node.value,
      resolvedValue: node.value,
    };
  }

  // Template literal
  if (t.isTemplateLiteral(node)) {
    const parts: string[] = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i].value.raw);
      if (i < node.expressions.length) {
        const expr = node.expressions[i];
        if (t.isIdentifier(expr)) {
          // Try to resolve identifier from localVars
          const localValue = vars.get(expr.name);
          if (localValue) {
            if (t.isStringLiteral(localValue)) {
              parts.push(localValue.value);
            } else if (t.isNumericLiteral(localValue)) {
              parts.push(String(localValue.value));
            } else {
              parts.push(`\${${expr.name}}`);
            }
          } else {
            parts.push(`\${${expr.name}}`);
          }
        } else if (t.isMemberExpression(expr)) {
          // Try to resolve member chain
          const path = getMemberExpressionPath(expr);
          const resolved = resolveMemberChain(path, vars);
          if (resolved !== null && (typeof resolved === 'string' || typeof resolved === 'number')) {
            parts.push(String(resolved));
          } else {
            // Try endpoint dictionary lookup (e.g., o.USER_UPDATE -> /api/v1/users/update)
            if (path.length >= 2) {
              const propName = path[path.length - 1];
              const dictValue = endpointDictionary.get(propName);
              if (dictValue) {
                parts.push(dictValue);
              } else {
                parts.push(`\${${path.join('.')}}`);
              }
            } else {
              parts.push(`\${${path.join('.')}}`);
            }
          }
        } else {
          parts.push('${X}');
        }
      }
    }
    return {
      type: 'template',
      value: parts.join(''),
    };
  }

  // Member expression (e.g., a.O.accountLogin or endpoints.AUTH_LOGIN)
  if (t.isMemberExpression(node)) {
    const path = getMemberExpressionPath(node);
    if (path.length > 0) {
      const rootVar = path[0];

      // First, try to resolve from local variables (e.g., endpoints.AUTH_LOGIN)
      const resolved = resolveMemberChain(path, vars);
      if (resolved !== null && typeof resolved === 'string') {
        return {
          type: 'variable',
          value: path.join('.'),
          resolvedValue: resolved,
        };
      }

      // Second, try endpoint dictionary lookup (for minified bundles where var names are reassigned)
      // Use the last part of the path as the property name (e.g., AUTH_LOGIN from o.AUTH_LOGIN)
      if (path.length >= 2) {
        const propName = path[path.length - 1];
        const dictValue = endpointDictionary.get(propName);
        if (dictValue) {
          return {
            type: 'variable',
            value: path.join('.'),
            resolvedValue: dictValue,
          };
        }
      }

      // Check if the root is a webpack import
      const imp = module.imports.find((i) => i.localVar === rootVar);
      if (imp) {
        return {
          type: 'import',
          value: path.join('.'),
          importPath: path,
        };
      }

      // Not resolved - return as variable placeholder
      return {
        type: 'variable',
        value: `\${${path.join('.')}}`,
      };
    }
  }

  // Identifier (variable reference)
  if (t.isIdentifier(node)) {
    // Check if it's a local variable (using scope-aware vars)
    const localValue = vars.get(node.name);
    if (localValue) {
      // If local value is a string literal, resolve directly
      if (t.isStringLiteral(localValue)) {
        return {
          type: 'variable',
          value: node.name,
          resolvedValue: localValue.value,
        };
      }
      // If local value is a conditional expression, extract both URLs
      if (t.isConditionalExpression(localValue)) {
        return extractUrlSource(localValue, module, vars);
      }
      // If local value is a binary expression (concatenation), resolve it
      if (t.isBinaryExpression(localValue) && localValue.operator === '+') {
        return extractUrlSource(localValue, module, vars);
      }
      // If local value is a template literal, resolve it
      if (t.isTemplateLiteral(localValue)) {
        return extractUrlSource(localValue, module, vars);
      }
      // If local value is a CallExpression (IIFE), resolve it
      // e.g., const e = function(t){return "/api/..."}(arg)
      if (t.isCallExpression(localValue)) {
        return extractUrlSource(localValue, module, vars);
      }
      // If local value is a MemberExpression (e.g., const e = o.USER_DELETE)
      if (t.isMemberExpression(localValue)) {
        return extractUrlSource(localValue, module, vars);
      }
    }

    // Check if it's an import
    const imp = module.imports.find((i) => i.localVar === node.name);
    if (imp) {
      return {
        type: 'import',
        value: node.name,
        importPath: [node.name],
      };
    }

    // Not resolved - return as variable placeholder
    return {
      type: 'variable',
      value: `\${${node.name}}`,
    };
  }

  // Binary expression (concatenation)
  if (t.isBinaryExpression(node) && node.operator === '+') {
    const parts: string[] = [];
    collectConcatenationParts(node, parts, vars);
    return {
      type: 'concatenation',
      value: parts.join(''),
    };
  }

  // Conditional expression: cond ? url1 : url2
  // Extract both URLs as alternatives
  if (t.isConditionalExpression(node)) {
    const consequent = extractUrlSource(node.consequent, module, vars);
    const alternate = extractUrlSource(node.alternate, module, vars);

    // Return both URLs joined with | to indicate alternatives
    const urls: string[] = [];
    if (consequent?.resolvedValue) {
      urls.push(consequent.resolvedValue);
    } else if (consequent?.value && !consequent.value.includes('${')) {
      urls.push(consequent.value);
    }
    if (alternate?.resolvedValue) {
      urls.push(alternate.resolvedValue);
    } else if (alternate?.value && !alternate.value.includes('${')) {
      urls.push(alternate.value);
    }

    if (urls.length > 0) {
      return {
        type: 'conditional',
        value: urls.join('|'),
        resolvedValue: urls[0], // Use first URL as primary
        alternatives: urls,
      };
    }
  }

  // CallExpression that returns a URL (e.g., function(t){return "/api/v1/users/search?q="+...}(query))
  if (t.isCallExpression(node)) {
    // Check if the callee is a function that returns a URL
    const callee = node.callee;
    if (t.isFunctionExpression(callee) || t.isArrowFunctionExpression(callee)) {
      const funcBody = callee.body;
      // Arrow function with expression body
      if (!t.isBlockStatement(funcBody)) {
        const urlFromBody = extractUrlSource(funcBody, module, vars);
        if (urlFromBody) return urlFromBody;
      }
      // Function with return statement
      if (t.isBlockStatement(funcBody)) {
        for (const stmt of funcBody.body) {
          if (t.isReturnStatement(stmt) && stmt.argument) {
            const urlFromReturn = extractUrlSource(stmt.argument, module, vars);
            if (urlFromReturn) return urlFromReturn;
          }
        }
      }
    }
  }

  return null;
}

/**
 * Collect parts of a string concatenation
 */
function collectConcatenationParts(
  node: t.Node,
  parts: string[],
  localVars: Map<string, t.Node>
): void {
  if (t.isBinaryExpression(node) && node.operator === '+') {
    collectConcatenationParts(node.left, parts, localVars);
    collectConcatenationParts(node.right, parts, localVars);
  } else if (t.isStringLiteral(node)) {
    parts.push(node.value);
  } else if (t.isIdentifier(node)) {
    const localValue = localVars.get(node.name);
    if (localValue) {
      if (t.isStringLiteral(localValue)) {
        parts.push(localValue.value);
        return;
      }
      if (t.isNumericLiteral(localValue)) {
        parts.push(String(localValue.value));
        return;
      }
      // If local value is a MemberExpression (e.g., const e = o.USER_DELETE)
      if (t.isMemberExpression(localValue)) {
        collectConcatenationParts(localValue, parts, localVars);
        return;
      }
    }
    // Try endpoint dictionary lookup for identifier (e.g., API_URL after assignment)
    const dictValue = endpointDictionary.get(node.name);
    if (dictValue) {
      parts.push(dictValue);
    } else {
      parts.push(`\${${node.name}}`);
    }
  } else if (t.isMemberExpression(node)) {
    const path = getMemberExpressionPath(node);
    // Try to resolve from local variables
    const resolved = resolveMemberChain(path, localVars);
    if (resolved !== null && (typeof resolved === 'string' || typeof resolved === 'number')) {
      parts.push(String(resolved));
    } else {
      // Try endpoint dictionary lookup
      if (path.length >= 2) {
        const propName = path[path.length - 1];
        const dictValue = endpointDictionary.get(propName);
        if (dictValue) {
          parts.push(dictValue);
        } else {
          parts.push(`\${${path.join('.')}}`);
        }
      } else {
        parts.push(`\${${path.join('.')}}`);
      }
    }
  } else {
    parts.push('${...}');
  }
}

/**
 * Extract body source from node
 */
function extractBodySource(
  node: t.Node,
  module: WebpackModule,
  localVars?: Map<string, t.Node>
): BodySource | undefined {
  const vars = localVars ?? module.localVars;

  if (t.isObjectExpression(node)) {
    const resolved = resolveObjectExpression(node, vars);
    return {
      type: 'object',
      value: resolved ?? {},
    };
  }

  if (t.isIdentifier(node)) {
    const localValue = vars.get(node.name);
    if (localValue && t.isObjectExpression(localValue)) {
      const resolved = resolveObjectExpression(localValue, vars);
      return {
        type: 'object',
        value: resolved ?? {},
      };
    }
    return {
      type: 'variable',
      value: `\${${node.name}}`,
    };
  }

  return undefined;
}

// =============================================================================
// Import Resolution
// =============================================================================

/**
 * Build import resolution map
 */
function buildImportResolutionMap(): void {
  for (const [moduleId, module] of bundleState.modules) {
    for (const imp of module.imports) {
      const key = `${moduleId}:${imp.localVar}`;
      bundleState.importResolution.set(key, {
        moduleId: imp.moduleId,
        contextModuleId: moduleId,
        localVar: imp.localVar,
      });
    }
  }
}

/**
 * Resolve import chains across modules
 */
function resolveImportChains(): void {
  for (const module of bundleState.modules.values()) {
    // Resolve HTTP call URLs
    for (const httpCall of module.httpCalls) {
      if (httpCall.urlSource.type === 'import' && httpCall.urlSource.importPath) {
        const resolved = resolveImportPath(httpCall.urlSource.importPath, module);
        if (resolved) {
          httpCall.urlSource.resolvedValue = resolved;
        }
      }
    }
  }
}

/**
 * Resolve an import path like ['a', 'O', 'accountLogin']
 */
function resolveImportPath(path: string[], contextModule: WebpackModule): string | null {
  if (path.length === 0) return null;

  const localVar = path[0];

  // Find the import
  const imp = contextModule.imports.find((i) => i.localVar === localVar);
  if (!imp) return null;

  // Get the imported module
  const importedModule = bundleState.modules.get(imp.moduleId);
  if (!importedModule) return null;

  // If only the import variable, can't resolve further
  if (path.length === 1) return null;

  // Find the export
  const exportName = path[1];
  const exp = importedModule.exports.find((e) => e.name === exportName);
  if (!exp || !exp.resolvedValue) return null;

  // Direct string export
  if (path.length === 2) {
    if (exp.resolvedValue.type === 'string') {
      return exp.resolvedValue.value;
    }
    if (exp.resolvedValue.type === 'object') {
      return JSON.stringify(exp.resolvedValue.value);
    }
    return null;
  }

  // Nested property access: a.O.accountLogin
  if (exp.resolvedValue.type === 'object' && path.length >= 3) {
    const propName = path[2];
    const value = exp.resolvedValue.value[propName];
    if (typeof value === 'string') {
      return value;
    }
    if (typeof value === 'object' && value !== null) {
      return JSON.stringify(value);
    }
  }

  return null;
}

/**
 * Resolve a webpack reference (public API)
 */
export function resolveWebpackReference(
  moduleId: string | number,
  varChain: string[]
): string | null {
  const module = bundleState.modules.get(moduleId);
  if (!module) return null;

  return resolveImportPath(varChain, module);
}

// =============================================================================
// FunctionMap Integration
// =============================================================================

/**
 * Register webpack functions in the function map
 */
function registerWebpackFunctions(functionMap: FunctionMap): void {
  for (const [moduleId, module] of bundleState.modules) {
    const modulePrefix = `webpack_${moduleId}`;

    for (const exp of module.exports) {
      const exportFullName = `${modulePrefix}.${exp.name}`;

      if (exp.resolvedValue?.type === 'object') {
        const resolvedObj = exp.resolvedValue.value as Record<string, unknown>;

        // Register the main export
        const exportDef: FunctionDefinition = {
          fullName: exportFullName,
          serviceName: modulePrefix,
          name: exp.name,
          params: [],
          startLine: 0,
          endLine: 0,
          returnedObject: resolvedObj as Record<string, string | Record<string, unknown>>,
        };
        functionMap.functions.set(exportFullName, exportDef);

        // Register each property
        for (const [key, value] of Object.entries(resolvedObj)) {
          if (typeof value === 'string') {
            const propFullName = `${exportFullName}.${key}`;
            const propDef: FunctionDefinition = {
              fullName: propFullName,
              serviceName: modulePrefix,
              name: key,
              params: [],
              startLine: 0,
              endLine: 0,
              returnedObject: { _value: value },
            };
            functionMap.functions.set(propFullName, propDef);
          }
        }
      } else if (exp.resolvedValue?.type === 'string') {
        const exportDef: FunctionDefinition = {
          fullName: exportFullName,
          serviceName: modulePrefix,
          name: exp.name,
          params: [],
          startLine: 0,
          endLine: 0,
          returnedObject: { _value: exp.resolvedValue.value },
        };
        functionMap.functions.set(exportFullName, exportDef);
      }
    }
  }
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Get property key value (for module IDs)
 */
function getPropertyKeyValue(key: t.Expression | t.PrivateName): string | number | null {
  if (t.isIdentifier(key)) {
    // Check if it's a numeric string
    if (/^\d+$/.test(key.name)) {
      return parseInt(key.name, 10);
    }
    return key.name;
  }
  if (t.isStringLiteral(key)) {
    // Check if it's a numeric string
    if (/^\d+$/.test(key.value)) {
      return parseInt(key.value, 10);
    }
    return key.value;
  }
  if (t.isNumericLiteral(key)) {
    return key.value;
  }
  return null;
}

/**
 * Get property key name (for export names)
 */
function getPropertyKeyName(key: t.Expression | t.PrivateName): string | null {
  if (t.isIdentifier(key)) {
    return key.name;
  }
  if (t.isStringLiteral(key)) {
    return key.value;
  }
  return null;
}

/**
 * Get value from simple node
 */
function getNodeValue(node: t.Node): string | number | null {
  if (t.isStringLiteral(node)) {
    return node.value;
  }
  if (t.isNumericLiteral(node)) {
    return node.value;
  }
  return null;
}

/**
 * Get member expression path as array of strings
 */
function getMemberExpressionPath(node: t.Node): string[] {
  const path: string[] = [];

  let current: t.Node = node;
  while (t.isMemberExpression(current)) {
    if (t.isIdentifier(current.property)) {
      path.unshift(current.property.name);
    } else if (t.isStringLiteral(current.property)) {
      path.unshift(current.property.value);
    }
    current = current.object;
  }

  // Handle SequenceExpression (comma operator) - common in Parcel bundles
  // Pattern: (0, $abc123$export$xyz).PROP_NAME  =>  SequenceExpression([0, Identifier])
  // The comma operator returns the last expression, so (0, x) === x
  if (t.isSequenceExpression(current)) {
    const lastExpr = current.expressions[current.expressions.length - 1];
    if (t.isIdentifier(lastExpr)) {
      path.unshift(lastExpr.name);
    } else if (t.isMemberExpression(lastExpr)) {
      // Recursively handle nested member expression
      const nestedPath = getMemberExpressionPath(lastExpr);
      path.unshift(...nestedPath);
    }
  } else if (t.isIdentifier(current)) {
    path.unshift(current.name);
  } else if (t.isThisExpression(current)) {
    path.unshift('this');
  }

  return path;
}

/**
 * Resolve member expression chain from local variables.
 * Example: ['user', 'profile', 'id'] with localVars containing user object -> resolves to actual value
 *
 * @param path - Array of property names from getMemberExpressionPath()
 * @param localVars - Map of local variable names to their AST nodes
 * @returns Resolved value or null if cannot be resolved
 */
function resolveMemberChain(
  path: string[],
  localVars: Map<string, t.Node>
): unknown | null {
  if (path.length === 0) return null;

  const rootVar = path[0];
  const rootValue = localVars.get(rootVar);
  if (!rootValue) return null;

  // Resolve root to object
  let current: unknown = null;
  if (t.isObjectExpression(rootValue)) {
    current = resolveObjectExpression(rootValue, localVars);
  } else if (t.isStringLiteral(rootValue)) {
    // Can't access property on string - but if path length is 1, return the string
    if (path.length === 1) {
      return rootValue.value;
    }
    return null;
  } else if (t.isNumericLiteral(rootValue)) {
    if (path.length === 1) {
      return rootValue.value;
    }
    return null;
  } else if (t.isBooleanLiteral(rootValue)) {
    if (path.length === 1) {
      return rootValue.value;
    }
    return null;
  }

  if (!current || typeof current !== 'object') return null;

  // Walk the path
  for (let i = 1; i < path.length; i++) {
    const key = path[i];
    current = (current as Record<string, unknown>)[key];
    if (current === undefined) return null;
  }

  return current;
}

/**
 * Resolve node to ResolvedExportValue
 */
function resolveNodeToValue(
  node: t.Node,
  localVars: Map<string, t.Node>
): ResolvedExportValue | undefined {
  if (t.isStringLiteral(node)) {
    return { type: 'string', value: node.value };
  }

  if (t.isObjectExpression(node)) {
    const resolved = resolveObjectExpression(node, localVars);
    if (resolved) {
      return { type: 'object', value: resolved };
    }
  }

  if (t.isArrayExpression(node)) {
    const resolved = resolveArrayExpression(node, localVars);
    if (resolved) {
      return { type: 'array', value: resolved };
    }
  }

  if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) {
    const params = node.params
      .map((p) => (t.isIdentifier(p) ? p.name : '?'))
      .filter((p) => p !== '?');
    return { type: 'function', params };
  }

  if (t.isIdentifier(node)) {
    const localValue = localVars.get(node.name);
    if (localValue) {
      return resolveNodeToValue(localValue, localVars);
    }
    return { type: 'unresolved', placeholder: `\${${node.name}}` };
  }

  return undefined;
}

/**
 * Resolve object expression to plain object
 */
function resolveObjectExpression(
  obj: t.ObjectExpression,
  localVars: Map<string, t.Node>
): Record<string, unknown> | undefined {
  const result: Record<string, unknown> = {};

  for (const prop of obj.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = getPropertyKeyName(prop.key);
    if (!keyName) continue;

    // Resolve value
    if (t.isStringLiteral(prop.value)) {
      result[keyName] = prop.value.value;
    } else if (t.isNumericLiteral(prop.value)) {
      result[keyName] = prop.value.value;
    } else if (t.isBooleanLiteral(prop.value)) {
      result[keyName] = prop.value.value;
    } else if (t.isNullLiteral(prop.value)) {
      result[keyName] = null;
    } else if (t.isObjectExpression(prop.value)) {
      const nested = resolveObjectExpression(prop.value, localVars);
      if (nested) result[keyName] = nested;
    } else if (t.isArrayExpression(prop.value)) {
      const arr = resolveArrayExpression(prop.value, localVars);
      if (arr) result[keyName] = arr;
    } else if (t.isIdentifier(prop.value)) {
      const localValue = localVars.get(prop.value.name);
      if (localValue) {
        // Recursive resolve for all types, not just StringLiteral
        if (t.isStringLiteral(localValue)) {
          result[keyName] = localValue.value;
        } else if (t.isNumericLiteral(localValue)) {
          result[keyName] = localValue.value;
        } else if (t.isBooleanLiteral(localValue)) {
          result[keyName] = localValue.value;
        } else if (t.isNullLiteral(localValue)) {
          result[keyName] = null;
        } else if (t.isObjectExpression(localValue)) {
          const nested = resolveObjectExpression(localValue, localVars);
          result[keyName] = nested ?? `\${${prop.value.name}}`;
        } else if (t.isArrayExpression(localValue)) {
          const arr = resolveArrayExpression(localValue, localVars);
          result[keyName] = arr ?? `\${${prop.value.name}}`;
        } else if (t.isMemberExpression(localValue)) {
          // Resolve member chain like config.api.version
          const path = getMemberExpressionPath(localValue);
          const resolved = resolveMemberChain(path, localVars);
          result[keyName] = resolved ?? `\${${path.join('.')}}`;
        } else {
          result[keyName] = `\${${prop.value.name}}`;
        }
      } else {
        result[keyName] = `\${${prop.value.name}}`;
      }
    } else if (t.isMemberExpression(prop.value)) {
      // Handle direct member expression in property value: {data: user.id}
      const path = getMemberExpressionPath(prop.value);
      const resolved = resolveMemberChain(path, localVars);
      result[keyName] = resolved ?? `\${${path.join('.')}}`;
    } else {
      result[keyName] = `\${${keyName}}`;
    }
  }

  return Object.keys(result).length > 0 ? result : undefined;
}

/**
 * Resolve array expression
 */
function resolveArrayExpression(
  arr: t.ArrayExpression,
  localVars: Map<string, t.Node>
): unknown[] | undefined {
  const result: unknown[] = [];

  for (const elem of arr.elements) {
    if (!elem) {
      result.push(null);
      continue;
    }

    if (t.isStringLiteral(elem)) {
      result.push(elem.value);
    } else if (t.isNumericLiteral(elem)) {
      result.push(elem.value);
    } else if (t.isBooleanLiteral(elem)) {
      result.push(elem.value);
    } else if (t.isNullLiteral(elem)) {
      result.push(null);
    } else if (t.isObjectExpression(elem)) {
      const obj = resolveObjectExpression(elem, localVars);
      result.push(obj ?? {});
    } else if (t.isArrayExpression(elem)) {
      const nested = resolveArrayExpression(elem, localVars);
      result.push(nested ?? []);
    } else if (t.isIdentifier(elem)) {
      // Handle identifiers in arrays: [id1, id2, "literal"]
      const localValue = localVars.get(elem.name);
      if (localValue) {
        if (t.isStringLiteral(localValue)) {
          result.push(localValue.value);
        } else if (t.isNumericLiteral(localValue)) {
          result.push(localValue.value);
        } else if (t.isBooleanLiteral(localValue)) {
          result.push(localValue.value);
        } else if (t.isNullLiteral(localValue)) {
          result.push(null);
        } else if (t.isObjectExpression(localValue)) {
          const obj = resolveObjectExpression(localValue, localVars);
          result.push(obj ?? `\${${elem.name}}`);
        } else if (t.isArrayExpression(localValue)) {
          const nested = resolveArrayExpression(localValue, localVars);
          result.push(nested ?? `\${${elem.name}}`);
        } else {
          result.push(`\${${elem.name}}`);
        }
      } else {
        result.push(`\${${elem.name}}`);
      }
    } else if (t.isMemberExpression(elem)) {
      // Handle member expressions in arrays: [user.id, config.version]
      const path = getMemberExpressionPath(elem);
      const resolved = resolveMemberChain(path, localVars);
      result.push(resolved ?? `\${${path.join('.')}}`);
    } else {
      result.push(`\${X}`);
    }
  }

  return result.length > 0 ? result : undefined;
}

// =============================================================================
// Debug
// =============================================================================

/**
 * Debug: Print webpack module map
 */
export function debugPrintWebpackModules(): void {
  console.log('\n=== WEBPACK MODULES DEBUG ===');
  console.log(`Total modules: ${bundleState.modules.size}`);

  for (const [id, module] of bundleState.modules) {
    console.log(`\nModule ${id}:`);
    console.log(`  Chunk: ${module.chunkId ?? 'N/A'}`);
    console.log(`  Vars: module=${module.moduleVar}, exports=${module.exportsVar}, require=${module.requireVar}`);

    console.log(`  Exports (${module.exports.length}):`);
    for (const exp of module.exports) {
      const value =
        exp.resolvedValue?.type === 'object'
          ? JSON.stringify(exp.resolvedValue.value)
          : exp.resolvedValue?.type === 'string'
            ? exp.resolvedValue.value
            : 'unresolved';
      console.log(`    - ${exp.name}: ${value}`);
    }

    console.log(`  Imports (${module.imports.length}):`);
    for (const imp of module.imports) {
      console.log(`    - ${imp.localVar} = require(${imp.moduleId})`);
    }

    console.log(`  HTTP Calls (${module.httpCalls.length}):`);
    for (const call of module.httpCalls) {
      const url = call.urlSource.resolvedValue ?? call.urlSource.value;
      console.log(`    - ${call.method.toUpperCase()} ${url}`);
    }
  }
  console.log('=============================\n');
}

// =============================================================================
// URL Validation
// =============================================================================

/**
 * Check if a string looks like a valid URL or URL path for HTTP requests.
 *
 * Valid URLs include:
 * - Absolute URLs: https://example.com/api, //example.com/api
 * - Relative paths: /api/endpoint, /users/123, api/endpoint, api-v2/users
 * - URLs with placeholders: /api/users/${id}, ${baseUrl}/endpoint
 * - WebSocket URLs: wss://example.com, ws://example.com
 *
 * Invalid (filtered out):
 * - Single letters/short variables: e, t, n, o, M
 * - HTTP headers: content-type, Content-Length
 * - Event names: popstate, click, load
 * - DOM properties: Location, location.pathname
 * - Property access patterns: e.key, t.pointerId
 * - Date formats: M/D/YYYY
 * - Constants/enum values: ALL, NONE
 */
function isValidUrl(url: string): boolean {
  // Empty or whitespace
  if (!url || !url.trim()) return false;

  // Single character - definitely not a URL
  if (url.length === 1) return false;

  // Very short strings that are likely variable names (2-3 chars without / or protocol)
  // But allow short paths like "/v1", "/v2", "/api"
  if (url.length <= 3 && !url.includes('/') && !url.includes('.') && !url.includes(':')) return false;

  // Pure variable placeholders (no static URL part)
  // Skip: ${e}, ${foo}, ${e.key}, ${obj.prop.value}
  // Allow: /api/${id}, ${baseUrl}/users, /users/${id}/profile
  if (/^\$\{[^}]+\}$/.test(url)) return false;

  // Valid URL patterns - must match at least one
  const validPatterns = [
    // Absolute URLs (http, https, ws, wss)
    /^(https?|wss?):\/\//i,
    // Protocol-relative URLs
    /^\/\//,
    // Absolute paths starting with /
    /^\//,
    // Relative paths with / in them - include hyphens (api-gateway/users, v2-beta/endpoint)
    /^[a-zA-Z0-9_-]+\//,
    // URLs with query strings (allow numeric and underscore params)
    /\?[a-zA-Z0-9_]/,
    // Template URLs with static parts + placeholders
    /^[a-zA-Z0-9_/-]+\$\{/,
    /\$\{[^}]+\}[a-zA-Z0-9_/-]+/,
  ];

  // Must match at least one valid pattern
  return validPatterns.some((pattern) => pattern.test(url));
}

// =============================================================================
// Extracted Request Conversion
// =============================================================================

/**
 * Extracted HTTP request from webpack modules.
 * This interface matches the ExtractedRequest type in requestpattern/types.ts
 */
export interface WebpackExtractedRequest {
  type: 'extractedRequest';
  url: string;
  method: string;
  params: string;
  body: string;
  headers: string[];
  cookies: string[];
}

/**
 * Resolve template placeholders in a string using tracked variables.
 * e.g., "${API_URL}/notification/save" -> "/site-visits-api/notification/save"
 */
function resolveTemplatePlaceholders(value: string, trackedVars: Record<string, string>): string {
  // Match ${varName} or ${obj.prop} patterns
  return value.replace(/\$\{([^}]+)\}/g, (match, varPath) => {
    // Try full path first (e.g., "this.API_URL")
    if (trackedVars[varPath]) {
      return trackedVars[varPath];
    }

    // Try last part of path (e.g., "API_URL" from "this.API_URL")
    const lastPart = varPath.split('.').pop();
    if (lastPart && trackedVars[lastPart]) {
      return trackedVars[lastPart];
    }

    // Return original placeholder if not resolved
    return match;
  });
}

/**
 * Normalize URL for deduplication comparison.
 * Normalizes template variable names to ${X} for consistent matching.
 */
function normalizeUrlForDedup(url: string): string {
  return url.replace(/\$\{[^}]+\}/g, '${X}');
}

/**
 * Convert webpack HTTP calls to extracted requests.
 * This provides properly resolved body params from webpack module context.
 * Results are deduplicated by URL+method+body to reduce redundant entries.
 *
 * @param trackedVars - Optional map of tracked variables for URL resolution
 */
export function getWebpackExtractedRequests(trackedVars?: Record<string, string>): WebpackExtractedRequest[] {
  const requests: WebpackExtractedRequest[] = [];
  const seen = new Set<string>();

  /**
   * Add request with deduplication check
   */
  function addRequest(url: string, method: string, body: string): void {
    // Normalize URL for dedup (${userId} and ${id} should be considered same)
    const normalizedUrl = normalizeUrlForDedup(url);
    const normalizedBody = normalizeUrlForDedup(body);
    const key = `${method}|${normalizedUrl}|${normalizedBody}`;

    if (seen.has(key)) return;
    seen.add(key);

    requests.push({
      type: 'extractedRequest',
      url,
      method,
      params: '',
      body,
      headers: [],
      cookies: [],
    });
  }

  /**
   * Extract body string from BodySource
   */
  function getBodyString(bodySource: BodySource | undefined): string {
    if (!bodySource) return '';
    if (bodySource.type === 'object' && typeof bodySource.value === 'object') {
      return JSON.stringify(bodySource.value);
    }
    if (typeof bodySource.value === 'string') {
      return bodySource.value;
    }
    return '';
  }

  for (const module of bundleState.modules.values()) {
    for (const call of module.httpCalls) {
      const method = call.method.toUpperCase();
      const body = getBodyString(call.bodySource);

      // Handle conditional URLs - create separate requests for each alternative
      if (call.urlSource.type === 'conditional' && call.urlSource.alternatives) {
        for (const altUrl of call.urlSource.alternatives) {
          let url = altUrl;

          // Resolve template placeholders using tracked variables
          if (trackedVars && url.includes('${')) {
            url = resolveTemplatePlaceholders(url, trackedVars);
          }

          // Skip invalid URLs
          if (!isValidUrl(url)) continue;

          addRequest(url, method, body);
        }
        continue;
      }

      // Get URL - resolve from import if possible
      let url = call.urlSource.value;
      if (call.urlSource.resolvedValue) {
        url = call.urlSource.resolvedValue;
      } else if (call.urlSource.type === 'import' && call.urlSource.importPath) {
        // Try to resolve import path
        const resolved = resolveWebpackReference(module.id, call.urlSource.importPath);
        if (resolved && typeof resolved === 'string') {
          url = resolved;
        } else {
          // Unresolved import - convert to placeholder
          url = `\${${call.urlSource.importPath.join('.')}}`;
        }
      }

      // Resolve template placeholders using tracked variables
      if (trackedVars && url.includes('${')) {
        url = resolveTemplatePlaceholders(url, trackedVars);
      }

      // Skip invalid URLs (false positives from map.get(), addEventListener, etc.)
      if (!isValidUrl(url)) continue;

      addRequest(url, method, body);
    }
  }

  return requests;
}
