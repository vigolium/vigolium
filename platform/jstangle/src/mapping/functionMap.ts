/**
 * Function Map State and Builder
 *
 * Provides global state for function mapping and the main entry point
 * for building the map before request extraction.
 */

import type { ParseResult } from '@babel/parser';
import type * as t from '@babel/types';
import type { FunctionMap, FunctionDefinition, CallSite, Framework } from './types';
import { detectFramework, hasWebpackStructureSignal } from './frameworkDetector';
import { extractAngularFunctions } from './extractors/angularExtractor';
import { extractWebpackFunctions } from './extractors/webpackExtractor';
import { extractInnerFunctions } from './extractors/innerFunctionExtractor';
import { indexCallSites } from './callSiteIndexer';
import { getEngineState } from '../context/engine-state';
import type { StructuralIndex } from '../structure';

/**
 * Maximum depth for nested function call resolution.
 * Can be changed via setMaxResolutionDepth().
 */
/**
 * Set the maximum depth for nested function call resolution.
 * @param depth - Maximum depth (default: 5)
 */
export function setMaxResolutionDepth(depth: number): void {
  getEngineState().maxResolutionDepth = Math.max(1, depth);
}

/**
 * Get the current maximum resolution depth.
 */
export function getMaxResolutionDepth(): number {
  return getEngineState().maxResolutionDepth;
}

/**
 * Create an empty function map
 */
export function createEmptyFunctionMap(): FunctionMap {
  return {
    framework: 'unknown',
    functions: new Map(),
    callSites: new Map(),
  };
}

/**
 * Get the current global function map
 */
export function getFunctionMap(): FunctionMap {
  return getEngineState().functionMap;
}

/**
 * Clear the global function map
 */
export function clearFunctionMap(): void {
  getEngineState().functionMap = createEmptyFunctionMap();
}

/**
 * Register a function definition
 */
export function registerFunction(def: FunctionDefinition): void {
  getFunctionMap().functions.set(def.fullName, def);
}

/**
 * Register a call site
 */
export function registerCallSite(callSite: CallSite): void {
  const map = getFunctionMap();
  const sites = map.callSites.get(callSite.targetFunction) || [];
  sites.push(callSite);
  map.callSites.set(callSite.targetFunction, sites);
}

/**
 * Build the function map from AST and source code
 *
 * This should be called BEFORE running request pattern transforms.
 *
 * @param ast - Parsed AST
 * @param sourceCode - Original source code
 * @returns The built function map
 */
export function buildFunctionMap(
  ast: ParseResult<t.File> | null,
  sourceCode: string,
  structuralIndex?: StructuralIndex,
): FunctionMap {
  // Clear previous state
  clearFunctionMap();
  const functionMap = getFunctionMap();

  if (!ast) {
    return functionMap;
  }

  // Step 1: Detect framework
  const framework = detectFramework(sourceCode);
  functionMap.framework = framework;

  // Step 2: Extract function definitions based on framework
  extractFunctionDefinitions(ast, framework, sourceCode, functionMap, structuralIndex);

  // Step 3: Index all call sites
  indexCallSites(ast, functionMap, sourceCode, structuralIndex);

  return functionMap;
}

/**
 * Extract function definitions based on detected framework
 */
function extractFunctionDefinitions(
  ast: ParseResult<t.File>,
  framework: Framework,
  sourceCode: string,
  functionMap: FunctionMap,
  structuralIndex?: StructuralIndex,
): void {
  // First, extract framework-specific functions (services, controllers, etc.)
  // Module graph extraction is substantially heavier than ordinary request
  // dispatch. Run it only after cheap, high-recall bundle structure signals.
  if (framework === 'webpack' || hasWebpackStructureSignal(sourceCode)) {
    extractWebpackFunctions(ast, functionMap, sourceCode);
  }

  switch (framework) {
    case 'angular':
      extractAngularFunctions(ast, functionMap, sourceCode);
      break;
    case 'webpack':
      // Already extracted above
      break;
    default:
      // 'unknown' framework - still works because:
      // 1. extractWebpackFunctions() is called above for all bundles
      // 2. extractInnerFunctions() catches nested function definitions
      // 3. fetchRequest.ts detects fetch() calls directly
      break;
  }

  // Then, extract inner/local functions (works for all frameworks)
  // This catches function declarations and variable function expressions
  // that are nested inside services, directives, controllers, etc.
  extractInnerFunctions(ast, functionMap, sourceCode, structuralIndex);
}

/**
 * Resolve a variable from the function map with recursive nested function support.
 *
 * When an argument is an unresolved variable (like `params`), we check if:
 * 1. The call site is inside another registered function
 * 2. The unresolved variable matches that function's parameter
 * 3. If so, we recursively resolve from that parent function's call sites
 *
 * @param varName - Variable name to resolve (e.g., "params")
 * @param currentFunction - Current function context (e.g., "CommentsService.getComments")
 * @param callSiteIndex - Optional index of call site to use (default: 0 for first)
 * @param parentCallSiteIndex - Optional index of parent function's call site (for nested resolution)
 * @param depth - Current recursion depth (internal use)
 * @param visited - Set of visited functions to prevent cycles (internal use)
 * @returns Resolved value or null if not found
 */
export function resolveFromFunctionMap(
  varName: string,
  currentFunction: string,
  callSiteIndex: number = 0,
  parentCallSiteIndex?: number,
  depth: number = 0,
  visited: Set<string> = new Set()
): string | Record<string, string> | null {
  // Prevent infinite recursion
  if (depth >= getEngineState().maxResolutionDepth) return null;

  // Prevent cycles
  const visitKey = `${currentFunction}:${callSiteIndex}:${varName}`;
  if (visited.has(visitKey)) return null;
  visited.add(visitKey);

  const funcMap = getFunctionMap();

  // Get function definition
  const funcDef = funcMap.functions.get(currentFunction);
  if (!funcDef) return null;

  // Check if varName is a parameter
  const paramIndex = funcDef.params.indexOf(varName);
  if (paramIndex === -1) return null;

  // Get all call sites for this function
  const callSites = funcMap.callSites.get(currentFunction) || [];

  // Return specified call site's argument value
  if (callSiteIndex < callSites.length) {
    const callSite = callSites[callSiteIndex];
    const arg = callSite.arguments[paramIndex];
    if (!arg) return null;

    const value = arg.value;

    // Check if value is an unresolved variable (${varName} pattern)
    if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
      const unresolvedVarName = value.slice(2, -1);

      // If this call site is inside another registered function,
      // try to resolve from that function's call sites
      if (callSite.containingFunction) {
        const parentFuncDef = funcMap.functions.get(callSite.containingFunction);
        if (parentFuncDef) {
          // Check if the unresolved variable is a parameter of the parent function
          const parentParamIdx = parentFuncDef.params.indexOf(unresolvedVarName);
          if (parentParamIdx !== -1) {
            // Get parent function's call sites
            const parentCallSites = funcMap.callSites.get(callSite.containingFunction) || [];

            // If parentCallSiteIndex is specified, use it directly
            if (parentCallSiteIndex !== undefined && parentCallSiteIndex < parentCallSites.length) {
              const resolved = resolveFromFunctionMap(
                unresolvedVarName,
                callSite.containingFunction,
                parentCallSiteIndex,
                undefined,
                depth + 1,
                visited
              );
              if (resolved !== null) {
                return resolved;
              }
            } else {
              // Try each call site of the parent function
              for (let i = 0; i < parentCallSites.length; i++) {
                const resolved = resolveFromFunctionMap(
                  unresolvedVarName,
                  callSite.containingFunction,
                  i,
                  undefined,
                  depth + 1,
                  visited
                );
                if (resolved !== null) {
                  return resolved;
                }
              }
            }
          }
        }
      }
    }

    return value;
  }

  return null;
}

/**
 * Get the number of call sites for a function
 */
export function getCallSiteCount(functionName: string): number {
  return getFunctionMap().callSites.get(functionName)?.length || 0;
}

/**
 * Iteration info for effective call site traversal
 */
export interface EffectiveIteration {
  /** Index for the direct call site of the function */
  callSiteIndex: number;
  /** Index for the parent function's call site (for nested resolution) */
  parentCallSiteIndex?: number;
}

/**
 * Get all effective iterations needed to cover nested function chains.
 *
 * For example:
 * - CommentsService.getComments has 1 call site (inside fillDownloads)
 * - fillDownloads has 2 call sites
 * - We need 2 iterations to cover all combinations
 *
 * @param functionName - The function containing the HTTP request
 * @returns Array of iteration info with call site indices
 */
export function getEffectiveIterations(functionName: string): EffectiveIteration[] {
  const funcMap = getFunctionMap();
  const callSites = funcMap.callSites.get(functionName) || [];

  if (callSites.length === 0) {
    // No call sites - return single iteration with no index
    return [{ callSiteIndex: 0 }];
  }

  const iterations: EffectiveIteration[] = [];
  const state = getEngineState();
  const limit = state.limits.maxTemplateCombinations;
  const addIteration = (iteration: EffectiveIteration): boolean => {
    if (iterations.length >= limit) {
      if (!state.limitHits.has('callsite_combination_limit_reached')) {
        state.limitHits.add('callsite_combination_limit_reached');
        state.reportLimit?.('callsite_combination_limit_reached', `Function call-site expansion limited to ${limit} combinations`);
      }
      return false;
    }
    iterations.push(iteration);
    return true;
  };

  for (let i = 0; i < callSites.length; i++) {
    const callSite = callSites[i];

    // Check if this call site is inside another registered function
    if (callSite.containingFunction) {
      const parentCallSites = funcMap.callSites.get(callSite.containingFunction) || [];

      if (parentCallSites.length > 0) {
        // For each parent call site, we need an iteration
        for (let j = 0; j < parentCallSites.length; j++) {
          if (!addIteration({
            callSiteIndex: i,
            parentCallSiteIndex: j,
          })) return iterations;
        }
      } else {
        // Parent function has no call sites
        if (!addIteration({ callSiteIndex: i })) return iterations;
      }
    } else {
      // Not inside a registered function
      if (!addIteration({ callSiteIndex: i })) return iterations;
    }
  }

  return iterations.length > 0 ? iterations : [{ callSiteIndex: 0 }];
}

/**
 * Get all call sites for a function
 */
export function getCallSites(functionName: string): CallSite[] {
  return getFunctionMap().callSites.get(functionName) || [];
}

/**
 * Check if a function is registered
 */
export function hasFunction(functionName: string): boolean {
  return getFunctionMap().functions.has(functionName);
}

/**
 * Get function definition by name
 */
export function getFunction(functionName: string): FunctionDefinition | undefined {
  return getFunctionMap().functions.get(functionName);
}

/**
 * Debug: Print function map summary
 */
export function debugPrintFunctionMap(): void {
  const map = getFunctionMap();
  console.log('\n=== FUNCTION MAP DEBUG ===');
  console.log(`Framework: ${map.framework}`);
  console.log(`Functions: ${map.functions.size}`);
  console.log(`Call Sites: ${map.callSites.size}`);

  console.log('\nRegistered Functions:');
  for (const [name, def] of map.functions) {
    console.log(`  ${name}(${def.params.join(', ')}) [lines ${def.startLine}-${def.endLine}]`);
  }

  console.log('\nCall Sites:');
  for (const [funcName, sites] of map.callSites) {
    console.log(`  ${funcName}: ${sites.length} call(s)`);
    for (const site of sites) {
      console.log(`    Line ${site.line}: ${JSON.stringify(site.arguments.map(a => a.rawCode))}`);
    }
  }
  console.log('=========================\n');
}

/**
 * Resolve a method call like this.prepareRecord(args) to an object.
 *
 * Uses the method's returnedObject template and substitutes:
 * 1. Call arguments for the method params
 * 2. Parent function's call site values for any remaining unresolved vars
 *
 * @param serviceName - The service containing the method (e.g., "LogService")
 * @param methodName - The method being called (e.g., "prepareRecord")
 * @param callerFunction - The function calling this method (e.g., "LogService.saveView")
 * @param callSiteIndex - Index of the caller function's call site
 * @returns Resolved object or null if resolution failed
 */
export function resolveMethodCall(
  serviceName: string,
  methodName: string,
  callerFunction: string,
  callSiteIndex: number = 0
): Record<string, unknown> | null {
  const funcMap = getFunctionMap();

  // Get the method definition
  const methodFullName = `${serviceName}.${methodName}`;
  const methodDef = funcMap.functions.get(methodFullName);
  if (!methodDef || !methodDef.returnedObject) {
    return null;
  }

  // Get the caller function definition
  const callerDef = funcMap.functions.get(callerFunction);
  if (!callerDef) {
    return null;
  }

  // Get the call sites for the caller function
  const callerCallSites = funcMap.callSites.get(callerFunction) || [];
  if (callSiteIndex >= callerCallSites.length) {
    return null;
  }

  const callerCallSite = callerCallSites[callSiteIndex];

  // Get call sites for the method (this.prepareRecord calls)
  // These should be indexed from callSiteIndexer for this.methodName() patterns
  const methodCallSites = funcMap.callSites.get(methodFullName) || [];

  // Find the call site inside the caller function
  const methodCallSiteInCaller = methodCallSites.find(
    cs => cs.containingFunction === callerFunction
  );

  // Build a map of parameter name -> resolved value
  const resolvedParams: Record<string, string | Record<string, string>> = {};

  // Step 1: Resolve method's own arguments from its call site
  if (methodCallSiteInCaller) {
    for (const arg of methodCallSiteInCaller.arguments) {
      let value = arg.value;

      // If the value is an unresolved ${param} from caller function params,
      // resolve it from caller's call site
      if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
        const unresolvedVarName = value.slice(2, -1);
        const callerParamIdx = callerDef.params.indexOf(unresolvedVarName);
        if (callerParamIdx !== -1 && callerParamIdx < callerCallSite.arguments.length) {
          value = callerCallSite.arguments[callerParamIdx].value;
        }
      }

      resolvedParams[arg.paramName] = value;
    }
  }

  // Step 2: Substitute into the returned object template
  return substituteTemplate(methodDef.returnedObject, resolvedParams);
}

/**
 * Substitute resolved values into an object template.
 */
function substituteTemplate(
  template: Record<string, string | Record<string, unknown>>,
  resolvedParams: Record<string, string | Record<string, string>>
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(template)) {
    if (typeof value === 'string') {
      // Check if it's a ${paramName} reference
      if (value.startsWith('${') && value.endsWith('}')) {
        const paramName = value.slice(2, -1);
        if (paramName in resolvedParams) {
          result[key] = resolvedParams[paramName];
        } else {
          // Keep the template reference
          result[key] = value;
        }
      } else {
        result[key] = value;
      }
    } else if (typeof value === 'object' && value !== null) {
      // Recursively substitute nested objects
      result[key] = substituteTemplate(
        value as Record<string, string | Record<string, unknown>>,
        resolvedParams
      );
    } else {
      result[key] = value;
    }
  }

  return result;
}
