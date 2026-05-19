import * as t from "@babel/types";
import type { NodePath } from "../ast-utils/babel";
import {
  getEffectiveIterations,
  hasFunction,
  resolveFromFunctionMap,
  resolveMethodCall,
  type EffectiveIteration,
} from "../mapping";
import type { ExtractedRequest, TrackedVariableMap } from "./types";
import { isURLLike } from "./utils";

/**
 * Wrap a complex expression as a ${...} placeholder.
 * Uses a consistent placeholder ${expr} for all complex expressions.
 * This avoids issues with spaces in expressions breaking URL parsing,
 * while still allowing deduplication to work (same placeholder = same URL).
 */
function wrapExpressionAsPlaceholder(): string {
  // Use consistent placeholder for all complex expressions
  // This prevents unique counters from causing request explosion
  return "${X}";
}

/**
 * Extract URL from a dispatch/commit call expression.
 * Handles patterns like:
 * - store.dispatch("setURL", "https://api.example.com")
 * - St.dispatch("setURL", "https://api.example.com")
 * - commit("SET_API_URL", "https://api.example.com")
 *
 * Returns the URL string if found, null otherwise.
 */
function extractUrlFromDispatchCall(node: t.CallExpression): string | null {
  const { callee, arguments: args } = node;

  // Check for X.dispatch() or X.commit() pattern
  if (
    t.isMemberExpression(callee) &&
    t.isIdentifier(callee.property) &&
    (callee.property.name === "dispatch" || callee.property.name === "commit")
  ) {
    // dispatch/commit typically takes (actionName, payload)
    // The URL is usually in the second argument
    if (args.length >= 2) {
      const urlArg = args[1];
      if (t.isStringLiteral(urlArg) && isURLLike(urlArg.value)) {
        return urlArg.value;
      }
    }
  }

  return null;
}

/**
 * Extract URLs from a single branch of a conditional expression.
 * Handles: StringLiteral, ConditionalExpression, CallExpression (dispatch), and other nodes.
 */
function extractUrlFromBranch(
  node: t.Expression,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] | null {
  // Direct string literal
  if (t.isStringLiteral(node)) {
    if (isURLLike(node.value)) {
      return [node.value];
    }
    return null;
  }

  // Nested conditional - recurse
  if (t.isConditionalExpression(node)) {
    return extractUrlsFromConditional(node, trackedVars, context);
  }

  // Call expression - check for dispatch/commit pattern
  if (t.isCallExpression(node)) {
    const dispatchUrl = extractUrlFromDispatchCall(node);
    if (dispatchUrl) {
      return [dispatchUrl];
    }
  }

  // Try to resolve other node types
  const resolved = resolveValueNoConditional(node, trackedVars, context);
  if (
    !resolved.includes("${X}") &&
    !resolved.includes("${unknown}") &&
    isURLLike(resolved)
  ) {
    return [resolved];
  }

  return null;
}

/**
 * Recursively extract all URL-like string values from a conditional expression chain.
 * Handles nested ternaries: a ? b : (c ? d : e)
 *
 * This is used to extract all environment-specific URLs from patterns like:
 * hostname === "prod" ? "https://prod.api" : hostname === "stage" ? "https://stage.api" : "https://dev.api"
 */
function extractUrlsFromConditional(
  node: t.ConditionalExpression,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] {
  const urls: string[] = [];

  // Extract from consequent (true branch)
  const consequentUrl = extractUrlFromBranch(
    node.consequent,
    trackedVars,
    context,
  );
  if (consequentUrl) {
    urls.push(...consequentUrl);
  }

  // Extract from alternate (false branch)
  const alternateUrl = extractUrlFromBranch(
    node.alternate,
    trackedVars,
    context,
  );
  if (alternateUrl) {
    urls.push(...alternateUrl);
  }

  // Deduplicate
  return [...new Set(urls)];
}

/**
 * Simplified resolveValue that doesn't recurse into conditionals.
 * Used by extractUrlsFromConditional to avoid infinite recursion.
 * Returns single string (not array) for simpler URL extraction logic.
 */
function resolveValueNoConditional(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string {
  if (!node) return "";

  if (t.isStringLiteral(node)) return node.value;
  if (t.isNumericLiteral(node)) return String(node.value);
  if (t.isBooleanLiteral(node)) return String(node.value);
  if (t.isNullLiteral(node)) return "null";

  if (t.isIdentifier(node)) {
    const values = trackedVars[node.name];
    if (values && values.length > 0) return values[0];
    return `\${${node.name}}`;
  }

  if (t.isBinaryExpression(node) && node.operator === "+") {
    const left = resolveValueNoConditional(node.left, trackedVars, context);
    const right = resolveValueNoConditional(node.right, trackedVars, context);
    return left + right;
  }

  // For conditionals, return placeholder (avoid recursion)
  if (t.isConditionalExpression(node) || t.isLogicalExpression(node)) {
    return "${X}";
  }

  return "${unknown}";
}

/**
 * Context for resolving values within a function
 */
export interface ResolutionContext {
  /** Current function we're in: "CommentsService.getComments" */
  currentFunction?: string;
  /** Index of call site to use for parameter resolution */
  callSiteIndex?: number;
  /** Index of parent function's call site (for nested resolution) */
  parentCallSiteIndex?: number;
}

/**
 * Find the current function containing this path.
 * Returns the function name for function mapping resolution.
 *
 * For Angular patterns like:
 *   .factory('ServiceName', function() { var api = { methodName: function() {...} }; return api; })
 * We need to find the factory name and combine with method name.
 */
export function findContainingFunction(path: NodePath): string | undefined {
  let current = path.parentPath;

  while (current) {
    // Check for function expression/declaration with name
    if (current.isFunctionDeclaration() || current.isFunctionExpression()) {
      const node = current.node as t.FunctionDeclaration | t.FunctionExpression;
      if (node.id && t.isIdentifier(node.id)) {
        return node.id.name;
      }
    }

    // Check for variable declarator with function
    if (current.isVariableDeclarator()) {
      const node = current.node as t.VariableDeclarator;
      if (
        t.isIdentifier(node.id) &&
        (t.isFunctionExpression(node.init) ||
          t.isArrowFunctionExpression(node.init))
      ) {
        return node.id.name;
      }
    }

    // Check for object property with function value
    if (current.isObjectProperty()) {
      const prop = current.node as t.ObjectProperty;
      if (
        t.isIdentifier(prop.key) &&
        (t.isFunctionExpression(prop.value) ||
          t.isArrowFunctionExpression(prop.value))
      ) {
        const methodName = prop.key.name;

        // Try to get service name from parent chain
        const objectExpr = current.parentPath;
        if (objectExpr?.isObjectExpression()) {
          const varDeclarator = objectExpr.parentPath;
          if (
            varDeclarator?.isVariableDeclarator() &&
            t.isIdentifier(varDeclarator.node.id)
          ) {
            // Check if this var is returned in an Angular factory/service pattern
            // by looking for .factory('ServiceName', ...) in ancestor chain
            const serviceName = findAngularServiceName(varDeclarator);
            if (serviceName) {
              return `${serviceName}.${methodName}`;
            }

            return `${varDeclarator.node.id.name}.${methodName}`;
          }
        }
        return methodName;
      }
    }

    // Check for assignment expression (scope.methodName = function)
    if (current.isAssignmentExpression()) {
      const node = current.node as t.AssignmentExpression;
      if (
        t.isMemberExpression(node.left) &&
        t.isIdentifier(node.left.property)
      ) {
        if (
          t.isFunctionExpression(node.right) ||
          t.isArrowFunctionExpression(node.right)
        ) {
          return node.left.property.name;
        }
      }
    }

    current = current.parentPath;
  }
  return undefined;
}

/**
 * Find Angular service/factory name from parent chain.
 * Looks for patterns like: .factory('ServiceName', function() { ... })
 */
function findAngularServiceName(path: NodePath): string | null {
  let current = path.parentPath;

  while (current) {
    // Look for CallExpression with .factory/.service/.controller
    if (current.isCallExpression()) {
      const callee = current.node.callee;
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
        const methodName = callee.property.name;
        if (
          methodName === "factory" ||
          methodName === "service" ||
          methodName === "controller"
        ) {
          // Get service name from first argument
          const args = current.node.arguments;
          if (args.length > 0 && t.isStringLiteral(args[0])) {
            return args[0].value;
          }
        }
      }
    }
    current = current.parentPath;
  }

  return null;
}

/**
 * Get effective iterations for function mapping resolution.
 * Returns array of iteration contexts, or a single default context if no mapping exists.
 */
export function getEffectiveIterationsForFunction(
  currentFunction: string | undefined,
): EffectiveIteration[] {
  if (currentFunction && hasFunction(currentFunction)) {
    return getEffectiveIterations(currentFunction);
  }
  return [{ callSiteIndex: 0 }];
}

/**
 * Create a resolution context for the given function and iteration.
 */
export function createResolutionContext(
  currentFunction: string | undefined,
  iteration: EffectiveIteration,
): ResolutionContext | undefined {
  if (!currentFunction || !hasFunction(currentFunction)) {
    return undefined;
  }
  return {
    currentFunction,
    callSiteIndex: iteration.callSiteIndex,
    parentCallSiteIndex: iteration.parentCallSiteIndex,
  };
}

/**
 * Resolve a node from Babel scope.
 * If node is an Identifier, looks up its binding and returns the initializer.
 */
export function resolveFromScope(
  node: t.Node | null | undefined,
  path: NodePath | null,
): t.Node | null {
  if (!node || !path) return node ?? null;

  if (t.isIdentifier(node)) {
    const binding = path.scope.getBinding(node.name);
    if (binding?.path.isVariableDeclarator()) {
      const init = (binding.path.node as t.VariableDeclarator).init;
      if (init) return init;
    }
  }

  return node;
}

/**
 * Resolve an AST node to string value(s).
 * Returns array of strings to support multiple values (e.g., from conditionals).
 * For unresolved variables, returns ${variableName} template format.
 *
 * @param node - The AST node to resolve
 * @param trackedVars - Map of tracked variable names to values (arrays)
 * @param context - Optional context for function-aware resolution
 */
export function resolveValue(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] {
  if (!node) return [""];

  // Case 1: Direct string literal
  if (t.isStringLiteral(node)) {
    return [node.value];
  }

  // Case 1b: Numeric literal
  if (t.isNumericLiteral(node)) {
    return [String(node.value)];
  }

  // Case 1c: Boolean literal
  if (t.isBooleanLiteral(node)) {
    return [String(node.value)];
  }

  // Case 1d: Null literal
  if (t.isNullLiteral(node)) {
    return ["null"];
  }

  // Case 1e: BigInt literal
  if (t.isBigIntLiteral(node)) {
    return [node.value];
  }

  // Case 2: Template literal
  if (t.isTemplateLiteral(node)) {
    return buildTemplateStrings(node, trackedVars, context);
  }

  // Case 3: Identifier - try to resolve from tracked variables or function map
  if (t.isIdentifier(node)) {
    const varName = node.name;

    // First: check tracked variables (now returns array)
    const trackedValues = trackedVars[varName];
    if (trackedValues && trackedValues.length > 0) {
      return trackedValues;
    }

    // Second: check function map if we have context
    if (context?.currentFunction) {
      const fromFuncMap = resolveFromFunctionMap(
        varName,
        context.currentFunction,
        context.callSiteIndex ?? 0,
        context.parentCallSiteIndex,
      );
      if (fromFuncMap !== null) {
        // If resolved to an object, convert to key=value format
        if (typeof fromFuncMap === "object") {
          return [Object.entries(fromFuncMap)
            .map(([k, v]) => `${k}=${v}`)
            .join("&")];
        }
        return [fromFuncMap];
      }
    }

    return [`\${${varName}}`];
  }

  // Case 4: Member expression (e.g., config.apiUrl, obj['key'], a.O.accountLogin)
  if (t.isMemberExpression(node)) {
    // Build full path for deep member expressions (e.g., a.O.accountLogin)
    const fullPath = buildMemberExpressionPath(node);

    // Try full path first (for webpack imports like a.O.accountLogin)
    const fullPathValues = fullPath ? trackedVars[fullPath] : undefined;
    if (fullPathValues && fullPathValues.length > 0) {
      return fullPathValues;
    }

    const propertyName = t.isIdentifier(node.property)
      ? node.property.name
      : t.isStringLiteral(node.property)
        ? node.property.value
        : "";

    const propValues = propertyName ? trackedVars[propertyName] : undefined;
    if (propValues && propValues.length > 0) {
      return propValues;
    }

    // Try 2-level path like "obj.prop"
    const objName = t.isIdentifier(node.object) ? node.object.name : "";
    const twoLevelPath =
      objName && propertyName ? `${objName}.${propertyName}` : propertyName;

    const twoLevelValues = twoLevelPath ? trackedVars[twoLevelPath] : undefined;
    if (twoLevelValues && twoLevelValues.length > 0) {
      return twoLevelValues;
    }

    return [`\${${propertyName || "unknown"}}`];
  }

  // Case 5: Call expression - return placeholder with function name
  if (t.isCallExpression(node)) {
    // Special case: Object({...}) - treat as ObjectExpression
    // This handles Vue.js/webpack environment config patterns like:
    // Object({VUE_APP_PROD_API: "https://...", VUE_APP_DEV_API: "https://..."})
    if (t.isIdentifier(node.callee) && node.callee.name === "Object") {
      const arg = node.arguments[0];
      if (arg && t.isObjectExpression(arg)) {
        return [objectToJSON(arg, trackedVars)];
      }
    }

    const calleeName = getCalleeName(node.callee);
    return [`\${${calleeName}()}`];
  }

  // Case 6: Binary expression (string concatenation)
  if (t.isBinaryExpression(node) && node.operator === "+") {
    const leftValues = resolveValue(node.left, trackedVars, context);
    const rightValues = resolveValue(node.right, trackedVars, context);

    // Cartesian product of all combinations
    const combinations: string[] = [];
    for (const l of leftValues) {
      for (const r of rightValues) {
        combinations.push(l + r);
      }
    }
    return combinations;
  }

  // Case 7: Conditional expression (ternary)
  // Extract all URL-like string values from all branches
  if (t.isConditionalExpression(node)) {
    const urls = extractUrlsFromConditional(node, trackedVars, context);
    if (urls.length > 0) {
      return urls;
    }
    // Fallback if no URLs found
    return [wrapExpressionAsPlaceholder()];
  }

  // Case 8: Logical expression (a || b, a && b)
  // These are also complex - wrap as placeholder
  if (t.isLogicalExpression(node)) {
    return [wrapExpressionAsPlaceholder()];
  }

  // Case 8b: Binary comparison expressions (===, !==, ==, !=, <, >, etc.)
  // These appear in minified optional chaining like: null===o||void 0===o
  if (t.isBinaryExpression(node) && node.operator !== "+") {
    return [wrapExpressionAsPlaceholder()];
  }

  // Case 9: Array expression - wrap as ${expr} if contains unresolved elements
  if (t.isArrayExpression(node)) {
    // Check if any element is complex/unresolved
    const hasUnresolvedElements = node.elements.some((elem) => {
      if (!elem) return false;
      if (t.isSpreadElement(elem)) return true;
      // Complex elements that will generate ${...} placeholders
      if (t.isObjectExpression(elem) || t.isArrayExpression(elem)) return true;
      if (t.isConditionalExpression(elem) || t.isLogicalExpression(elem))
        return true;
      if (t.isBinaryExpression(elem) && elem.operator !== "+") return true;
      if (
        t.isCallExpression(elem) ||
        t.isMemberExpression(elem) ||
        t.isIdentifier(elem)
      )
        return true;
      return false;
    });

    if (hasUnresolvedElements) {
      return [wrapExpressionAsPlaceholder()];
    }

    // All elements are simple literals - serialize as array
    const elements = node.elements.map((elem) => {
      if (!elem) return "null";
      return resolveValue(elem, trackedVars, context)[0];
    });
    return [`[${elements.join(",")}]`];
  }

  // Case 10: Nested object expression - use objectToJSON for proper JSON serialization
  if (t.isObjectExpression(node)) {
    // Note: objectToJSON uses path for scope resolution, not context
    return [objectToJSON(node, trackedVars)];
  }

  // Case 11: Unary expression (-1, !true, +value)
  if (t.isUnaryExpression(node)) {
    // Handle minified booleans: !0 -> true, !1 -> false
    if (node.operator === "!" && t.isNumericLiteral(node.argument)) {
      return [node.argument.value === 0 ? "true" : "false"];
    }

    const argumentValues = resolveValue(node.argument, trackedVars, context);
    // If any argument contains unresolved placeholder, wrap entire expression as ${expr}
    if (argumentValues.some(v => v.includes("${"))) {
      return [wrapExpressionAsPlaceholder()];
    }
    return argumentValues.map(arg => `${node.operator}${arg}`);
  }

  return ["${unknown}"];
}

/**
 * Resolve an AST node to a single string value.
 * Convenience wrapper that returns first value from resolveValue.
 * Use this when you only need one value (e.g., HTTP method, header value).
 */
export function resolveValueSingle(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string {
  const values = resolveValue(node, trackedVars, context);
  return values[0] ?? "";
}

/**
 * Build strings from a template literal, resolving expressions where possible.
 * Returns array to support multiple values from expressions.
 */
function buildTemplateStrings(
  node: t.TemplateLiteral,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] {
  // Start with just the first quasi
  let results: string[] = [node.quasis[0].value.raw];

  for (let i = 0; i < node.expressions.length; i++) {
    const expr = node.expressions[i];
    const resolvedValues = resolveValue(expr as t.Node, trackedVars, context);
    const nextQuasi = node.quasis[i + 1]?.value.raw ?? "";

    // Expand combinations: each result × each resolved value
    const newResults: string[] = [];
    for (const result of results) {
      for (const resolved of resolvedValues) {
        newResults.push(result + resolved + nextQuasi);
      }
    }
    results = newResults;
  }

  return results;
}

/**
 * Build full path from a MemberExpression.
 * e.g., a.O.accountLogin -> "a.O.accountLogin"
 */
function buildMemberExpressionPath(node: t.MemberExpression): string {
  const parts: string[] = [];

  let current: t.Node = node;
  while (t.isMemberExpression(current)) {
    if (t.isIdentifier(current.property)) {
      parts.unshift(current.property.name);
    } else if (t.isStringLiteral(current.property)) {
      parts.unshift(current.property.value);
    } else {
      // Can't build path with computed properties
      return "";
    }
    current = current.object;
  }

  if (t.isIdentifier(current)) {
    parts.unshift(current.name);
  } else {
    // Can't build path if root is not identifier
    return "";
  }

  return parts.join(".");
}

/**
 * Get the name of a callee (for call expressions).
 */
function getCalleeName(callee: t.Node): string {
  if (t.isIdentifier(callee)) {
    return callee.name;
  }
  if (t.isMemberExpression(callee)) {
    const propName = t.isIdentifier(callee.property)
      ? callee.property.name
      : "";
    const objName = t.isIdentifier(callee.object) ? callee.object.name : "";
    return objName && propName ? `${objName}.${propName}` : propName || objName;
  }
  return "unknown";
}

/**
 * Check if a node potentially represents a URL.
 * Handles: StringLiteral, TemplateLiteral, BinaryExpression, MemberExpression,
 *          CallExpression, Identifier
 *
 * This is a shared utility used by multiple request pattern transforms to validate
 * if an AST node could be a URL before attempting to extract it.
 */
export function isValidUrlNode(node: t.Node | null | undefined): boolean {
  if (!node) return false;

  // Direct string literal containing /
  if (t.isStringLiteral(node)) {
    return node.value.includes("/");
  }

  // Template literal containing /
  if (t.isTemplateLiteral(node)) {
    return node.quasis.some((quasi) => quasi.value.raw.includes("/"));
  }

  // Binary expression (string concatenation): a + b
  // Recursively check if either side contains a valid URL part
  if (t.isBinaryExpression(node) && node.operator === "+") {
    return isValidUrlNode(node.left) || isValidUrlNode(node.right);
  }

  // Member expression: config.apiUrl, this.API_URL
  if (t.isMemberExpression(node)) {
    if (t.isIdentifier(node.property)) {
      const name = node.property.name.toLowerCase();
      // Accept if property name looks URL-related or is not a single char
      return (
        name.includes("url") ||
        name.includes("endpoint") ||
        name.includes("api") ||
        name.includes("path") ||
        name.includes("uri") ||
        name.includes("href") ||
        name.length > 1
      );
    }
    return false;
  }

  // Identifier: API_URL, baseUrl, etc.
  if (t.isIdentifier(node)) {
    const name = node.name.toLowerCase();
    return (
      name.includes("url") ||
      name.includes("endpoint") ||
      name.includes("api") ||
      name.includes("path") ||
      name.includes("uri") ||
      name.includes("href")
    );
  }

  // Call expression: getUrl(), buildPath()
  if (t.isCallExpression(node)) {
    const callee = node.callee;
    if (t.isIdentifier(callee)) {
      return callee.name.length > 1;
    }
    if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
      return callee.property.name.length > 1;
    }
    return false;
  }

  return false;
}

/**
 * Extract URL and query params from a node.
 * Returns array of results to support multiple URLs.
 */
export function extractURL(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): Array<{ url: string; queryParams: string }> {
  const fullUrls = resolveValue(node, trackedVars, context);

  return fullUrls.map(fullUrl => {
    const questionIndex = fullUrl.indexOf("?");
    if (questionIndex === -1) {
      return { url: fullUrl, queryParams: "" };
    }
    return {
      url: fullUrl.substring(0, questionIndex),
      queryParams: fullUrl.substring(questionIndex + 1),
    };
  });
}

/**
 * Extract URL and query params from a node - single result version.
 * Returns first URL only. Use extractURL for multiple results.
 */
export function extractURLSingle(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): { url: string; queryParams: string } {
  const results = extractURL(node, trackedVars, context);
  return results[0] ?? { url: "", queryParams: "" };
}

/**
 * Find a property in an ObjectExpression by name.
 */
export function findProperty(
  obj: t.ObjectExpression | null | undefined,
  propertyName: string,
): t.Node | null {
  if (!obj || !t.isObjectExpression(obj)) return null;

  for (const prop of obj.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : null;

    if (keyName === propertyName) {
      return prop.value;
    }
  }

  return null;
}

/**
 * Extract a property value as a string.
 * Returns single value (first if multiple).
 */
export function extractProperty(
  obj: t.ObjectExpression | null | undefined,
  propertyName: string,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string {
  const propNode = findProperty(obj, propertyName);
  return resolveValueSingle(propNode, trackedVars, context);
}

/**
 * Extract headers from an ObjectExpression.
 * Also handles CallExpression by extracting from object arguments.
 */
export function extractHeaders(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] {
  if (!node) return [];

  // Handle ObjectExpression directly
  if (t.isObjectExpression(node)) {
    return extractHeadersFromObject(node, trackedVars, context);
  }

  // Handle CallExpression - try to extract from object arguments
  // Pattern: (0, a.A)({}, e, { actualHeaders })
  if (t.isCallExpression(node)) {
    const headers: string[] = [];
    for (let i = node.arguments.length - 1; i >= 0; i--) {
      const arg = node.arguments[i];
      if (t.isObjectExpression(arg)) {
        headers.push(...extractHeadersFromObject(arg, trackedVars, context));
      }
    }
    return headers;
  }

  return [];
}

/**
 * Extract headers from an ObjectExpression node.
 */
function extractHeadersFromObject(
  node: t.ObjectExpression,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] {
  const headers: string[] = [];

  for (const prop of node.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : resolveValueSingle(prop.key, trackedVars, context);

    // Skip Cookie header (handled separately)
    if (keyName.toLowerCase() === "cookie") continue;

    const value = resolveValueSingle(prop.value, trackedVars, context);
    headers.push(`${keyName}: ${value}`);
  }

  return headers;
}

/**
 * Extract cookies from headers ObjectExpression (looks for Cookie header).
 */
export function extractCookies(
  headersNode: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] {
  if (!headersNode || !t.isObjectExpression(headersNode)) return [];

  for (const prop of headersNode.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : null;

    if (keyName?.toLowerCase() === "cookie") {
      const value = resolveValueSingle(prop.value, trackedVars, context);
      return value
        .split(";")
        .map((c: string) => c.trim())
        .filter((c: string) => c.length > 0);
    }
  }

  return [];
}

/**
 * Extract cookies from a dedicated cookies property (e.g., cookies: { key: value }).
 * Converts each property to "key=value" format.
 */
export function extractCookiesFromProperty(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string[] {
  if (!node || !t.isObjectExpression(node)) return [];

  const cookies: string[] = [];
  for (const prop of node.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : null;

    if (!keyName) continue;

    const value = resolveValueSingle(prop.value, trackedVars, context);
    cookies.push(`${keyName}=${value}`);
  }

  return cookies;
}

/**
 * Resolve a call expression to a value, with scope resolution support.
 */
function resolveCallExpression(
  node: t.CallExpression,
  trackedVars: TrackedVariableMap,
  path?: NodePath | null,
  context?: ResolutionContext,
): unknown {
  const calleeName = getCalleeName(node.callee);

  // Special case: JSON.stringify(x) - inline the object
  if (calleeName === "JSON.stringify" && node.arguments.length > 0) {
    const arg = node.arguments[0];

    // Try scope resolution first
    const resolved = path ? resolveFromScope(arg, path) : arg;
    if (resolved && t.isObjectExpression(resolved)) {
      return JSON.parse(objectToJSON(resolved, trackedVars, path));
    }

    // Try function map resolution for identifiers (function parameters)
    if (t.isIdentifier(arg) && context?.currentFunction) {
      const fromFuncMap = resolveFromFunctionMap(
        arg.name,
        context.currentFunction,
        context.callSiteIndex ?? 0,
        context.parentCallSiteIndex,
      );
      if (fromFuncMap !== null && typeof fromFuncMap === "object") {
        return fromFuncMap;
      }
    }

    return `\${JSON.stringify(${t.isIdentifier(arg) ? arg.name : "unknown"})}`;
  }

  // Special case: xxx.stringify(obj) - try to inline
  if (calleeName.endsWith(".stringify") && node.arguments.length > 0) {
    const arg = node.arguments[0];

    // Try scope resolution first
    const resolved = path ? resolveFromScope(arg, path) : arg;
    if (resolved && t.isObjectExpression(resolved)) {
      return JSON.parse(objectToJSON(resolved, trackedVars, path));
    }

    // Try function map resolution for identifiers (function parameters)
    if (t.isIdentifier(arg) && context?.currentFunction) {
      const fromFuncMap = resolveFromFunctionMap(
        arg.name,
        context.currentFunction,
        context.callSiteIndex ?? 0,
        context.parentCallSiteIndex,
      );
      if (fromFuncMap !== null && typeof fromFuncMap === "object") {
        return fromFuncMap;
      }
    }

    if (t.isIdentifier(arg)) {
      return `\${stringify(${arg.name})}`;
    }
  }

  // Default: return placeholder with function name
  return `\${${calleeName}()}`;
}

/**
 * Convert an ObjectExpression to JSON string format.
 * Supports scope resolution when path is provided.
 */
export function objectToJSON(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  path?: NodePath | null,
): string {
  // If node is Identifier, resolve from scope first
  const resolved = path ? resolveFromScope(node, path) : node;

  if (!resolved || !t.isObjectExpression(resolved)) {
    return resolveValueSingle(resolved ?? node, trackedVars);
  }

  const obj: Record<string, unknown> = {};

  for (const prop of resolved.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : null;

    if (!keyName) continue;

    // Recursively resolve nested objects
    if (t.isObjectExpression(prop.value)) {
      obj[keyName] = JSON.parse(objectToJSON(prop.value, trackedVars, path));
    }
    // Resolve identifiers from scope
    else if (t.isIdentifier(prop.value)) {
      const resolvedValue = path ? resolveFromScope(prop.value, path) : null;
      if (resolvedValue && t.isObjectExpression(resolvedValue)) {
        obj[keyName] = JSON.parse(
          objectToJSON(resolvedValue, trackedVars, path),
        );
      } else {
        obj[keyName] = resolveValueSingle(prop.value, trackedVars);
      }
    }
    // Handle call expressions specially
    else if (t.isCallExpression(prop.value)) {
      obj[keyName] = resolveCallExpression(prop.value, trackedVars, path);
    }
    // Handle arrays
    else if (t.isArrayExpression(prop.value)) {
      obj[keyName] = arrayToValues(prop.value, trackedVars, path);
    }
    // Primitives
    else if (t.isNumericLiteral(prop.value)) {
      obj[keyName] = prop.value.value;
    } else if (t.isBooleanLiteral(prop.value)) {
      obj[keyName] = prop.value.value;
    } else if (t.isNullLiteral(prop.value)) {
      obj[keyName] = null;
    }
    // Handle minified booleans: !0 -> true, !1 -> false
    else if (
      t.isUnaryExpression(prop.value) &&
      prop.value.operator === "!" &&
      t.isNumericLiteral(prop.value.argument)
    ) {
      obj[keyName] = prop.value.argument.value === 0;
    } else {
      obj[keyName] = resolveValueSingle(prop.value, trackedVars);
    }
  }

  return JSON.stringify(obj);
}

/**
 * Convert an ArrayExpression to array of values.
 * Supports scope resolution when path is provided.
 */
function arrayToValues(
  node: t.ArrayExpression,
  trackedVars: TrackedVariableMap,
  path?: NodePath | null,
): unknown[] {
  return node.elements.map((elem) => {
    if (!elem) return null;
    if (t.isSpreadElement(elem))
      return `\${...${resolveValueSingle(elem.argument, trackedVars)}}`;
    if (t.isObjectExpression(elem))
      return JSON.parse(objectToJSON(elem, trackedVars, path));
    if (t.isArrayExpression(elem))
      return arrayToValues(elem, trackedVars, path);
    if (t.isNumericLiteral(elem)) return elem.value;
    if (t.isBooleanLiteral(elem)) return elem.value;
    if (t.isNullLiteral(elem)) return null;
    // Handle minified booleans: !0 -> true, !1 -> false
    if (
      t.isUnaryExpression(elem) &&
      elem.operator === "!" &&
      t.isNumericLiteral(elem.argument)
    ) {
      return elem.argument.value === 0;
    }
    // Resolve identifiers from scope
    if (t.isIdentifier(elem)) {
      const resolved = path ? resolveFromScope(elem, path) : null;
      if (resolved && t.isObjectExpression(resolved)) {
        return JSON.parse(objectToJSON(resolved, trackedVars, path));
      }
    }
    if (t.isCallExpression(elem)) {
      return resolveCallExpression(elem, trackedVars, path);
    }
    return resolveValueSingle(elem, trackedVars);
  });
}

/**
 * Convert an ObjectExpression to key=value format for params/body.
 */
export function objectToKeyValue(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
): string {
  if (!node || !t.isObjectExpression(node)) {
    return resolveValueSingle(node, trackedVars, context);
  }

  const pairs: string[] = [];

  for (const prop of node.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : null;

    if (!keyName) continue;

    const value = resolveValueSingle(prop.value, trackedVars, context);
    pairs.push(`${keyName}=${value}`);
  }

  return pairs.join("&");
}

/**
 * Convert an ObjectExpression to key=value format, with nested objects as JSON values.
 * For params in GET requests: { reqdate, data: { appid, zalopayid } } becomes
 * "reqdate=${...}&data={"appid":"...","zalopayid":"..."}"
 * Supports scope resolution when path is provided.
 */
export function objectToKeyValueWithNestedJSON(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  path?: NodePath | null,
  context?: ResolutionContext,
): string {
  // Resolve identifier from scope first
  const resolved = path ? resolveFromScope(node, path) : node;

  if (!resolved || !t.isObjectExpression(resolved)) {
    return resolveValueSingle(resolved ?? node, trackedVars, context);
  }

  const pairs: string[] = [];

  for (const prop of resolved.properties) {
    if (!t.isObjectProperty(prop)) continue;

    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : null;

    if (!keyName) continue;

    let value: string;
    // For nested objects, use JSON format
    if (t.isObjectExpression(prop.value)) {
      value = objectToJSON(prop.value, trackedVars, path);
    }
    // For identifiers that resolve to objects, also use JSON
    else if (t.isIdentifier(prop.value)) {
      const resolvedValue = path ? resolveFromScope(prop.value, path) : null;
      if (resolvedValue && t.isObjectExpression(resolvedValue)) {
        value = objectToJSON(resolvedValue, trackedVars, path);
      } else {
        value = resolveValueSingle(prop.value, trackedVars, context);
      }
    }
    // For primitives and other types, use resolveValueSingle
    else {
      value = resolveValueSingle(prop.value, trackedVars, context);
    }

    pairs.push(`${keyName}=${value}`);
  }

  return pairs.join("&");
}

/**
 * Extract body from a node. Returns JSON if object, key=value if simple object, or resolved string.
 * Supports scope resolution when path is provided.
 */
export function extractBody(
  node: t.Node | null | undefined,
  trackedVars: TrackedVariableMap,
  path?: NodePath | null,
  context?: ResolutionContext,
): string {
  if (!node) return "";

  // Resolve identifier from scope first
  const resolved = path ? resolveFromScope(node, path) : node;

  // Check if it's an ObjectExpression
  if (t.isObjectExpression(resolved)) {
    return objectToJSON(resolved, trackedVars, path);
  }

  // Handle Identifier that couldn't be resolved from scope - try function map
  // This handles cases like: $http.put(url, data) where data is a function parameter
  if (t.isIdentifier(node) && !resolved && context?.currentFunction) {
    const fromFuncMap = resolveFromFunctionMap(
      node.name,
      context.currentFunction,
      context.callSiteIndex ?? 0,
      context.parentCallSiteIndex,
    );
    if (fromFuncMap !== null && typeof fromFuncMap === "object") {
      return JSON.stringify(fromFuncMap);
    }
    if (fromFuncMap !== null && typeof fromFuncMap === "string") {
      return fromFuncMap;
    }
  }

  // Check for stringify calls (JSON.stringify or xxx.stringify)
  if (t.isCallExpression(resolved ?? node)) {
    const callNode = (resolved ?? node) as t.CallExpression;
    const callee = callNode.callee;

    // JSON.stringify(obj)
    if (
      t.isMemberExpression(callee) &&
      t.isIdentifier(callee.object) &&
      callee.object.name === "JSON" &&
      t.isIdentifier(callee.property) &&
      callee.property.name === "stringify"
    ) {
      const arg = callNode.arguments[0];

      // Try scope resolution first
      const argResolved = path ? resolveFromScope(arg, path) : arg;
      if (argResolved && t.isObjectExpression(argResolved)) {
        return objectToJSON(argResolved, trackedVars, path);
      }

      // Try function map resolution for identifiers (function parameters)
      if (t.isIdentifier(arg) && context?.currentFunction) {
        const fromFuncMap = resolveFromFunctionMap(
          arg.name,
          context.currentFunction,
          context.callSiteIndex ?? 0,
          context.parentCallSiteIndex,
        );
        if (fromFuncMap !== null && typeof fromFuncMap === "object") {
          return JSON.stringify(fromFuncMap);
        }
      }

      // For method calls like this.prepareRecord(...), try to resolve using function map
      if (t.isCallExpression(arg) && context?.currentFunction) {
        const calleeArg = arg.callee;
        if (
          t.isMemberExpression(calleeArg) &&
          t.isThisExpression(calleeArg.object)
        ) {
          const methodName = t.isIdentifier(calleeArg.property)
            ? calleeArg.property.name
            : "";
          if (methodName) {
            // Extract service name from current function (e.g., "LogService.saveView" -> "LogService")
            const dotIndex = context.currentFunction.indexOf(".");
            if (dotIndex !== -1) {
              const serviceName = context.currentFunction.substring(
                0,
                dotIndex,
              );
              const resolved = resolveMethodCall(
                serviceName,
                methodName,
                context.currentFunction,
                context.callSiteIndex ?? 0,
              );
              if (resolved) {
                return JSON.stringify(resolved);
              }
            }
          }
        }
      }
    }

    // xxx.stringify(obj) - e.g., Et().stringify(n)
    if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
      if (callee.property.name === "stringify") {
        const arg = callNode.arguments[0];

        // Try scope resolution first
        const argResolved = path ? resolveFromScope(arg, path) : arg;
        if (argResolved && t.isObjectExpression(argResolved)) {
          return objectToJSON(argResolved, trackedVars, path);
        }

        // Try function map resolution for identifiers (function parameters)
        if (t.isIdentifier(arg) && context?.currentFunction) {
          const fromFuncMap = resolveFromFunctionMap(
            arg.name,
            context.currentFunction,
            context.callSiteIndex ?? 0,
            context.parentCallSiteIndex,
          );
          if (fromFuncMap !== null && typeof fromFuncMap === "object") {
            return JSON.stringify(fromFuncMap);
          }
        }
      }
    }
  }

  return resolveValueSingle(node, trackedVars, context);
}

/**
 * Merge query params from URL with additional params.
 */
export function mergeParams(
  urlParams: string,
  additionalParams: string,
): string {
  if (!urlParams && !additionalParams) return "";
  if (!urlParams) return additionalParams;
  if (!additionalParams) return urlParams;
  return `${urlParams}&${additionalParams}`;
}

/**
 * Create an ExtractedRequest with default values.
 */
export function createExtractedRequest(
  overrides: Partial<Omit<ExtractedRequest, "type">> = {},
): ExtractedRequest {
  return {
    type: "extractedRequest",
    url: "",
    method: "GET",
    params: "",
    body: "",
    headers: [],
    cookies: [],
    ...overrides,
  };
}
