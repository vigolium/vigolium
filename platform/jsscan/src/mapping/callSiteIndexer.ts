/**
 * Call Site Indexer
 *
 * Indexes all call sites for registered functions, resolving argument values.
 * Handles:
 * - Direct object literal arguments: `fn({ key: value })`
 * - Variable references with object initialization: `var x = {}; x.key = value; fn(x)`
 * - Simple variable references: `var x = "value"; fn(x)`
 * - Nested function calls: tracks containing function for recursive resolution
 */

import type { ParseResult } from '@babel/parser';
import type { NodePath, Scope } from '@babel/traverse';
import * as t from '@babel/types';
import { traverse } from '../ast-utils/babel';
import { babelGenerate } from '../ast-utils/babel';
import type { FunctionMap, CallSite, ResolvedArgument } from './types';

/**
 * Generate minified code string from an AST node.
 * Uses minified output to avoid newlines and extra whitespace.
 */
function generateMinifiedCode(node: t.Node): string {
  return babelGenerate(node, { minified: true, comments: false }).code;
}

/**
 * Check if a node represents a complex expression that should be simplified to ${expr}.
 * Complex expressions include: ternary, logical operators, comparison operators, etc.
 */
function isComplexExpression(node: t.Node): boolean {
  return (
    t.isConditionalExpression(node) ||
    t.isLogicalExpression(node) ||
    (t.isBinaryExpression(node) && node.operator !== '+') ||
    t.isSequenceExpression(node) ||
    t.isAssignmentExpression(node) ||
    t.isUpdateExpression(node) ||
    t.isAwaitExpression(node) ||
    t.isYieldExpression(node) ||
    t.isNewExpression(node)
  );
}

/**
 * Generate a placeholder for complex or verbose expressions.
 * Returns ${expr} for complex expressions, or minified code wrapped in ${} for others.
 */
function generateExpressionPlaceholder(node: t.Node): string {
  // For complex expressions, use simple ${expr} placeholder
  if (isComplexExpression(node)) {
    return '${expr}';
  }

  // For simpler expressions, generate minified code
  const code = generateMinifiedCode(node);

  // If the code is too long or contains spaces/newlines, simplify to ${expr}
  if (code.length > 50 || /\s/.test(code)) {
    return '${expr}';
  }

  return `\${${code}}`;
}

/**
 * Function range info for determining containing function
 */
interface FunctionRange {
  name: string;
  startLine: number;
  endLine: number;
}

/**
 * Property assignment info for tracking variable mutations
 */
interface PropertyAssignment {
  line: number;
  propName: string;
  value: t.Node;
  // The scope path where the variable was declared (for proper scoping)
  declarationLine: number;
}

/**
 * Index all call sites for registered functions
 */
export function indexCallSites(
  ast: ParseResult<t.File>,
  functionMap: FunctionMap,
  _sourceCode: string
): void {
  // Build function ranges from registered functions
  const functionRanges: FunctionRange[] = [];
  for (const [name, def] of functionMap.functions) {
    functionRanges.push({
      name,
      startLine: def.startLine,
      endLine: def.endLine,
    });
  }
  // Sort by start line for efficient lookup
  functionRanges.sort((a, b) => a.startLine - b.startLine);

  // First pass: collect variable declarations and their property assignments
  // Key: variableName, Value: list of property assignments with scope info
  const variableAssignments = new Map<string, PropertyAssignment[]>();
  const variableDeclarations = new Map<string, number[]>(); // varName -> list of declaration lines

  // Collect all variable declarations (a variable may be declared multiple times in different scopes)
  traverse(ast, {
    VariableDeclarator(path) {
      if (t.isIdentifier(path.node.id)) {
        const varName = path.node.id.name;
        const line = path.node.loc?.start.line || 0;
        if (!variableDeclarations.has(varName)) {
          variableDeclarations.set(varName, []);
        }
        variableDeclarations.get(varName)!.push(line);
      }
    },
    noScope: true,
  });

  // Build a map of variable mutations (property assignments)
  traverse(ast, {
    AssignmentExpression(path) {
      const left = path.node.left;
      // Match: varName.property = value
      if (t.isMemberExpression(left) && t.isIdentifier(left.object) && t.isIdentifier(left.property)) {
        const varName = left.object.name;
        const propName = left.property.name;
        const line = path.node.loc?.start.line || 0;

        // Find the closest declaration before this assignment
        const declarations = variableDeclarations.get(varName) || [];
        let declarationLine = 0;
        for (const declLine of declarations) {
          if (declLine < line && declLine > declarationLine) {
            declarationLine = declLine;
          }
        }

        if (!variableAssignments.has(varName)) {
          variableAssignments.set(varName, []);
        }

        variableAssignments.get(varName)!.push({
          line,
          propName,
          value: path.node.right,
          declarationLine,
        });
      }
    },
    noScope: true,
  });

  // Second pass: index call sites with scope enabled
  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;
      const callLine = path.node.loc?.start.line || 0;

      // Find containing function for this call site
      const containingFunction = findContainingFunction(callLine, functionRanges);

      // Match: ServiceName.methodName(args) or scope.methodName(args)
      if (t.isMemberExpression(callee)) {
        const objectName = getIdentifierName(callee.object);
        const methodName = getIdentifierName(callee.property);
        const isThisCall = t.isThisExpression(callee.object);

        // Handle this.methodName() - internal method calls within a service
        if (isThisCall && methodName && containingFunction) {
          // Extract service name from containing function (e.g., "LogService.saveView" -> "LogService")
          const dotIndex = containingFunction.indexOf('.');
          if (dotIndex !== -1) {
            const serviceName = containingFunction.substring(0, dotIndex);
            const fullName = `${serviceName}.${methodName}`;

            if (functionMap.functions.has(fullName)) {
              const funcDef = functionMap.functions.get(fullName)!;
              const resolvedArgs = resolveArguments(path, funcDef.params, variableAssignments, callLine);

              const callSite: CallSite = {
                targetFunction: fullName,
                line: callLine,
                arguments: resolvedArgs,
                containingFunction,
              };

              const sites = functionMap.callSites.get(fullName) || [];
              sites.push(callSite);
              functionMap.callSites.set(fullName, sites);
            }
          }
        }

        if (objectName && methodName) {
          const fullName = `${objectName}.${methodName}`;

          // Check if this function is registered as full name (e.g., "CommentsService.getComments")
          // OR as just method name (e.g., "fillDownloads" registered from scope.fillDownloads = function)
          let targetName: string | null = null;
          if (functionMap.functions.has(fullName)) {
            targetName = fullName;
          } else if (functionMap.functions.has(methodName)) {
            // Member expression calling a function registered by its method name only
            // This handles: scope.fillDownloads() -> fillDownloads
            targetName = methodName;
          }

          if (targetName) {
            const funcDef = functionMap.functions.get(targetName)!;
            const resolvedArgs = resolveArguments(path, funcDef.params, variableAssignments, callLine);

            // Add to call sites with containing function info
            const callSite: CallSite = {
              targetFunction: targetName,
              line: callLine,
              arguments: resolvedArgs,
              containingFunction,
            };

            const sites = functionMap.callSites.get(targetName) || [];
            sites.push(callSite);
            functionMap.callSites.set(targetName, sites);
          }
        }
      }

      // Match: standalone function call: functionName(args)
      if (t.isIdentifier(callee)) {
        const funcName = callee.name;

        // Check if this function is registered
        if (functionMap.functions.has(funcName)) {
          const funcDef = functionMap.functions.get(funcName)!;
          const resolvedArgs = resolveArguments(path, funcDef.params, variableAssignments, callLine);

          // Add to call sites with containing function info
          const callSite: CallSite = {
            targetFunction: funcName,
            line: callLine,
            arguments: resolvedArgs,
            containingFunction,
          };

          const sites = functionMap.callSites.get(funcName) || [];
          sites.push(callSite);
          functionMap.callSites.set(funcName, sites);
        }
      }
    },
    // Enable scope tracking for proper variable resolution
    noScope: false,
  });
}

/**
 * Find which registered function contains the given line number
 */
function findContainingFunction(line: number, functionRanges: FunctionRange[]): string | undefined {
  // Find the innermost function that contains this line
  // (functions can be nested, so we want the smallest range)
  let best: FunctionRange | undefined;

  for (const range of functionRanges) {
    if (line >= range.startLine && line <= range.endLine) {
      if (!best || (range.endLine - range.startLine) < (best.endLine - best.startLine)) {
        best = range;
      }
    }
  }

  return best?.name;
}

/**
 * Get identifier name from a node
 */
function getIdentifierName(node: t.Node): string | null {
  if (t.isIdentifier(node)) {
    return node.name;
  }
  return null;
}

/**
 * Resolve arguments passed to a function call
 */
function resolveArguments(
  path: NodePath<t.CallExpression>,
  paramNames: string[],
  variableAssignments: Map<string, PropertyAssignment[]>,
  callLine: number
): ResolvedArgument[] {
  const args = path.node.arguments;
  const result: ResolvedArgument[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!t.isExpression(arg) && !t.isSpreadElement(arg)) continue;

    const paramName = paramNames[i] || `arg${i}`;
    const rawCode = generateMinifiedCode(arg);

    // Try to resolve argument value
    const value = resolveArgumentValue(arg, path.scope, variableAssignments, callLine);

    result.push({
      index: i,
      paramName,
      value,
      rawCode,
    });
  }

  return result;
}

/**
 * Resolve the value of an argument
 *
 * @returns Resolved value as string or Record<string, string>
 */
function resolveArgumentValue(
  node: t.Node,
  scope: Scope | null,
  variableAssignments: Map<string, PropertyAssignment[]>,
  callLine: number
): string | Record<string, string> {
  // Object literal: { key: value, ... }
  if (t.isObjectExpression(node)) {
    return resolveObjectLiteral(node, scope);
  }

  // Identifier: look up in scope and check for property mutations
  if (t.isIdentifier(node)) {
    const varName = node.name;

    // First, try to resolve from scope
    if (scope) {
      const resolved = resolveIdentifier(node, scope, variableAssignments, callLine);
      if (resolved !== null) {
        return resolved;
      }
    }

    // Check if we have property assignments for this variable
    const assignments = variableAssignments.get(varName);
    if (assignments) {
      const result: Record<string, string> = {};

      // Find the most recent declaration line for this variable that's before the call
      let relevantDeclarationLine = 0;
      for (const assignment of assignments) {
        if (assignment.declarationLine < callLine && assignment.declarationLine > relevantDeclarationLine) {
          relevantDeclarationLine = assignment.declarationLine;
        }
      }

      // Collect property assignments that belong to this declaration scope
      for (const assignment of assignments) {
        if (assignment.line < callLine &&
            assignment.line > relevantDeclarationLine &&
            assignment.declarationLine === relevantDeclarationLine) {
          result[assignment.propName] = resolveNodeToString(assignment.value, scope);
        }
      }

      if (Object.keys(result).length > 0) {
        return result;
      }
    }

    // Fallback to identifier name
    return `\${${varName}}`;
  }

  // String literal
  if (t.isStringLiteral(node)) {
    return node.value;
  }

  // Numeric literal
  if (t.isNumericLiteral(node)) {
    return String(node.value);
  }

  // Boolean literal
  if (t.isBooleanLiteral(node)) {
    return String(node.value);
  }

  // Null literal
  if (t.isNullLiteral(node)) {
    return 'null';
  }

  // Array literal: wrap as ${expr} if contains unresolved elements
  if (t.isArrayExpression(node)) {
    // Check if any element is complex/unresolved
    const hasUnresolvedElements = node.elements.some((elem) => {
      if (!elem) return false;
      if (t.isSpreadElement(elem)) return true;
      // Complex elements that will generate ${...} placeholders
      if (t.isObjectExpression(elem) || t.isArrayExpression(elem)) return true;
      if (t.isConditionalExpression(elem) || t.isLogicalExpression(elem)) return true;
      if (t.isBinaryExpression(elem) && elem.operator !== '+') return true;
      if (t.isCallExpression(elem) || t.isMemberExpression(elem) || t.isIdentifier(elem)) return true;
      return false;
    });

    if (hasUnresolvedElements) {
      return '${expr}';
    }

    // All elements are simple literals - serialize as array
    const elements = node.elements.map((elem) => {
      if (!elem) return 'null';
      return resolveNodeToString(elem, scope);
    });
    return `[${elements.join(',')}]`;
  }

  // Template literal (simple case)
  if (t.isTemplateLiteral(node)) {
    return resolveTemplateLiteral(node, scope);
  }

  // Member expression: obj.prop - use placeholder
  if (t.isMemberExpression(node)) {
    return generateExpressionPlaceholder(node);
  }

  // Call expression: fn(args) - use placeholder
  if (t.isCallExpression(node)) {
    return generateExpressionPlaceholder(node);
  }

  // Fallback to placeholder for any other expression type
  return generateExpressionPlaceholder(node);
}

/**
 * Resolve a template literal to a string
 */
function resolveTemplateLiteral(node: t.TemplateLiteral, scope: Scope | null): string {
  let result = '';

  for (let i = 0; i < node.quasis.length; i++) {
    result += node.quasis[i].value.raw;

    if (i < node.expressions.length) {
      const expr = node.expressions[i];
      result += resolveNodeToString(expr, scope);
    }
  }

  return result;
}

/**
 * Resolve an object literal to Record<string, string>
 */
function resolveObjectLiteral(
  node: t.ObjectExpression,
  scope: Scope | null
): Record<string, string> {
  const result: Record<string, string> = {};

  for (const prop of node.properties) {
    if (t.isObjectProperty(prop)) {
      // Get key
      let key: string | null = null;
      if (t.isIdentifier(prop.key)) {
        key = prop.key.name;
      } else if (t.isStringLiteral(prop.key)) {
        key = prop.key.value;
      }

      if (!key) continue;

      // Get value
      const value = prop.value;
      result[key] = resolveNodeToString(value, scope);
    }
  }

  return result;
}

/**
 * Resolve any node to a string value.
 * Complex expressions (function calls, member expressions, etc.) are wrapped in ${} placeholder format.
 */
function resolveNodeToString(node: t.Node, scope: Scope | null): string {
  if (t.isStringLiteral(node)) {
    return node.value;
  }

  if (t.isNumericLiteral(node)) {
    return String(node.value);
  }

  if (t.isBooleanLiteral(node)) {
    return String(node.value);
  }

  if (t.isNullLiteral(node)) {
    return 'null';
  }

  // Array literal - wrap as ${expr} if contains unresolved elements
  if (t.isArrayExpression(node)) {
    // Check if any element is complex/unresolved
    const hasUnresolvedElements = node.elements.some((elem) => {
      if (!elem) return false;
      if (t.isSpreadElement(elem)) return true;
      if (t.isObjectExpression(elem) || t.isArrayExpression(elem)) return true;
      if (t.isConditionalExpression(elem) || t.isLogicalExpression(elem)) return true;
      if (t.isBinaryExpression(elem) && elem.operator !== '+') return true;
      if (t.isCallExpression(elem) || t.isMemberExpression(elem) || t.isIdentifier(elem)) return true;
      return false;
    });

    if (hasUnresolvedElements) {
      return '${expr}';
    }

    // All elements are simple literals - serialize as array
    const elements = node.elements.map((elem) => {
      if (!elem) return 'null';
      return resolveNodeToString(elem, scope);
    });
    return `[${elements.join(',')}]`;
  }

  if (t.isIdentifier(node) && scope) {
    const binding = scope.getBinding(node.name);
    if (binding?.path.isVariableDeclarator()) {
      const init = binding.path.node.init;
      if (init) {
        if (t.isStringLiteral(init)) return init.value;
        if (t.isNumericLiteral(init)) return String(init.value);
        if (t.isBooleanLiteral(init)) return String(init.value);
        if (t.isNullLiteral(init)) return 'null';
        if (t.isArrayExpression(init)) return resolveNodeToString(init, scope);
      }
    }
    // Unresolved identifier - wrap in ${}
    return `\${${node.name}}`;
  }

  if (t.isIdentifier(node)) {
    // Identifier without scope - wrap in ${}
    return `\${${node.name}}`;
  }

  if (t.isTemplateLiteral(node)) {
    return resolveTemplateLiteral(node, scope);
  }

  // For complex expressions (call expressions, member expressions, etc.), use placeholder
  return generateExpressionPlaceholder(node);
}

/**
 * Resolve an identifier by looking up its binding in scope
 */
function resolveIdentifier(
  node: t.Identifier,
  scope: Scope,
  variableAssignments: Map<string, PropertyAssignment[]>,
  callLine: number
): string | Record<string, string> | null {
  const binding = scope.getBinding(node.name);
  if (!binding) return null;

  const bindingPath = binding.path;

  // Variable declarator: var x = value;
  if (bindingPath.isVariableDeclarator()) {
    const init = bindingPath.node.init;
    const varName = node.name;
    const declarationLine = bindingPath.node.loc?.start.line || 0;

    // Check for empty object initialization followed by property assignments
    // Pattern: var params = {}; params.key = value;
    if (t.isObjectExpression(init) && init.properties.length === 0) {
      const assignments = variableAssignments.get(varName);
      if (assignments) {
        const result: Record<string, string> = {};

        // Collect property assignments that belong to this declaration
        for (const assignment of assignments) {
          if (assignment.line < callLine &&
              assignment.line > declarationLine &&
              assignment.declarationLine === declarationLine) {
            result[assignment.propName] = resolveNodeToString(assignment.value, scope);
          }
        }

        if (Object.keys(result).length > 0) {
          return result;
        }
      }
    }

    if (!init) return null;

    // Object literal with properties
    if (t.isObjectExpression(init) && init.properties.length > 0) {
      const result = resolveObjectLiteral(init, scope);

      // Also check for additional property assignments
      const assignments = variableAssignments.get(varName);
      if (assignments) {
        for (const assignment of assignments) {
          if (assignment.line < callLine &&
              assignment.line > declarationLine &&
              assignment.declarationLine === declarationLine) {
            result[assignment.propName] = resolveNodeToString(assignment.value, scope);
          }
        }
      }

      return result;
    }

    // String literal
    if (t.isStringLiteral(init)) {
      return init.value;
    }

    // Numeric literal
    if (t.isNumericLiteral(init)) {
      return String(init.value);
    }

    // Template literal
    if (t.isTemplateLiteral(init)) {
      return resolveTemplateLiteral(init, scope);
    }

    // Return placeholder for complex expressions
    return generateExpressionPlaceholder(init);
  }

  return null;
}

/**
 * Find the most recent assignment to a variable before a given line
 */
export function findVariableAssignment(
  ast: ParseResult<t.File>,
  varName: string,
  beforeLine: number
): t.Node | null {
  let result: t.Node | null = null;
  let closestLine = -1;

  traverse(ast, {
    VariableDeclarator(path) {
      if (
        t.isIdentifier(path.node.id) &&
        path.node.id.name === varName &&
        path.node.init
      ) {
        const line = path.node.loc?.start.line || 0;
        if (line < beforeLine && line > closestLine) {
          closestLine = line;
          result = path.node.init;
        }
      }
    },
    AssignmentExpression(path) {
      if (
        t.isIdentifier(path.node.left) &&
        path.node.left.name === varName
      ) {
        const line = path.node.loc?.start.line || 0;
        if (line < beforeLine && line > closestLine) {
          closestLine = line;
          result = path.node.right;
        }
      }
    },
    noScope: true,
  });

  return result;
}
