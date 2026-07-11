/**
 * Angular Function Extractor
 *
 * Extracts function definitions from Angular code patterns:
 * - .factory('ServiceName', fn)
 * - .service('ServiceName', fn)
 * - .controller('ControllerName', fn)
 */

import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import { traverse } from '../../ast-utils/babel';
import type { FunctionMap, FunctionDefinition, ExtractedMethod } from '../types';

/**
 * Extract Angular function definitions from AST
 */
export function extractAngularFunctions(
  ast: ParseResult<t.File>,
  functionMap: FunctionMap,
  _sourceCode: string
): void {
  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;

      // Match: .factory("Name", ...) or .service("Name", ...) or .controller("Name", ...)
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
        const methodName = callee.property.name;

        if (methodName === 'factory') {
          extractFactory(path.node, functionMap);
        } else if (methodName === 'service') {
          extractService(path.node, functionMap);
        } else if (methodName === 'controller') {
          extractController(path.node, functionMap);
        }
      }
    },
    noScope: true,
  });
}

/**
 * Extract .factory('ServiceName', fn) pattern
 *
 * Factory returns an object with methods:
 * .factory('CommentsService', function($http) {
 *   return {
 *     getComments: function(params) { ... },
 *     createComment: function(data) { ... }
 *   };
 * })
 */
function extractFactory(node: t.CallExpression, functionMap: FunctionMap): void {
  const args = node.arguments;
  if (args.length < 2) return;

  // Get service name from first argument
  const serviceName = getStringValue(args[0]);
  if (!serviceName) return;

  // Get factory function from second argument
  const factoryFn = getFactoryFunction(args[1]);
  if (!factoryFn) return;

  // Find returned object and extract methods
  const methods = extractReturnedMethods(factoryFn);

  // Register each method
  for (const method of methods) {
    const fullName = `${serviceName}.${method.name}`;
    const def: FunctionDefinition = {
      fullName,
      serviceName,
      name: method.name,
      params: method.params,
      startLine: method.startLine,
      endLine: method.endLine,
      returnedObject: method.returnedObject,
    };
    functionMap.functions.set(fullName, def);
  }
}

/**
 * Extract .service('ServiceName', fn) pattern
 *
 * Service uses this.method pattern:
 * .service('MyService', function() {
 *   this.doSomething = function(params) { ... };
 * })
 */
function extractService(node: t.CallExpression, functionMap: FunctionMap): void {
  const args = node.arguments;
  if (args.length < 2) return;

  // Get service name from first argument
  const serviceName = getStringValue(args[0]);
  if (!serviceName) return;

  // Get service function from second argument
  const serviceFn = getFactoryFunction(args[1]);
  if (!serviceFn) return;

  // Find this.method assignments
  const methods = extractThisMethods(serviceFn);

  // Register each method
  for (const method of methods) {
    const fullName = `${serviceName}.${method.name}`;
    const def: FunctionDefinition = {
      fullName,
      serviceName,
      name: method.name,
      params: method.params,
      startLine: method.startLine,
      endLine: method.endLine,
      returnedObject: method.returnedObject,
    };
    functionMap.functions.set(fullName, def);
  }
}

/**
 * Extract .controller('ControllerName', fn) pattern
 *
 * Controller uses $scope.method pattern:
 * .controller('MyCtrl', function($scope) {
 *   $scope.loadData = function() { ... };
 * })
 */
function extractController(node: t.CallExpression, functionMap: FunctionMap): void {
  const args = node.arguments;
  if (args.length < 2) return;

  // Get controller name from first argument
  const controllerName = getStringValue(args[0]);
  if (!controllerName) return;

  // Get controller function from second argument
  const controllerFn = getFactoryFunction(args[1]);
  if (!controllerFn) return;

  // Find $scope.method assignments
  const methods = extractScopeMethods(controllerFn);

  // Register each method
  for (const method of methods) {
    const fullName = `${controllerName}.${method.name}`;
    const def: FunctionDefinition = {
      fullName,
      serviceName: controllerName,
      name: method.name,
      params: method.params,
      startLine: method.startLine,
      endLine: method.endLine,
      returnedObject: method.returnedObject,
    };
    functionMap.functions.set(fullName, def);
  }
}

/**
 * Get string value from a node (StringLiteral or first element of ArrayExpression)
 */
function getStringValue(node: t.Node): string | null {
  if (t.isStringLiteral(node)) {
    return node.value;
  }
  return null;
}

/**
 * Get factory function from argument (handles array syntax for DI)
 *
 * Can be:
 * - function($http) { ... }
 * - ['$http', function($http) { ... }]
 */
function getFactoryFunction(node: t.Node): t.Function | null {
  // Direct function
  if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) {
    return node;
  }

  // Array syntax: ['$http', function($http) { ... }]
  if (t.isArrayExpression(node)) {
    const lastElement = node.elements[node.elements.length - 1];
    if (lastElement && (t.isFunctionExpression(lastElement) || t.isArrowFunctionExpression(lastElement))) {
      return lastElement;
    }
  }

  return null;
}

/**
 * Extract methods from returned object in factory
 *
 * return {
 *   getComments: function(params) { ... },
 *   createComment: function(data) { ... }
 * }
 */
function extractReturnedMethods(fn: t.Function): ExtractedMethod[] {
  const methods: ExtractedMethod[] = [];
  const body = fn.body;

  if (!t.isBlockStatement(body)) return methods;

  // Find return statement
  for (const stmt of body.body) {
    if (t.isReturnStatement(stmt) && t.isObjectExpression(stmt.argument)) {
      // Extract methods from returned object
      for (const prop of stmt.argument.properties) {
        if (t.isObjectProperty(prop) && t.isIdentifier(prop.key)) {
          const methodName = prop.key.name;
          const methodFn = prop.value;

          if (t.isFunctionExpression(methodFn) || t.isArrowFunctionExpression(methodFn)) {
            const params = extractParams(methodFn);
            methods.push({
              name: methodName,
              params,
              startLine: methodFn.loc?.start.line || 0,
              endLine: methodFn.loc?.end.line || 0,
              returnedObject: extractReturnedObject(methodFn, params),
            });
          }
        }
      }
    }

    // Also check: var api = { ... }; return api;
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isIdentifier(decl.id) && t.isObjectExpression(decl.init)) {
          // Check if this variable is returned later
          const varName = decl.id.name;
          const isReturned = body.body.some(
            s => t.isReturnStatement(s) && t.isIdentifier(s.argument) && s.argument.name === varName
          );

          if (isReturned) {
            for (const prop of decl.init.properties) {
              if (t.isObjectProperty(prop) && t.isIdentifier(prop.key)) {
                const methodName = prop.key.name;
                const methodFn = prop.value;

                if (t.isFunctionExpression(methodFn) || t.isArrowFunctionExpression(methodFn)) {
                  const params = extractParams(methodFn);
                  methods.push({
                    name: methodName,
                    params,
                    startLine: methodFn.loc?.start.line || 0,
                    endLine: methodFn.loc?.end.line || 0,
                    returnedObject: extractReturnedObject(methodFn, params),
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return methods;
}

/**
 * Extract methods from this.method = function pattern
 */
function extractThisMethods(fn: t.Function): ExtractedMethod[] {
  const methods: ExtractedMethod[] = [];
  const body = fn.body;

  if (!t.isBlockStatement(body)) return methods;

  for (const stmt of body.body) {
    // this.methodName = function(params) { ... }
    if (t.isExpressionStatement(stmt) && t.isAssignmentExpression(stmt.expression)) {
      const left = stmt.expression.left;
      const right = stmt.expression.right;

      if (
        t.isMemberExpression(left) &&
        t.isThisExpression(left.object) &&
        t.isIdentifier(left.property) &&
        (t.isFunctionExpression(right) || t.isArrowFunctionExpression(right))
      ) {
        const params = extractParams(right);
        methods.push({
          name: left.property.name,
          params,
          startLine: right.loc?.start.line || 0,
          endLine: right.loc?.end.line || 0,
          returnedObject: extractReturnedObject(right, params),
        });
      }
    }
  }

  return methods;
}

/**
 * Extract methods from $scope.method = function pattern
 */
function extractScopeMethods(fn: t.Function): ExtractedMethod[] {
  const methods: ExtractedMethod[] = [];
  const body = fn.body;

  if (!t.isBlockStatement(body)) return methods;

  for (const stmt of body.body) {
    // $scope.methodName = function(params) { ... }
    // or scope.methodName = function(params) { ... }
    if (t.isExpressionStatement(stmt) && t.isAssignmentExpression(stmt.expression)) {
      const left = stmt.expression.left;
      const right = stmt.expression.right;

      if (
        t.isMemberExpression(left) &&
        t.isIdentifier(left.object) &&
        (left.object.name === '$scope' || left.object.name === 'scope') &&
        t.isIdentifier(left.property) &&
        (t.isFunctionExpression(right) || t.isArrowFunctionExpression(right))
      ) {
        const params = extractParams(right);
        methods.push({
          name: left.property.name,
          params,
          startLine: right.loc?.start.line || 0,
          endLine: right.loc?.end.line || 0,
          returnedObject: extractReturnedObject(right, params),
        });
      }
    }
  }

  return methods;
}

/**
 * Extract parameter names from a function
 */
function extractParams(fn: t.Function): string[] {
  return fn.params
    .map(param => {
      if (t.isIdentifier(param)) {
        return param.name;
      }
      if (t.isAssignmentPattern(param) && t.isIdentifier(param.left)) {
        return param.left.name;
      }
      if (t.isRestElement(param) && t.isIdentifier(param.argument)) {
        return `...${param.argument.name}`;
      }
      return null;
    })
    .filter((name): name is string => name !== null);
}

/**
 * Extract the returned object template from a function.
 * Looks for patterns like:
 *   var json = { key: param, ... }; return json;
 *   return { key: param, ... };
 */
function extractReturnedObject(
  fn: t.Function,
  paramNames: string[]
): Record<string, string | Record<string, unknown>> | undefined {
  const body = fn.body;
  if (!t.isBlockStatement(body)) return undefined;

  // Track local variables that might be returned
  const localVars = new Map<string, t.ObjectExpression>();

  for (const stmt of body.body) {
    // Track variable declarations: var json = { ... }
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (t.isIdentifier(decl.id) && t.isObjectExpression(decl.init)) {
          localVars.set(decl.id.name, decl.init);
        }
      }
    }

    // Check for return statement
    if (t.isReturnStatement(stmt) && stmt.argument) {
      let returnedObj: t.ObjectExpression | undefined;

      // Direct return: return { ... }
      if (t.isObjectExpression(stmt.argument)) {
        returnedObj = stmt.argument;
      }
      // Indirect return: return varName
      else if (t.isIdentifier(stmt.argument)) {
        returnedObj = localVars.get(stmt.argument.name);
      }

      if (returnedObj) {
        return buildObjectTemplate(returnedObj, paramNames);
      }
    }
  }

  return undefined;
}

/**
 * Build an object template from an ObjectExpression.
 * Maps identifier values to ${paramName} if they match function params.
 */
function buildObjectTemplate(
  obj: t.ObjectExpression,
  paramNames: string[]
): Record<string, string | Record<string, unknown>> {
  const result: Record<string, string | Record<string, unknown>> = {};

  for (const prop of obj.properties) {
    if (!t.isObjectProperty(prop)) continue;

    // Get key name
    let keyName: string | null = null;
    if (t.isIdentifier(prop.key)) {
      keyName = prop.key.name;
    } else if (t.isStringLiteral(prop.key)) {
      keyName = prop.key.value;
    }
    if (!keyName) continue;

    // Get value
    const value = prop.value;

    if (t.isIdentifier(value)) {
      // Check if it's a parameter reference
      if (paramNames.includes(value.name)) {
        result[keyName] = `\${${value.name}}`;
      } else {
        // Local variable or external reference
        result[keyName] = `\${${value.name}}`;
      }
    } else if (t.isStringLiteral(value)) {
      result[keyName] = value.value;
    } else if (t.isNumericLiteral(value)) {
      result[keyName] = String(value.value);
    } else if (t.isBooleanLiteral(value)) {
      result[keyName] = String(value.value);
    } else if (t.isObjectExpression(value)) {
      // Nested object
      result[keyName] = buildObjectTemplate(value, paramNames);
    } else if (t.isMemberExpression(value)) {
      // Member expression: obj.prop or $rootScope.currentBrand.brandId
      result[keyName] = `\${${memberExpressionToString(value)}}`;
    } else if (t.isCallExpression(value)) {
      // Function call: new Date().getTime()
      result[keyName] = `\${${callExpressionToString(value)}}`;
    } else if (t.isNewExpression(value)) {
      // New expression: new Date()
      result[keyName] = `\${new ${t.isIdentifier(value.callee) ? value.callee.name : 'unknown'}()}`;
    } else {
      // Other: use placeholder
      result[keyName] = `\${unknown}`;
    }
  }

  return result;
}

/**
 * Convert a MemberExpression to a string representation.
 */
function memberExpressionToString(node: t.MemberExpression): string {
  const parts: string[] = [];

  let current: t.Node = node;
  while (t.isMemberExpression(current)) {
    if (t.isIdentifier(current.property)) {
      parts.unshift(current.property.name);
    } else if (t.isStringLiteral(current.property)) {
      parts.unshift(current.property.value);
    }
    current = current.object;
  }

  if (t.isIdentifier(current)) {
    parts.unshift(current.name);
  } else if (t.isThisExpression(current)) {
    parts.unshift('this');
  } else if (t.isCallExpression(current)) {
    parts.unshift(callExpressionToString(current));
  }

  return parts.join('.');
}

/**
 * Convert a CallExpression to a string representation.
 */
function callExpressionToString(node: t.CallExpression): string {
  if (t.isIdentifier(node.callee)) {
    return `${node.callee.name}()`;
  }
  if (t.isMemberExpression(node.callee)) {
    return `${memberExpressionToString(node.callee)}()`;
  }
  return 'call()';
}
