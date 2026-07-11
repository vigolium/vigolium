/**
 * Inner Function Extractor
 *
 * Extracts function definitions from inner/local functions:
 * - function declarations: function fillDownloads(params) { ... }
 * - variable function expressions: var loadData = function(params) { ... }
 * - arrow functions: const loadData = (params) => { ... }
 * - member expression assignments: scope.methodName = function(params) { ... }
 *
 * These are typically nested inside services, directives, controllers, etc.
 */

import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import { traverse } from '../../ast-utils/babel';
import type { FunctionMap, FunctionDefinition } from '../types';
import type { StructuralIndex } from '../../structure';

/**
 * Extract inner function definitions from AST
 */
export function extractInnerFunctions(
  ast: ParseResult<t.File>,
  functionMap: FunctionMap,
  _sourceCode: string,
  structuralIndex?: StructuralIndex,
): void {
  if (structuralIndex) {
    for (const path of structuralIndex.functionPaths) {
      const node = path.node;
      let funcName: string | null = null;
      if (t.isFunctionDeclaration(node) && node.id) {
        funcName = node.id.name;
      } else if ((t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) && path.parentPath?.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id)) {
        funcName = path.parentPath.node.id.name;
      } else if ((t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) && path.parentPath?.isAssignmentExpression() && t.isMemberExpression(path.parentPath.node.left)) {
        const property = path.parentPath.node.left.property;
        funcName = t.isIdentifier(property) ? property.name : t.isStringLiteral(property) ? property.value : null;
      }
      if (!funcName || functionMap.functions.has(funcName)) continue;
      functionMap.functions.set(funcName, {
        fullName: funcName,
        name: funcName,
        params: extractParams(node),
        startLine: node.loc?.start.line || 0,
        endLine: node.loc?.end.line || 0,
      });
    }
    return;
  }
  traverse(ast, {
    // function fillDownloads(params, index) { ... }
    FunctionDeclaration(path) {
      const node = path.node;
      if (!node.id || !t.isIdentifier(node.id)) return;

      const funcName = node.id.name;

      // Skip if already registered (e.g., as a service method)
      if (functionMap.functions.has(funcName)) return;

      // Extract parameters
      const params = extractParams(node);

      const def: FunctionDefinition = {
        fullName: funcName,
        name: funcName,
        params,
        startLine: node.loc?.start.line || 0,
        endLine: node.loc?.end.line || 0,
      };

      functionMap.functions.set(funcName, def);
    },

    // var fillDownloads = function(params, index) { ... }
    // const fillDownloads = (params, index) => { ... }
    VariableDeclarator(path) {
      const node = path.node;
      if (!t.isIdentifier(node.id)) return;

      const funcName = node.id.name;

      // Check if the init is a function
      if (
        !t.isFunctionExpression(node.init) &&
        !t.isArrowFunctionExpression(node.init)
      ) {
        return;
      }

      // Skip if already registered (e.g., as a service method)
      if (functionMap.functions.has(funcName)) return;

      // Extract parameters
      const params = extractParams(node.init);

      const def: FunctionDefinition = {
        fullName: funcName,
        name: funcName,
        params,
        startLine: node.init.loc?.start.line || 0,
        endLine: node.init.loc?.end.line || 0,
      };

      functionMap.functions.set(funcName, def);
    },

    // scope.methodName = function(params) { ... }
    // this.methodName = function(params) { ... }
    // obj.methodName = (params) => { ... }
    AssignmentExpression(path) {
      const node = path.node;

      // Check if left side is a member expression: obj.property
      if (!t.isMemberExpression(node.left)) return;

      // Get the property name
      let funcName: string | null = null;
      if (t.isIdentifier(node.left.property)) {
        funcName = node.left.property.name;
      } else if (t.isStringLiteral(node.left.property)) {
        funcName = node.left.property.value;
      }
      if (!funcName) return;

      // Check if the right side is a function
      if (
        !t.isFunctionExpression(node.right) &&
        !t.isArrowFunctionExpression(node.right)
      ) {
        return;
      }

      // Skip if already registered
      if (functionMap.functions.has(funcName)) return;

      // Extract parameters
      const params = extractParams(node.right);

      const def: FunctionDefinition = {
        fullName: funcName,
        name: funcName,
        params,
        startLine: node.right.loc?.start.line || 0,
        endLine: node.right.loc?.end.line || 0,
      };

      functionMap.functions.set(funcName, def);
    },
    noScope: true,
  });
}

/**
 * Extract parameter names from a function
 */
function extractParams(fn: t.Function): string[] {
  return fn.params
    .map((param) => {
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
