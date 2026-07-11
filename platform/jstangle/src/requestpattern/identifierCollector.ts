import { parse } from '@babel/parser';
import * as t from '@babel/types';
import debug from 'debug';
import { traverse } from '../ast-utils/babel';

const log = debug('jstangle:identifierCollector');

/**
 * Collect all identifiers used as parameters/variables in code.
 * This function analyzes code and extracts identifiers in usage context, not declarations.
 *
 * @example
 * ```typescript
 * // Input code
 * const code = `
 *   // These identifiers will NOT be collected because they are declaration sites
 *   const config = {
 *     auth: {
 *       API_KEY: 'xxx'
 *     }
 *   };
 *
 *   // These identifiers WILL be collected because they are being used
 *   fetch(API_URL);
 *   headers['Authorization'] = config.auth.API_KEY;
 *   client.request(token);
 * `;
 *
 * const identifiers = collectIdentifiers(code);
 * console.log([...identifiers]);
 * // Output: ['API_URL', 'API_KEY', 'token']
 * ```
 *
 * @param code - JavaScript/TypeScript code snippet to analyze
 * @returns Set<string> - Set of unique identifiers found
 *
 * @remarks
 * - Only collects identifiers in usage context (e.g., function arguments, variables in expressions)
 * - Skips identifiers in declaration context (e.g., object declarations, variable declarations)
 * - If the code cannot be parsed, the function returns an empty Set and logs the error
 */
export function collectIdentifiers(code: string): Set<string> {
    const identifiers = new Set<string>();
    if (code == null || code == '' || code.length === 0) {
        return identifiers;
    }

    try {
        // Preprocess code to handle function declaration cases
        let codeToProcess = code.trim();

        // Case 1: Anonymous functions
        if (codeToProcess.startsWith('function(')) {
            codeToProcess = `const anonymousFunc = ${codeToProcess}`;
        }

        // Case 2: Arrow functions
        else if (codeToProcess.startsWith('(') && codeToProcess.includes('=>')) {
            codeToProcess = `const arrowFunc = ${codeToProcess}`;
        }

        // Case 3: IIFE
        else if (codeToProcess.startsWith('(function') || codeToProcess.startsWith('(async function')) {
            codeToProcess = `const result = ${codeToProcess}`;
        }

        // Case 4: Method shorthand
        else if (codeToProcess.match(/^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(/)) {
            codeToProcess = `const obj = {${codeToProcess}}`;
        }

        // Case 5: Generator functions
        else if (codeToProcess.startsWith('function*')) {
            codeToProcess = codeToProcess.startsWith('function* (')
                ? `const genFunc = ${codeToProcess}`
                : codeToProcess;
        }

        // Case 6: Async functions
        else if (codeToProcess.startsWith('async ')) {
            if (codeToProcess.startsWith('async function(')) {
                codeToProcess = `const asyncFunc = ${codeToProcess}`;
            } else if (codeToProcess.startsWith('async (')) {
                codeToProcess = `const asyncArrowFunc = ${codeToProcess}`;
            }
        }

        const ast = parse(codeToProcess, {
            sourceType: 'module',
            errorRecovery: true,
            plugins: [],
        });
        if (ast.errors && ast.errors.length > 0) {
            log('Parse warnings:', ast.errors);
        }
        traverse(ast, {
            MemberExpression(path) {
                // Recursively check if member expression is part of a call expression
                const isPartOfCallExpression = (currentPath: any): boolean => {
                    if (!currentPath) return false;
                    if (currentPath.isCallExpression()) return true;
                    if (currentPath.isMemberExpression()) {
                        return isPartOfCallExpression(currentPath.parentPath);
                    }
                    return false;
                };

                // Skip if member expression is part of a call expression
                if (isPartOfCallExpression(path.parentPath)) {
                    return;
                }

                // Only get the last property of the member expression chain
                if (t.isIdentifier(path.node.property) && !path.node.computed) {
                    identifiers.add(path.node.property.name);
                }
            },

            Identifier(path) {
                // Recursively check if identifier is part of a call expression
                const isPartOfCallExpression = (currentPath: any): boolean => {
                    if (!currentPath) return false;

                    // If we encounter a CallExpression, return true
                    if (currentPath.isCallExpression()) return true;

                    // If still in a MemberExpression chain, continue checking parent
                    if (currentPath.isMemberExpression()) {
                        return isPartOfCallExpression(currentPath.parentPath);
                    }

                    return false;
                };

                // Skip if identifier is part of a call expression
                if (isPartOfCallExpression(path.parentPath)) {
                    return;
                }

                // Collect identifier when it is used as an argument or in an expression
                const parentPath = path.parentPath;
                if (
                    t.isCallExpression(parentPath.node) ||
                    t.isAssignmentExpression(parentPath.node) ||
                    t.isConditionalExpression(parentPath.node) ||
                    t.isLogicalExpression(parentPath.node) ||
                    t.isTemplateLiteral(parentPath.node) ||
                    t.isForOfStatement(parentPath.node) ||
                    t.isForInStatement(parentPath.node) ||
                    t.isAwaitExpression(parentPath.node) ||
                    t.isThrowStatement(parentPath.node) ||
                    t.isYieldExpression(parentPath.node) ||
                    t.isExportSpecifier(parentPath.node) ||
                    t.isImportSpecifier(parentPath.node)
                ) {
                    identifiers.add(path.node.name);
                }

                // Handle object shorthand { API_KEY }
                if (t.isObjectProperty(parentPath.node) && parentPath.node.shorthand) {
                    identifiers.add(path.node.name);
                }

                // Handle object property key { globalId: value }
                if (t.isObjectProperty(parentPath.node) && parentPath.node.key === path.node && !parentPath.node.computed) {
                    identifiers.add(path.node.name);
                }

                // Add condition for destructuring assignment
                if (t.isObjectPattern(parentPath?.node)) {
                    // Only collect if on the right side of the assignment
                    if (parentPath.parentPath?.isVariableDeclarator() &&
                        parentPath.parentPath.node.id !== parentPath.node) {
                        identifiers.add(path.node.name);
                    }
                }
            }
        });
    } catch (error) {
        log('Failed to parse code:', error);
        log('Code snippet:', code.slice(0, 100));
        if (error instanceof SyntaxError) {
            log('Syntax error at position:', (error as any).pos);
        }
    }

    return identifiers;
} 