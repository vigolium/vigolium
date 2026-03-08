import type { ParseResult } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type { Transform } from '../ast-utils';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, isURLLike, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import type { TrackedVariableMap, ResolutionContext } from './types';
import {
    extractURLSingle,
    createExtractedRequest,
    resolveFromScope,
    objectToKeyValue,
    extractBody,
    mergeParams,
    findContainingFunction,
    getEffectiveIterationsForFunction,
    createResolutionContext,
} from './extractRequest';

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);

function hasHttpMethodPattern(code: string): boolean {
    const methods = 'GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT';
    const patterns = [
        new RegExp(`\\.(${methods.toLowerCase()})\\s*\\(`, 'i'),
        new RegExp(`\\s*(${methods.toLowerCase()})\\s*\\(`, 'i'),
        new RegExp(`["'](${methods})["']`)
    ];

    return patterns.some(pattern => pattern.test(code));
}

function isValid(node: t.Node): boolean {
    if (t.isTemplateLiteral(node)) {
        const quasis = node.quasis.map(quasi => quasi.value.raw);
        return quasis.some(quasi => quasi.includes('/') && isURLLike(quasi));
    }

    if (t.isStringLiteral(node)) {
        const value = node.value;
        if (!value.includes('/')) {
            return false;
        }
        return isURLLike(value);
    }

    return false;
}

interface CallUsage {
    callPath: NodePath<t.CallExpression>;
    argIndex: number;
}

/**
 * Find all call expressions where the URL variable is used as an argument
 */
function findCallExpressionUsages(
    path: NodePath<t.VariableDeclarator> | NodePath<t.AssignmentExpression>,
    variableName: string
): CallUsage[] {
    const binding = path.scope.getBinding(variableName);
    if (!binding) return [];

    const usages: CallUsage[] = [];

    for (const ref of binding.referencePaths) {
        // Check if reference is an argument in a CallExpression
        let parent = ref.parentPath;
        while (parent) {
            if (parent.isCallExpression()) {
                const callNode = parent.node;
                const argIndex = callNode.arguments.findIndex(arg => arg === ref.node);
                if (argIndex >= 0) {
                    usages.push({ callPath: parent as NodePath<t.CallExpression>, argIndex });
                }
                break;
            }
            parent = parent.parentPath;
        }
    }

    return usages;
}

/**
 * Extract method/params/body from call expression arguments
 */
function extractFromCallArgs(
    callPath: NodePath<t.CallExpression>,
    urlArgIndex: number,
    trackedVars: TrackedVariableMap,
    context?: ResolutionContext
): { method: string; params: string; body: string } {
    const args = callPath.node.arguments;
    let method = 'GET';
    let params = '';
    let body = '';

    // Check args around URL position for HTTP method string
    const searchRange = Math.min(args.length, urlArgIndex + 3);
    for (let i = 0; i < searchRange; i++) {
        const arg = args[i];
        if (t.isStringLiteral(arg) && HTTP_METHODS.has(arg.value.toUpperCase())) {
            method = arg.value.toUpperCase();
            break;
        }
    }

    // Look for params/body in remaining args (after url and method)
    const isBodyMethod = /^(POST|PUT|PATCH|DELETE)$/i.test(method);
    let foundFirstObject = false;

    for (let i = 2; i < args.length; i++) {
        const arg = args[i];
        if (!arg || t.isSpreadElement(arg)) continue;

        const resolved = resolveFromScope(arg, callPath);
        const nodeToCheck = resolved ?? arg;

        if (t.isObjectExpression(nodeToCheck) && nodeToCheck.properties.length > 0) {
            if (!foundFirstObject) {
                // First non-empty object becomes params
                params = objectToKeyValue(nodeToCheck, trackedVars, context);
                foundFirstObject = true;
            } else if (isBodyMethod && !body) {
                // Second object becomes body for body methods
                body = extractBody(nodeToCheck, trackedVars, callPath, context);
            }
        }
        // Handle JSON.stringify calls for body
        else if (t.isCallExpression(nodeToCheck)) {
            const callee = nodeToCheck.callee;
            if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && callee.property.name === 'stringify') {
                if (!body) {
                    body = extractBody(nodeToCheck, trackedVars, callPath, context);
                }
            }
        }
    }

    return { method, params, body };
}

export function createVariableContainsURLTransform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
    return {
        name: 'variableContainsURL',
        tags: ['safe'],
        visitor() {
            return {
                VariableDeclarator(path) {
                    const init = path.node.init;
                    if (init && isValid(init)) {
                        const result = tracebackVariables(path, [], { ast, sourceCode });
                        if (hasHttpMethodPattern(result.code)) {
                            // Output existing requestPattern
                            appendPattern(result, 'variableContainsURL');

                            const trackedVars = getTrackedVariablesMap();
                            const varName = t.isIdentifier(path.node.id) ? path.node.id.name : null;

                            // Find current function and get effective iterations
                            const currentFunction = findContainingFunction(path);
                            const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

                            for (const iteration of effectiveIterations) {
                                const context = createResolutionContext(currentFunction, iteration);

                                const { url, queryParams } = extractURLSingle(init, trackedVars, context);

                                // Find usages of this variable and extract context
                                if (varName) {
                                    const usages = findCallExpressionUsages(path, varName);

                                    if (usages.length > 0) {
                                        for (const { callPath, argIndex } of usages) {
                                            const { method, params, body } = extractFromCallArgs(callPath, argIndex, trackedVars, context);

                                            const request = createExtractedRequest({
                                                url,
                                                method,
                                                params: mergeParams(queryParams, params),
                                                body,
                                                headers: [],
                                                cookies: [],
                                            });
                                            appendExtractedRequest(request);
                                        }
                                    } else {
                                        // Fallback: no usages found, use default GET
                                        const request = createExtractedRequest({
                                            url,
                                            method: 'GET',
                                            params: queryParams,
                                            body: '',
                                            headers: [],
                                            cookies: [],
                                        });
                                        appendExtractedRequest(request);
                                    }
                                } else {
                                    // No variable name (destructuring, etc.), use default
                                    const request = createExtractedRequest({
                                        url,
                                        method: 'GET',
                                        params: queryParams,
                                        body: '',
                                        headers: [],
                                        cookies: [],
                                    });
                                    appendExtractedRequest(request);
                                }
                            }
                        }
                    }
                },

                AssignmentExpression(path) {
                    if (path.node.operator !== '=') return;

                    const right = path.node.right;
                    if (isValid(right)) {
                        const result = tracebackVariables(path, [], { ast, sourceCode });
                        if (hasHttpMethodPattern(result.code)) {
                            // Output existing requestPattern
                            appendPattern(result, 'variableContainsURL');

                            const trackedVars = getTrackedVariablesMap();
                            const varName = t.isIdentifier(path.node.left) ? path.node.left.name : null;

                            // Find current function and get effective iterations
                            const currentFunction = findContainingFunction(path);
                            const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

                            for (const iteration of effectiveIterations) {
                                const context = createResolutionContext(currentFunction, iteration);

                                const { url, queryParams } = extractURLSingle(right, trackedVars, context);

                                // Find usages of this variable and extract context
                                if (varName) {
                                    const usages = findCallExpressionUsages(path, varName);

                                    if (usages.length > 0) {
                                        for (const { callPath, argIndex } of usages) {
                                            const { method, params, body } = extractFromCallArgs(callPath, argIndex, trackedVars, context);

                                            const request = createExtractedRequest({
                                                url,
                                                method,
                                                params: mergeParams(queryParams, params),
                                                body,
                                                headers: [],
                                                cookies: [],
                                            });
                                            appendExtractedRequest(request);
                                        }
                                    } else {
                                        // Fallback: no usages found, use default GET
                                        const request = createExtractedRequest({
                                            url,
                                            method: 'GET',
                                            params: queryParams,
                                            body: '',
                                            headers: [],
                                            cookies: [],
                                        });
                                        appendExtractedRequest(request);
                                    }
                                } else {
                                    // No variable name, use default
                                    const request = createExtractedRequest({
                                        url,
                                        method: 'GET',
                                        params: queryParams,
                                        body: '',
                                        headers: [],
                                        cookies: [],
                                    });
                                    appendExtractedRequest(request);
                                }
                            }
                        }
                    }
                },

                noScope: true,
            };
        },
    } satisfies Transform;
}
