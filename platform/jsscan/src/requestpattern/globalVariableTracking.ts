import * as t from '@babel/types';
import type { Transform } from '../ast-utils';
import { getWebpackModuleMap, getWebpackBundleState } from '../mapping';
import { isURLLike } from './utils';
import type { TrackedVariableMap } from './types';

interface TrackedVariable {
    key: string;
    values: string[];  // Changed from single value to array
}

const trackedVariables: TrackedVariable[] = [];

// ============================================================================
// Constants for primitive value tracking
// ============================================================================

const MAX_STRING_LENGTH = 500;
const MAX_TRACKED_VARIABLES = 10000;
const MIN_VARIABLE_NAME_LENGTH = 2;

// Patterns for validation/error messages (DO NOT track)
const VALIDATION_MESSAGE_PATTERNS = [
    /\bmust be\b/i,
    /\bshould be\b/i,
    /\bis required\b/i,
    /\bis invalid\b/i,
    /\bcannot be\b/i,
    /\bexpected\b.*\bbut got\b/i,
    /\${path}/,  // yup/joi validation placeholder
];

// Patterns for HTML/CSS (DO NOT track)
const TEMPLATE_PATTERNS = [
    /^<[a-z]+/i,           // HTML tag start
    /<\/[a-z]+>$/i,        // HTML closing tag
    /^\s*\{[\s\S]*\}\s*$/, // CSS rule block
    /^@media\b/i,
    /^@import\b/i,
];

// Generic variable names that appear frequently with different values in different contexts.
// These should not be tracked globally as they cause false positive URL resolutions.
// Example: {id: "background-content"} and /api/facility/${id} would incorrectly resolve.
const GENERIC_VARIABLE_NAMES = new Set([
    // Common object property names
    'id', 'key', 'name', 'value', 'data', 'type', 'text', 'label',
    'title', 'content', 'message', 'result', 'status', 'state',
    'index', 'item', 'items', 'list', 'options', 'config', 'settings',
    // DOM/React specific
    'className', 'style', 'ref', 'children', 'src', 'alt', 'href',
    'onClick', 'onChange', 'onSubmit', 'onError', 'onLoad',
    // HTTP/fetch related
    'method', 'body', 'headers', 'params', 'query', 'url', 'path',
]);

// ============================================================================
// Helper functions for primitive value tracking
// ============================================================================

function shouldTrackValue(value: string): boolean {
    if (!value || !value.trim()) return false;
    if (value.length > MAX_STRING_LENGTH) return false;
    if (VALIDATION_MESSAGE_PATTERNS.some(p => p.test(value))) return false;
    if (TEMPLATE_PATTERNS.some(p => p.test(value))) return false;
    if (!/[a-zA-Z0-9]/.test(value)) return false;
    return true;
}

function shouldTrackVariableName(name: string): boolean {
    // Variable name must be >= 2 chars to avoid minified names like a, b, c, t, e
    if (name.length < MIN_VARIABLE_NAME_LENGTH) return false;
    // GENERIC_VARIABLE_NAMES check is performed in addTrackedVariable
    return true;
}

interface PrimitiveValue {
    type: 'string' | 'number' | 'boolean';
    value: string;
}

function extractPrimitiveValue(node: t.Node): PrimitiveValue | null {
    if (t.isStringLiteral(node)) {
        return shouldTrackValue(node.value) ? { type: 'string', value: node.value } : null;
    }
    if (t.isTemplateLiteral(node) && node.quasis.length === 1) {
        const value = node.quasis[0].value.raw;
        return shouldTrackValue(value) ? { type: 'string', value } : null;
    }
    if (t.isNumericLiteral(node)) {
        return { type: 'number', value: String(node.value) };
    }
    if (t.isBooleanLiteral(node)) {
        return { type: 'boolean', value: String(node.value) };
    }
    // Minified boolean: !0 -> true, !1 -> false
    if (t.isUnaryExpression(node) && node.operator === '!' && t.isNumericLiteral(node.argument)) {
        return { type: 'boolean', value: node.argument.value === 0 ? 'true' : 'false' };
    }
    return null;
}

function addTrackedVariable(key: string, value: string, allowMultiple = false) {
    // Performance limit
    if (trackedVariables.length >= MAX_TRACKED_VARIABLES) {
        return;
    }

    // Get last part of key if it contains dots
    const finalKey = key.split('.').pop() || key;

    // Skip generic variable names that appear in many contexts
    if (GENERIC_VARIABLE_NAMES.has(finalKey)) {
        return;
    }

    // Check if key exists
    const existingVar = trackedVariables.find(v => v.key === finalKey);
    if (existingVar) {
        if (allowMultiple) {
            // Add to values array if not already present
            if (!existingVar.values.includes(value)) {
                existingVar.values.push(value);
            }
        } else if (existingVar.values.length === 0 || (existingVar.values.length === 1 && !existingVar.values[0])) {
            // Only override if current values are empty
            existingVar.values = [value];
        }
        return;
    }

    trackedVariables.push({ key: finalKey, values: [value] });
}

/**
 * Add webpack exports to tracked variables for resolution.
 * This allows resolving patterns like a.O.accountLogin where:
 * - a = t(8947) (webpack require)
 * - module 8947 exports {O: () => endpoints}
 * - endpoints = {accountLogin: "/api/account/login"}
 */
function addWebpackExportsToTrackedVariables(): void {
    const moduleMap = getWebpackModuleMap();

    for (const [_moduleId, module] of moduleMap) {
        // For each import in each module, map localVar.exportName.property to value
        for (const imp of module.imports) {
            const importedModule = moduleMap.get(imp.moduleId);
            if (!importedModule) continue;

            for (const exp of importedModule.exports) {
                // Handle new ResolvedExportValue type structure
                const resolvedValue = exp.resolvedValue;
                if (!resolvedValue) continue;

                if (resolvedValue.type === 'object') {
                    // Add each property: a.O.accountLogin -> "/api/account/login"
                    for (const [key, value] of Object.entries(resolvedValue.value)) {
                        if (typeof value === 'string') {
                            const fullPath = `${imp.localVar}.${exp.name}.${key}`;
                            trackedVariables.push({ key: fullPath, values: [value] });
                            // Also add just the property name for simpler lookups
                            addTrackedVariable(key, value);
                        }
                    }
                } else if (resolvedValue.type === 'string') {
                    const fullPath = `${imp.localVar}.${exp.name}`;
                    trackedVariables.push({ key: fullPath, values: [resolvedValue.value] });
                    addTrackedVariable(exp.name, resolvedValue.value);
                }
            }
        }

        // Also add direct exports from each module
        for (const exp of module.exports) {
            const resolvedValue = exp.resolvedValue;
            if (!resolvedValue) continue;

            if (resolvedValue.type === 'object') {
                for (const [key, value] of Object.entries(resolvedValue.value)) {
                    if (typeof value === 'string') {
                        addTrackedVariable(key, value);
                    }
                }
            } else if (resolvedValue.type === 'string') {
                addTrackedVariable(exp.name, resolvedValue.value);
            }
        }
    }
}

/**
 * Add resolved HTTP call URLs from webpack modules
 */
function addWebpackHttpCallsToTrackedVariables(): void {
    const state = getWebpackBundleState();

    for (const module of state.modules.values()) {
        for (const httpCall of module.httpCalls) {
            // If URL was resolved from import, add it with the import path as key
            if (httpCall.urlSource.resolvedValue && httpCall.urlSource.importPath) {
                const key = httpCall.urlSource.importPath.join('.');
                trackedVariables.push({ key, values: [httpCall.urlSource.resolvedValue] });
            }
        }
    }
}

export function createGlobalVariableTracking(): Transform {
    return {
        name: 'globalVariableTracking',
        tags: ['safe'],
        visitor() {
            return {
                // Case 1: var a = "b" or var a = `b` or var a = 123 or var a = true
                // Track all primitive values (string, number, boolean)
                VariableDeclarator(path) {
                    const { id, init } = path.node;
                    if (t.isIdentifier(id) && init && shouldTrackVariableName(id.name)) {
                        const prim = extractPrimitiveValue(init);
                        if (prim) {
                            addTrackedVariable(id.name, prim.value);
                        }
                    }
                },

                // Case 2: {a:"b"} or {a: 123} or {a: true}
                // Track all primitive values (string, number, boolean)
                ObjectProperty(path) {
                    const { key, value } = path.node;
                    if (t.isIdentifier(key) && shouldTrackVariableName(key.name)) {
                        const prim = extractPrimitiveValue(value);
                        if (prim) {
                            addTrackedVariable(key.name, prim.value);
                        }
                    }
                },

                // Case 3: a="123" or a=456 or a=true
                // Track all primitive values (string, number, boolean)
                AssignmentExpression(path) {
                    const { left, right } = path.node;
                    let varName = '';
                    if (t.isIdentifier(left)) {
                        varName = left.name;
                    } else if (t.isMemberExpression(left) && t.isIdentifier(left.property)) {
                        varName = left.property.name;
                    }

                    if (varName && shouldTrackVariableName(varName)) {
                        const prim = extractPrimitiveValue(right);
                        if (prim) {
                            addTrackedVariable(varName, prim.value);
                        }
                    }
                },

                // Case 4: Object({...}) calls with primitive values
                // Handles Vue.js/webpack environment config patterns like:
                // Object({VUE_APP_PROD_API: "https://...", DEBUG: true, MAX_RETRIES: 3})
                CallExpression(path) {
                    const { callee, arguments: args } = path.node;

                    // Pattern A: Object({...}) - environment config
                    if (t.isIdentifier(callee) && callee.name === 'Object') {
                        if (args[0] && t.isObjectExpression(args[0])) {
                            const obj = args[0];
                            for (const prop of obj.properties) {
                                if (!t.isObjectProperty(prop)) continue;

                                const keyName = t.isIdentifier(prop.key)
                                    ? prop.key.name
                                    : t.isStringLiteral(prop.key)
                                        ? prop.key.value
                                        : null;

                                if (!keyName || !shouldTrackVariableName(keyName)) continue;

                                const prim = extractPrimitiveValue(prop.value);
                                if (prim) {
                                    addTrackedVariable(keyName, prim.value);
                                }
                            }
                        }
                        return;
                    }

                    // Pattern B: X.dispatch("setURL", "https://...") - Vuex store actions
                    // This tracks URLs set via Vuex dispatch with common key names
                    if (t.isMemberExpression(callee) &&
                        t.isIdentifier(callee.property) &&
                        (callee.property.name === 'dispatch' || callee.property.name === 'commit')) {
                        if (args.length >= 2 && t.isStringLiteral(args[0])) {
                            const actionName = args[0].value.toLowerCase();
                            // Check if action name relates to URL/API setting
                            if (actionName.includes('url') || actionName.includes('api') || actionName.includes('base')) {
                                const prim = extractPrimitiveValue(args[1]);
                                if (prim && isURLLike(prim.value)) {
                                    // Track with common URL-related keys (allow multiple for env-specific URLs)
                                    addTrackedVariable('apiURL', prim.value, true);
                                    addTrackedVariable('apiUrl', prim.value, true);
                                    addTrackedVariable('baseURL', prim.value, true);
                                    addTrackedVariable('baseUrl', prim.value, true);
                                    addTrackedVariable('API_URL', prim.value, true);
                                    addTrackedVariable('BASE_URL', prim.value, true);
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

export function getTrackedVariables(): TrackedVariable[] {
    return trackedVariables;
}

export function getTrackedVariablesMap(): TrackedVariableMap {
    // Add webpack exports and HTTP calls to tracked variables before returning
    addWebpackExportsToTrackedVariables();
    addWebpackHttpCallsToTrackedVariables();

    const map: TrackedVariableMap = {};
    for (const v of trackedVariables) {
        map[v.key] = v.values;
    }
    return map;
}

export function clearTrackedVariables(): void {
    trackedVariables.length = 0;
}

