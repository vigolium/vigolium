import type { ParseResult } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import * as m from '@codemod/matchers';
import type { Transform } from '../ast-utils';
import type { AnalysisContext } from '../context';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest, isURLLike } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  createExtractedRequest,
  resolveFromScope,
  objectToKeyValueWithNestedJSON,
  mergeParams,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
} from './extractRequest';

// Properties that indicate a config object (fetch options, ajax config, axios config, etc.)
const CONFIG_OBJECT_PROPERTIES = new Set([
  'method', 'headers', 'body', 'mode', 'credentials', 'cache', 'redirect',
  'referrer', 'referrerPolicy', 'integrity', 'keepalive', 'signal', // fetch options
  'url', 'type', 'dataType', 'contentType', 'async', 'timeout', 'data', 'success', 'error', // jQuery ajax
  'params', 'query', 'baseURL', 'transformRequest', 'transformResponse', 'paramsSerializer', // axios config
  'withCredentials', 'adapter', 'auth', 'responseType', 'responseEncoding', 'xsrfCookieName', // axios config
  'xsrfHeaderName', 'onUploadProgress', 'onDownloadProgress', 'maxContentLength', // axios config
  'maxBodyLength', 'validateStatus', 'maxRedirects', 'socketPath', 'httpAgent', 'httpsAgent', // axios config
  'proxy', 'cancelToken', 'decompress', // axios config
]);

const REQUEST_LIKE_CALLEE = /(?:request|http|api|fetch|load|send|submit|query|mutat|upload|download|client)/i;
const MAX_GENERIC_URLS = 8;

function calleeLabel(node: t.CallExpression['callee']): string {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const property = node.property;
    if (t.isIdentifier(property)) return property.name;
    if (t.isStringLiteral(property)) return property.value;
  }
  return '';
}

function renderDirectURL(node: t.Node, depth = 0): string | null {
  if (depth > 3) return null;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node)) {
    let rendered = '';
    for (let i = 0; i < node.quasis.length; i++) {
      rendered += node.quasis[i].value.raw;
      if (i < node.expressions.length) {
        const expression = node.expressions[i];
        rendered += t.isIdentifier(expression) ? `\${${expression.name}}` : '${value}';
      }
    }
    return rendered;
  }
  if (t.isBinaryExpression(node, { operator: '+' })) {
    const left = renderDirectURL(node.left, depth + 1);
    const right = renderDirectURL(node.right, depth + 1);
    if (left !== null && right !== null) return left + right;
  }
  if (t.isIdentifier(node)) return `\${${node.name}}`;
  if (t.isMemberExpression(node)) return '${member}';
  return null;
}

function collectBoundedURLs(node: t.Node | null | undefined, out: string[], depth = 0): void {
  if (!node || depth > 2 || out.length >= MAX_GENERIC_URLS) return;
  const rendered = renderDirectURL(node);
  if (rendered && isURLLike(rendered) && !out.includes(rendered)) out.push(rendered);
  if (t.isObjectExpression(node)) {
    for (const property of node.properties) {
      if (!t.isObjectProperty(property)) continue;
      const key = t.isIdentifier(property.key) ? property.key.name : t.isStringLiteral(property.key) ? property.key.value : '';
      if (/^(?:url|uri|path|endpoint|baseURL|action)$/i.test(key)) {
        collectBoundedURLs(property.value, out, depth + 1);
      }
    }
  } else if (t.isArrayExpression(node)) {
    for (const element of node.elements.slice(0, MAX_GENERIC_URLS)) {
      if (element && !t.isSpreadElement(element)) collectBoundedURLs(element, out, depth + 1);
    }
  }
}

function hasRequestConfig(args: t.CallExpression['arguments']): boolean {
  return args.some((argument) => t.isObjectExpression(argument) && argument.properties.some((property) => {
    if (!t.isObjectProperty(property)) return false;
    const key = t.isIdentifier(property.key) ? property.key.name : t.isStringLiteral(property.key) ? property.key.value : '';
    return /^(?:url|method|type|headers|body|data|params|query)$/i.test(key);
  }));
}

/**
 * Check if an object looks like a config object (fetch options, ajax config, etc.)
 * rather than a params object.
 */
function isConfigObject(node: t.ObjectExpression): boolean {
  for (const prop of node.properties) {
    if (!t.isObjectProperty(prop)) continue;
    const keyName = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
        ? prop.key.value
        : null;
    if (keyName && CONFIG_OBJECT_PROPERTIES.has(keyName)) {
      return true;
    }
  }
  return false;
}

export function createGenericRequestPattern4Transform(
  analysisContext: AnalysisContext,
  ast: ParseResult<t.File> | null = null,
  sourceCode: string = '',
): Transform {
  return {
    name: 'genericRequestPattern4',
    tags: ['safe'],
    visitor() {
      const matcher = m.callExpression(
        m.or(
          m.memberExpression(),
          m.identifier(),
          m.sequenceExpression(),
        ),
      );

      // HTTP methods that other patterns handle (genericRequestPattern1, jqueryMethod, genericRequestPattern2)
      const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);

      return {
        CallExpression: {
          exit(path: NodePath<t.CallExpression>) {
            if (matcher.match(path.node)) {
              if (analysisContext.isRequestNodeClaimed(path.node)) return;
              const args = path.node.arguments;
              if (args.length == 0) return;

              // Skip if callee is a member expression with HTTP method name as property
              // (e.g., axios.get, $e.a.post, http.delete)
              // These are handled by jqueryMethod, genericRequestPattern2, etc.
              if (t.isMemberExpression(path.node.callee) && t.isIdentifier(path.node.callee.property)) {
                const methodName = path.node.callee.property.name.toUpperCase();
                if (HTTP_METHODS.has(methodName)) {
                  return;
                }
                // Skip string methods that are used for URL building (concat, join, etc.)
                // These are intermediate expressions, not actual HTTP requests
                const STRING_METHODS = new Set(['concat', 'join', 'replace', 'substring', 'slice', 'split', 'trim']);
                if (STRING_METHODS.has(path.node.callee.property.name)) {
                  return;
                }
                // Skip Promise methods and common chaining methods
                // These are continuation/callback methods, not actual HTTP requests
                const PROMISE_METHODS = new Set(['then', 'catch', 'finally', 'done', 'fail', 'always', 'pipe']);
                if (PROMISE_METHODS.has(path.node.callee.property.name)) {
                  return;
                }
              }

              // Skip if first or second arg is HTTP method string
              // These are handled by genericRequestPattern1
              const firstTwoArgs = args.slice(0, 2);
              const hasHttpMethodInArgs = firstTwoArgs.some(arg =>
                t.isStringLiteral(arg) && HTTP_METHODS.has((arg as t.StringLiteral).value.toUpperCase())
              );
              if (hasHttpMethodInArgs) {
                return;
              }

              const apiUrls: string[] = [];
              for (const argument of args.slice(0, 3)) {
                if (!t.isSpreadElement(argument)) collectBoundedURLs(argument, apiUrls);
              }
              if (apiUrls.length == 0) return;
              const firstArgumentURLs: string[] = [];
              if (args[0] && !t.isSpreadElement(args[0])) collectBoundedURLs(args[0], firstArgumentURLs);
              if (!REQUEST_LIKE_CALLEE.test(calleeLabel(path.node.callee)) &&
                  !hasRequestConfig(args) && firstArgumentURLs.length === 0) return;
              analysisContext.claimRequestNode(path.node);

              // Output existing requestPattern
              if (analysisContext.has('requestEvidence')) {
                appendPattern(analysisContext, () => tracebackVariables(path, [], { ast, sourceCode, sourceLines: analysisContext.sourceLines }), 'genericRequestPattern4', path.node);
              }

              // Extract structured request data
              const trackedVars = getTrackedVariablesMap();

              // Find current function and get effective iterations
              const currentFunction = findContainingFunction(path);
              const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

              for (const apiUrl of apiUrls) {
                const questionIndex = apiUrl.indexOf('?');
                const url = questionIndex === -1 ? apiUrl : apiUrl.substring(0, questionIndex);
                const queryParams = questionIndex === -1 ? '' : apiUrl.substring(questionIndex + 1);

                for (const iteration of effectiveIterations) {
                  const context = createResolutionContext(currentFunction, iteration, path);

                  let params = queryParams;

                  // Check for params object in second argument
                  // Pattern: func(url, paramsObj, ...) or func(url, paramsObj)
                  if (args.length >= 2) {
                    const secondArg = args[1];
                    if (t.isExpression(secondArg) || t.isSpreadElement(secondArg)) {
                      const resolved = resolveFromScope(secondArg as t.Node, path);
                      if (resolved && t.isObjectExpression(resolved) && !isConfigObject(resolved)) {
                        params = mergeParams(queryParams, objectToKeyValueWithNestedJSON(resolved, trackedVars, path, context));
                      }
                    }
                  }

                  const request = createExtractedRequest({
                    url,
                    method: 'GET', // Default since we can't determine from this pattern
                    params,
                    body: '',
                    headers: [],
                    cookies: [],
                  });

                  appendExtractedRequest(analysisContext, request, {
                    extractor: 'generic-call-subtree-url', client: 'generic', confidence: 'low',
                    node: path.node, functionName: currentFunction,
                  });
                }
              }
            }
          },
        },
        noScope: true,
      };
    },
  } satisfies Transform;
}
