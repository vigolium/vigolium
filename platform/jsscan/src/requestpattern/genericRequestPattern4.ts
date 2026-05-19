import type { ParseResult } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import * as m from '@codemod/matchers';
import type { Transform } from '../ast-utils';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, collectAPIUrls, appendExtractedRequest } from './utils';
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

export function createGenericRequestPattern4Transform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
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

              const apiUrls = collectAPIUrls(path);
              if (apiUrls.length == 0) return;

              // Output existing requestPattern
              const result = tracebackVariables(path, [], { ast, sourceCode });
              appendPattern(result, 'genericRequestPattern4');

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
                  const context = createResolutionContext(currentFunction, iteration);

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

                  appendExtractedRequest(request);
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
