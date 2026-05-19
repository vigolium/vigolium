import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import * as m from '@codemod/matchers';
import type { Transform } from '../ast-utils';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  extractProperty,
  extractHeaders,
  extractBody,
  extractCookies,
  findProperty,
  createExtractedRequest,
  objectToKeyValue,
  mergeParams,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
} from './extractRequest';

export function createJqueryAjaxTransform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
  return {
    name: 'jqueryAjax',
    tags: ['safe'],
    visitor() {
      const objMatcher = m.capture(m.objectExpression(m.anything()));
      const matcher = m.callExpression(
        m.memberExpression(
          m.anything(),
          m.identifier('ajax'),
        ),
        [objMatcher]
      );
      const methodsRegex = /^(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH)$/i;
      return {
        CallExpression: {
          exit(path) {
            if (!matcher.match(path.node)) {
              return;
            }
            if (path.node.arguments.length === 0) return;

            const ajaxConfig = path.node.arguments[0];

            if (!t.isObjectExpression(ajaxConfig)) return;

            let hasUrl = false;
            let hasValidMethod = false;

            for (const prop of ajaxConfig.properties) {
              if (!t.isObjectProperty(prop)) continue;
              if (!t.isIdentifier(prop.key)) continue;

              if (prop.key.name === 'url') {
                hasUrl = true;
                continue;
              }

              if ((prop.key.name === 'type' || prop.key.name === 'method') && t.isStringLiteral(prop.value)) {
                if (methodsRegex.test(prop.value.value)) {
                  hasValidMethod = true;
                  continue;
                }
              }
            }

            if (hasUrl && hasValidMethod) {
              // Output existing requestPattern
              const result = tracebackVariables(path, [], { ast, sourceCode });
              appendPattern(result, 'jqueryAjax');

              // Extract structured request data
              const trackedVars = getTrackedVariablesMap();

              // Find current function and get effective iterations
              const currentFunction = findContainingFunction(path);
              const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

              for (const iteration of effectiveIterations) {
                const context = createResolutionContext(currentFunction, iteration);

                const urlNode = findProperty(ajaxConfig, 'url');
                const urlResults = extractURL(urlNode, trackedVars, context);

                for (const { url, queryParams } of urlResults) {
                  const method =
                    extractProperty(ajaxConfig, 'type', trackedVars, context) ||
                    extractProperty(ajaxConfig, 'method', trackedVars, context) ||
                    'GET';

                  const headersNode = findProperty(ajaxConfig, 'headers');
                  const dataNode = findProperty(ajaxConfig, 'data');
                  const isBodyMethod = /^(POST|PUT|PATCH|DELETE)$/i.test(method);

                  const request = createExtractedRequest({
                    url,
                    method: method.toUpperCase(),
                    params: isBodyMethod
                      ? queryParams
                      : mergeParams(queryParams, objectToKeyValue(dataNode, trackedVars, context)),
                    body: isBodyMethod ? extractBody(dataNode, trackedVars, path, context) : '',
                    headers: headersNode ? extractHeaders(headersNode, trackedVars, context) : [],
                    cookies: headersNode ? extractCookies(headersNode, trackedVars, context) : [],
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
