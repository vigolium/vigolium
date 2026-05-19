import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import * as m from '@codemod/matchers';
import type { Transform } from '../ast-utils';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  extractBody,
  objectToKeyValue,
  objectToKeyValueWithNestedJSON,
  findProperty,
  mergeParams,
  createExtractedRequest,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
  isValidUrlNode,
} from './extractRequest';

export function createJqueryMethodTransform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
  return {
    name: 'jqueryMethod',
    tags: ['safe'],
    visitor() {
      const methodCapture = m.capture(m.identifier());

      const matcher = m.callExpression(
        m.memberExpression(
          m.anything(),
          methodCapture
        ),
        m.anyList(
          m.anything(),  // Accept any first arg, validate with isValidUrlNode later
          m.zeroOrMore()
        )
      );

      const methodsRegex = /^(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH)$/i;
      const camelCaseRegex = /^[a-z][a-z0-9]*([A-Z][a-z0-9]+)*$/;
      const allLowerCaseRegex = /^[a-z]+$/;

      return {
        CallExpression: {
          exit(path) {
            if (matcher.match(path.node)) {
              if (path.node.arguments.length === 0) return;

              const method = methodCapture.current!.name.toUpperCase();
              if (!methodsRegex.test(method)) return;

              const firstArg = path.node.arguments[0];

              // Validate that first arg is a valid URL node
              if (!isValidUrlNode(firstArg)) return;

              // Check for false positives: if the resolved URL is just a camelCase/lowercase string
              let url: string | undefined;
              if (t.isStringLiteral(firstArg)) {
                url = firstArg.value;
              } else if (t.isTemplateLiteral(firstArg) && firstArg.expressions.length === 0) {
                url = firstArg.quasis[0].value.raw;
              }

              if (url && (camelCaseRegex.test(url) || allLowerCaseRegex.test(url))) {
                return;
              }

              // Output existing requestPattern
              const result = tracebackVariables(path, [], { ast, sourceCode });
              appendPattern(result, 'jqueryMethod');

              // Extract structured request data
              // $.get(url, data?, callback?), $.post(url, data?, callback?)
              const trackedVars = getTrackedVariablesMap();

              // Find current function and get effective iterations
              const currentFunction = findContainingFunction(path);
              const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

              for (const iteration of effectiveIterations) {
                const context = createResolutionContext(currentFunction, iteration);

                const urlResults = extractURL(firstArg, trackedVars, context);

                for (const { url: extractedUrl, queryParams } of urlResults) {
                  const isBodyMethod = /^(POST|PUT|PATCH|DELETE)$/i.test(method);
                  const dataArg = path.node.arguments[1];
                  const hasDataArg = dataArg && !t.isFunction(dataArg);

                  // Extract params for GET requests
                  let extractedParams = queryParams;
                  if (!isBodyMethod && hasDataArg) {
                    // Check if dataArg is an object with 'params' property (axios-style)
                    if (t.isObjectExpression(dataArg)) {
                      const paramsNode = findProperty(dataArg, 'params');
                      if (paramsNode) {
                        extractedParams = mergeParams(queryParams, objectToKeyValueWithNestedJSON(paramsNode, trackedVars, path, context));
                      } else {
                        extractedParams = objectToKeyValue(dataArg, trackedVars, context);
                      }
                    } else {
                      extractedParams = objectToKeyValue(dataArg, trackedVars, context);
                    }
                  }

                  const request = createExtractedRequest({
                    url: extractedUrl,
                    method,
                    params: extractedParams,
                    body: isBodyMethod && hasDataArg ? extractBody(dataArg, trackedVars, path, context) : '',
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
