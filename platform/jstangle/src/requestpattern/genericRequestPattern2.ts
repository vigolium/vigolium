import type { ParseResult } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type { Transform } from '../ast-utils';
import type { AnalysisContext } from '../context';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  extractBody,
  findProperty,
  objectToKeyValueWithNestedJSON,
  mergeParams,
  createExtractedRequest,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
  isValidUrlNode,
} from './extractRequest';

export function createGenericRequestPattern2Transform(
  analysisContext: AnalysisContext,
  ast: ParseResult<t.File> | null = null,
  sourceCode: string = '',
): Transform {
  return {
    name: 'genericRequestPattern2',
    tags: ['safe'],
    visitor() {
      const methodsRegex = /^(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH)$/i;

      return {
        CallExpression: {
          exit(path: NodePath<t.CallExpression>) {
            if (!t.isMemberExpression(path.node.callee)) return;

            const property = path.node.callee.property;
            if (!t.isIdentifier(property) || !methodsRegex.test(property.name)) return;

            const allArgs = path.node.arguments;
            if (!allArgs || allArgs.length === 0) return;

            const firstArg = allArgs[0];

            if (property.name.toLowerCase() === 'get') {
              if (t.isArrayExpression(firstArg)) {
                const allItems = firstArg.elements;
                if (allItems.every(item => t.isStringLiteral(item))) return;
              }
            }

            if (isValidUrlNode(firstArg)) {
              if (!analysisContext.isRequestNodeClaimed(path.node)) {
                analysisContext.claimRequestNode(path.node);
              }
              // Output existing requestPattern
              if (analysisContext.has('requestEvidence')) {
                appendPattern(analysisContext, () => tracebackVariables(path, [], { ast, sourceCode, sourceLines: analysisContext.sourceLines }), 'genericRequestPattern2', path.node);
              }

              // Extract structured request data
              // Pattern: obj.get(url, ...), obj.post(url, ...)
              const trackedVars = getTrackedVariablesMap();
              const method = property.name.toUpperCase();

              // Find current function and get effective iterations
              const currentFunction = findContainingFunction(path);
              const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

              for (const iteration of effectiveIterations) {
                const context = createResolutionContext(currentFunction, iteration, path);

                const urlResults = extractURL(firstArg, trackedVars, context);

                for (const { url, queryParams } of urlResults) {
                  // Process second argument for body/params
                  const secondArg = allArgs[1];
                  let body = '';
                  let params = queryParams;

                  if (secondArg) {
                    const isBodyMethod = /^(POST|PUT|PATCH|DELETE)$/i.test(method);

                    if (t.isObjectExpression(secondArg)) {
                      // Pattern: xt.get(url, { params: {...} }) or xt.post(url, { data: {...} })
                      const paramsNode = findProperty(secondArg, 'params');
                      if (paramsNode) {
                        params = mergeParams(queryParams, objectToKeyValueWithNestedJSON(paramsNode, trackedVars, path, context));
                      }
					  // For a method-specific client (`client.post(url, value)`), the
					  // second argument is the body itself. Explicit Axios/Angular
					  // adapters claim their config shapes before this fallback.
					  if (isBodyMethod) {
						body = extractBody(secondArg, trackedVars, path, context);
                      }
                    } else {
                      // Pattern: xt.post(url, body) - body could be CallExpression or Identifier
                      if (isBodyMethod) {
                        body = extractBody(secondArg, trackedVars, path, context);
                      }
                    }
                  }

                  const request = createExtractedRequest({
                    url,
                    method,
                    params,
                    body,
                    headers: [],
                    cookies: [],
                  });

                  appendExtractedRequest(analysisContext, request, {
                    extractor: 'generic-http-method', client: 'generic', confidence: 'medium',
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
