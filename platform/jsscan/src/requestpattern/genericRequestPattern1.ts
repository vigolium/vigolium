import type { ParseResult } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import * as m from '@codemod/matchers';
import type { Transform } from '../ast-utils';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  resolveValueSingle,
  createExtractedRequest,
  extractBody,
  objectToKeyValue,
  resolveFromScope,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
  isValidUrlNode,
} from './extractRequest';

export function createGenericRequestPattern1Transform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
  return {
    name: 'genericRequestPattern1',
    tags: ['safe'],
    visitor() {
      const methodCapture = m.capture(
        m.or(
          m.stringLiteral('GET'),
          m.stringLiteral('HEAD'),
          m.stringLiteral('OPTIONS'),
          m.stringLiteral('POST'),
          m.stringLiteral('PUT'),
          m.stringLiteral('PATCH'),
          m.stringLiteral('DELETE')
        )
      );

      const urlCapture = m.capture(m.or(
        m.stringLiteral(),
        m.templateLiteral(),
        m.memberExpression(),
        m.callExpression(),
        m.identifier()
      ));

      const nodesInArg = m.capture(
        m.or(
          m.anyList(
            methodCapture,
            urlCapture,
            m.zeroOrMore()
          ),
          m.anyList(
            urlCapture,
            methodCapture,
            m.zeroOrMore()
          )
        )
      );

      const matcher = m.callExpression(
        m.or(
          m.memberExpression(),
          m.identifier(),
          m.sequenceExpression(),
        ),
        nodesInArg
      );

      return {
        CallExpression: {
          exit(path: NodePath<t.CallExpression>) {
            if (!matcher.match(path.node)) return;

            const currentNodesInArg = nodesInArg.current!;
            if (currentNodesInArg.length < 2) return;

            const [firstArg, secondArg] = currentNodesInArg;
            if (isValidUrlNode(firstArg) || isValidUrlNode(secondArg)) {
              // Output existing requestPattern
              const result = tracebackVariables(path, [], { ast, sourceCode });
              appendPattern(result, 'genericRequestPattern1');

              // Extract structured request data
              // Pattern: func(method, url, ...) or func(url, method, ...)
              const trackedVars = getTrackedVariablesMap();

              // Determine which arg is method and which is URL based on position
              let methodNode: t.Node;
              let urlNode: t.Node;

              if (t.isStringLiteral(firstArg) && /^(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH)$/i.test(firstArg.value)) {
                methodNode = firstArg;
                urlNode = secondArg;
              } else {
                urlNode = firstArg;
                methodNode = secondArg;
              }

              // Find current function and get effective iterations
              const currentFunction = findContainingFunction(path);
              const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

              for (const iteration of effectiveIterations) {
                const context = createResolutionContext(currentFunction, iteration);

                const method = t.isStringLiteral(methodNode)
                  ? methodNode.value.toUpperCase()
                  : resolveValueSingle(methodNode, trackedVars, context);
                const urlResults = extractURL(urlNode, trackedVars, context);

                for (const { url, queryParams } of urlResults) {
                  // Extract params and body from remaining arguments
                  // Common patterns:
                  // - callApi(url, method, pathParams, queryParamsObj, headersObj, body, ...)
                  // - callApi(url, method, {}, {}, paramsObj, {}, body, ...)
                  let params = queryParams;
                  let body = '';

                  // Look through remaining arguments for potential params/body
                  const isBodyMethod = /^(POST|PUT|PATCH|DELETE)$/i.test(method);

                  for (let i = 2; i < currentNodesInArg.length; i++) {
                    const arg = currentNodesInArg[i];
                    if (!arg) continue;

                    // Resolve the argument if it's an identifier
                    const resolved = resolveFromScope(arg, path);
                    const nodeToCheck = resolved ?? arg;

                    // Check if it's an object expression (could be params or body)
                    if (t.isObjectExpression(nodeToCheck) && nodeToCheck.properties.length > 0) {
                      // First non-empty object becomes params, second becomes body for body methods
                      if (!params || params === queryParams) {
                        params = objectToKeyValue(nodeToCheck, trackedVars, context);
                      } else if (isBodyMethod && !body) {
                        body = extractBody(nodeToCheck, trackedVars, path, context);
                      }
                    }
                    // Handle JSON.stringify or xxx.stringify calls for body
                    else if (t.isCallExpression(nodeToCheck)) {
                      const callee = nodeToCheck.callee;
                      if (t.isMemberExpression(callee) && t.isIdentifier(callee.property) && callee.property.name === 'stringify') {
                        if (!body) {
                          body = extractBody(nodeToCheck, trackedVars, path, context);
                        }
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
