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
  extractProperty,
  extractHeaders,
  extractBody,
  extractCookies,
  findProperty,
  createExtractedRequest,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
  isValidUrlNode,
} from './extractRequest';

export function createFetchRequestTransform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
  return {
    name: 'fetchRequest',
    tags: ['safe'],
    visitor() {
      const matcher = m.callExpression(
        m.identifier('fetch'),
        m.anything()
      );

      return {
        CallExpression: {
          exit(path) {
            if (matcher.match(path.node)) {
              const args = path.node.arguments;

              if (!args.length || !isValidUrlNode(args[0])) {
                return;
              }

              if (args[1] && !t.isObjectExpression(args[1])) {
                return;
              }

              // Output existing requestPattern
              const result = tracebackVariables(path, [], { ast, sourceCode });
              appendPattern(result, 'fetchRequest');

              // Extract structured request data
              const trackedVars = getTrackedVariablesMap();
              const options = args[1] as t.ObjectExpression | undefined;
              const headersNode = options ? findProperty(options, 'headers') : null;

              // Find current function and get effective iterations
              const currentFunction = findContainingFunction(path);
              const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

              // Generate request for each effective iteration (call site chain)
              for (const iteration of effectiveIterations) {
                const context = createResolutionContext(currentFunction, iteration);

                // extractURL now returns array of {url, queryParams} for multiple values
                const urlResults = extractURL(args[0], trackedVars, context);

                for (const { url, queryParams } of urlResults) {
                  const request = createExtractedRequest({
                    url,
                    method: options ? extractProperty(options, 'method', trackedVars, context) || 'GET' : 'GET',
                    params: queryParams,
                    body: options ? extractBody(findProperty(options, 'body'), trackedVars, path, context) : '',
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
