import type { ParseResult } from '@babel/parser';
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
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
} from './extractRequest';

export function createXhrRequestTransform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
  return {
    name: 'xhrRequest',
    tags: ['safe'],
    visitor() {
      const matcher = m.callExpression(
        m.memberExpression(
          m.anything(),
          m.identifier('open')
        ),
        m.anyList(
          m.or(
            m.stringLiteral('GET'),
            m.stringLiteral('POST'),
            m.stringLiteral('HEAD'),
            m.stringLiteral('OPTIONS'),
            m.stringLiteral('PUT'),
            m.stringLiteral('PATCH'),
            m.stringLiteral('DELETE')
          ),
          m.zeroOrMore()
        )
      );

      return {
        CallExpression: {
          exit(path) {
            if (matcher.match(path.node)) {
              // Output existing requestPattern
              const result = tracebackVariables(path, [], { ast, sourceCode });
              appendPattern(result, 'xhrRequest');

              // Extract structured request data
              // xhr.open(method, url, async?, user?, password?)
              const args = path.node.arguments;
              if (args.length >= 2) {
                const trackedVars = getTrackedVariablesMap();

                // Find current function and get effective iterations
                const currentFunction = findContainingFunction(path);
                const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

                for (const iteration of effectiveIterations) {
                  const context = createResolutionContext(currentFunction, iteration);

                  const method = t.isStringLiteral(args[0])
                    ? args[0].value.toUpperCase()
                    : resolveValueSingle(args[0], trackedVars, context);
                  const urlResults = extractURL(args[1], trackedVars, context);

                  for (const { url, queryParams } of urlResults) {
                    const request = createExtractedRequest({
                      url,
                      method,
                      params: queryParams,
                      // XHR headers and body require tracking setRequestHeader/send calls
                      // which is beyond current scope - leaving empty
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
        },
        noScope: true,
      };
    },
  } satisfies Transform;
}
