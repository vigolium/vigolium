import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import * as m from '@codemod/matchers';
import type { Transform } from '../ast-utils';
import type { NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  extractBody,
  resolveValueSingle,
  createExtractedRequest,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
  type ResolutionContext,
} from './extractRequest';
import type { TrackedVariableMap } from './types';

/**
 * Build a stable structural key for an XHR receiver expression so that
 * `xhr.open()`, `xhr.setRequestHeader()` and `xhr.send()` calls on the SAME
 * receiver can be correlated. Supports identifiers, `this`, and simple member
 * chains (e.g. `this.xhr`, `a.b`). Returns null for receivers we can't key.
 */
function receiverKey(node: t.Node | null | undefined): string | null {
  if (!node) return null;
  if (t.isIdentifier(node)) return `id:${node.name}`;
  if (t.isThisExpression(node)) return 'this';
  if (t.isMemberExpression(node) && !node.computed) {
    const objKey = receiverKey(node.object);
    if (!objKey) return null;
    const prop = t.isIdentifier(node.property) ? node.property.name : null;
    if (!prop) return null;
    return `${objKey}.${prop}`;
  }
  return null;
}

interface CorrelatedXhr {
  headers: string[];
  cookies: string[];
  body: string;
}

/**
 * Walk the enclosing function/program scope for sibling calls on the same
 * receiver and collect headers (setRequestHeader) and body (send).
 * Best-effort within the immediate scope; minified reassignment of the
 * receiver is not tracked.
 */
function correlateXhrCalls(
  openPath: NodePath,
  recvKey: string,
  trackedVars: TrackedVariableMap,
  context?: ResolutionContext,
  analysisContext?: AnalysisContext,
): CorrelatedXhr {
  const result: CorrelatedXhr = { headers: [], cookies: [], body: '' };

  const consume = (p: NodePath<t.CallExpression>): 'continue' | 'stop' => {
    const callee = p.node.callee;
    if (!t.isMemberExpression(callee) || !t.isIdentifier(callee.property)) return 'continue';
    const method = callee.property.name;
    if (method === 'open' && p.node !== openPath.node) return 'stop';
    const args = p.node.arguments;
    if (method === 'setRequestHeader' && args.length >= 2) {
      const name = resolveValueSingle(args[0], trackedVars, context);
      const value = resolveValueSingle(args[1], trackedVars, context);
      if (!name || name.startsWith('${')) return 'continue';
      if (name.toLowerCase() === 'cookie') {
        result.cookies.push(...value.split(';').map((cookie) => cookie.trim()).filter(Boolean));
      } else {
        result.headers.push(`${name}: ${value}`);
      }
    } else if (method === 'send' && args.length >= 1) {
      const body = extractBody(args[0], trackedVars, p, context);
      if (body && body !== '${unknown}') result.body = body;
    }
    return 'continue';
  };

  const index = analysisContext?.structuralIndex;
  if (index && openPath.isCallExpression() && t.isMemberExpression(openPath.node.callee)) {
    const openCallee = openPath.node.callee;
    index.stats.xhrLifecycleQueries++;
    const openOffset = openPath.node.start ?? 0;
    const functionScope = openPath.scope.getFunctionParent();
    for (const operation of index.operationsForReceiver(openPath, openCallee.object)) {
      if ((operation.node.start ?? 0) <= openOffset) continue;
      if (operation.scope.getFunctionParent() !== functionScope) continue;
      if (consume(operation) === 'stop') break;
    }
    return result;
  }

  const container = openPath.findParent(
    (p) => p.isFunction() || p.isProgram(),
  );
  if (!container) return result;

  if (index) index.stats.xhrFallbackTraversals++;

  container.traverse({
    CallExpression(p: NodePath<t.CallExpression>) {
      const callee = p.node.callee;
      if (!t.isMemberExpression(callee) || !t.isIdentifier(callee.property)) return;
      if (receiverKey(callee.object) !== recvKey) return;
      consume(p);
    },
  });

  return result;
}

export function createXhrRequestTransform(
  analysisContext: AnalysisContext,
  ast: ParseResult<t.File> | null = null,
  sourceCode: string = '',
): Transform {
  return {
    name: 'xhrRequest',
    tags: ['safe'],
    visitor() {
      // Resolve the tracked-variable map once per run, not per matched node.
      const trackedVars = getTrackedVariablesMap();

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
              analysisContext.claimRequestNode(path.node);
              // Output existing requestPattern
              if (analysisContext.has('requestEvidence')) {
                appendPattern(analysisContext, () => tracebackVariables(path, [], { ast, sourceCode, sourceLines: analysisContext.sourceLines }), 'xhrRequest', path.node);
              }

              // Extract structured request data
              // xhr.open(method, url, async?, user?, password?)
              const args = path.node.arguments;
              if (args.length >= 2) {
                // Receiver of the .open() call — used to correlate
                // setRequestHeader()/send() calls on the same object.
                const callee = path.node.callee;
                const recvKey = t.isMemberExpression(callee)
                  ? receiverKey(callee.object)
                  : null;

                // Find current function and get effective iterations
                const currentFunction = findContainingFunction(path);
                const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

                // Correlate headers/cookies/body from sibling calls once: these
                // are sibling statements on the same receiver and don't vary per
                // call-site iteration, so avoid re-traversing the scope per
                // iteration. Resolve values with the first iteration's context.
                const baseContext = createResolutionContext(currentFunction, effectiveIterations[0]);
                const correlated = recvKey
                  ? correlateXhrCalls(path, recvKey, trackedVars, baseContext, analysisContext)
                  : { headers: [], cookies: [], body: '' };

                for (const iteration of effectiveIterations) {
                  const context = createResolutionContext(currentFunction, iteration, path);

                  const method = t.isStringLiteral(args[0])
                    ? args[0].value.toUpperCase()
                    : resolveValueSingle(args[0], trackedVars, context);
                  const urlResults = extractURL(args[1], trackedVars, context);

                  for (const { url, queryParams } of urlResults) {
                    const request = createExtractedRequest({
                      url,
                      method,
                      params: queryParams,
                      body: correlated.body,
                      headers: correlated.headers,
                      cookies: correlated.cookies,
                    });

                    appendExtractedRequest(analysisContext, request, {
                      extractor: 'xhr', client: 'xhr', confidence: 'high',
                      node: path.node, functionName: currentFunction,
                    });
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
