import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import type { Transform } from '../ast-utils';
import type { NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import { appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  extractBody,
  createExtractedRequest,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
  isValidUrlNode,
} from './extractRequest';

/**
 * Resolve a constructor/callee name from an Identifier or a `window.X` /
 * `self.X` style MemberExpression.
 */
function calleeName(node: t.Node): string | null {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) && t.isIdentifier(node.property)) {
    return node.property.name;
  }
  return null;
}

// Constructor name -> pseudo-method tag for non-HTTP protocols.
// These are recorded for discovery/reporting but never replayed as HTTP
// (see isReplayableMethod in the Go discovery layer).
const PROTOCOL_CONSTRUCTORS: Record<string, string> = {
  WebSocket: 'WS',
  EventSource: 'SSE',
};

/**
 * Detect non-HTTP protocol endpoints and beacon calls:
 *   - new WebSocket(url)        -> method WS
 *   - new EventSource(url)      -> method SSE
 *   - navigator.sendBeacon(url, data) -> method POST (real HTTP, replayable)
 */
export function createProtocolRequestTransform(
  analysisContext: AnalysisContext,
  ast: ParseResult<t.File> | null = null,
  _sourceCode: string = '',
): Transform {
  return {
    name: 'protocolRequest',
    tags: ['safe'],
    visitor() {
      // Resolve the tracked-variable map once per run, not per matched node.
      const trackedVars = getTrackedVariablesMap();

      const emit = (
        path: NodePath,
        urlNode: t.Node | null | undefined,
        method: string,
        dataNode?: t.Node | null,
      ) => {
        if (!isValidUrlNode(urlNode)) return;
        analysisContext.claimRequestNode(path.node);
        const currentFunction = findContainingFunction(path);
        const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

        for (const iteration of effectiveIterations) {
          const context = createResolutionContext(currentFunction, iteration, path);
          const urlResults = extractURL(urlNode, trackedVars, context);
          for (const { url, queryParams } of urlResults) {
            appendExtractedRequest(analysisContext, createExtractedRequest({
              url,
              method,
              params: queryParams,
              body: dataNode ? extractBody(dataNode, trackedVars, path, context) : '',
              headers: [],
              cookies: [],
            }), {
              extractor: 'browser-protocol', client: 'protocol', confidence: 'high',
              node: path.node, functionName: currentFunction,
            });
          }
        }
      };

      return {
        // new WebSocket(url) / new EventSource(url)
        NewExpression: {
          exit(path) {
            const name = calleeName(path.node.callee);
            if (!name) return;
            const method = PROTOCOL_CONSTRUCTORS[name];
            if (!method) return;
            emit(path, path.node.arguments[0], method);
          },
        },
        // navigator.sendBeacon(url, data)
        CallExpression: {
          exit(path) {
            const callee = path.node.callee;
            if (!t.isMemberExpression(callee) || !t.isIdentifier(callee.property)) return;
            if (callee.property.name !== 'sendBeacon') return;
            const dataNode = path.node.arguments[1] ?? null;
            emit(path, path.node.arguments[0], 'POST', dataNode);
          },
        },
        noScope: true,
      };
    },
  } satisfies Transform;
}
