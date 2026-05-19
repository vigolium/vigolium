import type { ParseResult } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import * as m from '@codemod/matchers';
import type { Transform } from '../ast-utils';
import { getFunctionMap, getEffectiveIterations } from '../mapping';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  extractProperty,
  extractHeaders,
  extractBody,
  extractCookies,
  extractCookiesFromProperty,
  findProperty,
  createExtractedRequest,
  objectToKeyValue,
  mergeParams,
  isValidUrlNode,
  type ResolutionContext,
} from './extractRequest';

/**
 * Detect the current function context from the AST path.
 * Returns the full function name like "ServiceName.methodName" if found.
 */
function detectCurrentFunction(path: NodePath): string | undefined {
  const functionMap = getFunctionMap();
  if (functionMap.functions.size === 0) return undefined;

  // Walk up the AST to find the enclosing function
  const funcParent = path.getFunctionParent();
  if (!funcParent) return undefined;

  const funcStartLine = funcParent.node.loc?.start.line || 0;
  const funcEndLine = funcParent.node.loc?.end.line || 0;

  // Find a registered function that matches this line range
  for (const [fullName, funcDef] of functionMap.functions) {
    // Check if the current function contains the path and matches registered function
    // The registered function should contain or be contained by the current function
    if (funcStartLine === funcDef.startLine && funcEndLine === funcDef.endLine) {
      return fullName;
    }
    // Also check for start line match (functions may have different end line detection)
    if (funcStartLine === funcDef.startLine) {
      return fullName;
    }
    // Check if the current path line is within the registered function range
    const currentLine = path.node.loc?.start.line || 0;
    if (currentLine >= funcDef.startLine && currentLine <= funcDef.endLine) {
      return fullName;
    }
  }

  return undefined;
}

export function createGenericRequestPattern3Transform(ast: ParseResult<t.File> | null = null, sourceCode: string = ''): Transform {
  return {
    name: 'genericRequestPattern3',
    tags: ['safe'],
    visitor() {
      const urlMatcher = m.objectProperty(
        m.identifier('url'),
        m.capture(m.or(
          m.stringLiteral(),
          m.templateLiteral(),
          m.memberExpression(),
          m.callExpression(),
          m.binaryExpression(),
          m.identifier()
        ))
      );

      const matcher = m.objectExpression(
        m.anyList(
          m.zeroOrMore(),
          urlMatcher,
          m.zeroOrMore()
        )
      );

      return {
        ObjectExpression: {
          exit(path: NodePath<t.ObjectExpression>) {
            if (!matcher.match(path.node)) return;

            const urlValue = path.node.properties.find(prop =>
              t.isObjectProperty(prop) &&
              t.isIdentifier(prop.key) &&
              prop.key.name === 'url'
            );

            if (!urlValue || !t.isObjectProperty(urlValue)) return;

            if (isValidUrlNode(urlValue.value)) {
              let currentPath: NodePath | null = path;
              let depth = 0;
              const MAX_DEPTH = 3;
              const SKIP_METHODS = new Set(['push', 'render', 'dialog']);

              while (currentPath && depth < MAX_DEPTH) {
                if (t.isCallExpression(currentPath.node)) {
                  const calleeNode = currentPath.node.callee;
                  if (t.isMemberExpression(calleeNode) && t.isIdentifier(calleeNode.property)) {
                    if (SKIP_METHODS.has(calleeNode.property.name)) {
                      return;
                    }
                  }
                }
                currentPath = currentPath.parentPath;
                depth++;
              }

              // Output existing requestPattern
              const result = tracebackVariables(path, [], { ast, sourceCode });
              appendPattern(result, 'genericRequestPattern3');

              // Extract structured request data
              // Pattern: { url: '...', method: '...', headers: {...}, data: {...} }
              const trackedVars = getTrackedVariablesMap();
              const config = path.node;

              // Detect current function context for function-aware resolution
              const currentFunction = detectCurrentFunction(path);

              // Determine how many requests to emit:
              // - If we're inside a registered function with call sites, emit one per effective iteration
              // - Effective iterations account for nested function chains
              // - Otherwise, emit a single request with unresolved params
              const effectiveIterations = currentFunction
                ? getEffectiveIterations(currentFunction)
                : [{ callSiteIndex: 0 }];

              for (const iteration of effectiveIterations) {
                const context: ResolutionContext | undefined = currentFunction
                  ? {
                      currentFunction,
                      callSiteIndex: iteration.callSiteIndex,
                      parentCallSiteIndex: iteration.parentCallSiteIndex,
                    }
                  : undefined;

                const urlNode = findProperty(config, 'url');
                const urlResults = extractURL(urlNode, trackedVars, context);

                for (const { url, queryParams } of urlResults) {
                  const method =
                    extractProperty(config, 'method', trackedVars, context) ||
                    extractProperty(config, 'type', trackedVars, context) ||
                    'GET';

                  const headersNode = findProperty(config, 'headers');
                  const cookiesNode = findProperty(config, 'cookies');
                  const queryNode = findProperty(config, 'query');
                  const dataNode = findProperty(config, 'data') || findProperty(config, 'body');
                  const paramsNode = findProperty(config, 'params');

                  const isBodyMethod = /^(POST|PUT|PATCH|DELETE)$/i.test(method);
                  // GraphQL requests use 'query' for body content
                  const hasQueryBody = queryNode !== null;

                  const request = createExtractedRequest({
                    url,
                    method: method.toUpperCase(),
                    params: isBodyMethod
                      ? mergeParams(queryParams, objectToKeyValue(paramsNode, trackedVars, context))
                      : mergeParams(queryParams, objectToKeyValue(hasQueryBody ? paramsNode : (dataNode || paramsNode), trackedVars, context)),
                    body: (isBodyMethod || hasQueryBody) ? extractBody(queryNode || dataNode, trackedVars, path, context) : '',
                    headers: extractHeaders(headersNode, trackedVars, context),
                    cookies: cookiesNode
                      ? extractCookiesFromProperty(cookiesNode, trackedVars, context)
                      : extractCookies(headersNode, trackedVars, context),
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
