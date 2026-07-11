import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import type { Transform } from '../ast-utils';
import { traverse, type NodePath, type TraverseOptions } from '../ast-utils/babel';
import { getEngineState, type AnalysisContext, type AxiosInstanceState } from '../context';
import { tracebackVariables } from '../traceback/tracebackVariables';
import { appendPattern, appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  extractURL,
  extractProperty,
  extractHeaders,
  extractCookies,
  extractBody,
  findProperty,
  mergeParams,
  objectToKeyValueWithNestedJSON,
  createExtractedRequest,
  findContainingFunction,
  getEffectiveIterationsForFunction,
  createResolutionContext,
  isValidUrlNode,
  resolveValueSingle,
  type ResolutionContext,
} from './extractRequest';
import type { TrackedVariableMap } from './types';

// axios methods that map directly to an HTTP verb.
// `request` takes a config object as its only argument (like axios(config)).
const AXIOS_METHODS = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request',
]);
const AXIOS_BODY_METHODS = new Set(['post', 'put', 'patch']);

/**
 * Per-run map of axios instance identifier -> resolved instance config.
 * Populated by collectAxiosInstances() for `const api = axios.create({ baseURL, headers })`
 * style instances so that relative URLs in `api.get('/users')` can be joined onto baseURL.
 */
type AxiosInstanceConfig = AxiosInstanceState;

function axiosInstances(): Map<string, AxiosInstanceConfig> {
  return getEngineState().axiosInstances;
}

export function clearAxiosInstances(): void {
  axiosInstances().clear();
}

/**
 * Join an axios instance baseURL with a (possibly relative) request URL.
 * Absolute and protocol-relative URLs are returned unchanged.
 */
function joinBaseURL(baseURL: string, url: string): string {
  if (!baseURL) return url;
  if (!url) return baseURL;
  // Absolute or protocol-relative URL: ignore baseURL.
  if (/^https?:\/\//i.test(url) || url.startsWith('//')) return url;
  const left = baseURL.replace(/\/+$/, '');
  const right = url.replace(/^\/+/, '');
  return `${left}/${right}`;
}

/**
 * Detect `X.create(configObject)` callee shape used by axios instance factories.
 * Matches the global `axios.create(...)` as well as minified/aliased forms like
 * `r.default.create(...)` as long as the config object carries a baseURL.
 */
function isAxiosCreateCall(node: t.CallExpression): { isAxios: boolean; requireBaseURL: boolean } | null {
  const callee = node.callee;
  if (!t.isMemberExpression(callee) || !t.isIdentifier(callee.property)) return null;
  if (callee.property.name !== 'create') return null;

  // `axios.create(...)` — definitely axios, baseURL optional.
  if (t.isIdentifier(callee.object) && callee.object.name === 'axios') {
    return { isAxios: true, requireBaseURL: false };
  }
  // Aliased `<something>.create(...)` — only treat as axios when the config
  // object has a baseURL, to avoid matching unrelated `.create()` factories.
  return { isAxios: true, requireBaseURL: true };
}

/**
 * Scan the AST for axios instances created via `axios.create({...})` and record
 * their baseURL / default headers keyed by the instance identifier name.
 *
 * Runs as a pre-pass (mirrors buildFunctionMap) because the request-pattern stage
 * is a single noScope traversal where instance creation may be visited after use.
 */
export function collectAxiosInstances(
  ast: ParseResult<t.File> | null,
  trackedVars: TrackedVariableMap,
): void {
  if (!ast) return;

  const record = (name: string, configArg: t.Node | undefined, requireBaseURL: boolean) => {
    let baseURL = '';
    let headers: string[] = [];
    if (configArg && t.isObjectExpression(configArg)) {
      const baseURLNode = findProperty(configArg, 'baseURL') ?? findProperty(configArg, 'baseUrl');
      if (baseURLNode) {
        baseURL = resolveValueSingle(baseURLNode, trackedVars);
      }
      const headersNode = findProperty(configArg, 'headers');
      if (headersNode) {
        headers = extractHeaders(headersNode, trackedVars);
      }
    }
    if (requireBaseURL && !baseURL) return;
    axiosInstances().set(name, { baseURL, headers });
  };

  traverse(ast, {
    noScope: true,
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!t.isIdentifier(id) || !init || !t.isCallExpression(init)) return;
      const info = isAxiosCreateCall(init);
      if (!info) return;
      record(id.name, init.arguments[0], info.requireBaseURL);
    },
    AssignmentExpression(path) {
      const { left, right } = path.node;
      if (!t.isIdentifier(left) || !t.isCallExpression(right)) return;
      const info = isAxiosCreateCall(right);
      if (!info) return;
      record(left.name, right.arguments[0], info.requireBaseURL);
    },
  } as TraverseOptions);
}

/**
 * Resolve the instance config for an axios method call's receiver object.
 * Returns the global axios marker (empty config) for `axios.get(...)`.
 */
function resolveReceiver(objectNode: t.Node): AxiosInstanceConfig | null {
  if (t.isIdentifier(objectNode)) {
    if (objectNode.name === 'axios') return { baseURL: '', headers: [] };
    return axiosInstances().get(objectNode.name) ?? null;
  }
  return null;
}

/**
 * Emit a request from a resolved set of fields, applying baseURL join and
 * instance default headers. Splits multi-valued URLs (from conditionals).
 */
function emitFromUrlNode(args: {
  analysisContext: AnalysisContext;
  urlNode: t.Node | null | undefined;
  method: string;
  instance: AxiosInstanceConfig;
  configObj?: t.ObjectExpression;
  dataNode?: t.Node | null;
  path: NodePath;
  trackedVars: TrackedVariableMap;
  context?: ResolutionContext;
}): void {
  const { analysisContext, urlNode, method, instance, configObj, dataNode, path, trackedVars, context } = args;

  // Per-call baseURL on the config object overrides the instance baseURL.
  let baseURL = instance.baseURL;
  if (configObj) {
    const cfgBase = findProperty(configObj, 'baseURL') ?? findProperty(configObj, 'baseUrl');
    if (cfgBase) {
      const resolved = resolveValueSingle(cfgBase, trackedVars, context);
      if (resolved) baseURL = resolved;
    }
  }

  const headersNode = configObj ? findProperty(configObj, 'headers') : null;
  const paramsNode = configObj ? findProperty(configObj, 'params') : null;
  const isBodyMethod = AXIOS_BODY_METHODS.has(method.toLowerCase());

  const urlResults = extractURL(urlNode, trackedVars, context);
  for (const { url, queryParams } of urlResults) {
    const joined = joinBaseURL(baseURL, url);

    let params = queryParams;
    if (paramsNode) {
      params = mergeParams(params, objectToKeyValueWithNestedJSON(paramsNode, trackedVars, path, context));
    }

    const headers = headersNode ? extractHeaders(headersNode, trackedVars, context) : [];
    const cookies = headersNode ? extractCookies(headersNode, trackedVars, context) : [];
    // Prepend instance default headers (call-level headers take precedence at replay time).
    const mergedHeaders = instance.headers.length ? [...instance.headers, ...headers] : headers;

    let body = '';
    if (isBodyMethod) {
      if (dataNode) {
        body = extractBody(dataNode, trackedVars, path, context);
      } else if (configObj) {
        const dataProp = findProperty(configObj, 'data');
        if (dataProp) body = extractBody(dataProp, trackedVars, path, context);
      }
    }

    appendExtractedRequest(analysisContext, createExtractedRequest({
      url: joined,
      method: method.toUpperCase(),
      params,
      body,
      headers: mergedHeaders,
      cookies,
    }), {
      extractor: 'axios', client: 'axios', confidence: 'high',
      node: path.node, functionName: context?.currentFunction,
    });
  }
}

export function createAxiosRequestTransform(
  analysisContext: AnalysisContext,
  ast: ParseResult<t.File> | null = null,
  sourceCode: string = '',
): Transform {
  return {
    name: 'axiosRequest',
    tags: ['safe'],
    visitor() {
      // Build the instance map once, before walking call sites.
      const trackedVars = getTrackedVariablesMap();
      collectAxiosInstances(ast, trackedVars);

      return {
        CallExpression: {
          exit(path) {
            const node = path.node;

            const currentFunction = findContainingFunction(path);
            const effectiveIterations = getEffectiveIterationsForFunction(currentFunction);

            // Form A: axios(config) or axios(url, config)
            if (t.isIdentifier(node.callee) && node.callee.name === 'axios') {
              const arg0 = node.arguments[0];
              const arg1 = node.arguments[1];
              analysisContext.claimRequestNode(node);

              if (analysisContext.has('requestEvidence')) {
                appendPattern(analysisContext, () => tracebackVariables(path, [], { ast, sourceCode, sourceLines: analysisContext.sourceLines }), 'axiosRequest', path.node);
              }

              for (const iteration of effectiveIterations) {
                const context = createResolutionContext(currentFunction, iteration, path);

                if (t.isObjectExpression(arg0)) {
                  // axios({ url, method, params, data, headers, baseURL })
                  const urlNode = findProperty(arg0, 'url');
                  if (!urlNode || !isValidUrlNode(urlNode)) continue;
                  const method = extractProperty(arg0, 'method', trackedVars, context) || 'GET';
                  emitFromUrlNode({
                    analysisContext, urlNode, method, instance: { baseURL: '', headers: [] },
                    configObj: arg0, path, trackedVars, context,
                  });
                } else if (isValidUrlNode(arg0)) {
                  // axios(url, config)
                  const configObj = t.isObjectExpression(arg1) ? arg1 : undefined;
                  const method = configObj
                    ? extractProperty(configObj, 'method', trackedVars, context) || 'GET'
                    : 'GET';
                  emitFromUrlNode({
                    analysisContext, urlNode: arg0, method, instance: { baseURL: '', headers: [] },
                    configObj, path, trackedVars, context,
                  });
                }
              }
              return;
            }

            // Form B/C: axios.METHOD(...) or instance.METHOD(...)
            if (t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.property)) {
              const method = node.callee.property.name;
              if (!AXIOS_METHODS.has(method.toLowerCase())) return;

              const instance = resolveReceiver(node.callee.object);
              if (!instance) return; // not axios global and not a known instance
              analysisContext.claimRequestNode(node);

              if (analysisContext.has('requestEvidence')) {
                appendPattern(analysisContext, () => tracebackVariables(path, [], { ast, sourceCode, sourceLines: analysisContext.sourceLines }), 'axiosRequest', path.node);
              }

              for (const iteration of effectiveIterations) {
                const context = createResolutionContext(currentFunction, iteration, path);

                if (method.toLowerCase() === 'request') {
                  // instance.request(config)
                  const cfg = node.arguments[0];
                  if (!t.isObjectExpression(cfg)) continue;
                  const urlNode = findProperty(cfg, 'url');
                  if (!urlNode || !isValidUrlNode(urlNode)) continue;
                  const reqMethod = extractProperty(cfg, 'method', trackedVars, context) || 'GET';
                  emitFromUrlNode({ analysisContext, urlNode, method: reqMethod, instance, configObj: cfg, path, trackedVars, context });
                  continue;
                }

                const urlNode = node.arguments[0];
                if (!isValidUrlNode(urlNode)) continue;

                if (AXIOS_BODY_METHODS.has(method.toLowerCase())) {
                  // axios.post(url, data, config)
                  const dataNode = node.arguments[1] && !t.isFunction(node.arguments[1])
                    ? node.arguments[1] : null;
                  const configObj = t.isObjectExpression(node.arguments[2]) ? node.arguments[2] : undefined;
                  emitFromUrlNode({ analysisContext, urlNode, method, instance, configObj, dataNode, path, trackedVars, context });
                } else {
                  // axios.get(url, config) / delete / head / options
                  const configObj = t.isObjectExpression(node.arguments[1]) ? node.arguments[1] : undefined;
                  emitFromUrlNode({ analysisContext, urlNode, method, instance, configObj, path, trackedVars, context });
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
