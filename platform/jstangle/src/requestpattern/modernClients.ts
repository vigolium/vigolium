import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import type { Transform } from '../ast-utils';
import { traverse, type NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import { appendExtractedRequest } from './utils';
import { getTrackedVariablesMap } from './globalVariableTracking';
import {
  createExtractedRequest,
  createResolutionContext,
  extractBody,
  extractHeaders,
  extractProperty,
  extractURL,
  findContainingFunction,
  findProperty,
  getEffectiveIterationsForFunction,
  objectToKeyValueWithNestedJSON,
  resolveValueSingle,
} from './extractRequest';
import type { HttpClientKind } from '../protocol';

interface ClientInstance {
  client: HttpClientKind;
  baseURL: string;
  headers: string[];
}

interface SuperAgentChain {
  method: string;
  url: t.Node;
  bodies: t.Node[];
  queries: t.Node[];
  headerCalls: t.CallExpression[];
}

const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
const BODY_METHODS = new Set(['post', 'put', 'patch']);

function memberName(node: t.Node): { receiver: string; method: string } | undefined {
  if (!t.isMemberExpression(node) || !t.isIdentifier(node.property)) return undefined;
  const receiver = t.isIdentifier(node.object) ? node.object.name : '';
  return receiver ? { receiver, method: node.property.name } : undefined;
}

function callName(node: t.CallExpression['callee']): string {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) && t.isIdentifier(node.property)) return node.property.name;
  return '';
}

function joinBase(baseURL: string, requestURL: string): string {
  if (!baseURL || /^(?:https?:)?\/\//i.test(requestURL)) return requestURL;
  return `${baseURL.replace(/\/+$/, '')}/${requestURL.replace(/^\/+/, '')}`;
}

function configObject(node: t.Node | null | undefined): t.ObjectExpression | undefined {
  return t.isObjectExpression(node) ? node : undefined;
}

function superAgentChain(node: t.Node): SuperAgentChain | undefined {
  if (!t.isCallExpression(node) || !t.isMemberExpression(node.callee) || !t.isIdentifier(node.callee.property)) return undefined;
  const method = node.callee.property.name.toLowerCase();
  if (METHODS.has(method) && t.isIdentifier(node.callee.object) && /^(?:superagent|request)$/i.test(node.callee.object.name)) {
    const url = node.arguments[0];
    return url && !t.isSpreadElement(url)
      ? { method: method.toUpperCase(), url, bodies: [], queries: [], headerCalls: [] }
      : undefined;
  }
  if (!t.isCallExpression(node.callee.object)) return undefined;
  const chain = superAgentChain(node.callee.object);
  if (!chain) return undefined;
  const argument = node.arguments[0];
  if (method === 'send' && argument && !t.isSpreadElement(argument)) chain.bodies.push(argument);
  if (method === 'query' && argument && !t.isSpreadElement(argument)) chain.queries.push(argument);
  if (method === 'set') chain.headerCalls.push(node);
  return chain;
}

function isSuperAgentChainChild(path: NodePath<t.CallExpression>): boolean {
  return path.parentPath?.isMemberExpression() && path.parentPath.node.object === path.node &&
    path.parentPath.parentPath?.isCallExpression() === true;
}

export function createModernClientTransform(
  analysisContext: AnalysisContext,
  ast: ParseResult<t.File> | null,
  sourceCode: string,
): Transform {
  const detected = {
    ky: /(?:from\s*["']ky["']|require\(["']ky["']\)|\bky\.(?:create|extend|get|post)\b)/.test(sourceCode),
    ofetch: /(?:\bofetch\b|\$fetch\s*\()/.test(sourceCode),
    angular: /(?:HttpClient|@angular\/common\/http)/.test(sourceCode),
    superagent: /(?:\bsuperagent\b|from\s*["']superagent["'])/.test(sourceCode),
	openapi: /(?:\bOpenAPI\b|\bBASE_PATH\b|new\s+Configuration\s*\(|(?:openapi|swagger)[-_ ]generated)/i.test(sourceCode),
  };
  const enabled = Object.values(detected).some(Boolean);
  const instances = new Map<string, ClientInstance>();
	const angularDefaultHeaders: string[] = [];

  return {
    name: 'modernHttpClients', tags: ['safe'], scope: true,
    run() {
      if (!enabled || !ast) return;
      const tracked = getTrackedVariablesMap();
      traverse(ast, {
		CallExpression(path) {
		  if (!detected.angular || !t.isMemberExpression(path.node.callee) || !t.isIdentifier(path.node.callee.property, { name: 'clone' })) return;
		  const config = configObject(path.node.arguments[0] as t.Node);
		  const setHeaders = config && findProperty(config, 'setHeaders');
		  for (const header of setHeaders ? extractHeaders(setHeaders, tracked) : []) {
			if (!/^(?:authorization|cookie|x-api-key)\s*:/i.test(header) && !angularDefaultHeaders.includes(header)) angularDefaultHeaders.push(header);
		  }
		},
        VariableDeclarator(path) {
          if (!t.isIdentifier(path.node.id) || !t.isCallExpression(path.node.init)) return;
          const call = path.node.init;
          const callee = memberName(call.callee);
          if (!callee || (callee.method !== 'create' && callee.method !== 'extend')) return;
          let client: HttpClientKind | undefined;
          if (detected.ky && (callee.receiver === 'ky' || instances.get(callee.receiver)?.client === 'ky')) client = 'ky';
          if (detected.ofetch && (callee.receiver === 'ofetch' || callee.receiver === '$fetch')) client = 'ofetch';
          if (!client) return;
          const config = configObject(call.arguments[0] as t.Node);
          const baseNode = config && (findProperty(config, 'prefixUrl') ?? findProperty(config, 'baseURL') ?? findProperty(config, 'baseUrl'));
          const headersNode = config && findProperty(config, 'headers');
          instances.set(path.node.id.name, {
            client,
            baseURL: baseNode ? resolveValueSingle(baseNode, tracked) : instances.get(callee.receiver)?.baseURL ?? '',
            headers: headersNode ? extractHeaders(headersNode, tracked) : instances.get(callee.receiver)?.headers ?? [],
          });
        },
      });
    },
    visitor() {
      if (!enabled) return {};
      const tracked = getTrackedVariablesMap();
      return {
        CallExpression: {
          exit(path: NodePath<t.CallExpression>) {
            const call = path.node;
			if (detected.openapi && /^(?:request|requestRaw|sendRequest|callApi)$/i.test(callName(call.callee))) {
			  const config = configObject(call.arguments[0] as t.Node);
			  const urlNode = config && (findProperty(config, 'path') ?? findProperty(config, 'url'));
			  const methodNode = config && findProperty(config, 'method');
			  if (config && urlNode && methodNode) {
				const currentFunction = findContainingFunction(path);
				for (const iteration of getEffectiveIterationsForFunction(currentFunction)) {
				  const resolution = createResolutionContext(currentFunction, iteration, path);
				  const method = resolveValueSingle(methodNode, tracked, resolution).toUpperCase();
				  const baseNode = findProperty(config, 'basePath') ?? findProperty(config, 'baseURL') ?? findProperty(config, 'baseUrl');
				  const baseURL = baseNode ? resolveValueSingle(baseNode, tracked, resolution) : '';
				  const queryNode = findProperty(config, 'query') ?? findProperty(config, 'queryParameters') ?? findProperty(config, 'params');
				  const bodyNode = findProperty(config, 'body') ?? findProperty(config, 'data');
				  const headersNode = findProperty(config, 'headers') ?? findProperty(config, 'headerParameters');
				  const params = queryNode ? objectToKeyValueWithNestedJSON(queryNode, tracked, path, resolution) : '';
				  const headers = headersNode ? extractHeaders(headersNode, tracked, resolution) : [];
				  for (const extracted of extractURL(urlNode, tracked, resolution)) appendExtractedRequest(analysisContext, createExtractedRequest({
					url: joinBase(baseURL, extracted.url), method,
					params: [extracted.queryParams, params].filter(Boolean).join('&'),
					body: bodyNode ? extractBody(bodyNode, tracked, path, resolution) : '', headers,
				  }), {
					extractor: 'openapi-generated-adapter', client: 'openapi', confidence: 'high',
					node: path.node, functionName: currentFunction,
				  });
				}
				analysisContext.claimRequestNode(path.node);
				return;
			  }
			}
			if (detected.superagent) {
			  const chain = superAgentChain(call);
			  if (chain) {
				if (isSuperAgentChainChild(path)) return;
				const currentFunction = findContainingFunction(path);
				for (const iteration of getEffectiveIterationsForFunction(currentFunction)) {
				  const resolution = createResolutionContext(currentFunction, iteration, path);
				  const headers: string[] = [];
				  for (const headerCall of chain.headerCalls) {
					const first = headerCall.arguments[0];
					const second = headerCall.arguments[1];
					if (first && !t.isSpreadElement(first) && t.isObjectExpression(first)) headers.push(...extractHeaders(first, tracked, resolution));
					else if (first && second && !t.isSpreadElement(first) && !t.isSpreadElement(second)) {
					  headers.push(`${resolveValueSingle(first, tracked, resolution)}: ${resolveValueSingle(second, tracked, resolution)}`);
					}
				  }
				  const params = chain.queries.map((query) => objectToKeyValueWithNestedJSON(query, tracked, path, resolution)).filter(Boolean).join('&');
				  const body = chain.bodies[0] ? extractBody(chain.bodies[0], tracked, path, resolution) : '';
				  for (const extracted of extractURL(chain.url, tracked, resolution)) appendExtractedRequest(analysisContext, createExtractedRequest({
					url: extracted.url, method: chain.method, params: [extracted.queryParams, params].filter(Boolean).join('&'), body, headers,
				  }), {
					extractor: 'superagent-adapter', client: 'superagent', confidence: 'high', node: path.node, functionName: currentFunction,
				  });
				}
				analysisContext.claimRequestNode(path.node);
				return;
			  }
			}
            let client: HttpClientKind | undefined;
            let method = 'GET';
            let urlNode: t.Node | undefined;
            let bodyNode: t.Node | undefined;
            let options: t.ObjectExpression | undefined;
            let baseURL = '';
            let defaultHeaders: string[] = [];

            if (t.isIdentifier(call.callee) && detected.ofetch && (call.callee.name === 'ofetch' || call.callee.name === '$fetch')) {
              client = 'ofetch';
              urlNode = call.arguments[0] as t.Node;
              options = configObject(call.arguments[1] as t.Node);
            } else if (t.isIdentifier(call.callee) && detected.ky && call.callee.name === 'ky') {
              client = 'ky';
              urlNode = call.arguments[0] as t.Node;
              options = configObject(call.arguments[1] as t.Node);
            } else {
              const callee = memberName(call.callee);
              if (!callee || !METHODS.has(callee.method.toLowerCase())) return;
              const instance = instances.get(callee.receiver);
              if (instance) {
                ({ client, baseURL, headers: defaultHeaders } = instance);
              } else if (detected.ky && callee.receiver === 'ky') client = 'ky';
			  else if (detected.angular && /^(?:http|httpClient|client)$/i.test(callee.receiver)) {
				client = 'angular';
				defaultHeaders = angularDefaultHeaders;
			  }
              else if (detected.superagent && /^(?:superagent|request)$/i.test(callee.receiver)) client = 'superagent';
              else return;
              method = callee.method.toUpperCase();
              urlNode = call.arguments[0] as t.Node;
              if (client === 'angular' || client === 'superagent') {
                if (BODY_METHODS.has(callee.method.toLowerCase())) bodyNode = call.arguments[1] as t.Node;
                options = configObject(call.arguments[BODY_METHODS.has(callee.method.toLowerCase()) ? 2 : 1] as t.Node);
              } else {
                options = configObject(call.arguments[1] as t.Node);
              }
            }

            if (!client || !urlNode) return;
            const currentFunction = findContainingFunction(path);
            for (const iteration of getEffectiveIterationsForFunction(currentFunction)) {
              const resolution = createResolutionContext(currentFunction, iteration, path);
              if (options) {
                method = extractProperty(options, 'method', tracked, resolution).toUpperCase() || method;
                const configBase = findProperty(options, 'prefixUrl') ?? findProperty(options, 'baseURL') ?? findProperty(options, 'baseUrl');
                if (configBase) baseURL = resolveValueSingle(configBase, tracked, resolution);
                bodyNode ??= findProperty(options, 'json') ?? findProperty(options, 'body') ?? findProperty(options, 'data') ?? undefined;
              }
              const headersNode = options && findProperty(options, 'headers');
              const headers = [...defaultHeaders, ...(headersNode ? extractHeaders(headersNode, tracked, resolution) : [])];
              const paramsNode = options && (findProperty(options, 'searchParams') ?? findProperty(options, 'query') ?? findProperty(options, 'params'));
              const params = paramsNode ? objectToKeyValueWithNestedJSON(paramsNode, tracked, path, resolution) : '';
              for (const extracted of extractURL(urlNode, tracked, resolution)) {
                appendExtractedRequest(analysisContext, createExtractedRequest({
                  url: joinBase(baseURL, extracted.url), method,
                  params: [extracted.queryParams, params].filter(Boolean).join('&'),
                  body: bodyNode ? extractBody(bodyNode, tracked, path, resolution) : '',
                  headers: bodyNode && options && findProperty(options, 'json')
                    ? [...headers, 'Content-Type: application/json'] : headers,
                }), {
                  extractor: `${client}-adapter`, client, confidence: 'high', node: path.node, functionName: currentFunction,
                });
              }
            }
            analysisContext.claimRequestNode(path.node);
          },
        },
      };
    },
  } satisfies Transform;
}
