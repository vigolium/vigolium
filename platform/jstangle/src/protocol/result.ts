import { createHash } from 'node:crypto';
import type { AnalysisContext, RequestOrigin } from '../context';
import type { JstangleResult } from '../index';
import type { ExtractedRequest } from '../requestpattern/types';
import { getCapabilities } from './capabilities';
import {
  RESULT_SCHEMA_VERSION,
  type AnalysisRecord,
  type AnalysisResultV2,
  type ArtifactDescriptor,
  type BodyTemplate,
  type DomFlowFact,
  type FieldTemplate,
  type HeaderTemplate,
  type HttpRequestFact,
  type SourceDescriptor,
  type ValueTemplate,
} from './types';

const TEMPLATE_VARIABLE = /\$\{([^}]+)\}/g;

export function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

export function valueTemplate(rendered: string, alternatives?: string[]): ValueTemplate {
  const variables = [...rendered.matchAll(TEMPLATE_VARIABLE)].map((match) => ({
    name: match[1],
    placeholder: match[0],
  }));
  const uniqueVariables = [...new Map(variables.map((variable) => [variable.placeholder, variable])).values()];
  const uniqueAlternatives = alternatives
    ? [...new Set(alternatives)].filter((value) => value !== rendered)
    : [];
  return {
    rendered,
    static: uniqueVariables.length === 0,
    variables: uniqueVariables,
    ...(uniqueAlternatives.length ? { alternatives: uniqueAlternatives } : {}),
  };
}

function decodeComponent(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

function fields(value: string): FieldTemplate[] {
  if (!value) return [];
  return value.split('&').filter(Boolean).map((part) => {
    const separator = part.indexOf('=');
    const name = separator === -1 ? part : part.slice(0, separator);
    const fieldValue = separator === -1 ? '' : part.slice(separator + 1);
    return {
      name: valueTemplate(decodeComponent(name)),
      value: valueTemplate(decodeComponent(fieldValue)),
    };
  });
}

function headers(values: string[]): HeaderTemplate[] {
  return values.map((header) => {
    const separator = header.indexOf(':');
    const name = (separator === -1 ? header : header.slice(0, separator)).trim();
    const value = (separator === -1 ? '' : header.slice(separator + 1)).trim();
    return {
      name: valueTemplate(name),
      value: valueTemplate(value),
      ...( /^(authorization|proxy-authorization|x-api-key)$/i.test(name) ? { sensitive: true } : {}),
    };
  });
}

function bodyTemplate(body: string, headerValues: string[], alternatives?: string[]): BodyTemplate | undefined {
  if (!body) return undefined;
  const contentTypeHeader = headerValues.find((header) => /^content-type\s*:/i.test(header));
  const contentType = contentTypeHeader?.slice(contentTypeHeader.indexOf(':') + 1).trim();
  let kind: BodyTemplate['kind'] = 'text';
  if (contentType?.includes('json') || /^[\[{]/.test(body.trim())) kind = 'json';
  else if (contentType?.includes('x-www-form-urlencoded') || /^[^=&]+=[^&]*(?:&|$)/.test(body)) kind = 'form';
  else if (body.includes('${unknown}')) kind = 'unknown';
  return {
    kind,
    value: valueTemplate(body, alternatives),
    ...(contentType ? { contentType } : {}),
  };
}

function requestFact(request: ExtractedRequest, origin: RequestOrigin, sourceHash: string): HttpRequestFact {
  const identity = [request.url, request.method.toUpperCase(), request.params, request.body, sourceHash].join('|');
  return {
    kind: 'httpRequest',
    id: `http-${sha256(identity).slice(0, 20)}`,
    url: valueTemplate(request.url, origin.alternatives.url),
    method: valueTemplate(request.method.toUpperCase(), origin.alternatives.method),
    query: fields(request.params),
    ...(origin.alternatives.params.length
      ? { queryAlternatives: origin.alternatives.params.map((value) => valueTemplate(value)) }
      : {}),
    headers: headers(request.headers),
    cookies: fields(request.cookies.join('&')),
    ...(bodyTemplate(request.body, request.headers, origin.alternatives.body)
      ? { body: bodyTemplate(request.body, request.headers, origin.alternatives.body) }
      : {}),
    client: origin.client,
    provenance: origin.provenance,
    ...(origin.extractors.length > 1 ? { alternateExtractors: origin.extractors.filter((name) => name !== origin.provenance.extractor) } : {}),
  };
}

function domFact(flow: JstangleResult['domFlows'][number], sourceHash: string): DomFlowFact {
  const line = Math.max(0, flow.line || 0);
  return {
    kind: 'domFlow',
    id: `dom-${sha256([flow.source, flow.sink, line, sourceHash].join('|')).slice(0, 20)}`,
    source: flow.source,
    sink: flow.sink,
    snippet: flow.snippet,
    line,
    confidence: flow.confidence,
    provenance: {
      extractor: 'dom-taint-v2',
      confidence: flow.confidence,
      ...(line ? { start: { line } } : {}),
      evidence: flow.snippet,
    },
    path: flow.path,
    flowType: flow.flowType,
  };
}

export interface ResultEnvelopeOptions {
  sourceUrl?: string;
  filename?: string;
  mediaType?: string;
  artifacts?: ArtifactDescriptor[];
}

export function buildAnalysisResultV2(
  result: JstangleResult,
  context: AnalysisContext,
  options: ResultEnvelopeOptions = {},
): AnalysisResultV2 {
  const capabilities = getCapabilities();
  const contentSha256 = sha256(context.source);
  const source: SourceDescriptor = {
    contentSha256,
    byteLength: Buffer.byteLength(context.source),
    ...(options.sourceUrl ? { url: options.sourceUrl } : {}),
    ...(options.filename ? { filename: options.filename } : {}),
    ...(options.mediaType ? { mediaType: options.mediaType } : {}),
    ...(result.beautified?.format && result.beautified.format !== 'none'
      ? { bundleFormat: result.beautified.format }
      : {}),
  };
  const records: AnalysisRecord[] = [
    ...result.extractedRequests.map((request, index) =>
      requestFact(request, context.requestOrigins[index] ?? context.defaultOrigin(), contentSha256)),
    ...result.domFlows.map((flow) => domFact(flow, contentSha256)),
    ...result.assetReferences,
    ...result.graphqlOperations,
    ...result.webSockets,
    ...result.eventSources,
    ...result.clientRoutes,
    ...result.browserSecurityFlows,
  ];
  return {
    type: 'analysisResult',
    schemaVersion: RESULT_SCHEMA_VERSION,
    jobId: context.scanId,
    profile: context.profile,
    tool: {
      version: capabilities.toolVersion,
      sourceHash: capabilities.sourceHash,
    },
    source,
    stats: {
      status: result.status,
      inputBytes: source.byteLength,
      durationMs: performance.now() - context.startedAt,
      recordCounts: {
        httpRequest: result.extractedRequests.length,
        domFlow: result.domFlows.length,
        assetReference: result.assetReferences.length,
        graphqlOperation: result.graphqlOperations.length,
        websocket: result.webSockets.length,
        eventSource: result.eventSources.length,
        clientRoute: result.clientRoutes.length,
        browserSecurityFlow: result.browserSecurityFlows.length,
      },
      stageMetrics: result.stageMetrics,
    },
    diagnostics: result.diagnostics,
    records,
    artifacts: options.artifacts ?? [],
  };
}
