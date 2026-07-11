import { describe, expect, test } from 'vitest';
import { jstangle } from '../index';
import { buildAnalysisResultV2 } from '../protocol';

const fixture = `
  const value = location.hash;
  document.body.innerHTML = value;
  fetch('/api/users?role=admin');
`;

describe('analysis profiles and isolation', () => {
  test('endpoints executes no DOM, generator, beautify, or evidence stages', async () => {
    const result = await jstangle(fixture, { profile: 'endpoints' });
    expect(result.extractedRequests).toHaveLength(1);
    expect(result.domFlows).toHaveLength(0);
    expect(result.code).toBe('');
    expect(result.requestPatterns).toHaveLength(0);
    expect(result.stageMetrics.find((metric) => metric.stage === 'domFlows')?.status).toBe('skipped');
    expect(result.stageMetrics.find((metric) => metric.stage === 'generateCode')?.status).toBe('skipped');
  });

  test('dom-security executes no endpoint or generator stages', async () => {
    const result = await jstangle(fixture, { profile: 'dom-security' });
    expect(result.extractedRequests).toHaveLength(0);
    expect(result.domFlows).toHaveLength(1);
    expect(result.code).toBe('');
    expect(result.stageMetrics.find((metric) => metric.stage === 'requestClients')?.status).toBe('skipped');
  });

  test('discovery-lite retains typed intelligence but skips transformed code', async () => {
    const result = await jstangle(`
      fetch('/api/users');
      import('./lazy.js');
      const Q = gql\`query Q { viewer { id } }\`;
    `, { profile: 'discovery-lite' });
    expect(result.extractedRequests).toHaveLength(1);
    expect(result.assetReferences.some((fact) => fact.url.rendered === './lazy.js')).toBe(true);
    expect(result.graphqlOperations).toHaveLength(1);
    expect(result.code).toBe('');
    expect(result.stageMetrics.find((metric) => metric.stage === 'generateCode')?.status).toBe('skipped');
  });

  test('focused profile records are strict subsets of full', async () => {
    const [full, endpoints, dom] = await Promise.all([
      jstangle(fixture, { profile: 'full' }),
      jstangle(fixture, { profile: 'endpoints' }),
      jstangle(fixture, { profile: 'dom-security' }),
    ]);
    expect(endpoints.extractedRequests).toEqual(full.extractedRequests);
    expect(dom.domFlows).toEqual(full.domFlows);
    expect(endpoints.domFlows).toHaveLength(0);
    expect(dom.extractedRequests).toHaveLength(0);
  });

  test('preserves distinct query parameter variants', async () => {
    const result = await jstangle(
      `fetch('/api/users?a=1'); fetch('/api/users?b=2')`,
      { profile: 'endpoints' },
    );
    expect(result.extractedRequests.map((request) => request.params)).toEqual(['a=1', 'b=2']);
  });

  test('builds expensive request evidence only after candidate deduplication', async () => {
    const result = await jstangle(`fetch('/api/same'); fetch('/api/same');`, { profile: 'inspect' });
    expect(result.extractedRequests).toHaveLength(1);
    expect(result.analysisContext.evidenceBuilds).toBe(1);
    expect(result.requestPatterns).toHaveLength(1);
  });

  test('curated high-confidence precision gate rejects UI/documentation strings', async () => {
    const result = await jstangle(`
      fetch('/api/real-one');
      const xhr = new XMLHttpRequest(); xhr.open('POST', '/api/real-two'); xhr.send('{}');
      console.warn('Example: GET /api/docs-only');
      renderIcon({url:'/api/not-a-request.svg', path:'/api/component-prop'});
      Promise.resolve('/api/promise-value');
      builder.post('/api/lookalike-builder', {value:1});
    `, { profile: 'endpoints' });
    const highConfidence = result.extractedRequests.filter((_, index) =>
      result.analysisContext.requestOrigins[index]?.provenance.confidence === 'high');
    const truePositives = highConfidence.filter((request) =>
      request.url === '/api/real-one' || request.url === '/api/real-two').length;
    const falsePositives = highConfidence.length - truePositives;
    const precision = truePositives / Math.max(1, truePositives + falsePositives);
    expect(truePositives).toBe(2);
    expect(precision).toBeGreaterThanOrEqual(0.98);
  });

  test('concurrent calls do not contaminate endpoint results', async () => {
    const [alpha, beta] = await Promise.all([
      jstangle(`fetch('/api/alpha')`, { profile: 'endpoints' }),
      jstangle(`fetch('/api/beta')`, { profile: 'endpoints' }),
    ]);
    expect(alpha.extractedRequests.map((request) => request.url)).toEqual(['/api/alpha']);
    expect(beta.extractedRequests.map((request) => request.url)).toEqual(['/api/beta']);
  });

  test('state remains isolated when concurrent scans yield between every stage', async () => {
    const yieldStage = async () => new Promise<void>((resolve) => queueMicrotask(resolve));
    const [alpha, beta] = await Promise.all([
      jstangle(`const API_URL='/api/alpha'; fetch(API_URL)`, { profile: 'endpoints', onStageComplete: yieldStage }),
      jstangle(`const API_URL='/api/beta'; fetch(API_URL)`, { profile: 'endpoints', onStageComplete: yieldStage }),
    ]);
    expect(alpha.extractedRequests.map((request) => request.url)).toEqual(['/api/alpha']);
    expect(beta.extractedRequests.map((request) => request.url)).toEqual(['/api/beta']);
  });

  test('parse failures become explicit failed diagnostics', async () => {
    const result = await jstangle('function broken( {', { profile: 'endpoints' });
    expect(result.status).toBe('failed');
    expect(result.diagnostics.some((diagnostic) => diagnostic.code === 'parse_unrecoverable')).toBe(true);
  });

  test('AST node limits stop expensive stages with an explicit diagnostic', async () => {
    const result = await jstangle(`const values = [1, 2, 3, 4, 5]; fetch('/api');`, {
      profile: 'endpoints', limits: { maxAstNodes: 5 },
    });
    expect(result.status).toBe('failed');
    expect(result.diagnostics.some((diagnostic) => diagnostic.code === 'ast_node_limit_reached')).toBe(true);
    expect(result.stageMetrics.find((metric) => metric.stage === 'requestClients')?.status).toBe('skipped');
  });

  test('v2 envelope carries typed templates, source, confidence, and provenance', async () => {
    const source = `fetch('/api/users/' + userId, {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({name})});`;
    const result = await jstangle(source, {
      profile: 'endpoints',
      scanId: 'typed-contract',
      sourceUrl: 'https://app.example/static/app.js',
      filename: 'app.js',
      mediaType: 'application/javascript',
    });
    const envelope = buildAnalysisResultV2(result, result.analysisContext, {
      sourceUrl: 'https://app.example/static/app.js',
      filename: 'app.js',
      mediaType: 'application/javascript',
    });
    expect(envelope.schemaVersion).toBe(2);
    expect(envelope.source.url).toBe('https://app.example/static/app.js');
    expect(envelope.source.contentSha256).toMatch(/^[a-f0-9]{64}$/);
    const fact = envelope.records.find((record) => record.kind === 'httpRequest');
    expect(fact?.kind).toBe('httpRequest');
    if (!fact || fact.kind !== 'httpRequest') throw new Error('missing HTTP fact');
    expect(fact.client).toBe('fetch');
    expect(fact.provenance.extractor).toBe('fetch');
    expect(fact.provenance.confidence).toBe('high');
    expect(fact.url.static).toBe(false);
    expect(fact.url.variables.length).toBeGreaterThan(0);
    expect(fact.body?.kind).toBe('json');
  });
});
