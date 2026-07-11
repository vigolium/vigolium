import { describe, expect, test } from 'vitest';
import { jstangle } from '../../index';

describe('asset reference extraction', () => {
  test('emits typed lazy chunks, workers, manifests, config, wasm, and source maps', async () => {
    const sourceUrl = 'https://example.test/assets/app.js';
    const source = `
      import './eager.js';
      export * from './reexport.js';
      import('./lazy.js');
      new Worker(new URL('./worker.js', import.meta.url));
      new SharedWorker('/shared.js');
      navigator.serviceWorker.register('./sw.js');
      importScripts('./inside-worker.js');
      workbox.precacheAndRoute([{url:'/precache.js', revision:'1'}]);
      fetch('/config.json');
      fetch('/module.wasm');
      script.src = '/runtime.js';
      //` + '# sourceMapping' + `URL=app.js.map
    `;
    const result = await jstangle(source, { profile: 'discovery', sourceUrl });

    const compact = result.assetReferences.map((fact) => [fact.assetType, fact.url.rendered]);
    expect(compact).toEqual(expect.arrayContaining([
      ['script', './eager.js'],
      ['script', './reexport.js'],
      ['dynamic-import', './lazy.js'],
      ['worker', './worker.js'],
      ['shared-worker', '/shared.js'],
      ['service-worker', './sw.js'],
      ['script', './inside-worker.js'],
      ['manifest', '/precache.js'],
      ['config', '/config.json'],
      ['wasm', '/module.wasm'],
      ['script', '/runtime.js'],
      ['source-map', 'app.js.map'],
    ]));
    expect(result.assetReferences.every((fact) => fact.parentSourceUrl === sourceUrl)).toBe(true);
    expect(result.assetReferences.every((fact) => fact.provenance.extractor.length > 0)).toBe(true);
  });

  test('marks inline source maps without copying their payload into the URL fact', async () => {
    const payload = Buffer.from(JSON.stringify({ version: 3, sources: [], mappings: '' })).toString('base64');
    const source = 'const x=1;\n//' + '# sourceMapping' + `URL=data:application/json;base64,${payload}`;
    const result = await jstangle(source, {
      profile: 'discovery', sourceUrl: 'https://example.test/app.js',
    });
    const map = result.assetReferences.find((fact) => fact.assetType === 'source-map');
    expect(map).toMatchObject({ inline: true, url: { rendered: 'inline:source-map' } });
    expect(JSON.stringify(map)).not.toContain(payload);
  });

  test('enforces the per-analysis asset reference budget', async () => {
    const result = await jstangle(`
      import('./one.js'); import('./two.js'); import('./three.js');
    `, { profile: 'discovery', limits: { maxAssetReferences: 2 } });
    expect(result.assetReferences).toHaveLength(2);
    expect(result.status).toBe('partial');
    expect(result.diagnostics.some((item) => item.code === 'asset_reference_limit_reached')).toBe(true);
  });
});
