import { describe, expect, test } from 'vitest';
import { jstangle } from '../index';

// Minified webpack-5 bundle (same shape as the beautify fixture): base URL lives
// in module 200, endpoints in modules 100 and 300.
const WEBPACK5 =
  '(()=>{"use strict";var e={100:(e,t,r)=>{const n=r(200);' +
  't.listUsers=function(){return fetch(n.base+"/users",{method:"GET"}).then(x=>x.json())};' +
  't.createUser=function(u){return fetch(n.base+"/users",{method:"POST",body:JSON.stringify(u)})};' +
  't.deleteUser=function(id){return fetch(n.base+"/users/"+id,{method:"DELETE"})}},' +
  '200:(e,t)=>{t.base="/api/v3";t.timeout=3e4;t.headers={"X-Api":"1"}},' +
  '300:(e,t,r)=>{const n=r(200);t.listPosts=function(p){return fetch(n.base+"/posts?page="+p)}}},t={};' +
  'function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};' +
  'return e[n](o,o.exports,r),o.exports}r.n=e=>e;var n=r(100),s=r(300);console.log(n,s)})();';

function urls(res: Awaited<ReturnType<typeof jstangle>>): string[] {
  return res.extractedRequests.map((r) => r.url);
}

describe('bundle module re-scan (unpackModules)', () => {
  test('extracts endpoints from unpacked modules', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints', unpackModules: true });
    const found = urls(res);
    expect(found.some((u) => u.includes('/users'))).toBe(true);
    expect(found.some((u) => u.includes('/posts'))).toBe(true);
  });

  test('stamps module-path provenance on re-scanned endpoints', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints', unpackModules: true });
    const origins = res.analysisContext.requestOrigins;
    // Provenance uses the stable `bundle-module` extractor plus a structured modulePath.
    expect(origins.some((o) => o.extractors.includes('bundle-module'))).toBe(true);
    expect(origins.some((o) => !!o.provenance.modulePath)).toBe(true);
  });

  test('does not run the module scan when the option is off', async () => {
    const res = await jstangle(WEBPACK5, { profile: 'endpoints' });
    const origins = res.analysisContext.requestOrigins;
    expect(origins.some((o) => o.extractors.includes('bundle-module'))).toBe(false);
    // Baseline extraction still works from the monolithic AST.
    expect(res.extractedRequests.length).toBeGreaterThan(0);
  });

  test('is a no-op for non-bundle scripts even when enabled', async () => {
    const res = await jstangle('fetch("/api/plain");', {
      profile: 'endpoints',
      unpackModules: true,
    });
    // No bundle → no module provenance, but the plain endpoint is still found.
    const origins = res.analysisContext.requestOrigins;
    expect(origins.some((o) => o.extractors.includes('bundle-module'))).toBe(false);
    expect(urls(res).some((u) => u.includes('/api/plain'))).toBe(true);
  });
});
