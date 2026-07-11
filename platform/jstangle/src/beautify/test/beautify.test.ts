import { describe, expect, test } from 'vitest';
import { beautifyBundle, looksWorthBeautifying } from '..';
import { jstangle } from '../../index';

// A minified webpack-5 bundle with a couple of fetch endpoints.
const WEBPACK5 =
  '(()=>{"use strict";var e={100:(e,t,r)=>{const n=r(200);' +
  't.listUsers=function(){return fetch(n.base+"/users",{method:"GET"}).then(x=>x.json())};' +
  't.createUser=function(u){return fetch(n.base+"/users",{method:"POST",body:JSON.stringify(u)})};' +
  't.deleteUser=function(id){return fetch(n.base+"/users/"+id,{method:"DELETE"})}},' +
  '200:(e,t)=>{t.base="/api/v3";t.timeout=3e4;t.headers={"X-Api":"1"}},' +
  '300:(e,t,r)=>{const n=r(200);t.listPosts=function(p){return fetch(n.base+"/posts?page="+p)}}},t={};' +
  'function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};' +
  'return e[n](o,o.exports,r),o.exports}r.n=e=>e;var n=r(100),s=r(300);console.log(n,s)})();';

// A minified but NOT bundled script (long single line), still worth unminifying.
// Kept comfortably over the ~500-char worth-beautifying gate.
const MINIFIED_PLAIN =
  'function a(x){return x*2}function b(y){return y+1}var c=[];for(var i=0;i<50;i++){c.push(a(i)+b(i))}' +
  'var d=c.filter(function(v){return v>10}).map(function(v){return v-1}).reduce(function(p,q){return p+q},0);' +
  'console.log(d);var e=function(t){return t?"yes":"no"};window.result=e(d>100);' +
  'var f={g:function(){return 1},h:function(){return 2},i:function(){return 3}};console.log(f.g()+f.h()+f.i());' +
  'function scale(list,factor){return list.map(function(v){return v*factor})}var g=scale(c,3);' +
  'var h=g.reduce(function(p,q){return p+q},0);console.log(h);window.scaled=h;' +
  'var config={retries:3,timeout:30000,verbose:false,tags:["a","b","c"]};console.log(config.retries+config.timeout);';

describe('looksWorthBeautifying', () => {
  test('rejects tiny scripts', () => {
    expect(looksWorthBeautifying('var x = 1;')).toBe(false);
  });

  test('rejects short, already-readable scripts', () => {
    expect(looksWorthBeautifying('function ok() {\n  return 1;\n}\n')).toBe(false);
  });

  test('accepts a long minified single line', () => {
    expect(looksWorthBeautifying(MINIFIED_PLAIN)).toBe(true);
  });

  test('accepts anything with bundle markers', () => {
    const code = '(function(){ __webpack_require__(3); })();' + ' //x'.repeat(200);
    expect(looksWorthBeautifying(code)).toBe(true);
  });

  test('accepts a Next.js flight marker payload', () => {
    expect(looksWorthBeautifying('self.__next_f.push([1,"x"]);' + 'z'.repeat(600))).toBe(true);
  });
});

describe('beautifyBundle', () => {
  test('unpacks a webpack bundle into module-annotated source', async () => {
    const res = await beautifyBundle(WEBPACK5);
    expect(res.format).toBe('webpack');
    expect(res.moduleCount).toBeGreaterThanOrEqual(3);
    expect(res.changed).toBe(true);
    // Recovered module paths are exposed for evidence.
    expect(res.modulePaths.length).toBe(res.moduleCount);
    expect(res.modulePaths.some((p) => p.endsWith('.js'))).toBe(true);
    // The document is module-annotated and multi-line (unminified).
    expect(res.content).toContain('// =====');
    expect(res.content).toContain('fetch');
    expect(res.content.split('\n').length).toBeGreaterThan(10);
  });

  test('unminifies a non-bundled script (format none, no modules)', async () => {
    const res = await beautifyBundle(MINIFIED_PLAIN);
    expect(res.format).toBe('none');
    expect(res.moduleCount).toBe(0);
    expect(res.modulePaths).toEqual([]);
    expect(res.changed).toBe(true);
    // Unminified: the single input line becomes several output lines.
    expect(res.content.split('\n').length).toBeGreaterThan(5);
  });

  test('is idempotent: re-beautifying its own output is a no-op', async () => {
    const first = await beautifyBundle(MINIFIED_PLAIN);
    expect(first.changed).toBe(true);
    // Feeding the already-unminified output back through must be stable.
    const second = await beautifyBundle(first.content);
    expect(second.changed).toBe(false);
  });

  test('every recovered module path appears in the assembled document', async () => {
    const res = await beautifyBundle(WEBPACK5);
    for (const p of res.modulePaths) {
      expect(res.content).toContain(p);
    }
  });
});

describe('jstangle() with beautify option', () => {
  test('emits a beautified result alongside extracted requests', async () => {
    const res = await jstangle(WEBPACK5, { beautify: true });
    // Requests are still extracted.
    expect(res.extractedRequests.length).toBeGreaterThan(0);
    // Beautified document is attached.
    expect(res.beautified).toBeDefined();
    expect(res.beautified?.format).toBe('webpack');
    expect(res.beautified?.moduleCount).toBeGreaterThanOrEqual(3);
  });

  test('omits beautified output when the option is off', async () => {
    const res = await jstangle(WEBPACK5);
    expect(res.beautified).toBeUndefined();
  });

  test('omits beautified output for scripts not worth beautifying', async () => {
    const res = await jstangle('var api = "/api/x"; fetch(api);', { beautify: true });
    expect(res.beautified).toBeUndefined();
  });
});
