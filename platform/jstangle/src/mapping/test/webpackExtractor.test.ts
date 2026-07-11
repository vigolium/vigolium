import { describe, expect, test, beforeEach } from 'vitest';
import { parse } from '@babel/parser';
import { readFile } from 'fs/promises';
import { join } from 'path';
import {
  extractWebpackFunctions,
  clearWebpackState,
  getWebpackModuleMap,
  getWebpackBundleState,
  resolveWebpackReference,
} from '../extractors/webpackExtractor';
import { createEmptyFunctionMap, clearFunctionMap } from '../functionMap';

const TESTDATA_DIR = join(__dirname, '../../../testdata');

describe('webpackExtractor', () => {
  beforeEach(() => {
    clearWebpackState();
    clearFunctionMap();
  });

  describe('Webpack 5 push pattern', () => {
    test('extracts modules from basic push pattern', () => {
      const code = `
        (self.webpackChunk=self.webpackChunk||[]).push([[178],{
          8947:(e,l,t)=>{
            t.d(l,{O:()=>n});
            const n={accountLogin:"/api/account/login",accountLogout:"/api/account/logout"};
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      expect(moduleMap.size).toBe(1);

      const mod8947 = moduleMap.get(8947);
      expect(mod8947).toBeDefined();
      expect(mod8947?.exports).toHaveLength(1);
      expect(mod8947?.exports[0].name).toBe('O');
      expect(mod8947?.exports[0].resolvedValue).toEqual({
        type: 'object',
        value: {
          accountLogin: '/api/account/login',
          accountLogout: '/api/account/logout',
        },
      });
    });

    test('extracts imports between modules', () => {
      const code = `
        (self.webpackChunk||[]).push([[178],{
          8947:(e,l,t)=>{
            t.d(l,{O:()=>n});
            const n={endpoint:"/api/users"};
          },
          9688:(e,l,t)=>{
            t.d(l,{A:()=>r});
            var s=t(4850),a=t(8947);
            const r=()=>{};
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      expect(moduleMap.size).toBe(2);

      const mod9688 = moduleMap.get(9688);
      expect(mod9688).toBeDefined();
      expect(mod9688?.imports).toHaveLength(2);
      expect(mod9688?.imports[0]).toEqual({
        moduleId: 4850,
        localVar: 's',
        usages: [],
      });
      expect(mod9688?.imports[1]).toEqual({
        moduleId: 8947,
        localVar: 'a',
        usages: [],
      });
    });

    test('extracts default exports', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            t.r(l);
            t.d(l,{default:()=>MyComponent});
            const MyComponent=()=>{};
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      const mod = moduleMap.get(100);
      expect(mod?.exports).toHaveLength(1);
      expect(mod?.exports[0].name).toBe('default');
      expect(mod?.exports[0].exportType).toBe('default');
    });
  });

  describe('Webpack IIFE pattern', () => {
    test('extracts modules from IIFE pattern', () => {
      const code = `
        (()=>{
          var e={
            4850:(e,t,n)=>{
              n.d(t,{S:()=>r});
              const r={post:function(e,t){},get:function(e){}};
            }
          };
        })();
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      expect(moduleMap.has(4850)).toBe(true);

      const mod = moduleMap.get(4850);
      expect(mod?.exports).toHaveLength(1);
      expect(mod?.exports[0].name).toBe('S');
    });

    test('handles multiple modules in IIFE', () => {
      const code = `
        (()=>{
          var e={
            100:(e,t,n)=>{
              n.d(t,{A:()=>a});
              const a="/api/endpoint1";
            },
            200:(e,t,n)=>{
              n.d(t,{B:()=>b});
              const b="/api/endpoint2";
            }
          };
        })();
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      expect(moduleMap.size).toBe(2);
      expect(moduleMap.has(100)).toBe(true);
      expect(moduleMap.has(200)).toBe(true);
    });
  });

  describe('HTTP call detection', () => {
    test('detects axios-style HTTP calls', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            s.S.post("/api/endpoint",{data:"value"});
            s.S.get("/api/other");
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(2);
      expect(mod?.httpCalls[0].method).toBe('post');
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/endpoint');
      expect(mod?.httpCalls[0].urlSource.resolvedValue).toBe('/api/endpoint');
      expect(mod?.httpCalls[1].method).toBe('get');
    });

    test('detects fetch calls', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            fetch("/api/data",{method:"POST",body:JSON.stringify({id:1})});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].method).toBe('post');
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/data');
      expect(mod?.httpCalls[0].clientVar).toBe('fetch');
    });

    test('detects HTTP calls with imported URL', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var a=t(200);
            fetch(a.O.endpoint);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('import');
      expect(mod?.httpCalls[0].urlSource.importPath).toEqual(['a', 'O', 'endpoint']);
    });
  });

  describe('Cross-module resolution', () => {
    test('resolves URL from imported module', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            t.d(l,{O:()=>n});
            const n={endpoint:"/api/users"};
          },
          200:(e,l,t)=>{
            var a=t(100),s=t(300);
            s.S.post(a.O.endpoint,{});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(200);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.resolvedValue).toBe('/api/users');
    });

    test('resolveWebpackReference works correctly', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            t.d(l,{O:()=>n});
            const n={login:"/api/login",logout:"/api/logout"};
          },
          200:(e,l,t)=>{
            var a=t(100);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      // Resolve from module 200's perspective
      const resolved = resolveWebpackReference(200, ['a', 'O', 'login']);
      expect(resolved).toBe('/api/login');

      const resolved2 = resolveWebpackReference(200, ['a', 'O', 'logout']);
      expect(resolved2).toBe('/api/logout');
    });
  });

  describe('FunctionMap integration', () => {
    test('registers webpack exports in function map', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            t.d(l,{O:()=>n});
            const n={endpoint:"/api/users"};
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      expect(functionMap.functions.has('webpack_100.O')).toBe(true);
      expect(functionMap.functions.has('webpack_100.O.endpoint')).toBe(true);

      const endpointFunc = functionMap.functions.get('webpack_100.O.endpoint');
      expect(endpointFunc?.returnedObject).toEqual({ _value: '/api/users' });
    });
  });

  describe('Edge cases', () => {
    test('handles string literal module IDs', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          "abc123":(e,l,t)=>{
            t.d(l,{X:()=>x});
            const x="value";
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      expect(moduleMap.has('abc123')).toBe(true);
    });

    test('handles nested object exports', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            t.d(l,{config:()=>c});
            const c={api:{base:"/api",version:"v1"},auth:{login:"/login"}};
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      const mod = moduleMap.get(100);
      expect(mod?.exports[0].resolvedValue?.type).toBe('object');
      const value = mod?.exports[0].resolvedValue as { type: 'object'; value: Record<string, unknown> };
      expect(value.value.api).toEqual({ base: '/api', version: 'v1' });
    });

    test('handles template literal URLs', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            const baseUrl="/api";
            fetch(\`\${baseUrl}/users\`);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('template');
    });

    test('handles URL concatenation', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            const base="/api";
            fetch(base + "/users");
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('concatenation');
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/users');
    });
  });

  describe('Real-world bundles', () => {
    test('178.d8d45500.chunk.js - extracts modules', async () => {
      const code = await readFile(join(TESTDATA_DIR, '178.d8d45500.chunk.js'), 'utf8');

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();

      // Should find multiple modules
      expect(moduleMap.size).toBeGreaterThan(0);

      // Module 9688 should have imports
      const mod9688 = moduleMap.get(9688);
      if (mod9688) {
        expect(mod9688.imports.length).toBeGreaterThan(0);
      }

      // Should detect HTTP calls
      const state = getWebpackBundleState();
      let totalHttpCalls = 0;
      for (const mod of state.modules.values()) {
        totalHttpCalls += mod.httpCalls.length;
      }
      expect(totalHttpCalls).toBeGreaterThan(0);
    });

    test('178.d8d45500.chunk.js - detects s.S.post pattern', async () => {
      const code = await readFile(join(TESTDATA_DIR, '178.d8d45500.chunk.js'), 'utf8');

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();

      // Find HTTP calls with s.S.post pattern
      const axiosCalls: Array<{ moduleId: string | number; url: string; method: string }> = [];
      for (const [moduleId, mod] of state.modules) {
        for (const call of mod.httpCalls) {
          if (call.clientAccessPath.includes('S')) {
            axiosCalls.push({
              moduleId,
              url: call.urlSource.resolvedValue ?? call.urlSource.value,
              method: call.method,
            });
          }
        }
      }

      // Should find s.S.post calls
      expect(axiosCalls.length).toBeGreaterThan(0);
      expect(axiosCalls.some((c) => c.method === 'post')).toBe(true);
    });

    test('webpack4 IIFE - extracts modules', async () => {
      const code = await readFile(
        join(TESTDATA_DIR, 'webpack4-iife.sample.js'),
        'utf8'
      );

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();

      // Should extract modules from Webpack 4 format
      expect(moduleMap.size).toBeGreaterThan(0);
    });
  });

  describe('Body parameter resolution', () => {
    test('resolves identifier to string value', () => {
      // Using axios-style which directly takes object as body
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const userId = "user_12345";
            s.S.post("/api/login", {user_id: userId, action: "login"});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].bodySource?.type).toBe('object');
      const body = mod?.httpCalls[0].bodySource?.value as Record<string, unknown>;
      expect(body.user_id).toBe('user_12345');
      expect(body.action).toBe('login');
    });

    test('resolves identifier to numeric value', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const count = 42;
            s.S.post("/api/update", {count: count});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      const body = mod?.httpCalls[0].bodySource?.value as Record<string, unknown>;
      expect(body.count).toBe(42);
    });

    test('resolves array with identifiers', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const id1 = "abc";
            const id2 = "def";
            s.S.post("/api/batch", {ids: [id1, id2, "ghi"]});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      const body = mod?.httpCalls[0].bodySource?.value as Record<string, unknown>;
      expect(body.ids).toEqual(['abc', 'def', 'ghi']);
    });

    test('resolves member expression in body', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const config = {api: {version: "v2"}};
            s.S.post("/api", {version: config.api.version});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      const body = mod?.httpCalls[0].bodySource?.value as Record<string, unknown>;
      expect(body.version).toBe('v2');
    });

    test('fallback to placeholder for unresolved identifiers', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            s.S.post("/api/data", {userId: e});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      const body = mod?.httpCalls[0].bodySource?.value as Record<string, unknown>;
      expect(body.userId).toBe('${e}');
    });
  });

  describe('Template literal resolution', () => {
    test('resolves identifier in template URL', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            const version = "v2";
            fetch(\`/api/\${version}/users\`);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('template');
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v2/users');
    });

    test('resolves member expression in template URL', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            const config = {api: {version: "v3"}};
            fetch(\`/api/\${config.api.version}/data\`);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v3/data');
    });
  });

  describe('UnaryExpression IIFE pattern', () => {
    test('extracts from !function(e){...}({...}) pattern', () => {
      const code = `
        !function(e){
          function t(n){return e[n].call(e.exports,e,e.exports,t),e.exports}
        }({
          0:function(e,t,a){
            a.d(t,{X:()=>x});
            const x="/api/v1";
          },
          1:function(e,t,a){
            var s=a(0);
            fetch(s.X);
          }
        });
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      expect(moduleMap.size).toBe(2);
      expect(moduleMap.has(0)).toBe(true);
      expect(moduleMap.has(1)).toBe(true);
    });
  });

  describe('Array-based modules', () => {
    test('extracts modules from array format', () => {
      const code = `
        !function(e){
          function t(n){return e[n].call(e.exports,e,e.exports,t),e.exports}
        }([
          function(e,t,a){
            a.d(t,{A:()=>x});
            const x="/first";
          },
          function(e,t,a){
            a.d(t,{B:()=>y});
            const y="/second";
          }
        ]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const moduleMap = getWebpackModuleMap();
      expect(moduleMap.size).toBe(2);
      expect(moduleMap.has(0)).toBe(true);
      expect(moduleMap.has(1)).toBe(true);
    });
  });

  describe('Conditional URL patterns', () => {
    test('extracts both URLs from conditional expression: cond ? url1 : url2', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const isProd = true;
            const url = isProd ? "/api/v1/prod" : "/api/v1/staging";
            s.S.post(url, {});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('conditional');
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/prod|/api/v1/staging');
      expect(mod?.httpCalls[0].urlSource.alternatives).toEqual(['/api/v1/prod', '/api/v1/staging']);
      expect(mod?.httpCalls[0].urlSource.resolvedValue).toBe('/api/v1/prod');
    });

    test('extracts conditional URL inline: s.post(cond ? url1 : url2)', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            s.S.post(e ? "/api/auth/sso/prod" : "/api/auth/sso/staging", {provider: "google"});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('conditional');
      expect(mod?.httpCalls[0].urlSource.alternatives).toEqual(['/api/auth/sso/prod', '/api/auth/sso/staging']);
    });
  });

  describe('IIFE URL patterns', () => {
    test('resolves URL from IIFE: const e = function(t){return "/api/..."}(arg)', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const url = function(t){return "/api/v1/users/search?q="+encodeURIComponent(t)}("query");
            s.S.get(url);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      // The URL should be partially resolved - the string part is extracted
      expect(mod?.httpCalls[0].urlSource.value).toContain('/api/v1/users/search');
    });

    test('resolves URL from arrow IIFE: const e = (t => "/api/" + t)("users")', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const url = (t => "/api/v2/" + t)("items");
            s.S.get(url);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.value).toContain('/api/v2/');
    });
  });

  describe('MemberExpression URL resolution', () => {
    test('resolves URL from variable assigned to MemberExpression: const e = o.USER_DELETE', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const o = {USER_DELETE: "/api/v1/users/delete"};
            const url = o.USER_DELETE;
            s.S.delete(url + "/" + e);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('concatenation');
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/users/delete/${e}');
    });

    test('resolves nested MemberExpression: config.api.baseUrl', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const config = {api: {baseUrl: "/api/v1"}};
            s.S.get(config.api.baseUrl + "/health");
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/health');
    });
  });

  describe('Endpoint dictionary lookup', () => {
    test('resolves template literal with endpoint dictionary: `${o.AUTH_LOGIN}`', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const o = {AUTH_LOGIN: "/api/v1/auth/login", AUTH_LOGOUT: "/api/v1/auth/logout"};
            s.S.post(\`\${o.AUTH_LOGIN}\`, {});
            s.S.post(\`\${o.AUTH_LOGOUT}\`, {});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(2);
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/auth/login');
      expect(mod?.httpCalls[1].urlSource.value).toBe('/api/v1/auth/logout');
    });

    test('resolves template with path: `${o.USER_UPDATE}/${userId}`', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const o = {USER_UPDATE: "/api/v1/users/update"};
            s.S.put(\`\${o.USER_UPDATE}/\${e}\`, {name: "test"});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/users/update/${e}');
    });

    test('resolves concatenation with endpoint dictionary: e + "/" + t where e = o.USER_BY_ID', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const o = {USER_BY_ID: "/api/v1/users"};
            const endpoint = o.USER_BY_ID;
            s.S.get(endpoint + "/" + e);
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/users/${e}');
    });
  });

  describe('Scope-aware variable resolution', () => {
    test('resolves variable from nested arrow function scope', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const outer = "/api/outer";
            const handler = async (id) => {
              const inner = "/api/v1/nested";
              s.S.get(inner + "/" + id);
            };
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/nested/${id}');
    });

    test('inner scope variable takes precedence over outer scope', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const url = "/api/outer";
            const handler = async () => {
              const url = "/api/v1/inner";
              s.S.get(url);
            };
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.resolvedValue).toBe('/api/v1/inner');
    });
  });

  describe('Complex real-world patterns', () => {
    test('pattern: ssoLogin with conditional URL', () => {
      // Real pattern from webpack5 bundle
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const p = {
              ssoLogin: async(provider, isProd) => {
                const url = isProd ? "/api/v1/auth/sso/prod" : "/api/v1/auth/sso/staging";
                return (await s.S.post(url, {provider})).data.redirectUrl;
              }
            };
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('conditional');
      expect(mod?.httpCalls[0].urlSource.alternatives).toContain('/api/v1/auth/sso/prod');
      expect(mod?.httpCalls[0].urlSource.alternatives).toContain('/api/v1/auth/sso/staging');
    });

    test('pattern: multiple concatenations with endpoint dictionary', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const o = {MFA_SETUP: "/api/v1/auth/mfa/setup"};
            const basePath = "/api/v1";
            const authPath = "/auth/mfa";
            const fullUrl = basePath + authPath + "/setup/" + e;
            s.S.post(fullUrl, {user_id: e});
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.value).toBe('/api/v1/auth/mfa/setup/${e}');
    });

    test('pattern: Angular-style service with baseUrl', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            class ApiService {
              constructor() {
                this.baseUrl = "/api/v1";
                this.http = t(200).S;
              }
              getUsers() {
                return this.http.get(\`\${this.baseUrl}/users\`);
              }
            }
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      // Should detect the http.get call (this.baseUrl may not resolve but pattern is detected)
      expect(mod?.httpCalls).toHaveLength(1);
      expect(mod?.httpCalls[0].urlSource.type).toBe('template');
    });

    test('pattern: fetch in try-catch block', () => {
      const code = `
        (self.webpackChunk||[]).push([[1],{
          100:(e,l,t)=>{
            var s=t(200);
            const primary = "/api/v1/analytics/batch";
            const fallback = "/api/v1/analytics/batch-fallback";
            try {
              s.S.post(primary, {events: e});
            } catch(err) {
              s.S.post(fallback, {events: e});
            }
          }
        }]);
      `;

      const ast = parse(code);
      const functionMap = createEmptyFunctionMap();
      extractWebpackFunctions(ast, functionMap, code);

      const state = getWebpackBundleState();
      const mod = state.modules.get(100);
      expect(mod?.httpCalls).toHaveLength(2);
      expect(mod?.httpCalls[0].urlSource.resolvedValue).toBe('/api/v1/analytics/batch');
      expect(mod?.httpCalls[1].urlSource.resolvedValue).toBe('/api/v1/analytics/batch-fallback');
    });
  });
});
