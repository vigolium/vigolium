import { describe, expect, test } from 'vitest';
import { jstangle } from '../index';
import { isPathLiteral } from '../capabilities';
import {
  buildAnalysisResultV2,
  fitEnvelope,
  getCapabilities,
  truncationReason,
  type ClientRouteFact,
  type HttpRequestFact,
  type PathLiteralFact,
} from '../protocol';

async function envelope(code: string, profile: 'full' | 'discovery' | 'endpoints' = 'full') {
  const result = await jstangle(code, { profile });
  return { result, envelope: buildAnalysisResultV2(result, result.analysisContext) };
}

function requests(records: Array<{ kind: string }>): HttpRequestFact[] {
  return records.filter((record): record is HttpRequestFact => record.kind === 'httpRequest');
}

function byUrl(records: Array<{ kind: string }>, url: string, method = 'GET'): HttpRequestFact | undefined {
  return requests(records).find((fact) => fact.url.rendered === url && fact.method.rendered === method);
}

function queryNames(fact: HttpRequestFact | undefined): string[] {
  return fact?.query.map((field) => field.name.rendered) ?? [];
}

describe('capabilities', () => {
  test('advertises release-1 fact features without a protocol bump', () => {
    const caps = getCapabilities();
    expect(caps.protocolVersion).toBe(2);
    for (const feature of [
      'facts.pathLiteral', 'facts.httpRequest.auth', 'facts.httpRequest.callSite',
      'facts.httpRequest.suppressed', 'facts.httpRequest.urlModel', 'facts.clientRoute.fullPath',
      'facts.clientRoute.meta', 'completion.truncated', 'pathLiterals',
    ]) {
      expect(caps.capabilities).toContain(feature);
    }
    expect(caps.schemaVersions.pathLiteral).toBe(1);
    expect(caps.schemaVersions.httpRequest).toBe(3);
    expect(caps.schemaVersions.clientRoute).toBe(4);
  });
});

describe('pathLiteral facts', () => {
  const source = `
    const routes = { profile: "/api/v2/profile", admin: "/api/v2/admin/config" };
    const EXPORT_PATH = "/api/v2/export";
    const list = ["/account/settings"];
    function go(target = "/dashboard/home") { return target; }
    function legacy() { return "/legacy/rpc"; }
    let fallback; fallback = "/internal/fallback";
    fetch("/api/v2/consumed");
    const twice = { a: "/repeated/path", b: "/repeated/path" };
  `;

  test('emits bound path literals with reason and key', async () => {
    const { result } = await envelope(source);
    const facts = new Map(result.pathLiterals.map((fact) => [fact.value.rendered, fact]));
    expect(facts.get('/api/v2/profile')).toMatchObject({ reason: 'object-value', key: 'profile' });
    expect(facts.get('/api/v2/admin/config')).toMatchObject({ reason: 'object-value', key: 'admin' });
    expect(facts.get('/api/v2/export')).toMatchObject({ reason: 'const-init', key: 'EXPORT_PATH' });
    expect(facts.get('/account/settings')).toMatchObject({ reason: 'array-element', key: 'list' });
    expect(facts.get('/dashboard/home')).toMatchObject({ reason: 'default-param', key: 'target' });
    expect(facts.get('/legacy/rpc')).toMatchObject({ reason: 'return' });
    expect(facts.get('/internal/fallback')).toMatchObject({ reason: 'assignment', key: 'fallback' });
    for (const fact of facts.values()) expect(fact.provenance.confidence).toBe('low');
  });

  test('skips literals consumed by a request and dedupes repeats', async () => {
    const { result } = await envelope(source);
    const values = result.pathLiterals.map((fact) => fact.value.rendered);
    expect(values).not.toContain('/api/v2/consumed');
    expect(values.filter((value) => value === '/repeated/path')).toHaveLength(1);
  });

  test('is off for profiles that do not request it', async () => {
    const { result } = await envelope(source, 'endpoints');
    expect(result.pathLiterals).toHaveLength(0);
  });

  test('shape filter rejects decoys', () => {
    for (const decoy of ['/yyyy/mm/dd', 'text/html', '/', '/a.b.c.d.e', '/not a path', '/./x', '// TODO', '/^x$', '/${a}/${b}', '/1/2']) {
      expect(isPathLiteral(decoy), decoy).toBe(false);
    }
    for (const real of ['/api/v2/profile', '/users/:id', '/items/${id}', '/static/app.min.js', '/~user']) {
      expect(isPathLiteral(real), real).toBe(true);
    }
  });

  test('cap truncates and reports the overflow', async () => {
    const literals = Array.from({ length: 30 }, (_, index) => `p${index}: "/cap/path-${index}"`).join(',');
    const result = await jstangle(`const table = {${literals}};`, { profile: 'full', limits: { maxPathLiterals: 10 } });
    expect(result.pathLiterals).toHaveLength(10);
    expect(result.truncated.pathLiteral).toBe(20);
    expect(result.status).toBe('partial');
    expect(result.diagnostics.filter((diagnostic) => diagnostic.code === 'path_literal_limit_reached')).toHaveLength(1);
  });
});

describe('URL and URLSearchParams modelling', () => {
  test('folds searchParams mutations into the fetched URL', async () => {
    const { envelope: env } = await envelope(`
      function search(term, page) {
        const u = new URL("/api/v6/search", location.origin);
        u.searchParams.set("q", term);
        u.searchParams.append("page", String(page));
        return fetch(u);
      }
      function suggest(prefix) {
        const target = new URL("https://api.example.test/v1/suggest");
        target.searchParams.set("prefix", prefix);
        return fetch(target.toString());
      }
      function lookup(sku) {
        const endpoint = new URL("lookup", "https://api.example.test/v6/");
        endpoint.searchParams.set("sku", sku);
        endpoint.searchParams.delete("unused");
        return fetch(\`\${endpoint}\`);
      }
    `);
    expect(queryNames(byUrl(env.records, '/api/v6/search'))).toEqual(['q', 'page']);
    expect(queryNames(byUrl(env.records, 'https://api.example.test/v1/suggest'))).toEqual(['prefix']);
    expect(queryNames(byUrl(env.records, 'https://api.example.test/v6/lookup'))).toEqual(['sku']);
  });

  test('URLSearchParams as query string, body and axios params', async () => {
    const { envelope: env } = await envelope(`
      function filter(status) {
        const params = new URLSearchParams({ status: status, limit: "25" });
        params.append("sort", "desc");
        params.set("limit", "50");
        return fetch("/api/v6/orders?" + params);
      }
      function login(user, pass) {
        const form = new URLSearchParams();
        form.append("username", user);
        form.append("password", pass);
        return fetch("/api/v6/login", { method: "POST", body: form });
      }
      function report(kind) {
        const qp = new URLSearchParams({ kind: kind });
        return axios.get("/api/v6/reports", { params: qp });
      }
    `);
    const orders = byUrl(env.records, '/api/v6/orders');
    expect(orders?.query.map((field) => `${field.name.rendered}=${field.value.rendered}`))
      .toEqual(['status=${status}', 'limit=50', 'sort=desc']);
    const login = byUrl(env.records, '/api/v6/login', 'POST');
    expect(login?.body).toMatchObject({ kind: 'form', value: { rendered: 'username=${user}&password=${pass}' } });
    expect(queryNames(byUrl(env.records, '/api/v6/reports'))).toEqual(['kind']);
  });
});

describe('query population from rendered URLs', () => {
  test('splits a query left in the rendered URL and keeps the raw form', async () => {
    const result = await jstangle('fetch("/api/raw")', { profile: 'endpoints' });
    result.extractedRequests[0].url = '/api/raw?q=${term}&page=2';
    const env = buildAnalysisResultV2(result, result.analysisContext);
    const fact = requests(env.records)[0];
    expect(fact.url.rendered).toBe('/api/raw');
    expect(fact.url.alternatives?.[0]).toBe('/api/raw?q=${term}&page=2');
    expect(fact.query.map((field) => [field.name.rendered, field.name.static, field.value.static]))
      .toEqual([['q', true, false], ['page', true, true]]);
    expect(fact.query[0].value.rendered).toBe('${term}');
  });

  test('leaves a non-query tail alone', async () => {
    const result = await jstangle('fetch("/api/raw")', { profile: 'endpoints' });
    result.extractedRequests[0].url = '/api/raw?${opaque}';
    const fact = requests(buildAnalysisResultV2(result, result.analysisContext).records)[0];
    expect(fact.url.rendered).toBe('/api/raw?${opaque}');
  });
});

describe('prefix/suffix suppression', () => {
  test('folds base URL and un-prefixed paths into the resolved axios fact', async () => {
    const { envelope: env } = await envelope(`
      const api = axios.create({ baseURL: "/api/v3" });
      function list() { return api.get("/things"); }
      function create(p) { return api.post("/things", p); }
    `);
    const urls = requests(env.records).map((fact) => `${fact.method.rendered} ${fact.url.rendered}`).sort();
    expect(urls).toEqual(['GET /api/v3/things', 'POST /api/v3/things']);
    const suppressed = requests(env.records).flatMap((fact) => fact.suppressed ?? []);
    expect(suppressed.map((entry) => `${entry.reason} ${entry.url}`).sort())
      .toEqual(['prefix /api/v3', 'suffix /things', 'suffix /things']);
    expect(env.stats.recordCounts.httpRequest).toBe(2);
  });

  test('never suppresses a URL that is also used at its own call site', async () => {
    const { envelope: env } = await envelope(`
      const api = axios.create({ baseURL: "/api/v3" });
      function list() { return api.get("/things"); }
      fetch("/api/v3");
    `);
    expect(byUrl(env.records, '/api/v3')).toBeDefined();
  });

  test('every request fact carries a call site id', async () => {
    const { envelope: env } = await envelope('fetch("/api/a"); fetch("/api/b");');
    const sites = requests(env.records).map((fact) => fact.callSite);
    expect(sites.every(Boolean)).toBe(true);
    expect(new Set(sites).size).toBe(2);
  });
});

describe('auth token source', () => {
  test('names the storage slot and never the value', async () => {
    const { envelope: env } = await envelope(`
      fetch("/api/me", { headers: { Authorization: "Bearer " + localStorage.getItem("jwt") } });
      function orders() {
        const token = sessionStorage.getItem("access_token");
        return fetch("/api/orders", { headers: { Authorization: \`Bearer \${token}\` } });
      }
      fetch("/api/cart", { headers: { "X-API-Key": Cookies.get("api_key") } });
      function state(store) {
        return fetch("/api/state", { headers: { Authorization: "Bearer " + store.getState().auth.token } });
      }
      fetch("/api/legacy", { headers: { Authorization: "Basic dXNlcjpwYXNz" } });
      fetch("/api/csrf", { method: "POST", headers: { "X-XSRF-TOKEN": document.cookie.match(/XSRF-TOKEN=([^;]+)/)[1] } });
    `);
    expect(byUrl(env.records, '/api/me')?.auth).toEqual({
      kind: 'bearer', header: 'Authorization', scheme: 'Bearer', source: 'localStorage:jwt', sourceKind: 'localStorage',
    });
    expect(byUrl(env.records, '/api/orders')?.auth?.source).toBe('sessionStorage:access_token');
    expect(byUrl(env.records, '/api/cart')?.auth).toMatchObject({ kind: 'apikey-header', source: 'cookie:api_key' });
    expect(byUrl(env.records, '/api/state')?.auth?.source).toBe('state:auth.token');
    const legacy = byUrl(env.records, '/api/legacy')?.auth;
    expect(legacy).toMatchObject({ kind: 'basic', sourceKind: 'literal', source: 'literal' });
    expect(JSON.stringify(legacy)).not.toContain('dXNlcjpwYXNz');
    expect(byUrl(env.records, '/api/csrf', 'POST')?.auth).toMatchObject({ kind: 'custom', source: 'cookie:XSRF-TOKEN' });
  });

  test('applies an axios interceptor credential to axios requests', async () => {
    const { envelope: env } = await envelope(`
      axios.interceptors.request.use((config) => {
        config.headers.Authorization = "Bearer " + localStorage.getItem("token");
        return config;
      });
      axios.get("/api/feed");
    `);
    expect(byUrl(env.records, '/api/feed')?.auth).toMatchObject({ kind: 'bearer', source: 'localStorage:token' });
  });

  test('flags an API key carried in the query', async () => {
    const { envelope: env } = await envelope('function f(k) { return fetch("/api/geo?api_key=" + k); }');
    expect(byUrl(env.records, '/api/geo')?.auth).toMatchObject({ kind: 'apikey-query', query: 'api_key', sourceKind: 'unknown' });
  });
});

describe('client route normalization', () => {
  test('joins nested children into absolute full paths', async () => {
    const { result } = await envelope(`
      const routes = [
        { path: "login", component: Login },
        { path: "admin", component: Admin, children: [
          { path: "", component: AdminIndex },
          { path: "reports", component: Reports, children: [{ path: ":id", component: Report }] },
        ] },
        { path: "/users", component: Users, children: [{ path: "/user-search", component: Search }] },
      ];
      const lazyRoutes = [{ path: "profile", component: Profile }];
      RouterModule.forChild(lazyRoutes);
    `);
    const routes = new Map<string, ClientRouteFact>(result.clientRoutes.map((route) => [route.path.rendered, route]));
    expect(routes.get('login')?.fullPath?.rendered).toBe('/login');
    expect(routes.get('reports')?.fullPath?.rendered).toBe('/admin/reports');
    expect(routes.get(':id')?.fullPath?.rendered).toBe('/admin/reports/:id');
    expect(routes.get(':id')?.parentId).toBe(routes.get('reports')?.id);
    expect(routes.get('reports')?.parentId).toBe(routes.get('admin')?.id);
    expect(routes.get('/user-search')?.fullPath?.rendered).toBe('/user-search');
    const lazy = routes.get('profile')?.fullPath;
    expect(lazy).toMatchObject({ rendered: '${parent}/profile', static: false });
  });

  test('same child path under different parents stays distinct', async () => {
    const { result } = await envelope(`
      const routes = [
        { path: "a", component: A, children: [{ path: "edit", component: E }] },
        { path: "b", component: B, children: [{ path: "edit", component: E }] },
      ];
    `);
    const edits = result.clientRoutes.filter((route) => route.path.rendered === 'edit');
    expect(edits.map((route) => route.fullPath?.rendered).sort()).toEqual(['/a/edit', '/b/edit']);
  });
});

describe('request cap truncation', () => {
  test('marks the run partial with request_cap and counts the overflow once', async () => {
    const calls = Array.from({ length: 25 }, (_, index) => `fetch("/api/cap/${index}");`).join('\n');
    const result = await jstangle(calls, { profile: 'endpoints', limits: { maxRequests: 10 } });
    expect(result.status).toBe('partial');
    expect(result.truncated).toEqual({ httpRequest: 15 });
    expect(result.diagnostics.filter((diagnostic) => diagnostic.code === 'request_limit_reached')).toHaveLength(1);
    const env = buildAnalysisResultV2(result, result.analysisContext);
    expect(env.stats.truncated).toEqual({ httpRequest: 15 });
    expect(truncationReason(env.stats.truncated)).toBe('request_cap');
  });

  test('reason codes by kind', () => {
    expect(truncationReason(undefined)).toBeUndefined();
    expect(truncationReason({})).toBeUndefined();
    expect(truncationReason({ pathLiteral: 3 })).toBe('fact_cap:pathLiteral');
    expect(truncationReason({ pathLiteral: 3, httpRequest: 1 })).toBe('request_cap');
  });

  test('output budget omissions are counted per kind', async () => {
    const literals = Array.from({ length: 200 }, (_, index) => `p${index}: "/budget/path-${index}"`).join(',');
    const result = await jstangle(`const t = {${literals}};`, { profile: 'full' });
    const fitted = fitEnvelope(buildAnalysisResultV2(result, result.analysisContext), 8 * 1024);
    expect(fitted.omitted).toBeGreaterThan(0);
    expect(fitted.envelope.stats.truncated?.pathLiteral).toBe(fitted.omitted);
    const kept = fitted.envelope.records.filter((record): record is PathLiteralFact => record.kind === 'pathLiteral');
    expect(kept.length).toBe(200 - fitted.omitted);
  });
});
