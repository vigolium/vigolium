import { describe, expect, test } from 'vitest';
import { jstangle } from '../../index';

describe('modern HTTP client adapters', () => {
  test('extracts ky instances with prefixUrl, JSON body, query, and headers', async () => {
    const result = await jstangle(`
      import ky from 'ky';
      const api = ky.create({prefixUrl:'https://api.example.test/v2', headers:{Accept:'application/json'}});
      api.post('/users', {json:{name:'alice'}, searchParams:{notify:true}, headers:{'X-App':'web'}});
    `, { profile: 'endpoints' });
    const request = result.extractedRequests.find((item) => item.url.includes('/users'));
    expect(request).toMatchObject({
      url: 'https://api.example.test/v2/users', method: 'POST', params: 'notify=true', body: '{"name":"alice"}',
    });
    expect(request?.headers).toEqual(expect.arrayContaining(['Accept: application/json', 'X-App: web', 'Content-Type: application/json']));
    const index = result.extractedRequests.indexOf(request!);
    expect(result.analysisContext.requestOrigins[index]?.provenance.extractor).toBe('ky-adapter');
  });

  test('extracts ofetch and Angular HttpClient argument semantics', async () => {
    const result = await jstangle(`
      import {ofetch} from 'ofetch';
      import {HttpClient} from '@angular/common/http';
      ofetch('/api/config', {method:'PATCH', body:{enabled:true}, query:{tenant:'a'}});
      http.post('/api/users', {name:'bob'}, {headers:{'X-Version':'2'}});
    `, { profile: 'endpoints' });
    expect(result.extractedRequests).toEqual(expect.arrayContaining([
      expect.objectContaining({ url: '/api/config', method: 'PATCH', params: 'tenant=a', body: '{"enabled":true}' }),
      expect.objectContaining({ url: '/api/users', method: 'POST', body: '{"name":"bob"}' }),
    ]));
    const extractors = result.analysisContext.requestOrigins.map((origin) => origin.provenance.extractor);
    expect(extractors).toEqual(expect.arrayContaining(['ofetch-adapter', 'angular-adapter']));
  });

  test('does not promote lookalike builders without a client detection signal', async () => {
    const result = await jstangle(`builder.post('/not-an-http-client', {value:1});`, { profile: 'endpoints' });
    expect(result.analysisContext.requestOrigins.some((origin) => /-adapter$/.test(origin.provenance.extractor))).toBe(false);
  });

  test('preserves SuperAgent chain semantics', async () => {
	const result = await jstangle(`
	  import request from 'superagent';
	  request.post('/api/users').query({notify:true}).send({name:'alice'}).set('X-App', 'web');
	`, { profile: 'endpoints' });
	const request = result.extractedRequests.find((item) => item.url === '/api/users');
	expect(request).toMatchObject({ method: 'POST', params: 'notify=true', body: '{"name":"alice"}' });
	expect(request?.headers).toContain('X-App: web');
	expect(result.analysisContext.requestOrigins[result.extractedRequests.indexOf(request!)]?.provenance.extractor).toBe('superagent-adapter');
  });

  test('retains safe static Angular interceptor defaults without auth material', async () => {
	const result = await jstangle(`
	  import {HttpClient, HttpInterceptor} from '@angular/common/http';
	  req.clone({setHeaders:{'X-Tenant':'public', Authorization:'Bearer literal'}});
	  http.get('/api/profile');
	`, { profile: 'endpoints' });
	const request = result.extractedRequests.find((item) => item.url === '/api/profile');
	expect(request?.headers).toContain('X-Tenant: public');
	expect(request?.headers.some((header) => /^Authorization:/i.test(header))).toBe(false);
  });

	test('extracts generated OpenAPI runtime request objects with typed semantics', async () => {
		const result = await jstangle(`
		  // OpenAPI generated runtime
		  const BASE_PATH = 'https://api.example.test/v2';
		  request({
			basePath: BASE_PATH,
			path: '/users/' + userId,
			method: 'PATCH',
			queryParameters: {expand: 'roles'},
			headerParameters: {'Content-Type':'application/json'},
			body: {enabled: true}
		  });
		`, { profile: 'endpoints' });
		const request = result.extractedRequests.find((item) => item.method === 'PATCH');
		expect(request?.url).toContain('https://api.example.test/v2/users/');
		expect(request?.params).toContain('expand=roles');
		expect(request?.body).toContain('enabled');
		const origin = result.analysisContext.requestOrigins[result.extractedRequests.indexOf(request!)];
		expect(origin?.client).toBe('openapi');
		expect(origin?.provenance.extractor).toBe('openapi-generated-adapter');
	});
});
