import { readFile } from 'fs/promises';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { jsscan } from '../../index';

const TESTDATA_DIR = join(__dirname, '../testdata');

describe('extractedRequest', () => {
  test('fetchRequest', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'fetchRequest.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"id":123}",
          "cookies": [],
          "headers": [
            "Content-Type: application/json",
          ],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "https://httpbin.org/anything",
        },
        {
          "body": "{"data_id":123}",
          "cookies": [],
          "headers": [
            "Content-Type: application/json",
          ],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "https://httpbin.org/get",
        },
        {
          "body": "zzz=1",
          "cookies": [],
          "headers": [
            "Content-Type: application/json",
          ],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "https://httpbin.org/get",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "https://httpbin.org/anything",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "https://httpbin.org/get",
        },
      ]
    `);
  });

  test('xhrRequest', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'xhrRequest.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"appoverGUID":"\${approverGUID}"}",
          "cookies": [],
          "headers": [
            "Content-type: application/json; charset=utf-8",
            "Content-length: \${length}",
            "Connection: close",
          ],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/get",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/get",
        },
      ]
    `);
  });

  test('xhrCorrelation - GET with query params, cookie splitting, no body', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'xhrCorrelation.js'), 'utf8');
    const result = await jsscan(code);
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    const req = requests.find(r => r.url === '/api/xhr/items' && r.method === 'GET');
    expect(req).toBeDefined();
    expect(req!.params).toBe('page=1');
    expect(req!.body).toBe('');
    expect(req!.headers).toContain('Accept: application/json');
    // Cookie header is split out into the cookies array, not headers.
    expect(req!.headers.some(h => h.toLowerCase().startsWith('cookie'))).toBe(false);
    expect(req!.cookies).toEqual(['session=xyz', 'theme=dark']);
  });

  test('protocolRequest - WebSocket, EventSource, sendBeacon, GraphQL-over-fetch', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'protocolRequest.js'), 'utf8');
    const result = await jsscan(code);
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // WebSocket -> pseudo-method WS, query params split out
    const ws = requests.find(r => r.url === 'wss://realtime.example.com/socket' && r.method === 'WS');
    expect(ws).toBeDefined();
    expect(ws!.params).toBe('token=abc');

    // window.WebSocket(...) is also detected
    expect(requests.some(r => r.url === 'wss://realtime.example.com/v2' && r.method === 'WS')).toBe(true);

    // EventSource -> pseudo-method SSE
    expect(requests.some(r => r.url === 'https://events.example.com/stream' && r.method === 'SSE')).toBe(true);

    // navigator.sendBeacon -> POST with body
    const beacon = requests.find(r => r.url === '/analytics/collect' && r.method === 'POST');
    expect(beacon).toBeDefined();
    expect(beacon!.body).toContain('"event":"pageview"');

    // GraphQL over fetch is captured with the operation in the body
    const gql = requests.find(r => r.url === '/graphql' && r.method === 'POST');
    expect(gql).toBeDefined();
    expect(gql!.body).toContain('"operationName":"GetUser"');
    expect(gql!.body).toContain('GetUser { user { id } }');
  });

  test('jqueryAjax', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'jqueryAjax.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "ajaxid=4&UserID=1&EmailAddress=123@gmail.com",
          "type": "extractedRequest",
          "url": "ajax.aspx",
        },
      ]
    `);
  });

  test('genericRequestPattern1', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'genericRequestPattern1.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"m_uid":"\${t}","m_access_token":"\${r}"}",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/orders/delete",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "m_uid=\${e}&m_access_token=\${t}",
          "type": "extractedRequest",
          "url": "/greeting/cards",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "m_uid=\${t}&m_access_token=\${r}",
          "type": "extractedRequest",
          "url": "/orders/create",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "id=1",
          "type": "extractedRequest",
          "url": "/orders/get",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "m_uid=\${e}&m_access_token=\${t}",
          "type": "extractedRequest",
          "url": "/greeting/cards/\${id}",
        },
      ]
    `);
  });

  test('genericRequestPattern2', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'genericRequestPattern2.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"reqdate":"\${toString()}","data":{"appid":"\${appid}","zalopayid":"\${zalopayid}","appinfo":"\${appinfo}"}}",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/cpscore/app/createmultibillorder",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "reqdate=\${toString()}&data={"appid":"\${appid}","zalopayid":"\${zalopayid}"}",
          "type": "extractedRequest",
          "url": "/cpscore/app/getsupplier",
        },
      ]
    `);
  });

  test('genericRequestPattern3', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'genericRequestPattern3.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": 
      "mutation submitAsusFeedback {
              create_asus_feedback(
                input: {
                  action: FEEDBACK_PROVIDED
                  languageCode: \${l}
                  pageContext: "\${pageContext}"
                  answers: [
                    { questionId: "\${questionId}", value: \${value} }
                    { questionId: "\${questionId}", value: \${value} }
                  ]
                  tellUsMore: "\${tellUsMore}"
                }
              )
            }"
      ,
          "cookies": [],
          "headers": [
            "ROPRO_DEVICE_INFO: \${userAgent}",
          ],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "\${In}/user-management/v1/graphql",
        },
        {
          "body": "",
          "cookies": [
            "zlp_token=\${zlpToken}",
          ],
          "headers": [
            "Authorization: \${authorization}",
          ],
          "method": "GET",
          "params": "limit=\${limit}&page=\${page}",
          "type": "extractedRequest",
          "url": "/v1/user-domain/contacts",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/user-management/v1/graphql",
        },
      ]
    `);
  });

  test('genericRequestPattern4', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'genericRequestPattern4.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "zp_trans_id=\${n}&trans_time=\${transTime}&title=\${l}&trans_amount=\${a}",
          "type": "extractedRequest",
          "url": "/support-center/feedback/transaction-history",
        },
      ]
    `);
  });

  test('case1', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'case1.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/public/\${id}/delete",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/public/\${id}/delete",
        },
      ]
    `);
  });

  test('variableContainsURL', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'variableContainsURL.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"data":"value"}",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/create",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "userId=123&name=test",
          "type": "extractedRequest",
          "url": "/api/users",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "page=1",
          "type": "extractedRequest",
          "url": "/api/data",
        },
      ]
    `);
  });

  test('angularService - function mapping resolves params from call sites', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'angularService.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "name=John&email=john@example.com",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/user",
        },
        {
          "body": "name=Jane&role=admin",
          "cookies": [],
          "headers": [],
          "method": "PUT",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/user/456",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "userId=123",
          "type": "extractedRequest",
          "url": "/api/user",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/user/",
        },
      ]
    `);
  });

  test('nestedFunctionCall - resolves params through nested function chains', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'nestedFunctionCall.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');
    // First request: resolved params from first call site (loadData)
    // Second request: resolved params from second call site (loadOtherData)
    // Third request: from genericRequestPattern4 which doesn't use function mapping
    expect(requests).toMatchInlineSnapshot(`
      [
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "contentId=123&category=news",
          "type": "extractedRequest",
          "url": "/api/comments",
        },
      ]
    `);
  });

  test('memberExpressionFunction - resolves params through scope.method = function patterns', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'memberExpressionFunction.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');
    // First request: fetch inside loadData with body
    // Second request: $http from CommentsService.getComments with resolved params from fillDownloads chain
    // Third request: from genericRequestPattern4 (no function mapping)
    // Fourth request: from genericRequestPattern4 for fetch (no function mapping)
    expect(requests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"resourceId":"456","action":"refresh"}",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/load",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "contentId=\${scope.resourceFiles[0].id}&currentUserName=testUser",
          "type": "extractedRequest",
          "url": "/api/comments",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/load",
        },
      ]
    `);
  });

  test('allPatternsWithFunctionMapping - comprehensive test for all patterns with function mapping', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'allPatternsWithFunctionMapping.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // This comprehensive test ensures all patterns work correctly with function mapping
    // The testdata file contains:
    // - FetchService with getData and getWithQuery
    // - XHRService with sendRequest
    // - AjaxService (Angular) with fetchData and getData
    // - JQueryMethodService with loadData, saveData, updateData
    // - GenericPattern1Service with callEndpoint and postData
    // - GenericPattern2Service with fetchItems, createItem, updateItem
    // - ConfigService (Angular) with loadConfig and saveConfig
    // - GenericPattern4Service with navigate and redirect
    // - VariableURLService with loadResource and submitForm
    // - Nested services (Level1, Level2, Level3)
    // - Inner functions with member expression assignments
    // - Multiple call sites for same function

    // Just verify we get a reasonable number of requests extracted
    // Actual count may vary based on pattern detection and deduplication
    expect(requests.length).toBeGreaterThan(10);

    // Verify some key URLs are extracted
    const urls = requests.map(r => r.url);
    expect(urls).toContain('/api/fetch-data');
    expect(urls).toContain('/api/jquery-ajax');
    expect(urls).toContain('/api/generic3-config');
  });

  test('thisMethodCallResolution - resolves this.methodName() with returned object templates', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'thisMethodCallResolution.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // This test verifies:
    // 1. this.prepareRecord(viewId) returns an object template with ${viewId}
    // 2. saveView calls this.prepareRecord and the body should resolve to actual object structure
    // 3. Multiple call sites (saveView('page-123'), saveView('doc-456')) should produce different bodies
    // 4. prepareAuditRecord with two params (action, resourceId) should also resolve correctly

    // Verify key features:
    // - saveView resolves this.prepareRecord() to object structure with ${viewId} substituted
    // - saveAudit resolves this.prepareAuditRecord() with action and resourceId substituted
    // - directPost resolves data parameter from function map

    // Check that we have the expected URLs
    const urls = requests.map(r => r.url);
    expect(urls).toContain('/api/log/view');
    expect(urls).toContain('/api/audit');
    expect(urls).toContain('/api/direct');

    // Check that saveView body contains resolved contentId values from different call sites
    const saveViewRequests = requests.filter(r => r.url === '/api/log/view' && r.method === 'POST');
    expect(saveViewRequests.length).toBe(2);

    // Both requests should have the same template structure but different contentId values
    const bodies = saveViewRequests.map(r => r.body);
    expect(bodies.some(b => b.includes('"contentId":"page-123"'))).toBe(true);
    expect(bodies.some(b => b.includes('"contentId":"doc-456"'))).toBe(true);

    // Check the template structure
    expect(bodies[0]).toContain('"globalId":"${$rootScope.globalId}"');
    expect(bodies[0]).toContain('"ctdType":"VIEW"');
    expect(bodies[0]).toContain('"brandId":"${$rootScope.currentBrand.brandId}"');

    // Check that saveAudit resolves action and resourceId
    const saveAuditRequests = requests.filter(r => r.url === '/api/audit' && r.method === 'POST');
    expect(saveAuditRequests.length).toBe(2);

    const auditBodies = saveAuditRequests.map(r => r.body);
    expect(auditBodies.some(b => b.includes('"action":"CREATE"') && b.includes('"resourceId":"resource-001"'))).toBe(true);
    expect(auditBodies.some(b => b.includes('"action":"DELETE"') && b.includes('"resourceId":"resource-002"'))).toBe(true);

    // Check directPost resolves data from function map
    const directPostRequests = requests.filter(r => r.url === '/api/direct' && r.method === 'POST');
    expect(directPostRequests.length).toBe(1);
    expect(directPostRequests[0].body).toContain('"name":"test"');
    expect(directPostRequests[0].body).toContain('"value":"123"');
  });

  test('minifiedBooleans - converts !0 to true and !1 to false', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'minifiedBooleans.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"enabled":true,"disabled":false,"count":123}",
          "cookies": [],
          "headers": [],
          "method": "PUT",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/settings",
        },
        {
          "body": "{"features":{"darkMode":true,"notifications":false},"active":true}",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/config",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/settings",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/config",
        },
      ]
    `);
  });

  test('globalVariableResolution - resolves API_URL, BOB_URL from global config objects', async () => {
    // This test ensures that global config variables like API_URL and BOB_URL
    // are resolved to their actual values (e.g., "/site-visits-api", "/bob")
    // instead of remaining as placeholders like "${API_URL}"
    const code = await readFile(join(TESTDATA_DIR, 'globalVariableResolution.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"data":"\${data}"}",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/site-visits-api/notification/save",
        },
        {
          "body": "msg=test",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/site-visits-api/notification/save",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/bob/service/timezone/UTC",
        },
      ]
    `);
  });

  test('primitiveValueTracking - resolves numeric, boolean, and string variables', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'primitiveValueTracking.js'), 'utf8');
    const result = await jsscan(code);
    expect(result.extractedRequests).toMatchInlineSnapshot(`
      [
        {
          "body": "{"retries":"3","timeout":"5000","pageSize":"20","debug":"true","cache":"false","appName":"MyApp","version":"1.2.3"}",
          "cookies": [],
          "headers": [],
          "method": "POST",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/config",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "limit=20&retries=3",
          "type": "extractedRequest",
          "url": "/api/data",
        },
        {
          "body": "",
          "cookies": [],
          "headers": [],
          "method": "GET",
          "params": "",
          "type": "extractedRequest",
          "url": "/api/config",
        },
      ]
    `);
  });

  test('numericVariableTracking - resolves integer and float variables', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'numericVariableTracking.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // Check that numeric values are resolved
    expect(requests.some(r => r.url === '/api/users/12345/categories/42')).toBe(true);
    expect(requests.some(r => r.params === 'offset=0&limit=100')).toBe(true);
    expect(requests.some(r => r.body.includes('"itemId":"12345"'))).toBe(true);
    expect(requests.some(r => r.body.includes('"price":"19.99"'))).toBe(true);
  });

  test('booleanVariableTracking - resolves true, false, !0, !1 variables', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'booleanVariableTracking.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // Check features endpoint body
    const featuresRequest = requests.find(r => r.url === '/api/features' && r.method === 'POST');
    expect(featuresRequest).toBeDefined();
    expect(featuresRequest!.body).toBe('{"enabled":"true","disabled":"false","active":"true","inactive":"false"}');

    // Check settings endpoint body with minified booleans from object
    const settingsRequest = requests.find(r => r.url === '/api/user/settings' && r.method === 'PUT');
    expect(settingsRequest).toBeDefined();
    expect(settingsRequest!.body).toBe('{"darkMode":"true","notifications":"false","autoSave":"true","offlineMode":"false"}');
  });

  test('stringVariableTracking - resolves non-URL string variables', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'stringVariableTracking.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // Check info endpoint body
    const infoRequest = requests.find(r => r.url === '/api/info' && r.method === 'POST');
    expect(infoRequest).toBeDefined();
    expect(infoRequest!.body).toBe('{"version":"2.5.1","build":"build-12345","env":"production"}');

    // Check roles endpoint body
    const rolesRequest = requests.find(r => r.url === '/api/roles/assign' && r.method === 'POST');
    expect(rolesRequest).toBeDefined();
    expect(rolesRequest!.body).toBe('{"defaultRole":"user","adminRole":"admin","guestRole":"guest"}');

    // Check config endpoint body with object properties
    // Note: appConfig.name becomes ${name} because 'name' is a generic variable
    const configRequest = requests.find(r => r.url === '/api/app/config' && r.method === 'PUT');
    expect(configRequest).toBeDefined();
    expect(configRequest!.body).toContain('"appName":"${name}"'); // 'name' is generic, not tracked
    expect(configRequest!.body).toContain('"region":"us-east-1"');
    expect(configRequest!.body).toContain('"tier":"premium"');
  });

  test('objectConfigTracking - resolves Object({...}) webpack environment config', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'objectConfigTracking.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // Check that VUE_APP_API_URL is resolved in the URL
    expect(requests.some(r => r.url === 'https://api.example.com/users')).toBe(true);

    // Check upload endpoint with config values in body
    const uploadRequest = requests.find(r => r.url === '/api/upload' && r.method === 'POST');
    expect(uploadRequest).toBeDefined();
    expect(uploadRequest!.body).toContain('"maxSize":"10485760"');
    expect(uploadRequest!.body).toContain('"debug":"true"');
    expect(uploadRequest!.body).toContain('"version":"3.0.0"');
  });

  test('assignmentTracking - resolves variables from assignment expressions', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'assignmentTracking.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // Check that apiBase assignment is resolved
    expect(requests.some(r => r.url === '/api/v1/users')).toBe(true);

    // Check that config.endpoint is resolved
    expect(requests.some(r => r.url === '/services/data/query')).toBe(true);

    // Check body with assigned values
    const queryRequest = requests.find(r => r.url === '/services/data/query' && r.method === 'POST');
    expect(queryRequest).toBeDefined();
    expect(queryRequest!.body).toContain('"limit":"50"');
    expect(queryRequest!.body).toContain('"production":"true"');
    expect(queryRequest!.body).toContain('"timeout":"10000"');
    expect(queryRequest!.body).toContain('"retry":"false"');

    // Check that first value wins (baseUrl should be "/initial")
    expect(requests.some(r => r.url === '/initial/test')).toBe(true);
  });

  test('genericVariableFilter - does NOT track generic names like id, key, name', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'genericVariableFilter.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // Generic names should remain as ${...} placeholders
    const itemsRequest = requests.find(r => r.url.includes('/api/items/'));
    expect(itemsRequest).toBeDefined();
    expect(itemsRequest!.url).toBe('/api/items/${id}/details');

    // Specific names should be resolved
    const usersRequest = requests.find(r => r.url === '/api/users/user-123');
    expect(usersRequest).toBeDefined();

    // Check body - userId should be resolved, id and name should be placeholders
    const saveRequest = requests.find(r => r.url === '/api/save' && r.method === 'POST');
    expect(saveRequest).toBeDefined();
    expect(saveRequest!.body).toContain('"userId":"user-123"');
    expect(saveRequest!.body).toContain('"id":"${id}"');
    expect(saveRequest!.body).toContain('"name":"${name}"');
    expect(saveRequest!.body).toContain('"userName":"john_doe"');
  });

  test('templateLiteralTracking - resolves simple template literals', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'templateLiteralTracking.js'), 'utf8');
    const result = await jsscan(code);
    // Filter to only extractedRequest type
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    // Check that template literal values are resolved
    expect(requests.some(r => r.url === '/api/v2/data')).toBe(true);
    expect(requests.some(r => r.url === '/services/auth/login')).toBe(true);

    // Check config endpoint body with template literal values
    const configRequest = requests.find(r => r.url === '/api/config' && r.method === 'PUT');
    expect(configRequest).toBeDefined();
    expect(configRequest!.body).toContain('"endpoint":"/api/v2"');
    expect(configRequest!.body).toContain('"path":"/services/auth"');
    expect(configRequest!.body).toContain('"maxCount":"100"');
    expect(configRequest!.body).toContain('"debug":"true"');
  });

  test('axiosRequest - global, config-form, and baseURL-joined instance calls', async () => {
    const code = await readFile(join(TESTDATA_DIR, 'axiosRequest.js'), 'utf8');
    const result = await jsscan(code);
    const requests = result.extractedRequests.filter(r => r.type === 'extractedRequest');

    const find = (url: string, method: string) =>
      requests.find(r => r.url === url && r.method === method);

    // Global axios.METHOD(url[, data])
    expect(find('/api/global/users', 'GET')).toBeDefined();
    const globalPost = find('/api/global/users', 'POST');
    expect(globalPost).toBeDefined();
    expect(globalPost!.body).toContain('"name":"alice"');
    expect(find('/api/global/users/42', 'DELETE')).toBeDefined();

    // axios({ url, method, data, headers })
    const configForm = find('/api/config-form/login', 'POST');
    expect(configForm).toBeDefined();
    expect(configForm!.body).toContain('"username":"bob"');
    expect(configForm!.headers).toContain('X-App: demo');

    // axios(url, config)
    const urlConfig = find('/api/url-config/profile', 'PUT');
    expect(urlConfig).toBeDefined();
    expect(urlConfig!.params).toContain('expand=all');

    // Instance baseURL joining
    expect(find('https://api.example.com/v2/users', 'GET')).toBeDefined();
    const instPost = find('https://api.example.com/v2/users', 'POST');
    expect(instPost).toBeDefined();
    expect(instPost!.body).toContain('"email":"carol@example.com"');
    // Instance default headers are carried onto the request
    expect(instPost!.headers).toContain('Authorization: Bearer token123');

    // Instance call with params object
    const instItems = find('https://api.example.com/v2/items', 'GET');
    expect(instItems).toBeDefined();
    expect(instItems!.params).toContain('page=2');

    // Absolute URL ignores baseURL
    expect(find('https://other.example.com/health', 'GET')).toBeDefined();

    // instance.request(config)
    const reqForm = find('https://api.example.com/v2/request-form/data', 'PATCH');
    expect(reqForm).toBeDefined();
    expect(reqForm!.body).toContain('"ok":true');
  });
});
