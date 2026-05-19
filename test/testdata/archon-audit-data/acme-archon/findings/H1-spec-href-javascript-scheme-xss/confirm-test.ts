/** Confirm H1: Spec Href Javascript Scheme Xss */
import * as fs from 'fs';
import { ApiInfoModel } from '../../../src/services/models/ApiInfo';
import { OpenAPIParser } from '../../../src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';

const sessionShortId = '00000000';

test('test_confirm_spec_href_javascript_scheme_xss_' + sessionShortId, () => {
  const maliciousUrl = 'javascript:alert(1)';
  const parser = new OpenAPIParser(
    {
      openapi: '3.0.0',
      info: {
        title: 'Demo',
        version: '1.0.0',
        license: { name: 'Click me', url: maliciousUrl },
        contact: { url: maliciousUrl, email: 'safe@example.com' },
        termsOfService: maliciousUrl,
      },
    } as any,
    undefined,
    new AcmeNormalizedOptions({}),
  );

  const info = new ApiInfoModel(parser);
  expect(info.license?.url).toBe(maliciousUrl);
  expect(info.contact?.url).toBe(maliciousUrl);
  expect(info.termsOfService).toBe(maliciousUrl);

  const sinkSource = fs.readFileSync('src/components/ApiInfo/ApiInfo.tsx', 'utf8');
  expect(sinkSource).toContain('href={info.license.url}');
  expect(sinkSource).toContain('href={info.contact.url}');
  expect(sinkSource).toContain('href={info.termsOfService}');
  expect(sinkSource).not.toMatch(/safeUrl|allowedProtocols|sanitizeUrl|new URL\(/);
});
