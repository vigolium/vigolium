/** Confirm H1: Spec Href Javascript Scheme Xss */
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ApiInfo } from '../../../src/components/ApiInfo/ApiInfo';

const sessionShortId = '00000000';

test('test_confirm_spec_href_javascript_scheme_xss_' + sessionShortId, () => {
  const maliciousUrl = 'javascript:alert(1)';
  const store: any = {
    spec: {
      info: {
        title: 'Demo',
        version: '1.0.0',
        summary: '',
        description: '',
        license: { name: 'Click me', url: maliciousUrl },
        contact: { url: maliciousUrl, email: 'safe@example.com' },
        termsOfService: maliciousUrl,
        downloadUrls: [],
      },
      externalDocs: null,
    },
    options: { hideDownloadButtons: true },
  };

  const html = renderToStaticMarkup(<ApiInfo store={store} />);

  expect(html).toContain('href="javascript:alert(1)"');
  expect((html.match(/href="javascript:alert\(1\)"/g) || []).length).toBeGreaterThanOrEqual(3);
});
