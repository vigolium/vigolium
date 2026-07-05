import { describe, it, expect } from 'vitest';
import { rawRequestToCurl } from '../curl';

const raw = (target: string, extra = '') =>
  `GET ${target} HTTP/1.1\nHost: login.example.com${extra ? `\n${extra}` : ''}\n\n`;

describe('rawRequestToCurl (workbench)', () => {
  it('leaves normal requests untouched (no --path-as-is)', () => {
    const cmd = rawRequestToCurl(raw('/catalog?searchTerm=apple'));
    expect(cmd).toContain("'https://login.example.com/catalog?searchTerm=apple'");
    expect(cmd).not.toContain('--path-as-is');
  });

  it('does not flag legit dotted segments', () => {
    expect(rawRequestToCurl(raw('/demo.php'))).not.toContain('--path-as-is');
    expect(rawRequestToCurl(raw('/.well-known/oauth'))).not.toContain('--path-as-is');
  });

  it('encodes a literal "#" and adds --path-as-is for fragment bypass', () => {
    const cmd = rawRequestToCurl(raw('/#/../demo.log'));
    expect(cmd).toContain('--path-as-is');
    expect(cmd).toContain("'https://login.example.com/%23/../demo.log'");
    // The raw '#' must not survive unencoded — curl would drop it as a fragment.
    expect(cmd).not.toContain('/#/../demo.log');
  });

  it('adds --path-as-is for pre-encoded %23 and dot-segment bypasses', () => {
    expect(rawRequestToCurl(raw('/%23/../admin'))).toContain('--path-as-is');
    expect(rawRequestToCurl(raw('/pages/../demo.log'))).toContain('--path-as-is');
    expect(rawRequestToCurl(raw('/api/./v1/users'))).toContain('--path-as-is');
  });

  it('recovers scheme from matchedAt and preserves the bypass', () => {
    const cmd = rawRequestToCurl(raw('/#/../x'), undefined as never);
    expect(cmd).toContain('https://');
    const http = rawRequestToCurl(
      'GET /#/../x HTTP/1.1\nHost: h.example.com\n\n',
      ['http://h.example.com/'],
    );
    expect(http).toContain("'http://h.example.com/%23/../x'");
    expect(http).toContain('--path-as-is');
  });
});
