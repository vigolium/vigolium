import { describe, expect, test } from 'vitest';
import { jstangle } from '../index';

// A control-flow-object obfuscation: `standard`+ should inline it away, while
// `strict` must leave it intact (it is a heuristic obfuscator pattern, not a
// provably-safe transform).
const SRC = `
  var _0xabc = {
    rLxJs: function (a, b) { return a + b; },
    kHAOU: function (a, b) { return a(b); }
  };
  fetch(_0xabc.rLxJs("/api/", path));
`;

async function transformedCode(rewriteLevel: 'strict' | 'standard' | 'aggressive') {
  const res = await jstangle(SRC, { profile: 'legacy', rewriteLevel });
  return res.code;
}

describe('rewriteLevel gating', () => {
  test('strict leaves the control-flow object intact', async () => {
    expect(await transformedCode('strict')).toContain('_0xabc');
  });

  test('standard (default) inlines the control-flow object', async () => {
    expect(await transformedCode('standard')).not.toContain('_0xabc');
  });

  test('aggressive also inlines the control-flow object', async () => {
    expect(await transformedCode('aggressive')).not.toContain('_0xabc');
  });

  test('default level is standard when unspecified', async () => {
    const res = await jstangle(SRC, { profile: 'legacy' });
    expect(res.code).not.toContain('_0xabc');
  });
});
