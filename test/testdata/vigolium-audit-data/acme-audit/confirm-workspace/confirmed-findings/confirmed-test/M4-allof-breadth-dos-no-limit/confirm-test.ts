/** Confirm M4: allOf breadth DoS no limit */
import { OpenAPIParser } from '../../../src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';

const SESSION = '00000000';

test(`test_confirm_allof_breadth_dos_no_limit_${SESSION}`, () => {
  const CHILDREN = 20000;
  const schema = {
    type: 'object',
    allOf: Array.from({ length: CHILDREN }, (_, i) => ({
      type: 'object',
      properties: { ['p' + i]: { type: 'string' } },
    })),
  } as any;
  const spec = { openapi: '3.0.0', info: { title: 'x', version: '1' }, paths: {} } as any;
  const parser = new OpenAPIParser(spec, undefined, new AcmeNormalizedOptions({}));

  let derefCalls = 0;
  const originalDeref = parser.deref.bind(parser);
  parser.deref = ((obj: any, baseRefsStack: string[] = [], mergeAsAllOf = false) => {
    derefCalls++;
    return originalDeref(obj, baseRefsStack, mergeAsAllOf);
  }) as any;

  const merged = parser.mergeAllOf(schema, '#/components/schemas/Attack', []);

  expect(derefCalls).toBe(CHILDREN);
  expect(merged['x-circular-ref']).toBeUndefined();
  expect(Object.keys(merged.properties || {})).toHaveLength(CHILDREN);
});
