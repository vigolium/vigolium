/** Confirm M10: findDerived quadratic DoS */
import { OpenAPIParser } from '../../../src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';

function buildSpec(schemaCount: number) {
  const schemas: Record<string, any> = {
    Base: { type: 'object' },
  };

  for (let i = 0; i < schemaCount; i++) {
    schemas[`Child${i}`] = {
      allOf: [{ $ref: '#/components/schemas/Base' }],
      'x-discriminator-value': `child-${i}`,
    };
  }

  return {
    openapi: '3.0.0',
    info: { title: 'confirm-m10', version: '1.0.0' },
    paths: {},
    components: { schemas },
  } as any;
}

test('test_confirm_findderived_quadratic_dos_00000000', () => {
  const schemaCount = 400;
  const discriminatorCalls = 25;
  const parser = new OpenAPIParser(buildSpec(schemaCount), undefined, new AcmeNormalizedOptions({}));
  const derefSpy = jest.spyOn(parser, 'deref');

  for (let i = 0; i < discriminatorCalls; i++) {
    const derived = parser.findDerived(['#/components/schemas/Base']);
    expect(Object.keys(derived)).toHaveLength(schemaCount);
  }

  expect(derefSpy).toHaveBeenCalledTimes((schemaCount + 1) * discriminatorCalls);
});
