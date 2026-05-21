/** Confirm M6: x-refsStack injection cycle detection bypass */
import { OpenAPIParser } from '../../../src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';
import { SchemaModel } from '../../../src/services/models';

const sessionId = '00000000';
const testName = `test_confirm_x_refsstack_injection_cycle_detection_bypass_${sessionId}`;

describe('confirmation', () => {
  test(testName, () => {
    const spec: any = {
      openapi: '3.0.0',
      info: { title: 't', version: '1.0.0' },
      paths: {},
      components: {
        schemas: {
          VictimSchema: {
            type: 'object',
            properties: { apiKey: { type: 'string' }, role: { type: 'string' } },
          },
          AttackSchema: {
            type: 'object',
            properties: {
              victim: {
                $ref: '#/components/schemas/VictimSchema',
                'x-refsStack': Array.from({ length: 1000 }, (_, i) => `#/fake${i}`),
              },
            },
          },
        },
      },
    };

    const parser = new OpenAPIParser(spec, undefined, new AcmeNormalizedOptions({}));
    const attackedRef = spec.components.schemas.AttackSchema.properties.victim;
    const { resolved, refsStack } = parser.deref(attackedRef, [], true);

    expect(refsStack.length).toBeGreaterThan(999);
    expect(resolved['x-circular-ref']).toBe(true);

    const schema = new SchemaModel(
      parser,
      attackedRef,
      '#/components/schemas/VictimSchema',
      new AcmeNormalizedOptions({}),
    );

    expect(schema.isCircular).toBe(true);
    expect(schema.fields).toBeUndefined();
  });
});
