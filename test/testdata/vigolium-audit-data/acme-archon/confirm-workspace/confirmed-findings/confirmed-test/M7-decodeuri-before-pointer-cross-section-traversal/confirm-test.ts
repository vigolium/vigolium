/** @jest-environment node */
/** Confirm M7: decodeURIComponent before pointer split enables cross-section traversal */
import { OpenAPIParser } from '../../../src/services/OpenAPIParser';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';

const sessionId = '00000000';
const testName = `test_confirm_decodeuri_before_pointer_cross_section_traversal_${sessionId}`;

describe('confirmation', () => {
  test(testName, () => {
    const spec: any = {
      openapi: '3.0.0',
      info: {
        title: 'Test API',
        version: '1.0.0',
        description: '<script>alert(1)</script> ATTACKER_CONTROLLED_CONTENT',
      },
      paths: {},
      components: {
        schemas: {
          SafeSchema: {
            type: 'object',
            properties: { id: { type: 'integer' } },
          },
        },
      },
    };

    const parser = new OpenAPIParser(spec, undefined, new AcmeNormalizedOptions({}));
    const baseline = parser.byRef<any>('#/components/schemas/SafeSchema');
    const attacked = parser.byRef<any>('#/info%2Fdescription');
    const derefResult = parser.deref({ $ref: '#/info%2Fdescription' } as any, [], true);

    expect(baseline.type).toBe('object');
    expect(typeof attacked).toBe('string');
    expect(attacked).toContain('ATTACKER_CONTROLLED_CONTENT');
    expect(derefResult.resolved).toBe(attacked);
    expect(typeof derefResult.resolved).toBe('string');
    expect(() => parser.deref({ $ref: '#/info%2Fdescription' } as any, [], true)).not.toThrow();
  });
});
