/** Confirm M1: Parseprops Redos */
import type { MDXComponentMeta } from '../../../src/services/types';
import { MarkdownRenderer } from '../../../src/services/MarkdownRenderer';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';

const TestComponent = () => null;

function buildRenderer() {
  return new MarkdownRenderer(
    new AcmeNormalizedOptions({
      allowedMdComponents: {
        'security-definitions': {
          component: TestComponent,
          propsSelector: () => ({}),
        },
      },
    }),
  );
}

function measureMs(fn: () => unknown): number {
  const start = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - start) / 1e6;
}

test('test_confirm_parseprops_redos_00000000', () => {
  const renderer = buildRenderer();
  const benign = '<security-definitions pointer="ok" />';
  const small = `<security-definitions aaaa=${'-'.repeat(4000)} />`;
  const large = `<security-definitions aaaa=${'-'.repeat(12000)} />`;

  const benignMs = measureMs(() => {
    const parts = renderer.renderMdWithComponents(benign);
    expect((parts[0] as MDXComponentMeta).props).toEqual({ pointer: 'ok' });
  });

  const smallMs = measureMs(() => renderer.renderMdWithComponents(small));
  const largeMs = measureMs(() => renderer.renderMdWithComponents(large));

  expect(smallMs).toBeGreaterThan(10);
  expect(largeMs).toBeGreaterThan(100);
  expect(largeMs).toBeGreaterThan(smallMs * 4);
  expect(largeMs).toBeGreaterThan(benignMs * 100);
});
