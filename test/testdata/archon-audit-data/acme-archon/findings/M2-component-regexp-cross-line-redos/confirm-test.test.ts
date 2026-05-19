/** Confirm M2: Component Regexp Cross Line Redos */
import { MarkdownRenderer } from '../../../src/services/MarkdownRenderer';
import { AcmeNormalizedOptions } from '../../../src/services/AcmeNormalizedOptions';

const sessionShortId = '00000000';
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

function makePayload(size: number): string {
  return '<security-definitions ' + '>a'.repeat(Math.floor(size / 2));
}

test('test_confirm_component_regexp_cross_line_redos_' + sessionShortId, () => {
  const renderer = buildRenderer();
  const benign = '<security-definitions pointer="ok" />';
  const medium = makePayload(15000);
  const large = makePayload(60000);

  const benignMs = measureMs(() => renderer.renderMdWithComponents(benign));
  const mediumMs = measureMs(() => renderer.renderMdWithComponents(medium));
  const largeMs = measureMs(() => renderer.renderMdWithComponents(large));

  expect(benignMs).toBeLessThan(20);
  expect(mediumMs).toBeGreaterThan(5);
  expect(largeMs).toBeGreaterThan(100);
  expect(largeMs).toBeGreaterThan(mediumMs * 8);
  expect(largeMs).toBeGreaterThan(benignMs * 20);
});
