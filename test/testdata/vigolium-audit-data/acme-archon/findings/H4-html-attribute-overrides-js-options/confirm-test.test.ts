/** Confirm H4: Html Attribute Overrides Js Options */
import { argValueToBoolean } from '../../../src/services/AcmeNormalizedOptions';

const renderMock = jest.fn();
let capturedRootArg: any;

(globalThis as any).__ACME_VERSION__ = 'test';
(globalThis as any).__ACME_REVISION__ = 'test';

jest.mock('react-dom/client', () => ({
  ...jest.requireActual('react-dom/client'),
  createRoot: (arg: any) => {
    capturedRootArg = arg;
    return { render: renderMock, unmount: jest.fn() };
  },
  hydrateRoot: jest.fn(),
}));

import { init } from '../../../src/standalone';

describe('confirm H4 html attribute overrides js options', () => {
  test('test_confirm_html_attribute_overrides_js_options_00000000', () => {
    document.body.innerHTML = '<acme sanitize="false"></acme>';
    const element = document.querySelector('acme')!;

    init('https://example.test/openapi.yaml', { sanitize: true }, element);

    expect(capturedRootArg).toBe(element);
    expect(renderMock).toHaveBeenCalled();

    const renderedElement = renderMock.mock.calls[0][0];
    const mergedOptions = renderedElement.props.options;

    expect(mergedOptions.sanitize).toBe('false');
    expect(argValueToBoolean(mergedOptions.sanitize)).toBe(false);
  });
});
