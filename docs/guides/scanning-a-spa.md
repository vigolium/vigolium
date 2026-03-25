# Scanning a Single-Page Application (SPA)

## Overview

Single-page applications built with frameworks like React, Angular, or Vue render content dynamically in the browser. Traditional crawlers that parse raw HTML will miss most endpoints because routes, API calls, and UI interactions are driven by JavaScript. Vigolium addresses this with browser-based spidering that executes JavaScript and captures network traffic as it navigates the application.

## How Vigolium Handles SPAs

Vigolium's browser-based spidering engine (Spitolas) uses Chromium via the Chrome DevTools Protocol (CDP) to:

- **Render JavaScript**: Pages are fully rendered in a headless browser, allowing Vigolium to discover routes that only exist after JS execution.
- **Capture network traffic**: All HTTP requests made by the application (XHR, fetch, WebSocket upgrades) are intercepted via CDP and fed into the scanner as inputs.
- **Interact with the DOM**: The spider clicks buttons, fills forms, and triggers UI events to discover endpoints behind user interactions.
- **Extract client-side routes**: SPA router configurations and navigation links are identified even when they do not result in full page loads.

## Running a SPA Scan

The default `balanced` strategy includes browser spidering automatically:

```bash
vigolium scan -t https://spa.example.com
```

For deeper coverage, use the `deep` strategy which increases spidering depth and interaction aggressiveness:

```bash
vigolium scan -t https://spa.example.com --strategy deep
```

If you only want the spidering phase (e.g., for reconnaissance), isolate it with `--only`:

```bash
vigolium scan -t https://spa.example.com --only spidering
```

## Browser Requirements

Vigolium requires a Chromium-based browser for spidering. On first use, it automatically downloads a compatible Chromium binary. No manual installation is needed in most cases.

For environments where auto-download is not possible (air-gapped systems, containers), you can:

1. Pre-install Chromium and point Vigolium to it via the `browser.executable_path` config option.
2. Build an embedded binary that bundles Chromium:
   ```bash
   make deps-chrome && make build-embedded
   ```

To verify the browser is available:

```bash
vigolium scan -t https://example.com --only spidering --dry-run
```

## Tuning Spidering

Spidering behavior is configurable via `vigolium-configs.yaml` or CLI flags:

```yaml
spidering:
  max_depth: 5          # Maximum navigation depth from the entry point
  max_pages: 100        # Maximum number of pages to visit
  max_duration: 300     # Timeout in seconds for the spidering phase
  interaction:
    click_buttons: true  # Click discovered buttons
    fill_forms: true     # Auto-fill and submit forms
    scroll: true         # Scroll pages to trigger lazy loading
```

For large SPAs, increase `max_pages` and `max_depth` to ensure full coverage. For quick assessments, reduce them to keep scan times short.

## Common Issues

### Browser Not Found

If you see an error about a missing browser executable:

- Ensure you have internet access for the auto-download, or set `browser.executable_path` to a local Chromium installation.
- In Docker containers, use the embedded build or install Chromium in the image.

### Timeouts

SPAs with heavy client-side rendering or slow APIs may cause page load timeouts:

- Increase the page timeout via `spidering.page_timeout` in the config.
- Ensure the target application is responsive and accessible from the scanner host.

### Headless Detection

Some applications block headless browsers. Vigolium applies common evasion techniques by default, but if the application still blocks requests:

- Try setting `browser.headless: false` for headed mode (requires a display server or Xvfb).
- Use a custom user agent via `browser.user_agent` in the config.
- Consider feeding pre-recorded traffic (HAR, Burp XML) as input instead of relying on live spidering.
