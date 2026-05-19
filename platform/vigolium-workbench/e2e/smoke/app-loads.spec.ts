import { test, expect, seedAuth } from '../fixtures';

// Every top-level route should mount without crashing and without unhandled
// React errors. Catches: import-time exceptions, missing default exports,
// theme component import errors, hard 500s on dev. Mirrors the parallel
// suite in vigolium-console — same goal, simpler stack.

const ROUTES = [
  '/',
  '/findings/',
  '/http-records/',
  '/oast-interactions/',
  '/scan/',
  '/scope/',
  '/agentic-scan/',
  '/extensions/',
  '/modules/',
  '/database/',
  '/config/',
  '/ingest/',
  '/settings/',
  '/unauthorized/',
];

test.describe('routes mount cleanly', () => {
  test.beforeEach(async ({ page }) => {
    await seedAuth(page);
  });

  for (const route of ROUTES) {
    test(`renders ${route} without unhandled errors`, async ({ page, consoleErrors }) => {
      const response = await page.goto(route);
      expect(response?.status(), `${route} returned ${response?.status()}`).toBeLessThan(500);
      // Wait for React to finish hydrating + initial effects.
      await page.waitForLoadState('networkidle', { timeout: 10_000 });

      expect(consoleErrors.unhandled, `Unhandled errors on ${route}`).toEqual([]);
      // We don't assert .errors is empty: dev mode logs noisy network 4xx
      // even when the page renders correctly.
    });
  }
});
