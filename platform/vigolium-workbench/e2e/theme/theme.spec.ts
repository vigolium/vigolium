import { test, expect, seedAuth } from '../fixtures';

// Every page has parallel dark/ + light/ implementations under src/designs/.
// Route components branch on `useTheme().themeId === 'dark' ? <DarkX/> : <LightX/>`.
// This suite checks both branches mount on a representative subset of routes
// without unhandled errors — catches missing default exports, broken imports,
// and CSS-var application errors in the light tree (which is exercised less
// often during local dev).

const DARK_SCHEME = 'default-dark';
const LIGHT_SCHEME = 'default-light';

const ROUTES = ['/', '/findings/', '/http-records/', '/settings/', '/database/', '/ingest/'];

async function seedTheme(page: import('@playwright/test').Page, schemeId: string) {
  await page.addInitScript((id) => {
    window.localStorage.setItem('vigolium_scheme', id);
  }, schemeId);
}

test.describe('dark theme', () => {
  test.beforeEach(async ({ page }) => {
    await seedAuth(page);
    await seedTheme(page, DARK_SCHEME);
  });

  for (const route of ROUTES) {
    test(`${route} renders the dark variant cleanly`, async ({ page, consoleErrors }) => {
      await page.goto(route);
      await page.waitForLoadState('networkidle');
      const stored = await page.evaluate(() => window.localStorage.getItem('vigolium_scheme'));
      expect(stored).toBe(DARK_SCHEME);
      expect(consoleErrors.unhandled, `Unhandled errors on ${route}`).toEqual([]);
    });
  }
});

test.describe('light theme', () => {
  test.beforeEach(async ({ page }) => {
    await seedAuth(page);
    await seedTheme(page, LIGHT_SCHEME);
  });

  for (const route of ROUTES) {
    test(`${route} renders the light variant cleanly`, async ({ page, consoleErrors }) => {
      await page.goto(route);
      await page.waitForLoadState('networkidle');
      const stored = await page.evaluate(() => window.localStorage.getItem('vigolium_scheme'));
      expect(stored).toBe(LIGHT_SCHEME);
      expect(consoleErrors.unhandled, `Unhandled errors on ${route}`).toEqual([]);
    });
  }
});

test('dark and light schemes apply distinct CSS vars on the document root', async ({
  browser,
}) => {
  // Use two separate browser contexts so each gets its own init-script
  // sequence. Driving this through a single page + reload doesn't work —
  // `addInitScript` runs on every navigation and would clobber a mid-test
  // localStorage write.
  const darkContext = await browser.newContext();
  const lightContext = await browser.newContext();
  try {
    const darkPage = await darkContext.newPage();
    const lightPage = await lightContext.newPage();

    const { installApiMocks } = await import('../fixtures');
    await installApiMocks(darkPage);
    await installApiMocks(lightPage);

    await seedAuth(darkPage);
    await seedTheme(darkPage, DARK_SCHEME);
    await seedAuth(lightPage);
    await seedTheme(lightPage, LIGHT_SCHEME);

    await darkPage.goto('/');
    await darkPage.waitForLoadState('networkidle');
    await lightPage.goto('/');
    await lightPage.waitForLoadState('networkidle');

    const darkBg = await darkPage.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue('--v-bg').trim(),
    );
    const lightBg = await lightPage.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue('--v-bg').trim(),
    );

    expect(darkBg, 'dark scheme should set --v-bg').not.toBe('');
    expect(lightBg, 'light scheme should set --v-bg').not.toBe('');
    expect(lightBg, 'light scheme must produce a different --v-bg than dark').not.toBe(
      darkBg,
    );
  } finally {
    await darkContext.close();
    await lightContext.close();
  }
});
