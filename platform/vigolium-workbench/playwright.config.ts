import { defineConfig, devices } from '@playwright/test';

const PORT = Number(process.env.E2E_PORT || 3099);
const BASE_URL = process.env.E2E_BASE_URL || `http://localhost:${PORT}`;

// The workbench is a static-export Next.js app. In dev it talks directly to
// the Go backend at NEXT_PUBLIC_API_BASE_URL. The e2e suite never spins up a
// real Go server — every backend call is stubbed via `page.route(...)` from
// e2e/fixtures.ts. Pointing NEXT_PUBLIC_API_BASE_URL at the dev origin keeps
// the absolute URLs the client builds matching the routes we mock.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : [['list'], ['html', { open: 'never' }]],
  timeout: 30_000,
  expect: { timeout: 5_000 },

  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: {
    command: `next dev --turbopack -p ${PORT}`,
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      NEXT_PUBLIC_API_BASE_URL: BASE_URL,
      NEXT_DIST_DIR: '.next-e2e',
    },
  },
});
