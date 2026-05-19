import { test as base, expect, type Page, type Route } from '@playwright/test';

// ──────────────────────────────────────────────────────────────────────────
// Mock backend
// ──────────────────────────────────────────────────────────────────────────
//
// The workbench is the static-export UI. In dev it talks DIRECTLY to the Go
// scan server at NEXT_PUBLIC_API_BASE_URL — there is no Next.js proxy, no
// /api/proxy prefix, no middleware. The e2e suite never boots a real Go
// server; instead `installApiMocks` stubs every endpoint the UI hits via
// `page.route(...)` so pages render their normal "data loaded" state.
//
// Pattern: catch-all FIRST, specific routes after — Playwright matches
// handlers LIFO and we want the specific routes to win.
//
// Tests can override individual routes with `page.route(...)` after this
// returns; a fresh registration takes precedence over what we wired up here.

export const FIXTURE_PROJECT = {
  uuid: 'e2e00000-0000-0000-0000-000000000001',
  name: 'E2E Project',
  description: 'Fixture project used by Playwright',
  is_default: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

export const FIXTURE_PROJECT_2 = {
  uuid: 'e2e00000-0000-0000-0000-000000000002',
  name: 'E2E Project Alt',
  description: 'Second fixture project for switching tests',
  is_default: false,
  created_at: '2026-01-02T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
};

export const FIXTURE_USER = {
  uuid: 'e2e-user-0000',
  name: 'E2E Tester',
  email: 'tester@example.com',
  role: 'admin',
};

export const FIXTURE_API_KEY = 'vgl_e2e_test_api_key_not_real';

const SERVER_INFO = {
  name: 'vigolium',
  version: 'e2e-test',
  author: 'test',
  docs: 'https://vigolium.com',
  uptime: '0s',
  service_addr: 'localhost:9002',
  queue_depth: 0,
  total_records: 0,
  total_findings: 0,
};

const STATS_RESPONSE = {
  http_records: { total: 0 },
  modules: {
    active: { total: 0, enabled: 0 },
    passive: { total: 0, enabled: 0 },
  },
  findings: {
    total: 0,
    by_severity: {},
  },
};

const PROJECT_STATS = {
  http_records: 0,
  findings: 0,
  scans: 0,
  oast_interactions: 0,
};

const EMPTY_PAGE = { data: [], total: 0, limit: 50, offset: 0, has_more: false };

async function jsonRoute(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

export async function installApiMocks(page: Page) {
  // Catch-all: any backend path we don't explicitly stub gets an empty 200
  // instead of a connection refused (no Go server is running).
  // Match both the dev origin and any explicit NEXT_PUBLIC_API_BASE_URL.
  await page.route('**/api/**', (r) => jsonRoute(r, {}));
  await page.route('**/server-info', (r) => jsonRoute(r, SERVER_INFO));
  await page.route('**/health', (r) => jsonRoute(r, { ok: true }));

  // Auth + user
  await page.route('**/api/user/info', (r) => jsonRoute(r, FIXTURE_USER));
  await page.route('**/api/auth/login', async (r) => {
    if (r.request().method() !== 'POST') return jsonRoute(r, {}, 405);
    const body = r.request().postDataJSON() as { username?: string; access_code?: string };
    if (!body?.username || !body?.access_code) {
      return jsonRoute(r, { error: 'username and access_code are required', code: 400 }, 400);
    }
    if (body.access_code === 'wrong') {
      return jsonRoute(r, { error: 'invalid credentials', code: 401 }, 401);
    }
    await jsonRoute(r, {
      token: 'e2e-issued-token',
      user: FIXTURE_USER,
    });
  });

  // Projects
  await page.route('**/api/projects', (r) => jsonRoute(r, [FIXTURE_PROJECT, FIXTURE_PROJECT_2]));
  await page.route('**/api/projects/*/stats', (r) => jsonRoute(r, PROJECT_STATS));
  await page.route('**/api/projects/*', (r) => {
    const url = new URL(r.request().url());
    const uuid = url.pathname.split('/').pop();
    if (uuid === FIXTURE_PROJECT.uuid) return jsonRoute(r, FIXTURE_PROJECT);
    if (uuid === FIXTURE_PROJECT_2.uuid) return jsonRoute(r, FIXTURE_PROJECT_2);
    return jsonRoute(r, { error: 'project not found', code: 404 }, 404);
  });

  // Stats / scans
  await page.route('**/api/stats', (r) => jsonRoute(r, STATS_RESPONSE));
  await page.route('**/api/scan/status', (r) => jsonRoute(r, { status: 'idle' }));
  await page.route('**/api/scans*', (r) => jsonRoute(r, EMPTY_PAGE));

  // Data tables
  await page.route('**/api/findings*', (r) => jsonRoute(r, EMPTY_PAGE));
  await page.route('**/api/http-records*', (r) => jsonRoute(r, EMPTY_PAGE));
  await page.route('**/api/oast-interactions*', (r) => jsonRoute(r, EMPTY_PAGE));

  // Config / scope / modules / extensions
  await page.route('**/api/scope*', (r) =>
    jsonRoute(r, { in_scope: [], out_of_scope: [] }),
  );
  await page.route('**/api/config*', (r) => jsonRoute(r, { config: [] }));
  await page.route('**/api/modules*', (r) =>
    jsonRoute(r, { active: [], passive: [] }),
  );
  await page.route('**/api/extensions/docs*', (r) =>
    jsonRoute(r, { docs: [] }),
  );
  await page.route('**/api/extensions*', (r) =>
    jsonRoute(r, { extensions: [] }),
  );

  // Database explorer
  await page.route('**/api/db/tables', (r) => jsonRoute(r, { tables: [] }));
  await page.route('**/api/db/tables/**', (r) => jsonRoute(r, {}));

  // Agent
  await page.route('**/api/agent/sessions*', (r) => jsonRoute(r, EMPTY_PAGE));
  await page.route('**/api/agent/status/list*', (r) => jsonRoute(r, { runs: [] }));
  await page.route('**/api/agent/status/*', (r) => jsonRoute(r, {}));
}

// ──────────────────────────────────────────────────────────────────────────
// Console-error helper
// ──────────────────────────────────────────────────────────────────────────

export interface ConsoleErrorHook {
  errors: string[];
  unhandled: string[];
}

export function watchConsoleErrors(page: Page): ConsoleErrorHook {
  const hook: ConsoleErrorHook = { errors: [], unhandled: [] };
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return;
    const text = msg.text();
    if (shouldIgnoreError(text)) return;
    hook.errors.push(text);
  });
  page.on('pageerror', (err) => {
    const text = err.message || String(err);
    if (shouldIgnoreError(text)) return;
    hook.unhandled.push(text);
  });
  return hook;
}

const IGNORED_ERROR_PATTERNS: RegExp[] = [
  // Next dev emits this when HMR / RSC probes 404 — irrelevant here.
  /Failed to load resource: the server responded with a status of 404/i,
  // Hot reload websocket noise.
  /WebSocket connection to 'wss?:\/\//i,
  // Source-map loader complaints in dev.
  /Source map .* could not be loaded/i,
];

function shouldIgnoreError(text: string): boolean {
  return IGNORED_ERROR_PATTERNS.some((re) => re.test(text));
}

// ──────────────────────────────────────────────────────────────────────────
// Auth helpers
// ──────────────────────────────────────────────────────────────────────────

// Seed an authenticated session in localStorage so AuthGate skips the login
// form. Pair with `installApiMocks` so /server-info answers 200 and the
// "ready" branch fires.
export async function seedAuth(
  page: Page,
  opts: { token?: string; projectUUID?: string } = {},
) {
  const token = opts.token ?? FIXTURE_API_KEY;
  const projectUUID = opts.projectUUID ?? FIXTURE_PROJECT.uuid;
  await page.addInitScript(
    ({ token, projectUUID, user }) => {
      window.localStorage.setItem('vigolium_api_token', token);
      window.localStorage.setItem('vigolium_project_uuid', projectUUID);
      window.localStorage.setItem('vigolium_user_info', JSON.stringify(user));
    },
    { token, projectUUID, user: FIXTURE_USER },
  );
}

// ──────────────────────────────────────────────────────────────────────────
// Test fixture
// ──────────────────────────────────────────────────────────────────────────

export const test = base.extend<{
  page: Page;
  consoleErrors: ConsoleErrorHook;
}>({
  page: async ({ page }, use) => {
    await installApiMocks(page);
    await use(page);
  },
  consoleErrors: async ({ page }, use) => {
    const hook = watchConsoleErrors(page);
    await use(hook);
  },
});

export { expect };
