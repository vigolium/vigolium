import { test, expect, seedAuth, FIXTURE_PROJECT, FIXTURE_PROJECT_2 } from '../fixtures';

// ProjectContext invariants we want to lock in:
//   1. First load with no stored UUID auto-seeds the active project from the
//      /api/projects list (so a fresh tab "just works").
//   2. A stored UUID that no longer exists in the list gets replaced with a
//      live one — otherwise every X-Project-UUID-bearing request 403s and
//      the user is stranded.
//   3. Project-scoped requests carry X-Project-UUID; project bootstrap and
//      utility endpoints don't (matches the unit-test contract in
//      src/api/__tests__/client.test.ts).
//   4. Project bootstrap endpoints (/api/projects, /server-info) MUST NOT
//      receive X-Project-UUID even with a stored UUID — sending it locks
//      users out of recovery if the stored UUID is stale.

test('first load with no stored UUID seeds the project from the API list', async ({ page }) => {
  await page.goto('/');
  await page.waitForLoadState('networkidle');

  await expect
    .poll(async () =>
      page.evaluate(() => window.localStorage.getItem('vigolium_project_uuid')),
    )
    .toBe(FIXTURE_PROJECT.uuid);
});

test('stale stored UUID gets replaced when not in the API list', async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem(
      'vigolium_project_uuid',
      'stale-aaaa-bbbb-cccc-deadbeefdead',
    );
  });

  await page.goto('/findings/');
  await page.waitForLoadState('networkidle');

  await expect
    .poll(async () =>
      page.evaluate(() => window.localStorage.getItem('vigolium_project_uuid')),
    )
    .toBe(FIXTURE_PROJECT.uuid);
});

test('project-scoped requests carry the active X-Project-UUID', async ({ page }) => {
  // Capture every X-Project-UUID value seen on /api/findings calls.
  const seenUUIDs: string[] = [];
  await page.route('**/api/findings*', (r) => {
    const header = r.request().headers()['x-project-uuid'];
    if (header) seenUUIDs.push(header);
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: [], total: 0, limit: 50, offset: 0, has_more: false }),
    });
  });

  // Project A
  await seedAuth(page, { projectUUID: FIXTURE_PROJECT.uuid });
  await page.goto('/findings/');
  await page.waitForLoadState('networkidle');
  expect(seenUUIDs, 'project A UUID should be on the wire').toContain(FIXTURE_PROJECT.uuid);
});

test('a different seeded project produces a different X-Project-UUID', async ({ page }) => {
  const seenUUIDs: string[] = [];
  await page.route('**/api/findings*', (r) => {
    const header = r.request().headers()['x-project-uuid'];
    if (header) seenUUIDs.push(header);
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: [], total: 0, limit: 50, offset: 0, has_more: false }),
    });
  });

  await seedAuth(page, { projectUUID: FIXTURE_PROJECT_2.uuid });
  await page.goto('/findings/');
  await page.waitForLoadState('networkidle');
  expect(seenUUIDs).toContain(FIXTURE_PROJECT_2.uuid);
  expect(seenUUIDs, 'project A UUID must not leak when project B is active').not.toContain(
    FIXTURE_PROJECT.uuid,
  );
});

test('project-bootstrap endpoints never receive X-Project-UUID', async ({ page }) => {
  await seedAuth(page);

  const projectsHeader: (string | undefined)[] = [];
  const serverInfoHeader: (string | undefined)[] = [];

  await page.route('**/api/projects', (r) => {
    projectsHeader.push(r.request().headers()['x-project-uuid']);
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([FIXTURE_PROJECT, FIXTURE_PROJECT_2]),
    });
  });
  await page.route('**/server-info', (r) => {
    serverInfoHeader.push(r.request().headers()['x-project-uuid']);
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ name: 'vigolium' }),
    });
  });

  await page.goto('/');
  await page.waitForLoadState('networkidle');

  expect(projectsHeader.length, '/api/projects should be hit').toBeGreaterThan(0);
  for (const h of projectsHeader) {
    expect(h, '/api/projects must not carry X-Project-UUID').toBeFalsy();
  }
  for (const h of serverInfoHeader) {
    expect(h, '/server-info must not carry X-Project-UUID').toBeFalsy();
  }
});
