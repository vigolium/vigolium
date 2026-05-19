import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

async function loadClient() {
  vi.resetModules();
  return import('../client');
}

afterEach(() => {
  localStorage.clear();
  delete process.env.NEXT_PUBLIC_API_BASE_URL;
});

describe('getBaseUrl', () => {
  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
  });

  it('uses NEXT_PUBLIC_API_BASE_URL when set', async () => {
    process.env.NEXT_PUBLIC_API_BASE_URL = 'http://localhost:9002';
    const { getBaseUrl } = await loadClient();
    expect(getBaseUrl()).toBe('http://localhost:9002');
  });

  it('falls back to window.location.origin when env is unset and no localStorage override', async () => {
    delete process.env.NEXT_PUBLIC_API_BASE_URL;
    const { getBaseUrl } = await loadClient();
    expect(getBaseUrl()).toBe('http://localhost:3002');
  });

  it('localStorage override wins over env', async () => {
    process.env.NEXT_PUBLIC_API_BASE_URL = 'http://localhost:9002';
    localStorage.setItem('vigolium_api_url', 'http://override:1234');
    const { getBaseUrl } = await loadClient();
    expect(getBaseUrl()).toBe('http://override:1234');
  });
});

describe('project UUID localStorage', () => {
  it('round-trips through getProjectUUID/setProjectUUID', async () => {
    const { getProjectUUID, setProjectUUID } = await loadClient();
    setProjectUUID('11111111-2222-3333-4444-555555555555');
    expect(getProjectUUID()).toBe('11111111-2222-3333-4444-555555555555');
  });

  it('clears UUID when set to null', async () => {
    const { getProjectUUID, setProjectUUID } = await loadClient();
    setProjectUUID('abc');
    setProjectUUID(null);
    expect(getProjectUUID()).toBe(null);
  });
});

describe('apiGet — X-Project-UUID header injection', () => {
  // Project bootstrap and public-utility paths must not carry the header.
  // Otherwise a stale localStorage UUID makes /api/projects un-recoverable.
  const exemptPaths = [
    '/server-info',
    '/health',
    '/metrics',
    '/swagger/index.html',
    '/api/projects',
    '/api/projects/stats',
  ];
  const projectScopedPaths = [
    '/api/findings',
    '/api/scan/list',
    '/api/http-records',
  ];

  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
  });

  async function setupClient() {
    const client = await loadClient();
    client.setProjectUUID('proj-uuid-xyz');
    return client;
  }

  it.each(exemptPaths)('does NOT send X-Project-UUID for exempt path %s', async (path) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200 }),
    );
    const { apiGet } = await setupClient();
    await apiGet(path);
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = init?.headers as Record<string, string> | undefined;
    expect(headers?.['X-Project-UUID']).toBeUndefined();
  });

  it.each(projectScopedPaths)('SENDS X-Project-UUID for scoped path %s', async (path) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200 }),
    );
    const { apiGet } = await setupClient();
    await apiGet(path);
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = init?.headers as Record<string, string> | undefined;
    expect(headers?.['X-Project-UUID']).toBe('proj-uuid-xyz');
  });

  it('does not send the header when no project is selected', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200 }),
    );
    const { apiGet, setProjectUUID } = await loadClient();
    setProjectUUID(null);
    await apiGet('/api/findings');
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = init?.headers as Record<string, string> | undefined;
    expect(headers?.['X-Project-UUID']).toBeUndefined();
  });
});

describe('ApiError', () => {
  it('parses error body when the response is not ok', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify({ error: 'forbidden', code: 403, details: 'no access' }), {
        status: 403,
      }),
    );
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new URL('http://localhost:3002/'),
    });
    const { apiGet, ApiError } = await loadClient();
    expect.assertions(3);
    try {
      await apiGet('/api/findings');
    } catch (e) {
      const err = e as InstanceType<typeof ApiError>;
      expect(err).toBeInstanceOf(ApiError);
      expect(err.code).toBe(403);
      expect(err.details).toBe('no access');
    }
  });
});
