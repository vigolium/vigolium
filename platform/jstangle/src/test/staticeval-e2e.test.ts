import { describe, expect, test } from 'vitest';
import { jstangle } from '../index';

async function urls(code: string): Promise<string[]> {
  const res = await jstangle(code, { profile: 'endpoints' });
  return res.extractedRequests.map((r) => r.url);
}

describe('static value recovery feeds endpoint extraction', () => {
  test('recovers an endpoint hidden behind String.fromCharCode', async () => {
    // "/api/hidden"
    const chars = '/api/hidden'.split('').map((c) => c.charCodeAt(0)).join(', ');
    const found = await urls(`fetch(String.fromCharCode(${chars}));`);
    expect(found.some((u) => u.includes('/api/hidden'))).toBe(true);
  });

  test('recovers an endpoint hidden behind atob', async () => {
    // btoa("/api/secret") === "L2FwaS9zZWNyZXQ="
    const found = await urls('fetch(atob("L2FwaS9zZWNyZXQ="));');
    expect(found.some((u) => u.includes('/api/secret'))).toBe(true);
  });

  test('recovers an endpoint from an eval payload', async () => {
    const found = await urls(`eval("fetch('/api/from-eval')");`);
    expect(found.some((u) => u.includes('/api/from-eval'))).toBe(true);
  });
});
