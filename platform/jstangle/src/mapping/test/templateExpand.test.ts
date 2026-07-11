import { describe, expect, test } from 'vitest';
import { expandTemplatePlaceholders } from '../extractors/webpackExtractor';

const LIMITS = { maxAlternativesPerValue: 16, maxTemplateCombinations: 64 };

describe('expandTemplatePlaceholders', () => {
  test('returns the input verbatim when there are no placeholders', () => {
    expect(expandTemplatePlaceholders('/api/users', {}, LIMITS)).toEqual(['/api/users']);
  });

  test('expands a single variable over all its values (no first-value truncation)', () => {
    const out = expandTemplatePlaceholders('${BASE}/users', { BASE: ['/api/v1', '/api/v2'] }, LIMITS);
    expect(out).toEqual(['/api/v1/users', '/api/v2/users']);
  });

  test('resolves by last path segment when the full path is unknown', () => {
    const out = expandTemplatePlaceholders('${this.API_URL}/x', { API_URL: ['/svc'] }, LIMITS);
    expect(out).toEqual(['/svc/x']);
  });

  test('leaves unresolved placeholders intact', () => {
    const out = expandTemplatePlaceholders('${BASE}/${id}', { BASE: ['/api'] }, LIMITS);
    expect(out).toEqual(['/api/${id}']);
  });

  test('produces the cartesian product across multiple variables', () => {
    const out = expandTemplatePlaceholders(
      '${BASE}/${VER}/users',
      { BASE: ['/api', '/svc'], VER: ['v1', 'v2'] },
      LIMITS,
    );
    expect(new Set(out)).toEqual(
      new Set(['/api/v1/users', '/api/v2/users', '/svc/v1/users', '/svc/v2/users']),
    );
  });

  test('caps the cartesian product at maxTemplateCombinations', () => {
    const many = Array.from({ length: 10 }, (_, i) => `a${i}`);
    const out = expandTemplatePlaceholders(
      '${A}/${B}',
      { A: many, B: many },
      { maxAlternativesPerValue: 16, maxTemplateCombinations: 5 },
    );
    expect(out.length).toBeLessThanOrEqual(5);
  });

  test('caps per-placeholder candidates at maxAlternativesPerValue', () => {
    const many = Array.from({ length: 50 }, (_, i) => `/v${i}`);
    const out = expandTemplatePlaceholders('${A}/x', { A: many }, {
      maxAlternativesPerValue: 3,
      maxTemplateCombinations: 64,
    });
    expect(out).toEqual(['/v0/x', '/v1/x', '/v2/x']);
  });

  test('treats `$` in candidate values literally', () => {
    const out = expandTemplatePlaceholders('${A}', { A: ['a$&b'] }, LIMITS);
    expect(out).toEqual(['a$&b']);
  });
});
