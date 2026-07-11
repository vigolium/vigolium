import { parseExpression } from '@babel/parser';
import type * as t from '@babel/types';
import { describe, expect, test } from 'vitest';
import { tryEvaluate } from '../evaluate';

function ev(code: string): unknown {
  const node = parseExpression(code) as t.Node;
  const r = tryEvaluate(node);
  return r ? r.value : Symbol.for('UNRESOLVED');
}

const UNRESOLVED = Symbol.for('UNRESOLVED');

describe('tryEvaluate — primitives & operators', () => {
  test.each([
    ['"a" + "b"', 'ab'],
    ['1 + 2', 3],
    ['2 * 3 + 1', 7],
    ['0x2f', 0x2f],
    ['-5', -5],
    ['!0', true],
    ['true ? "y" : "n"', 'y'],
    ['1 > 2 ? "a" : "b"', 'b'],
    ['"x" && "y"', 'y'],
    ['0 || "fallback"', 'fallback'],
    ['null ?? "d"', 'd'],
    ['`/api/${1 + 1}/x`', '/api/2/x'],
    ['typeof "s"', 'string'],
  ])('%s → %o', (code, want) => {
    expect(ev(code)).toEqual(want);
  });
});

describe('tryEvaluate — decoders', () => {
  test('String.fromCharCode', () => {
    expect(ev('String.fromCharCode(47, 97, 112, 105)')).toBe('/api');
  });

  test('reversed-string idiom', () => {
    expect(ev('"ipa/".split("").reverse().join("")')).toBe('/api');
  });

  test('atob base64', () => {
    // btoa("/api/v1/users") === "L2FwaS92MS91c2Vycw=="
    expect(ev('atob("L2FwaS92MS91c2Vycw==")')).toBe('/api/v1/users');
  });

  test('decodeURIComponent', () => {
    expect(ev('decodeURIComponent("%2Fapi%2Fx")')).toBe('/api/x');
  });

  test('literal string methods', () => {
    expect(ev('"/API/USERS".toLowerCase()')).toBe('/api/users');
    expect(ev('"api".concat("/", "v2")')).toBe('api/v2');
    expect(ev('"/a/b/c".slice(0, 2)')).toBe('/a');
    expect(ev('"x".repeat(3)')).toBe('xxx');
  });

  test('JSON.parse of literal', () => {
    expect(ev('JSON.parse(\'{"path":"/api/x"}\')')).toEqual({ path: '/api/x' });
    expect(ev('JSON.parse(\'"just-a-string"\')')).toBe('just-a-string');
  });

  test('parseInt / Number', () => {
    expect(ev('parseInt("0x1a")')).toBe(26);
    expect(ev('Number("42")')).toBe(42);
  });

  test('Math methods', () => {
    expect(ev('Math.max(1, 7, 3)')).toBe(7);
  });
});

describe('tryEvaluate — refuses the unknowable', () => {
  test.each([
    'foo',
    'foo()',
    'obj.bar',
    'window.location',
    'fetch("/x")',
    'a + b',
    'Date.now()',
    'require("fs")',
  ])('%s → unresolved', (code) => {
    expect(ev(code)).toBe(UNRESOLVED);
  });

  test('shadowed global is not folded', () => {
    // `atob` here is a call, but tryEvaluate has no scope, so it treats atob as
    // the global. With scope binding present the transform-level test covers
    // shadowing; here we assert a non-base64 arg is rejected.
    expect(ev('atob("not valid base64 !!!")')).toBe(UNRESOLVED);
  });
});
