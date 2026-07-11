import { parseExpression } from '@babel/parser';
import type * as t from '@babel/types';
import { describe, expect, test } from 'vitest';
import { isProvablyString } from '../ast';
import { isPureForInline } from '../inline';

const expr = (code: string): t.Node => parseExpression(code) as t.Node;

describe('isProvablyString', () => {
  test.each([
    ['"x"', true],
    ['`t`', true],
    ['`t${x}`', true],
    ['"a" + x', true],
    ['x + "a"', true],
    ['1 + "a"', true],
    ['a + b', false],
    ['1 + 2', false],
    ['foo', false],
    ['foo.bar', false],
    ['String(x)', false],
  ])('%s → %s', (code, want) => {
    expect(isProvablyString(expr(code))).toBe(want);
  });
});

describe('isPureForInline', () => {
  test.each([
    ['x', true],
    ['"s"', true],
    ['1 + 2', true],
    ['-x', true],
    ['typeof x', true],
    ['a ? b : c', true],
    ['a || b', true],
    ['f()', false],
    ['new C()', false],
    ['obj.prop', false],
    ['x = 1', false],
    ['x++', false],
    ['delete o.x', false],
    ['[a, b]', false],
  ])('%s → %s', (code, want) => {
    expect(isPureForInline(expr(code))).toBe(want);
  });
});
