import { parse } from '@babel/parser';
import { describe, expect, test } from 'vitest';
import { applyTransforms, generate } from '../../ast-utils';
import { controlFlowObject } from '../control-flow-object';

function run(code: string, allowImpureArgs = false): string {
  const ast = parse(code);
  applyTransforms(ast, [controlFlowObject({ allowImpureArgs })]);
  return generate(ast).replace(/\s+/g, ' ').trim();
}

describe('control-flow-object purity guard', () => {
  test('pure-arg wrappers inline and the object is removed', () => {
    const out = run(`
      var _0xabc = {
        rLxJs: function (a, b) { return a + b; },
        kHAOU: function (a, b) { return a(b); }
      };
      _0xabc.rLxJs(x, y);
      _0xabc.kHAOU(f, z);
    `);
    expect(out).not.toContain('_0xabc');
    expect(out).toContain('x + y');
    expect(out).toContain('f(z)');
  });

  test('order-preserving wrapper inlines even with impure args', () => {
    // `return a(b)` evaluates a then b, exactly once, in order — identical to
    // the call itself, so impure args are safe.
    const out = run(`
      var _0xabc = { rLxJs: function (a, b) { return a(b); } };
      _0xabc.rLxJs(getFn(), side());
    `);
    expect(out).not.toContain('_0xabc');
    expect(out).toContain('getFn()(side())');
  });

  test('logical wrapper with an impure arg is NOT inlined', () => {
    // `return a || b` may skip evaluating `b`; inlining `side()` there would
    // drop or reorder its side effect. The whole object must be left intact.
    const out = run(`
      var _0xdef = { aaaaa: function (a, b) { return a || b; } };
      _0xdef.aaaaa(x, side());
    `);
    expect(out).toContain('_0xdef');
    expect(out).not.toContain('x || side()');
  });

  test('reversed-argument wrapper with impure args is NOT inlined', () => {
    // `return b + a` reverses evaluation order relative to the call.
    const out = run(`
      var _0xdef = { bbbbb: function (a, b) { return b + a; } };
      _0xdef.bbbbb(first(), second());
    `);
    expect(out).toContain('_0xdef');
  });

  test('logical wrapper with pure args still inlines', () => {
    const out = run(`
      var _0xdef = { ccccc: function (a, b) { return a || b; } };
      _0xdef.ccccc(x, y);
    `);
    expect(out).not.toContain('_0xdef');
    expect(out).toContain('x || y');
  });

  test('aggressive mode (allowImpureArgs) inlines the impure logical wrapper', () => {
    const out = run(
      `
      var _0xdef = { aaaaa: function (a, b) { return a || b; } };
      _0xdef.aaaaa(x, side());
    `,
      true,
    );
    expect(out).not.toContain('_0xdef');
    expect(out).toContain('x || side()');
  });
});
