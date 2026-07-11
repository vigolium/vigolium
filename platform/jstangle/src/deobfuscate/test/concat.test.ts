import { parse } from '@babel/parser';
import { describe, expect, test } from 'vitest';
import { applyTransforms, generate } from '../../ast-utils';
import concatToPlus from '../concat-to-plus';
import mergeStrings from '../merge-strings';

function run(code: string): string {
  const ast = parse(code);
  applyTransforms(ast, [concatToPlus, mergeStrings]);
  return generate(ast).replace(/\s+/g, ' ').trim();
}

describe('concat-to-plus receiver guard', () => {
  test('string-literal receiver is converted', () => {
    const out = run('"".concat(a, "/path");');
    expect(out).not.toContain('.concat(');
    expect(out).toContain('a + "/path"');
  });

  test('string-literal receiver folds adjacent literals', () => {
    expect(run('"api".concat("/v1");')).toContain('"api/v1"');
  });

  test('template-literal receiver is converted', () => {
    const out = run('`x`.concat(y);');
    expect(out).not.toContain('.concat(');
  });

  test('`+`-chain string receiver is converted', () => {
    const out = run('("api" + v).concat("/x");');
    expect(out).not.toContain('.concat(');
  });

  test('const string binding receiver is converted via scope', () => {
    const out = run('var p = "/api"; p.concat(x);');
    expect(out).not.toContain('.concat(');
    expect(out).toContain('p + x');
  });

  // Regression: array.concat and array + x are different operations.
  test('array receiver is left untouched', () => {
    expect(run('[1, 2].concat(3);')).toContain('.concat(');
  });

  test('unknown receiver is left untouched', () => {
    expect(run('foo.concat(bar);')).toContain('.concat(');
  });

  test('numeric-binding receiver is left untouched', () => {
    expect(run('var n = 5; n.concat(x);')).toContain('.concat(');
  });

  test('computed .concat access is left untouched', () => {
    expect(run('"a"["concat"](b);')).toContain('concat');
  });

  test('spread argument is left untouched', () => {
    expect(run('"a".concat(...rest);')).toContain('.concat(');
  });
});
