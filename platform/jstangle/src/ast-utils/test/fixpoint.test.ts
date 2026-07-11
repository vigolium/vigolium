import { parse } from '@babel/parser';
import { describe, expect, test } from 'vitest';
import { applyTransformsToFixpoint, generate } from '..';
import concatToPlus from '../../deobfuscate/concat-to-plus';
import mergeStrings from '../../deobfuscate/merge-strings';

describe('applyTransformsToFixpoint', () => {
  test('folds a nested concat chain and reports pass counts', () => {
    const ast = parse('"a".concat("b").concat("c");');
    const state = applyTransformsToFixpoint(ast, [concatToPlus, mergeStrings]);

    expect(generate(ast).replace(/\s+/g, '')).toContain('"abc"');
    // Converges: the final pass makes zero changes.
    expect(state.passes.at(-1)).toBe(0);
    expect(state.changes).toBeGreaterThan(0);
  });

  test('stops immediately when there is nothing to do', () => {
    const ast = parse('const a = 1;');
    const state = applyTransformsToFixpoint(ast, [concatToPlus, mergeStrings]);
    expect(state.passes).toEqual([0]);
    expect(state.changes).toBe(0);
  });

  test('honors the maxPasses budget', () => {
    const ast = parse('"a".concat(x).concat(y).concat(z);');
    const state = applyTransformsToFixpoint(ast, [concatToPlus, mergeStrings], {
      maxPasses: 1,
    });
    expect(state.passes).toHaveLength(1);
  });

  test('honors an already-passed deadline (runs no passes)', () => {
    const ast = parse('"a".concat("b");');
    const state = applyTransformsToFixpoint(ast, [concatToPlus, mergeStrings], {
      deadline: performance.now() - 1,
    });
    expect(state.passes).toHaveLength(0);
    expect(state.changes).toBe(0);
  });
});
