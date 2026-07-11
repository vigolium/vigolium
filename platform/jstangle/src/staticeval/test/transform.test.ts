import { parse } from '@babel/parser';
import { describe, expect, test } from 'vitest';
import { applyTransformsToFixpoint, generate } from '../../ast-utils';
import mergeStrings from '../../deobfuscate/merge-strings';
import staticEval from '../transform';

function run(code: string): string {
  const ast = parse(code);
  applyTransformsToFixpoint(ast, [staticEval, mergeStrings]);
  return generate(ast).replace(/\s+/g, ' ').trim();
}

describe('static-eval folding', () => {
  test('folds String.fromCharCode into a string', () => {
    expect(run('fetch(String.fromCharCode(47, 97, 112, 105));')).toContain('fetch("/api")');
  });

  test('folds atob', () => {
    expect(run('fetch(atob("L2FwaS94"));')).toContain('fetch("/api/x")');
  });

  test('folds the reversed-string idiom', () => {
    expect(run('fetch("ipa/".split("").reverse().join(""));')).toContain('fetch("/api")');
  });

  test('folds a decoder chain then merges with an adjacent literal', () => {
    const out = run('fetch("/api/" + String.fromCharCode(120));');
    expect(out).toContain('"/api/x"');
  });

  test('folds a const-bound string method chain via scope', () => {
    const out = run('var b = "L2FwaS92Mg=="; fetch(atob(b));');
    expect(out).toContain('"/api/v2"');
  });
});

describe('static-eval eval/Function payloads (parsed, not executed)', () => {
  test('inlines a single-expression eval payload', () => {
    const out = run('eval("fetch(\'/api/eval\')");');
    expect(out).toContain("fetch('/api/eval')");
    expect(out).not.toMatch(/eval\(/);
  });

  test('wraps a multi-statement eval payload in an IIFE', () => {
    const out = run('eval("var u = \'/api/u\'; fetch(u);");');
    expect(out).toContain('/api/u');
    expect(out).not.toMatch(/eval\(/);
  });

  test('inlines new Function payload into a function expression', () => {
    const out = run('var f = new Function("a", "return fetch(\'/api/\' + a)");');
    expect(out).toContain("fetch('/api/' + a)");
    expect(out).not.toContain('new Function');
  });
});

describe('static-eval scope safety', () => {
  test('does not fold a shadowed global function', () => {
    const out = run('function atob(x) { return x; } var y = atob("L2FwaQ==");');
    // Local atob is not base64 decode; must stay a call.
    expect(out).toContain('atob("L2FwaQ==")');
  });

  test('does not treat a shadowed String as the namespace', () => {
    const out = run('var String = window.String; String.fromCharCode(47);');
    expect(out).toContain('String.fromCharCode(47)');
  });

  test('does not inline eval when eval is shadowed', () => {
    const out = run('function eval(s){ return s; } eval("fetch(1)");');
    expect(out).toContain('eval("fetch(1)")');
  });
});
