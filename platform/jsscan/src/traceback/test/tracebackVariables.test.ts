import { parse } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { traverse } from '../../ast-utils/babel';
import { describe, expect, test } from 'vitest';
import { generate } from '../../ast-utils';
import { tracebackVariables } from '../tracebackVariables';

describe('tracebackVariables - Line-Based Context Extractor', () => {
  // Helper để parse code với source code được inject vào hub
  const parseWithSource = (code: string) => {
    const ast = parse(code, {
      sourceType: 'module',
      plugins: ['typescript'],
      errorRecovery: true
    });
    return ast;
  };

  // Helper function để parse code và lấy NodePath của CallExpression đầu tiên
  const getFirstCallExpressionPath = (code: string): { path: NodePath<t.CallExpression>; sourceCode: string } => {
    const ast = parseWithSource(code);

    let callExprPath: NodePath<t.CallExpression> | undefined = undefined;

    traverse(ast, {
      CallExpression(path) {
        if (!callExprPath) {
          callExprPath = path;
          path.stop();
        }
      }
    });

    if (!callExprPath) {
      throw new Error('No CallExpression found');
    }

    console.log("first call expression:", generate((callExprPath as NodePath<t.CallExpression>).node));
    return { path: callExprPath, sourceCode: code };
  };

  // Helper để lấy CallExpression cụ thể
  const getSpecificCallExpressionPath = (
    code: string,
    matcher: (path: NodePath<t.CallExpression>) => boolean
  ): { path: NodePath<t.CallExpression>; sourceCode: string } => {
    const ast = parseWithSource(code);

    let callExprPath: NodePath<t.CallExpression> | undefined = undefined;

    traverse(ast, {
      CallExpression(path) {
        if (!callExprPath && matcher(path)) {
          callExprPath = path;
          path.stop();
        }
      }
    });

    if (!callExprPath) {
      throw new Error('No matching CallExpression found');
    }

    console.log("matched call expression:", generate((callExprPath as NodePath<t.CallExpression>).node));
    return { path: callExprPath, sourceCode: code };
  };

  test('should return Grep-style formatted output', () => {
    const code = `const x = 5;
const y = x + 3;
console.log(y);`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    // Should have header
    expect(result.code).toContain('TRACEBACK:');
    expect(result.code).toContain('═');

    // Should have context section
    expect(result.code).toContain('[CONTEXT]');
    expect(result.code).toContain('─');

    // Should contain source code with line numbers
    expect(result.code).toContain('const x = 5');
    expect(result.code).toContain('const y = x + 3');
    expect(result.code).toContain('console.log(y)');
  });

  test('should extract literals from context', () => {
    const code = `
function fetchData() {
  const url = "/api/users";
  const endpoint = "https://example.com/api/v1";
  fetch(url);
}`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    // Should find URL literals
    expect(result.literals).toContain('/api/users');
    expect(result.literals).toContain('https://example.com/api/v1');

    // Should have LITERALS section
    expect(result.code).toContain('[LITERALS FOUND]');
  });

  test('should extract function name and param count', () => {
    const code = `
function processData(userId, options, callback) {
  const url = "/api/process";
  fetch(url);
}`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    expect(result.functionName).toBe('processData');
    expect(result.paramCount).toBe(3);
    expect(result.code).toContain('processData(3 params)');
  });

  test('should find call sites for named functions', () => {
    const code = `
function getData(id) {
  return fetch("/api/data/" + id);
}

// First usage
getData(1);

// Second usage
getData(2);

// Third usage
getData(3);`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    // Should find call sites
    expect(result.callSites.length).toBeGreaterThan(0);
    expect(result.code).toContain('[CALL SITES]');
  });

  test('should handle minified code (long single line)', () => {
    const code = `!function(e){var n=e.api;n.get=function(t,r){return fetch("/api/"+t,{headers:r})};n.post=function(t,r,d){return fetch("/api/"+t,{method:"POST",headers:r,body:d})}}(window);`;

    // Find fetch call
    const { path, sourceCode } = getSpecificCallExpressionPath(code, (p) => {
      return t.isIdentifier(p.node.callee) && p.node.callee.name === 'fetch';
    });

    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    // Should still capture context (the whole line since it's minified)
    expect(result.code).toContain('fetch');
    expect(result.code).toContain('/api/');
    expect(result.literals).toContain('/api/');
  });

  test('should track traced variables', () => {
    const code = `
const baseUrl = "/api";
const headers = { "Content-Type": "application/json" };
const options = { headers };
fetch(baseUrl, options);`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    // Should track variable declarations found in context
    expect(result.tracedVariables.has('baseUrl')).toBe(true);
    expect(result.tracedVariables.has('headers')).toBe(true);
    expect(result.tracedVariables.has('options')).toBe(true);
  });

  test('should respect contextLines option', () => {
    const code = `
// Line 1
// Line 2
// Line 3
// Line 4
// Line 5
const x = 1;
// Line 7
// Line 8
// Line 9
// Line 10
console.log(x);
// Line 12
// Line 13
// Line 14
// Line 15`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);

    // With small context
    const result1 = tracebackVariables(path, [], { contextLines: 2, sourceCode });
    console.log('Small context:', result1.code);

    // With large context
    const result2 = tracebackVariables(path, [], { contextLines: 10, sourceCode });
    console.log('Large context:', result2.code);

    // Larger context should have more lines
    expect(result2.code.length).toBeGreaterThan(result1.code.length);
  });

  test('should handle arrow functions', () => {
    const code = `
const processUser = (userId, callback) => {
  const url = "/api/users/" + userId;
  fetch(url).then(callback);
};`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    expect(result.functionName).toBe('processUser');
    expect(result.paramCount).toBe(2);
  });

  test('should handle method definitions', () => {
    const code = `
const api = {
  getUser(id, options) {
    return fetch("/api/users/" + id, options);
  }
};`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    expect(result.functionName).toBe('getUser');
    expect(result.paramCount).toBe(2);
  });

  test('should handle assignment expressions', () => {
    const code = `
api.fetchData = function(endpoint) {
  return fetch("/api/" + endpoint);
};`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    expect(result.functionName).toBe('fetchData');
  });

  test('should handle jQuery ajax patterns', () => {
    const code = `
!function(e) {
  var $ = window.$;
  $.ajax({
    url: "https://api.example.com/data",
    method: "POST",
    data: {key: "value"},
    headers: {"X-Custom-Header": "123"}
  }).done(function(e) {
    console.log(e);
  });
}({});`;

    // Find ajax() call
    const { path, sourceCode } = getSpecificCallExpressionPath(code, (p) => {
      const callee = p.node.callee;
      return t.isMemberExpression(callee) &&
        t.isIdentifier(callee.property) &&
        callee.property.name === 'ajax';
    });

    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    expect(result.code).toContain('$.ajax');
    expect(result.code).toContain('X-Custom-Header');
    expect(result.literals).toContain('https://api.example.com/data');
  });

  test('should handle XMLHttpRequest patterns', () => {
    const code = `
!function(e) {
  var r = new XMLHttpRequest();
  r.open("GET", "https://api.example.com/data", true);
  r.setRequestHeader("Content-Type", "application/json");
  r.onreadystatechange = function() {
    if(r.readyState === 4 && r.status === 200) {
      console.log(r.responseText);
    }
  };
  r.send(JSON.stringify({data: "test"}));
}({});`;

    // Find send() call
    const { path, sourceCode } = getSpecificCallExpressionPath(code, (p) => {
      const callee = p.node.callee;
      return t.isMemberExpression(callee) &&
        t.isIdentifier(callee.property) &&
        callee.property.name === 'send';
    });

    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    expect(result.code).toContain('XMLHttpRequest');
    expect(result.code).toContain('setRequestHeader');
    expect(result.literals).toContain('https://api.example.com/data');
  });

  test('should return empty result when no source code', () => {
    const ast = parse('console.log(1)', {
      sourceType: 'module',
    });

    let callExprPath: NodePath<t.CallExpression> | undefined;
    traverse(ast, {
      CallExpression(path) {
        callExprPath = path;
        path.stop();
      }
    });

    if (!callExprPath) throw new Error('No path');

    // Don't pass sourceCode option - should return empty
    const result = tracebackVariables(callExprPath);
    expect(result.code).toBe('');
    expect(result.literals).toEqual([]);
    expect(result.callSites).toEqual([]);
  });

  test('should handle anonymous functions', () => {
    const code = `
(function() {
  fetch("/api/data");
})();`;

    const { path, sourceCode } = getFirstCallExpressionPath(code);
    const result = tracebackVariables(path, [], { sourceCode });
    console.log(result.code);

    expect(result.code).toContain('<anonymous>');
    expect(result.functionName).toBe('');
  });
});
