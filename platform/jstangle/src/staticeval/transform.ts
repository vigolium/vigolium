import { parse } from '@babel/parser';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type { Transform } from '../ast-utils';
import { tryEvaluate, tryEvaluateString, type StaticValue } from './evaluate';

/**
 * Static value recovery: fold pure, statically-knowable expressions to literals
 * so downstream request extraction sees the real endpoint strings hidden behind
 * `String.fromCharCode`, base64/URI decoding, reversed-string idioms, literal
 * string/array methods, constant folding, and `JSON.parse` of literals.
 *
 * It also *parses* (never executes) literal `eval("…")` and
 * `new Function("…")` payloads back into AST so their bodies can be scanned.
 * The rewritten AST is an analysis artifact, not a program that gets run.
 *
 * Every fold is a side-effect-free operation, so this transform is `strict`.
 */

const MAX_PAYLOAD_SOURCE = 200_000;

/**
 * Only scalar results are materialized back into the AST. We deliberately do
 * NOT fold recovered objects/arrays (e.g. from `JSON.parse`): the request-body,
 * GraphQL, and value-tracking extractors walk those structures symbolically, so
 * collapsing them to an object literal would fight, not help, extraction. The
 * high-value recovery target is hidden *strings* (and the occasional number).
 */
function isScalar(value: StaticValue): value is string | number | boolean | null {
  if (value === null) return true;
  if (typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  return false;
}

function foldScalar(path: NodePath, value: StaticValue): boolean {
  if (!isScalar(value)) return false;
  try {
    path.replaceWith(t.valueToNode(value));
    return true;
  } catch {
    return false;
  }
}

/** Parse a recovered `eval` / `Function` payload string into statements. */
function parsePayload(source: string): t.Statement[] | null {
  if (source.length > MAX_PAYLOAD_SOURCE) return null;
  try {
    const file = parse(source, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      errorRecovery: false,
      plugins: ['jsx'],
    });
    return file.program.body;
  } catch {
    return null;
  }
}

/** Replace a recovered `eval("…")` call with its parsed payload (not executed). */
function inlineEvalPayload(path: NodePath<t.CallExpression>): boolean {
  const callee = path.node.callee;
  if (!t.isIdentifier(callee, { name: 'eval' })) return false;
  if (path.scope.getBinding('eval')) return false;
  if (path.node.arguments.length !== 1) return false;
  const arg = path.node.arguments[0];
  if (!t.isExpression(arg)) return false;
  const source = tryEvaluateString(arg, { scope: path.scope });
  if (source === undefined) return false;

  const body = parsePayload(source);
  if (!body) return false;

  let replacement: t.Expression;
  if (body.length === 1 && t.isExpressionStatement(body[0])) {
    replacement = body[0].expression;
  } else {
    // Keep it a valid expression the extractors can still walk into.
    replacement = t.callExpression(
      t.arrowFunctionExpression([], t.blockStatement(body)),
      [],
    );
  }
  t.addComment(replacement, 'leading', ' jstangle:eval-payload ');
  path.replaceWith(replacement);
  path.skip();
  return true;
}

/** Replace a recovered `new Function("a,b", "body")` with a function expression. */
function inlineFunctionConstructor(
  path: NodePath<t.CallExpression | t.NewExpression>,
): boolean {
  const callee = path.node.callee;
  if (!t.isIdentifier(callee, { name: 'Function' })) return false;
  if (path.scope.getBinding('Function')) return false;

  const parts: string[] = [];
  for (const a of path.node.arguments) {
    if (!t.isExpression(a)) return false;
    const s = tryEvaluateString(a, { scope: path.scope });
    if (s === undefined) return false;
    parts.push(s);
  }
  const bodySource = parts.length ? parts[parts.length - 1] : '';
  const params = parts.slice(0, -1).join(',');
  const wrapped = parsePayload(`(function(${params}){${bodySource}})`);
  if (!wrapped || wrapped.length !== 1 || !t.isExpressionStatement(wrapped[0])) {
    return false;
  }
  const fn = wrapped[0].expression;
  if (!t.isFunctionExpression(fn)) return false;
  t.addComment(fn, 'leading', ' jstangle:function-payload ');
  path.replaceWith(fn);
  path.skip();
  return true;
}

export default {
  name: 'static-eval',
  tags: ['safe'],
  minLevel: 'strict',
  scope: true,
  visitor() {
    return {
      CallExpression: {
        exit(path) {
          if (inlineEvalPayload(path)) {
            this.changes++;
            return;
          }
          if (inlineFunctionConstructor(path)) {
            this.changes++;
            return;
          }
          const r = tryEvaluate(path.node, { scope: path.scope });
          if (r && foldScalar(path, r.value)) this.changes++;
        },
      },
      NewExpression: {
        exit(path) {
          if (inlineFunctionConstructor(path)) this.changes++;
        },
      },
      // Fold only to strings here to avoid churning unrelated numeric arithmetic.
      TemplateLiteral: {
        exit(path) {
          if (path.node.expressions.length === 0) return;
          const s = tryEvaluateString(path.node, { scope: path.scope });
          if (s !== undefined && foldScalar(path, s)) this.changes++;
        },
      },
      BinaryExpression: {
        exit(path) {
          const s = tryEvaluateString(path.node, { scope: path.scope });
          if (s !== undefined && foldScalar(path, s)) this.changes++;
        },
      },
    };
  },
} satisfies Transform;
