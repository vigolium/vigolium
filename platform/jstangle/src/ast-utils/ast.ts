import type { Scope } from '@babel/traverse';
import * as t from '@babel/types';

export function getPropName(node: t.Node): string | undefined {
  if (t.isIdentifier(node)) {
    return node.name;
  }
  if (t.isStringLiteral(node)) {
    return node.value;
  }
  if (t.isNumericLiteral(node)) {
    return node.value.toString();
  }
}

/**
 * Returns true when `node` is *provably* a string value under JavaScript
 * semantics, using only syntactic evidence (plus an optional scope for
 * const-binding resolution). Used to gate transforms that are only sound for
 * string receivers, e.g. rewriting `str.concat(x)` to `str + x`.
 *
 * - String and template literals are strings.
 * - `a + b` yields a string whenever *either* operand is provably a string
 *   (the `+` operator coerces the other side to a string).
 * - A constant binding initialized to a provable string is a string.
 *
 * Anything else (unknown identifiers, member reads, calls, numbers) returns
 * false — we never *assume* a value is a string.
 */
export function isProvablyString(
  node: t.Node,
  scope?: Scope,
  depth = 0,
): boolean {
  if (depth > 6) return false;
  if (t.isStringLiteral(node) || t.isTemplateLiteral(node)) return true;
  if (t.isBinaryExpression(node) && node.operator === '+') {
    return (
      (t.isExpression(node.left) && isProvablyString(node.left, scope, depth + 1)) ||
      isProvablyString(node.right, scope, depth + 1)
    );
  }
  if (scope && t.isIdentifier(node)) {
    const binding = scope.getBinding(node.name);
    if (
      binding?.constant &&
      binding.path.isVariableDeclarator() &&
      binding.path.node.init
    ) {
      return isProvablyString(binding.path.node.init, scope, depth + 1);
    }
  }
  return false;
}
