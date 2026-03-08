import * as t from '@babel/types';
import type { Transform } from '../ast-utils';

/**
 * Transform .concat() method calls into binary expressions with + operator.
 * This allows merge-strings transform to then merge adjacent string literals.
 *
 * Examples:
 * - "".concat(a, "/path") → "" + a + "/path"
 * - "hello".concat(" world") → "hello" + " world"
 * - str.concat("a", "b", c) → str + "a" + "b" + c
 */
export default {
  name: 'concat-to-plus',
  tags: ['safe'],
  visitor() {
    return {
      CallExpression: {
        exit(path) {
          const { callee, arguments: args } = path.node;

          // Match pattern: <something>.concat(...)
          if (!t.isMemberExpression(callee)) return;
          if (!t.isIdentifier(callee.property) || callee.property.name !== 'concat') return;

          // Skip if no arguments
          if (args.length === 0) return;

          // Skip if any argument is a SpreadElement - can't convert to +
          if (args.some(arg => t.isSpreadElement(arg))) return;

          // Build binary expression chain: obj + arg1 + arg2 + ...
          let result: t.Expression = callee.object as t.Expression;

          for (const arg of args) {
            if (t.isSpreadElement(arg)) continue; // Already checked, but TypeScript needs this
            result = t.binaryExpression('+', result, arg as t.Expression);
          }

          path.replaceWith(result);
          this.changes++;
        },
      },
    };
  },
} satisfies Transform;
