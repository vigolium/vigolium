import * as t from '@babel/types';
import { isProvablyString, type Transform } from '../ast-utils';

/**
 * Transform String.prototype.concat() calls into binary `+` expressions so the
 * merge-strings transform can fold adjacent string literals.
 *
 * SAFETY: `.concat()` is only rewritten when the receiver is *provably* a
 * string. `array.concat(x)` and `array + x` are entirely different operations
 * (`[1,2].concat(3)` is `[1,2,3]`, but `[1,2] + 3` is the string `"1,23"`), so
 * rewriting an unknown or non-string receiver would corrupt the program. When
 * the receiver type cannot be proven, the call is left untouched.
 *
 * Examples (receiver provably a string):
 * - `"".concat(a, "/path")` → `"" + a + "/path"`
 * - `"hello".concat(" world")` → `"hello" + " world"`
 * - `("api" + v).concat("/x")` → `"api" + v + "/x"`
 *
 * Left untouched:
 * - `[1, 2].concat(3)`
 * - `foo.concat(bar)` (unknown receiver)
 */
export default {
  name: 'concat-to-plus',
  tags: ['safe'],
  minLevel: 'strict',
  // Enable scope so a receiver bound to a constant string (`var p = "/api";
  // p.concat(x)`) can still be resolved. Harmless when merged with a scoped
  // transform; the standalone deobfuscate stage already runs with scope.
  scope: true,
  visitor() {
    return {
      CallExpression: {
        exit(path) {
          const { callee, arguments: args } = path.node;

          // Match pattern: <something>.concat(...)
          if (!t.isMemberExpression(callee)) return;
          if (callee.computed) return;
          if (!t.isIdentifier(callee.property) || callee.property.name !== 'concat') return;

          // Skip if no arguments
          if (args.length === 0) return;

          // Skip if any argument is a SpreadElement - can't convert to +
          if (args.some((arg) => t.isSpreadElement(arg))) return;

          const receiver = callee.object;
          if (!t.isExpression(receiver)) return;

          // Only sound when the receiver is a string: then `.concat` is
          // String.prototype.concat and folds identically to `+`.
          if (!isProvablyString(receiver, path.scope)) return;

          // Build binary expression chain: obj + arg1 + arg2 + ...
          let result: t.Expression = receiver;

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
