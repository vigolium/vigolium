import type { Binding, NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { traverse } from './babel';
import * as m from '@codemod/matchers';
import { getPropName } from '.';
import { findParent } from './matcher';

/**
 * Replace all references of a variable with the initializer.
 * Example:
 * `const a = 1; console.log(a);` -> `console.log(1);`
 *
 * Example with `unsafeAssignments` being `true`:
 * `let a; a = 2; console.log(a);` -> `console.log(2);`
 *
 * @param unsafeAssignments Also inline assignments to the variable (not guaranteed to be the final value)
 */
export function inlineVariable(
  binding: Binding,
  value = m.anyExpression(),
  unsafeAssignments = false,
) {
  const varDeclarator = binding.path.node;
  const varMatcher = m.variableDeclarator(
    m.identifier(binding.identifier.name),
    value,
  );
  const assignmentMatcher = m.assignmentExpression(
    '=',
    m.identifier(binding.identifier.name),
    value,
  );

  if (binding.constant && varMatcher.match(varDeclarator)) {
    binding.referencePaths.forEach((ref) => {
      ref.replaceWith(varDeclarator.init!);
    });
    binding.path.remove();
  } else if (unsafeAssignments && binding.constantViolations.length >= 1) {
    const assignments = binding.constantViolations
      .map((path) => path.node)
      .filter((node) => assignmentMatcher.match(node));
    if (!assignments.length) return;

    function getNearestAssignment(location: number) {
      return assignments.findLast((assignment) => assignment.start! < location);
    }

    for (const ref of binding.referencePaths) {
      const assignment = getNearestAssignment(ref.node.start!);
      if (assignment) ref.replaceWith(assignment.right);
    }

    for (const path of binding.constantViolations) {
      if (path.parentPath?.isExpressionStatement()) {
        path.remove();
      } else if (path.isAssignmentExpression()) {
        path.replaceWith(path.node.right);
      }
    }

    binding.path.remove();
  }
}

/**
 * Make sure the array is immutable and references are valid before using!
 *
 * Example:
 * `const arr = ["foo", "bar"]; console.log(arr[0]);` -> `console.log("foo");`
 */
export function inlineArrayElements(
  array: t.ArrayExpression,
  references: NodePath[],
): void {
  for (const reference of references) {
    const memberPath = reference.parentPath! as NodePath<t.MemberExpression>;
    const property = memberPath.node.property as t.NumericLiteral;
    const index = property.value;
    const replacement = array.elements[index]!;
    memberPath.replaceWith(t.cloneNode(replacement));
  }
}

export function inlineObjectProperties(
  binding: Binding,
  property = m.objectProperty(),
): void {
  const varDeclarator = binding.path.node;
  const objectProperties = m.capture(m.arrayOf(property));
  const varMatcher = m.variableDeclarator(
    m.identifier(binding.identifier.name),
    m.objectExpression(objectProperties),
  );
  if (!varMatcher.match(varDeclarator)) return;

  const propertyMap = new Map(
    objectProperties.current!.map((p) => [getPropName(p.key), p.value]),
  );
  if (
    !binding.referencePaths.every((ref) => {
      const member = ref.parent as t.MemberExpression;
      const propName = getPropName(member.property)!;
      return propertyMap.has(propName);
    })
  )
    return;

  binding.referencePaths.forEach((ref) => {
    const memberPath = ref.parentPath as NodePath<t.MemberExpression>;
    const propName = getPropName(memberPath.node.property)!;
    const value = propertyMap.get(propName)!;

    memberPath.replaceWith(value);
  });

  binding.path.remove();
}

/**
 * Conservative purity check for an expression that would be substituted into a
 * caller during function inlining. Returns true only when re-ordering,
 * duplicating, or dropping the expression is guaranteed to be observationally
 * equivalent to evaluating it once — i.e. it has no side effects and its value
 * cannot change between evaluations at the same program point.
 *
 * Deliberately strict: calls, `new`, assignments/updates, `await`/`yield`,
 * `delete`, and member reads (potential getters/proxies) are all treated as
 * impure.
 */
export function isPureForInline(node: t.Node): boolean {
  switch (node.type) {
    case 'StringLiteral':
    case 'NumericLiteral':
    case 'BooleanLiteral':
    case 'NullLiteral':
    case 'BigIntLiteral':
    case 'DecimalLiteral':
    case 'RegExpLiteral':
    case 'Identifier':
    case 'ThisExpression':
      return true;
    case 'TemplateLiteral':
      return node.expressions.every((e) => isPureForInline(e as t.Node));
    case 'UnaryExpression':
      return node.operator !== 'delete' && isPureForInline(node.argument);
    case 'BinaryExpression':
      return (
        node.operator !== 'in' &&
        node.operator !== 'instanceof' &&
        t.isExpression(node.left) &&
        isPureForInline(node.left) &&
        isPureForInline(node.right)
      );
    case 'LogicalExpression':
      return isPureForInline(node.left) && isPureForInline(node.right);
    case 'ConditionalExpression':
      return (
        isPureForInline(node.test) &&
        isPureForInline(node.consequent) &&
        isPureForInline(node.alternate)
      );
    default:
      return false;
  }
}

/**
 * A control-flow wrapper is "order-preserving" when its body references every
 * parameter exactly once, in declaration order, and never inside a branch that
 * may be short-circuited (right side of `&&`/`||`/`??`, either arm of `?:`).
 *
 * When that holds, inlining `f(x, y, z)` produces an expression whose sub-terms
 * evaluate `x` then `y` then `z`, exactly once each — identical to how the call
 * itself would have evaluated its arguments. Inlining is then sound even for
 * impure arguments.
 */
function isOrderPreservingWrapper(
  fn: t.FunctionExpression | t.FunctionDeclaration,
): boolean {
  if (!fn.params.every((p) => t.isIdentifier(p))) return false;
  const names = fn.params.map((p) => (p as t.Identifier).name);
  const nameSet = new Set(names);
  const body = fn.body.body;
  if (body.length !== 1 || !t.isReturnStatement(body[0]) || !body[0].argument) {
    return false;
  }

  const seq: string[] = [];
  let bad = false;
  const walk = (node: t.Node | null | undefined, conditional: boolean): void => {
    if (!node || bad) return;
    if (t.isIdentifier(node)) {
      if (nameSet.has(node.name)) {
        if (conditional) bad = true;
        else seq.push(node.name);
      }
      return;
    }
    if (t.isLogicalExpression(node)) {
      walk(node.left, conditional);
      walk(node.right, true);
      return;
    }
    if (t.isConditionalExpression(node)) {
      walk(node.test, conditional);
      walk(node.consequent, true);
      walk(node.alternate, true);
      return;
    }
    // Member/optional-member reads or nested functions can hide or reorder
    // parameter evaluation; refuse to treat them as order-preserving.
    if (t.isFunction(node)) {
      bad = true;
      return;
    }
    for (const key of t.VISITOR_KEYS[node.type] ?? []) {
      const child = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) {
        for (const c of child) if (t.isNode(c)) walk(c, conditional);
      } else if (t.isNode(child)) {
        walk(child, conditional);
      }
    }
  };
  walk(body[0].argument, false);
  if (bad) return false;
  if (seq.length !== names.length) return false;
  for (let i = 0; i < names.length; i++) if (seq[i] !== names[i]) return false;
  return true;
}

/**
 * Decide whether `inlineFunction(fn, caller)` is semantics-preserving.
 *
 * Safe when:
 * - the wrapper is the `function (a, ...b) { return a(...b) }` spread form, or
 * - every caller argument is pure (`isPureForInline`), or
 * - the wrapper is order-preserving (`isOrderPreservingWrapper`), or
 * - `allowImpureArgs` is set (aggressive rewrite level opts into changing
 *   obscure evaluation-order/short-circuit semantics).
 *
 * Callers must treat a `false` result as "leave this call site alone".
 */
export function canInlineFunction(
  fn: t.FunctionExpression | t.FunctionDeclaration,
  caller: NodePath<t.CallExpression>,
  allowImpureArgs = false,
): boolean {
  // `function (a, ...b) { return a(...b) }` — arguments are forwarded in order,
  // each evaluated once, so it is always order-preserving.
  if (t.isRestElement(fn.params[1])) return true;

  const body = fn.body.body;
  if (body.length !== 1 || !t.isReturnStatement(body[0]) || !body[0].argument) {
    return false;
  }

  const args = caller.node.arguments;
  // Any non-expression argument (spread, etc.) cannot be positionally
  // substituted; a mismatched arity would substitute `undefined`.
  if (args.length !== fn.params.length) return false;
  if (args.some((a) => !t.isExpression(a))) return false;

  if (args.every((a) => isPureForInline(a as t.Node))) return true;
  if (allowImpureArgs) return true;
  return isOrderPreservingWrapper(fn);
}

/**
 * Inline function used in control flow flattening (that only returns an expression)
 * Example:
 * fn: `function (a, b) { return a(b) }`
 * caller: `fn(a, 1)`
 * ->
 * `a(1)`
 */
export function inlineFunction(
  fn: t.FunctionExpression | t.FunctionDeclaration,
  caller: NodePath<t.CallExpression>,
): void {
  if (t.isRestElement(fn.params[1])) {
    caller.replaceWith(
      t.callExpression(
        caller.node.arguments[0] as t.Identifier,
        caller.node.arguments.slice(1),
      ),
    );
    return;
  }

  const returnedValue = (fn.body.body[0] as t.ReturnStatement).argument!;
  const clone = t.cloneNode(returnedValue, true);

  // Inline all arguments
  traverse(clone, {
    Identifier(path) {
      const paramIndex = fn.params.findIndex(
        (p) => (p as t.Identifier).name === path.node.name,
      );
      if (paramIndex !== -1) {
        path.replaceWith(caller.node.arguments[paramIndex]);
        path.skip();
      }
    },
    noScope: true,
  });

  caller.replaceWith(clone);
}

/**
 * Example:
 * `function alias(a, b) { return decode(b - 938, a); } alias(1071, 1077);`
 * ->
 * `decode(1077 - 938, 1071)`
 */
export function inlineFunctionAliases(binding: Binding): { changes: number } {
  const state = { changes: 0 };
  const refs = [...binding.referencePaths];
  for (const ref of refs) {
    const fn = findParent(ref, m.functionDeclaration());

    // E.g. alias
    const fnName = m.capture(m.anyString());
    // E.g. decode(b - 938, a)
    const returnedCall = m.capture(
      m.callExpression(
        m.identifier(binding.identifier.name),
        m.anyList(m.slice({ min: 2 })),
      ),
    );
    const matcher = m.functionDeclaration(
      m.identifier(fnName),
      m.anyList(m.slice({ min: 2 })),
      m.blockStatement([m.returnStatement(returnedCall)]),
    );

    if (fn && matcher.match(fn.node)) {
      // Avoid false positives of functions that return a string
      // It's only a wrapper if the function's params are used in the decode call
      const paramUsedInDecodeCall = fn.node.params.some((param) => {
        const binding = fn.scope.getBinding((param as t.Identifier).name);
        return binding?.referencePaths.some((ref) =>
          ref.findParent((p) => p.node === returnedCall.current),
        );
      });
      if (!paramUsedInDecodeCall) continue;

      const fnBinding = fn.scope.parent.getBinding(fnName.current!);
      if (!fnBinding) continue;
      // Check all further aliases (`function alias2(a, b) { return alias(a - 1, b + 3); }`)
      const fnRefs = fnBinding.referencePaths;
      refs.push(...fnRefs);

      // E.g. [alias(1071, 1077), alias(1, 2)]
      const callRefs = fnRefs
        .filter(
          (ref) =>
            t.isCallExpression(ref.parent) &&
            t.isIdentifier(ref.parent.callee, { name: fnName.current! }),
        )
        .map((ref) => ref.parentPath!) as NodePath<t.CallExpression>[];

      // All-or-nothing: only inline (and remove the wrapper) when every call
      // site can be inlined without altering evaluation order/short-circuiting.
      // Otherwise a leftover call would reference the removed declaration.
      if (!callRefs.every((callRef) => canInlineFunction(fn.node, callRef))) {
        continue;
      }

      for (const callRef of callRefs) {
        inlineFunction(fn.node, callRef);
        state.changes++;
      }

      fn.remove();
      state.changes++;
    }
  }

  // Have to crawl again because renaming messed up the references
  binding.scope.crawl();
  return state;
}

/**
 * Recursively renames all references to the binding.
 * Make sure the binding name isn't shadowed anywhere!
 *
 * Example: `var alias = decoder; alias(1);` -> `decoder(1);`
 */

export function inlineVariableAliases(
  binding: Binding,
  targetName = binding.identifier.name,
): { changes: number } {
  const state = { changes: 0 };
  const refs = [...binding.referencePaths];
  const varName = m.capture(m.anyString());
  const matcher = m.or(
    m.variableDeclarator(
      m.identifier(varName),
      m.identifier(binding.identifier.name),
    ),
    m.assignmentExpression(
      '=',
      m.identifier(varName),
      m.identifier(binding.identifier.name),
    ),
  );

  for (const ref of refs) {
    if (matcher.match(ref.parent)) {
      const varScope = ref.scope;
      const varBinding = varScope.getBinding(varName.current!);
      if (!varBinding) continue;
      // Avoid infinite loop from `alias = alias;` (caused by dead code injection?)
      if (ref.isIdentifier({ name: varBinding.identifier.name })) continue;

      // Check all further aliases (`var alias2 = alias;`)
      state.changes += inlineVariableAliases(varBinding, targetName).changes;

      if (ref.parentPath?.isAssignmentExpression()) {
        // Remove `var alias;` when the assignment happens separately
        varBinding.path.remove();

        if (t.isExpressionStatement(ref.parentPath.parent)) {
          // Remove `alias = decoder;`
          ref.parentPath.remove();
        } else {
          // Replace `(alias = decoder)(1);` with `decoder(1);`
          ref.parentPath.replaceWith(t.identifier(targetName));
        }
      } else if (ref.parentPath?.isVariableDeclarator()) {
        // Remove `alias = decoder;` of declarator
        ref.parentPath.remove();
      }
      state.changes++;
    } else {
      // Rename the reference
      ref.replaceWith(t.identifier(targetName));
      state.changes++;
    }
  }

  return state;
}
