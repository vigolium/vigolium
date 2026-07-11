import type { Scope } from '@babel/traverse';
import * as t from '@babel/types';
import { getPropName } from '../ast-utils';

/**
 * Pure, bounded static evaluation of an expression to a concrete JavaScript
 * value — without executing any target code. Only side-effect-free, whitelisted
 * operations are folded; anything unknown yields `undefined` ("not statically
 * knowable"). Used to recover endpoint strings hidden behind constant folding,
 * `String.fromCharCode`, base64/URI decoding, reversed-string idioms, literal
 * string/array methods, and `JSON.parse` of literals.
 */

export type StaticValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | RegExp
  | StaticValue[]
  | { [key: string]: StaticValue };

/** Wrapper so a resolved `undefined` is distinguishable from "unresolvable". */
export interface Resolved {
  value: StaticValue;
}

export interface EvaluateOptions {
  scope?: Scope;
  maxDepth?: number;
  maxStringLength?: number;
  maxVisits?: number;
}

const DEFAULT_MAX_DEPTH = 40;
const DEFAULT_MAX_STRING = 100_000;
const DEFAULT_MAX_VISITS = 8_000;

// Instance methods that are pure and safe to fold when the receiver and all
// arguments are statically known.
const STRING_METHODS = new Set([
  'slice', 'substring', 'substr', 'toUpperCase', 'toLowerCase', 'trim',
  'trimStart', 'trimEnd', 'charAt', 'charCodeAt', 'codePointAt', 'at',
  'padStart', 'padEnd', 'repeat', 'replace', 'replaceAll', 'split', 'concat',
  'normalize', 'indexOf', 'lastIndexOf', 'includes', 'startsWith', 'endsWith',
  'toString', 'valueOf',
]);
const ARRAY_METHODS = new Set([
  'join', 'reverse', 'slice', 'concat', 'indexOf', 'lastIndexOf', 'includes',
  'at', 'flat',
]);
const NUMBER_METHODS = new Set(['toString', 'toFixed', 'valueOf']);

// Global functions callable as `name(...)`.
const GLOBAL_FUNCTIONS = new Set([
  'atob', 'btoa', 'decodeURIComponent', 'encodeURIComponent', 'decodeURI',
  'encodeURI', 'unescape', 'escape', 'parseInt', 'parseFloat', 'Number',
  'String', 'Boolean',
]);

const MATH_METHODS = new Set([
  'abs', 'floor', 'ceil', 'round', 'trunc', 'sign', 'sqrt', 'cbrt', 'pow',
  'max', 'min', 'log2', 'log10',
]);

class Budget {
  visits = 0;
  constructor(
    readonly maxVisits: number,
    readonly maxDepth: number,
    readonly maxString: number,
  ) {}
  tick(): boolean {
    return ++this.visits <= this.maxVisits;
  }
  okString(s: unknown): boolean {
    return typeof s !== 'string' || s.length <= this.maxString;
  }
}

/**
 * Attempt to statically evaluate `node`. Returns `{ value }` on success or
 * `undefined` when the value is not statically knowable.
 */
export function tryEvaluate(
  node: t.Node,
  options: EvaluateOptions = {},
): Resolved | undefined {
  const budget = new Budget(
    options.maxVisits ?? DEFAULT_MAX_VISITS,
    options.maxDepth ?? DEFAULT_MAX_DEPTH,
    options.maxStringLength ?? DEFAULT_MAX_STRING,
  );
  const r = evalNode(node, options.scope, budget, 0);
  if (!r) return undefined;
  if (!budget.okString(r.value)) return undefined;
  return r;
}

/** Convenience: evaluate and require the result to be a string. */
export function tryEvaluateString(
  node: t.Node,
  options: EvaluateOptions = {},
): string | undefined {
  const r = tryEvaluate(node, options);
  return r && typeof r.value === 'string' ? r.value : undefined;
}

function ok(value: StaticValue): Resolved {
  return { value };
}

function evalNode(
  node: t.Node,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  if (depth > budget.maxDepth || !budget.tick()) return null;

  switch (node.type) {
    case 'StringLiteral':
    case 'NumericLiteral':
    case 'BooleanLiteral':
      return ok(node.value);
    case 'NullLiteral':
      return ok(null);
    case 'Identifier':
      if (node.name === 'undefined') return ok(undefined);
      if (node.name === 'NaN') return ok(NaN);
      if (node.name === 'Infinity') return ok(Infinity);
      return resolveIdentifier(node, scope, budget, depth);
    case 'TemplateLiteral':
      return evalTemplate(node, scope, budget, depth);
    case 'RegExpLiteral':
      try {
        return ok(new RegExp(node.pattern, node.flags));
      } catch {
        return null;
      }
    case 'UnaryExpression':
      return evalUnary(node, scope, budget, depth);
    case 'BinaryExpression':
      return evalBinary(node, scope, budget, depth);
    case 'LogicalExpression':
      return evalLogical(node, scope, budget, depth);
    case 'ConditionalExpression': {
      const test = evalNode(node.test, scope, budget, depth + 1);
      if (!test) return null;
      return evalNode(test.value ? node.consequent : node.alternate, scope, budget, depth + 1);
    }
    case 'ArrayExpression':
      return evalArray(node, scope, budget, depth);
    case 'ObjectExpression':
      return evalObject(node, scope, budget, depth);
    case 'ParenthesizedExpression':
      return evalNode(node.expression, scope, budget, depth);
    case 'CallExpression':
      return evalCall(node, scope, budget, depth);
    case 'MemberExpression':
      return evalMemberRead(node, scope, budget, depth);
    default:
      return null;
  }
}

function resolveIdentifier(
  node: t.Identifier,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  if (!scope) return null;
  const binding = scope.getBinding(node.name);
  if (!binding || !binding.constant) return null;
  if (binding.path.isVariableDeclarator() && binding.path.node.init) {
    return evalNode(binding.path.node.init, binding.scope, budget, depth + 1);
  }
  return null;
}

function evalTemplate(
  node: t.TemplateLiteral,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  let out = '';
  for (let i = 0; i < node.quasis.length; i++) {
    out += node.quasis[i].value.cooked ?? node.quasis[i].value.raw;
    if (i < node.expressions.length) {
      const e = node.expressions[i];
      if (!t.isExpression(e)) return null;
      const r = evalNode(e, scope, budget, depth + 1);
      if (!r) return null;
      out += String(r.value);
    }
    if (out.length > budget.maxString) return null;
  }
  return ok(out);
}

function evalUnary(
  node: t.UnaryExpression,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  if (node.operator === 'delete' || node.operator === 'throw') return null;
  if (node.operator === 'typeof' && t.isIdentifier(node.argument)) {
    // Only evaluate `typeof x` when x resolves; otherwise it depends on runtime.
    const r = resolveIdentifier(node.argument, scope, budget, depth);
    if (!r) return null;
    return ok(typeof r.value);
  }
  const arg = evalNode(node.argument, scope, budget, depth + 1);
  if (!arg) return null;
  switch (node.operator) {
    case '-': return ok(-(arg.value as number));
    case '+': return ok(+(arg.value as number));
    case '~': return ok(~(arg.value as number));
    case '!': return ok(!arg.value);
    case 'void': return ok(undefined);
    case 'typeof': return ok(typeof arg.value);
    default: return null;
  }
}

function evalBinary(
  node: t.BinaryExpression,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  if (!t.isExpression(node.left)) return null; // PrivateName (only with `in`)
  const l = evalNode(node.left, scope, budget, depth + 1);
  if (!l) return null;
  const r = evalNode(node.right, scope, budget, depth + 1);
  if (!r) return null;
  const a = l.value as never;
  const b = r.value as never;
  switch (node.operator) {
    case '+': return ok((a as never) + (b as never));
    case '-': return ok(a - b);
    case '*': return ok(a * b);
    case '/': return ok(a / b);
    case '%': return ok(a % b);
    case '**': return ok((a as number) ** (b as number));
    case '&': return ok(a & b);
    case '|': return ok(a | b);
    case '^': return ok(a ^ b);
    case '<<': return ok(a << b);
    case '>>': return ok(a >> b);
    case '>>>': return ok((a as number) >>> (b as number));
    case '==': return ok(a == b);
    case '!=': return ok(a != b);
    case '===': return ok(a === b);
    case '!==': return ok(a !== b);
    case '<': return ok(a < b);
    case '>': return ok(a > b);
    case '<=': return ok(a <= b);
    case '>=': return ok(a >= b);
    default: return null; // in, instanceof, |>
  }
}

function evalLogical(
  node: t.LogicalExpression,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  const l = evalNode(node.left, scope, budget, depth + 1);
  if (!l) return null;
  switch (node.operator) {
    case '&&': return l.value ? evalNode(node.right, scope, budget, depth + 1) : l;
    case '||': return l.value ? l : evalNode(node.right, scope, budget, depth + 1);
    case '??': return l.value === null || l.value === undefined
      ? evalNode(node.right, scope, budget, depth + 1)
      : l;
    default: return null;
  }
}

function evalArray(
  node: t.ArrayExpression,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  const arr: StaticValue[] = [];
  for (const el of node.elements) {
    if (el === null) {
      arr.push(undefined);
      continue;
    }
    if (t.isSpreadElement(el)) return null;
    const r = evalNode(el, scope, budget, depth + 1);
    if (!r) return null;
    arr.push(r.value);
  }
  return ok(arr);
}

function evalObject(
  node: t.ObjectExpression,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  const obj: { [key: string]: StaticValue } = {};
  for (const prop of node.properties) {
    if (!t.isObjectProperty(prop) || prop.computed) return null;
    const key = getPropName(prop.key);
    if (key === undefined) return null;
    if (!t.isExpression(prop.value)) return null;
    const r = evalNode(prop.value, scope, budget, depth + 1);
    if (!r) return null;
    obj[key] = r.value;
  }
  return ok(obj);
}

/** Read `obj.prop` / `obj["prop"]` from a statically-known object or array. */
function evalMemberRead(
  node: t.MemberExpression,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  const obj = evalNode(node.object, scope, budget, depth + 1);
  if (!obj) return null;
  const target = obj.value;
  if (target === null || target === undefined) return null;

  let key: string | number | undefined;
  if (!node.computed && t.isIdentifier(node.property)) key = node.property.name;
  else if (node.computed) {
    const k = evalNode(node.property, scope, budget, depth + 1);
    if (!k) return null;
    key = k.value as string | number;
  }
  if (key === undefined) return null;

  if (typeof target === 'string' || Array.isArray(target)) {
    if (key === 'length') return ok(target.length);
    const idx = Number(key);
    if (Number.isInteger(idx)) return ok(target[idx]);
    return null;
  }
  if (typeof target === 'object') {
    const rec = target as { [k: string]: StaticValue };
    if (Object.prototype.hasOwnProperty.call(rec, key)) return ok(rec[key]);
    return null;
  }
  return null;
}

function evalArgs(
  nodes: (t.Expression | t.SpreadElement | t.ArgumentPlaceholder)[],
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): StaticValue[] | null {
  const args: StaticValue[] = [];
  for (const a of nodes) {
    if (!t.isExpression(a)) return null; // no spreads / placeholders
    const r = evalNode(a, scope, budget, depth + 1);
    if (!r) return null;
    args.push(r.value);
  }
  return args;
}

function evalCall(
  node: t.CallExpression,
  scope: Scope | undefined,
  budget: Budget,
  depth: number,
): Resolved | null {
  const callee = node.callee;

  // Global function: `name(...)` where `name` is an unshadowed whitelisted
  // global. Reject other identifier callees before touching arguments so
  // ordinary calls don't descend into every argument subtree.
  if (t.isIdentifier(callee)) {
    if (scope?.getBinding(callee.name) || !GLOBAL_FUNCTIONS.has(callee.name)) return null;
    const args = evalArgs(node.arguments, scope, budget, depth);
    return args && applyGlobal(callee.name, args, budget);
  }

  if (t.isMemberExpression(callee) && !callee.computed && t.isIdentifier(callee.property)) {
    const method = callee.property.name;
    // Static namespaces: String.fromCharCode, JSON.parse, Math.*, ...
    if (t.isIdentifier(callee.object) && !scope?.getBinding(callee.object.name)) {
      const args = evalArgs(node.arguments, scope, budget, depth);
      return args && applyNamespace(callee.object.name, method, args, budget);
    }
    // Instance method: reject a non-static receiver before evaluating args.
    const recv = evalNode(callee.object, scope, budget, depth + 1);
    if (!recv) return null;
    const args = evalArgs(node.arguments, scope, budget, depth);
    return args && applyMethod(recv.value, method, args, budget);
  }

  return null;
}

function applyGlobal(name: string, args: StaticValue[], budget: Budget): Resolved | null {
  try {
    switch (name) {
      case 'atob': {
        if (typeof args[0] !== 'string') return null;
        if (!/^[A-Za-z0-9+/\s]*={0,2}$/.test(args[0])) return null;
        return ok(Buffer.from(args[0], 'base64').toString('latin1'));
      }
      case 'btoa': {
        if (typeof args[0] !== 'string') return null;
        return ok(Buffer.from(args[0], 'latin1').toString('base64'));
      }
      case 'decodeURIComponent': return ok(decodeURIComponent(String(args[0])));
      case 'encodeURIComponent': return ok(encodeURIComponent(String(args[0])));
      case 'decodeURI': return ok(decodeURI(String(args[0])));
      case 'encodeURI': return ok(encodeURI(String(args[0])));
      case 'unescape': return ok(unescape(String(args[0])));
      case 'escape': return ok(escape(String(args[0])));
      case 'parseInt': return ok(parseInt(String(args[0]), args[1] as number));
      case 'parseFloat': return ok(parseFloat(String(args[0])));
      case 'Number': return ok(args.length ? Number(args[0] as never) : 0);
      case 'String': return ok(args.length ? String(args[0]) : '');
      case 'Boolean': return ok(Boolean(args[0]));
      default: return null;
    }
  } catch {
    return null;
  }
}

function applyNamespace(
  ns: string,
  method: string,
  args: StaticValue[],
  budget: Budget,
): Resolved | null {
  try {
    if (ns === 'String') {
      if (method === 'fromCharCode') {
        return capString(String.fromCharCode(...(args as number[])), budget);
      }
      if (method === 'fromCodePoint') {
        return capString(String.fromCodePoint(...(args as number[])), budget);
      }
      return null;
    }
    if (ns === 'JSON') {
      // Only `JSON.parse` (decodes a hidden literal). `JSON.stringify` is
      // re-serialization owned by the request-body extractor — folding it would
      // collapse the object AST the body/GraphQL analyzers inspect.
      if (method === 'parse' && typeof args[0] === 'string') {
        return ok(JSON.parse(args[0]) as StaticValue);
      }
      return null;
    }
    if (ns === 'Math' && MATH_METHODS.has(method)) {
      const fn = (Math as unknown as Record<string, (...n: number[]) => number>)[method];
      return ok(fn(...(args as number[])));
    }
    if (ns === 'Number') {
      if (method === 'parseInt') return ok(parseInt(String(args[0]), args[1] as number));
      if (method === 'parseFloat') return ok(parseFloat(String(args[0])));
      return null;
    }
    return null;
  } catch {
    return null;
  }
}

function applyMethod(
  receiver: StaticValue,
  method: string,
  args: StaticValue[],
  budget: Budget,
): Resolved | null {
  try {
    if (typeof receiver === 'string' && STRING_METHODS.has(method)) {
      // Bound the expensive expanders before running them.
      if ((method === 'repeat' || method === 'padStart' || method === 'padEnd')) {
        const count = Number(args[0]);
        if (!Number.isFinite(count) || count < 0 || count > budget.maxString) return null;
      }
      const fn = (receiver as unknown as Record<string, (...a: unknown[]) => unknown>)[method];
      const result = fn.apply(receiver, args) as StaticValue;
      if (typeof result === 'string' && !budget.okString(result)) return null;
      return ok(result);
    }
    if (Array.isArray(receiver) && ARRAY_METHODS.has(method)) {
      const fn = (receiver as unknown as Record<string, (...a: unknown[]) => unknown>)[method];
      const result = fn.apply(receiver, args) as StaticValue;
      if (typeof result === 'string' && !budget.okString(result)) return null;
      return ok(result);
    }
    if (typeof receiver === 'number' && NUMBER_METHODS.has(method)) {
      const fn = (receiver as unknown as Record<string, (...a: unknown[]) => unknown>)[method];
      return ok(fn.apply(receiver, args) as StaticValue);
    }
    return null;
  } catch {
    return null;
  }
}

function capString(s: string, budget: Budget): Resolved | null {
  return budget.okString(s) ? ok(s) : null;
}
