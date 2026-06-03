/**
 * Lightweight DOM-XSS taint analysis.
 *
 * Unlike a "a source and a sink both appear in this script" heuristic, this pass
 * requires the *same data* to flow from a DOM-controlled source into a dangerous
 * sink. It is intentionally pragmatic (name-based, intra-file, forward def-use to
 * a fixpoint) rather than a full inter-procedural taint engine, but that is
 * enough to cut the bulk of the false positives the regex approach produces.
 */

import type { Node } from '@babel/traverse';
import * as t from '@babel/types';
import { traverse } from '../ast-utils/babel';

export interface DomFlow {
  type: 'domFlow';
  source: string;
  sink: string;
  snippet: string;
  line: number;
}

// Explicit source member-paths (lowercased match). Matching is name-based and
// scope-unaware: a local that shadows `location`/`document`/`window` would be
// treated as the global. In practice these globals are virtually never
// shadowed, and the browser-confirming XSS modules provide execution proof.
const SOURCE_SET = new Set([
  'location.hash',
  'location.search',
  'location.href',
  'location.pathname',
  'window.location.hash',
  'window.location.search',
  'window.location.href',
  'window.location.pathname',
  'document.location.hash',
  'document.location.search',
  'document.location.href',
  'document.url',
  'document.documenturi',
  'document.baseuri',
  'document.cookie',
  'document.referrer',
  'window.name',
]);

// Member-path of getItem-style sources.
const STORAGE_GETTERS = new Set([
  'localstorage.getitem',
  'sessionstorage.getitem',
  'window.localstorage.getitem',
  'window.sessionstorage.getitem',
]);

const MAX_FLOWS = 100;
const SNIPPET_MAX = 180;
// Bounds recursion in memberPath/taintSourceOf. Minified bundles can contain
// huge left-nested binary or member chains that Babel parses iteratively but
// would overflow a naive recursive walk; past this depth we give up (return
// null) rather than crash.
const MAX_DEPTH = 400;

/** Dotted member path, or null if any part is dynamic or the chain is too deep. */
function memberPath(node: Node, depth = 0): string | null {
  if (depth > MAX_DEPTH) return null;
  if (t.isIdentifier(node)) return node.name;
  if (t.isThisExpression(node)) return 'this';
  if (t.isMemberExpression(node)) {
    const obj = memberPath(node.object, depth + 1);
    if (obj == null) return null;
    let prop: string | null = null;
    if (!node.computed && t.isIdentifier(node.property)) prop = node.property.name;
    else if (node.computed && t.isStringLiteral(node.property)) prop = node.property.value;
    if (prop == null) return null;
    return `${obj}.${prop}`;
  }
  return null;
}

function isSourceExpr(node: Node): string | null {
  const path = memberPath(node);
  if (path && SOURCE_SET.has(path.toLowerCase())) return path;
  return null;
}

/** True if node refers to the document object (document, window.document, …). */
function isDocumentObject(node: Node): boolean {
  const p = memberPath(node);
  if (!p) return false;
  const lp = p.toLowerCase();
  return lp === 'document' || lp.endsWith('.document');
}

/** True if node refers to the location object (location, window.location, …). */
function isLocationObject(node: Node): boolean {
  const p = memberPath(node);
  if (!p) return false;
  const lp = p.toLowerCase();
  return lp === 'location' || lp.endsWith('.location');
}

/** True if node is a jQuery wrapper: $(...) / jQuery(...) or a $-prefixed name. */
function isJQueryObject(node: Node): boolean {
  if (
    t.isCallExpression(node) &&
    !t.isV8IntrinsicIdentifier(node.callee) &&
    t.isIdentifier(node.callee) &&
    (node.callee.name === '$' || node.callee.name === 'jQuery')
  ) {
    return true;
  }
  const p = memberPath(node);
  return !!p && p.startsWith('$');
}

interface Assignment {
  name: string;
  rhs: Node;
}

/**
 * Returns the source label if expr is tainted under the current tainted-variable
 * map, else null. Walks the common taint-carrying expression shapes.
 */
function taintSourceOf(
  node: Node | null | undefined,
  tainted: Map<string, string>,
  depth = 0,
): string | null {
  if (!node || depth > MAX_DEPTH) return null;
  const d = depth + 1;

  const direct = isSourceExpr(node);
  if (direct) return direct;

  if (t.isIdentifier(node)) {
    return tainted.get(node.name) ?? null;
  }

  if (t.isMemberExpression(node)) {
    // e.g. tainted.foo, tainted[i]
    return (
      taintSourceOf(node.object, tainted, d) ??
      (node.computed ? taintSourceOf(node.property, tainted, d) : null)
    );
  }

  if (t.isCallExpression(node) || t.isNewExpression(node)) {
    const calleePath = t.isV8IntrinsicIdentifier(node.callee)
      ? null
      : memberPath(node.callee as Node);
    // localStorage.getItem(...) / sessionStorage.getItem(...) are sources.
    if (calleePath && STORAGE_GETTERS.has(calleePath.toLowerCase())) {
      return 'localStorage';
    }
    // x.method(...) carries x's taint (substring, replace, slice, split, get...).
    if (!t.isV8IntrinsicIdentifier(node.callee)) {
      const calleeTaint = taintSourceOf(node.callee as Node, tainted, d);
      if (calleeTaint) return calleeTaint;
    }
    // A tainted argument propagates conservatively — covers decoders like
    // decodeURIComponent(x) and constructors like new URLSearchParams(x). This
    // does not model sanitizers, so a sanitized value can still be reported;
    // the browser-confirming XSS modules supply the execution proof.
    for (const arg of node.arguments) {
      const at = taintSourceOf(arg as Node, tainted, d);
      if (at) return at;
    }
    return null;
  }

  if (t.isBinaryExpression(node)) {
    return taintSourceOf(node.left as Node, tainted, d) ?? taintSourceOf(node.right, tainted, d);
  }
  if (t.isLogicalExpression(node)) {
    return taintSourceOf(node.left, tainted, d) ?? taintSourceOf(node.right, tainted, d);
  }
  if (t.isConditionalExpression(node)) {
    return taintSourceOf(node.consequent, tainted, d) ?? taintSourceOf(node.alternate, tainted, d);
  }
  if (t.isTemplateLiteral(node)) {
    for (const e of node.expressions) {
      const et = taintSourceOf(e as Node, tainted, d);
      if (et) return et;
    }
    return null;
  }
  if (t.isSequenceExpression(node)) {
    return node.expressions.length
      ? taintSourceOf(node.expressions[node.expressions.length - 1], tainted, d)
      : null;
  }
  return null;
}

interface SinkHit {
  label: string;
  arg: Node;
  node: Node;
}

/** Classify a node as a sink and return the tainted-candidate argument. */
function classifySink(node: Node): SinkHit | null {
  // obj.innerHTML = x / obj.outerHTML = x / el.src = x / location = x
  if (t.isAssignmentExpression(node) && node.operator === '=') {
    const left = node.left;
    if (t.isMemberExpression(left) && !left.computed && t.isIdentifier(left.property)) {
      const prop = left.property.name;
      if (prop === 'innerHTML' || prop === 'outerHTML') return { label: prop, arg: node.right, node };
      if (prop === 'src') return { label: 'src', arg: node.right, node };
      if (prop === 'href') {
        const lp = (memberPath(left) ?? '').toLowerCase();
        if (lp.endsWith('location.href')) return { label: 'location.href', arg: node.right, node };
      }
    }
    const lp = memberPath(left as Node);
    if (lp && (lp === 'location' || lp.toLowerCase().endsWith('.location'))) {
      return { label: 'location', arg: node.right, node };
    }
    return null;
  }

  if (t.isCallExpression(node)) {
    // Global-function sinks: eval / setTimeout / setInterval.
    if (!t.isV8IntrinsicIdentifier(node.callee) && t.isIdentifier(node.callee)) {
      const name = node.callee.name;
      if (name === 'eval') return { label: 'eval', arg: node.arguments[0] as Node, node };
      if (name === 'setTimeout' || name === 'setInterval') {
        const a0 = node.arguments[0];
        // Only a string/expression first arg is a sink; a function body isn't.
        if (a0 && !t.isFunctionExpression(a0) && !t.isArrowFunctionExpression(a0)) {
          return { label: name, arg: a0 as Node, node };
        }
      }
    }
    // Method-call sinks: classify by the method name AND its receiver, so a
    // CallExpression receiver like $('#a').html(x) is handled while unrelated
    // methods (stream.write, config.html) are not misclassified.
    if (
      t.isMemberExpression(node.callee) &&
      !node.callee.computed &&
      t.isIdentifier(node.callee.property)
    ) {
      const method = node.callee.property.name;
      const obj = node.callee.object;
      switch (method) {
        case 'write':
        case 'writeln':
          if (isDocumentObject(obj)) {
            return { label: 'document.write', arg: node.arguments[0] as Node, node };
          }
          break;
        case 'insertAdjacentHTML':
          return { label: 'insertAdjacentHTML', arg: node.arguments[1] as Node, node };
        case 'html':
          if (isJQueryObject(obj)) {
            return { label: 'jquery.html', arg: node.arguments[0] as Node, node };
          }
          break;
        case 'assign':
        case 'replace':
          if (isLocationObject(obj)) {
            return {
              label: method === 'assign' ? 'location.assign' : 'location.replace',
              arg: node.arguments[0] as Node,
              node,
            };
          }
          break;
      }
    }
  }

  // new Function(payload)
  if (t.isNewExpression(node) && t.isIdentifier(node.callee) && node.callee.name === 'Function') {
    const last = node.arguments[node.arguments.length - 1];
    if (last) return { label: 'Function', arg: last as Node, node };
  }
  return null;
}

function snippetFor(node: Node, code: string): string {
  const start = (node as { start?: number }).start;
  const end = (node as { end?: number }).end;
  let s = '';
  if (typeof start === 'number' && typeof end === 'number' && end > start) {
    s = code.slice(start, end);
  }
  s = s.replace(/\s+/g, ' ').trim();
  return s.length > SNIPPET_MAX ? `${s.slice(0, SNIPPET_MAX)}…` : s;
}

/**
 * Analyze the AST for DOM-XSS source→sink flows. `code` is the (deobfuscated)
 * source used for snippet extraction.
 */
export function analyzeDomXss(ast: Node, code: string): DomFlow[] {
  const assignments: Assignment[] = [];
  const sinks: SinkHit[] = [];

  const visitor = {
    noScope: true,
    enter(path: { node: Node }) {
      const node = path.node;
      // Collect variable taint sources: `var x = <expr>` and `x = <expr>`.
      if (t.isVariableDeclarator(node) && t.isIdentifier(node.id) && node.init) {
        assignments.push({ name: node.id.name, rhs: node.init });
      } else if (
        t.isAssignmentExpression(node) &&
        (node.operator === '=' || node.operator === '+=') &&
        t.isIdentifier(node.left)
      ) {
        assignments.push({ name: node.left.name, rhs: node.right });
      }
      const sink = classifySink(node);
      if (sink && sink.arg) sinks.push(sink);
    },
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  traverse(ast, visitor as any);

  // Fixpoint over assignments: a var is tainted if its RHS is tainted. Each
  // pass taints at least one new name or stops, so it converges in at most
  // (#assignments + 1) passes — the bound just guarantees termination.
  const tainted = new Map<string, string>();
  const maxPasses = assignments.length + 1;
  let changed = true;
  let pass = 0;
  while (changed && pass < maxPasses) {
    changed = false;
    pass++;
    for (const a of assignments) {
      if (tainted.has(a.name)) continue;
      const src = taintSourceOf(a.rhs, tainted);
      if (src) {
        tainted.set(a.name, src);
        changed = true;
      }
    }
  }

  const flows: DomFlow[] = [];
  const seen = new Set<string>();
  for (const s of sinks) {
    const src = taintSourceOf(s.arg, tainted);
    if (!src) continue;
    const line = (s.node as { loc?: { start?: { line?: number } } }).loc?.start?.line ?? 0;
    const snippet = snippetFor(s.node, code);
    const key = `${src}|${s.label}|${line}|${snippet}`;
    if (seen.has(key)) continue;
    seen.add(key);
    flows.push({ type: 'domFlow', source: src, sink: s.label, snippet, line });
    if (flows.length >= MAX_FLOWS) break;
  }
  return flows;
}
