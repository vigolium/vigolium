/**
 * Binding-, scope-, and order-aware browser taint analysis.
 *
 * The resolver walks backwards from each sink through Babel bindings and only
 * considers writes that can precede that sink. It also summarizes local
 * function returns and replays sink summaries at concrete call sites. This is
 * deliberately bounded, but avoids the name-collision and after-sink false
 * positives of the former file-wide fixpoint.
 */

import type { Binding, NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import * as t from '@babel/types';
import { babelGenerate, traverse } from '../ast-utils/babel';
import type { Confidence, SourceLocation } from '../protocol';

export interface DomFlowStep {
  kind: 'source' | 'assignment' | 'call' | 'return' | 'sink';
  label: string;
  location?: SourceLocation;
}

export interface DomFlow {
  type: 'domFlow';
  source: string;
  sink: string;
  snippet: string;
  line: number;
  confidence: Confidence;
  path: DomFlowStep[];
  flowType: 'domXss' | 'openRedirect' | 'scriptUrlInjection' | 'sensitiveExfiltration' | 'clientRequestInjection' | 'dynamicExecution' | 'prototypePollution';
}

type AnyPath = NodePath<any>;

const SOURCE_SET = new Set([
  'location.hash', 'location.search', 'location.href', 'location.pathname',
  'window.location.hash', 'window.location.search', 'window.location.href', 'window.location.pathname',
  'document.location.hash', 'document.location.search', 'document.location.href',
  'document.url', 'document.documenturi', 'document.baseuri', 'document.cookie', 'document.referrer',
  'window.name', 'history.state', 'window.history.state',
]);

const STORAGE_GETTERS = new Set([
  'localstorage.getitem', 'sessionstorage.getitem',
  'window.localstorage.getitem', 'window.sessionstorage.getitem',
]);

const STRONG_SANITIZERS = new Set([
  'dompurify.sanitize', 'window.dompurify.sanitize', 'sanitizehtml', 'sanitize-html',
]);

const PASS_THROUGH_CALLS = new Set([
  'decodeuri', 'decodeuricomponent', 'atob', 'string', 'unescape',
  'json.parse', 'parseint', 'parsefloat',
]);

const MAX_DEPTH = 80;
const MAX_FLOWS = 100;
const MAX_FUNCTION_DEPTH = 8;
const SNIPPET_MAX = 220;

function locationOf(path: AnyPath): SourceLocation | undefined {
  const loc = path.node.loc?.start;
  if (!loc) return undefined;
  return {
    line: loc.line,
    column: loc.column,
    ...(typeof path.node.start === 'number' ? { offset: path.node.start } : {}),
  };
}

function step(path: AnyPath, kind: DomFlowStep['kind'], label: string): DomFlowStep {
  return { kind, label, ...(locationOf(path) ? { location: locationOf(path) } : {}) };
}

function memberPath(node: Node, depth = 0): string | null {
  if (depth > MAX_DEPTH) return null;
  if (t.isIdentifier(node)) return node.name;
  if (t.isThisExpression(node)) return 'this';
  if (!t.isMemberExpression(node) && !t.isOptionalMemberExpression(node)) return null;
  const object = memberPath(node.object as Node, depth + 1);
  if (!object) return null;
  let property: string | null = null;
  if (!node.computed && t.isIdentifier(node.property)) property = node.property.name;
  else if (node.computed && t.isStringLiteral(node.property)) property = node.property.value;
  return property ? `${object}.${property}` : null;
}

function rootIdentifier(node: Node): t.Identifier | null {
  let current: Node = node;
  while (t.isMemberExpression(current) || t.isOptionalMemberExpression(current)) {
    current = current.object as Node;
  }
  return t.isIdentifier(current) ? current : null;
}

/** Return a member path only when its browser-global root is not shadowed. */
function unshadowedGlobalPath(path: AnyPath): string | null {
  const rendered = memberPath(path.node as Node);
  const root = rootIdentifier(path.node as Node);
  if (!rendered || !root) return null;
  if (path.scope.getBinding(root.name)) return null;
  return rendered;
}

function isDocumentObject(path: AnyPath): boolean {
  const rendered = unshadowedGlobalPath(path);
  if (!rendered) return false;
  const lower = rendered.toLowerCase();
  return lower === 'document' || lower === 'window.document';
}

function isLocationObject(path: AnyPath): boolean {
  const rendered = unshadowedGlobalPath(path);
  if (!rendered) return false;
  const lower = rendered.toLowerCase();
  return lower === 'location' || lower === 'window.location' || lower === 'document.location';
}

function isJQueryObject(path: AnyPath): boolean {
  const node = path.node as Node;
  if (t.isCallExpression(node) && t.isIdentifier(node.callee) &&
      (node.callee.name === '$' || node.callee.name === 'jQuery') &&
      !path.scope.getBinding(node.callee.name)) return true;
  const rendered = memberPath(node);
  return !!rendered && rendered.startsWith('$');
}

function directSource(path: AnyPath): Taint | null {
  const rendered = unshadowedGlobalPath(path);
  if (rendered && SOURCE_SET.has(rendered.toLowerCase())) {
    return {
      source: rendered,
      confidence: 'high',
      path: [step(path, 'source', rendered)],
    };
  }
  return null;
}

interface Taint {
  source: string;
  confidence: Confidence;
  path: DomFlowStep[];
}

interface ResolverState {
  overrides: Map<Binding, Taint | null>;
  bindingIDs: WeakMap<Binding, number>;
  nextBindingID: number;
  resolving: Set<string>;
  functionStack: Set<Node>;
  depth: number;
  maxFunctionDepth: number;
  maxResolutionDepth: number;
  messageOriginValidation: WeakMap<Node, boolean>;
}

function childState(state: ResolverState, overrides = state.overrides): ResolverState {
  return { ...state, overrides, resolving: new Set(state.resolving), functionStack: new Set(state.functionStack) };
}

function confidenceMin(a: Confidence, b: Confidence): Confidence {
  const rank: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };
  return rank[a] <= rank[b] ? a : b;
}

function weaken(taint: Taint, confidence: Confidence): Taint {
  return { ...taint, confidence: confidenceMin(taint.confidence, confidence) };
}

function bindingID(binding: Binding, state: ResolverState): number {
  const existing = state.bindingIDs.get(binding);
  if (existing) return existing;
  const id = state.nextBindingID++;
  state.bindingIDs.set(binding, id);
  return id;
}

function isConditionalWrite(path: AnyPath): boolean {
  let current = path.parentPath;
  while (current && !current.isFunction() && !current.isProgram()) {
    if (current.isIfStatement() || current.isConditionalExpression() || current.isSwitchCase() ||
        current.isLoop() || current.isLogicalExpression() || current.isTryStatement()) return true;
    current = current.parentPath;
  }
  return false;
}

interface BindingWrite {
  path: AnyPath;
  value: AnyPath;
  conditional: boolean;
  operator: string;
}

function writesBefore(binding: Binding, before: number): BindingWrite[] {
  const writes: BindingWrite[] = [];
  if (binding.path.isVariableDeclarator()) {
    const init = binding.path.get('init');
    if (init?.node && (binding.path.node.start ?? -1) < before) {
      writes.push({ path: binding.path, value: init as AnyPath, conditional: isConditionalWrite(binding.path), operator: '=' });
    }
  }
  for (const violation of binding.constantViolations) {
    if ((violation.node.start ?? Number.MAX_SAFE_INTEGER) >= before) continue;
    if (violation.isAssignmentExpression()) {
      const right = violation.get('right');
      if (right?.node) {
        writes.push({
          path: violation,
          value: right as AnyPath,
          conditional: isConditionalWrite(violation),
          operator: violation.node.operator,
        });
      }
    }
  }
  return writes.sort((a, b) => (b.path.node.start ?? 0) - (a.path.node.start ?? 0));
}

function messageEventSource(binding: Binding, usePath: AnyPath, state: ResolverState): Taint | null {
  if (binding.kind !== 'param') return null;
  const functionPath = binding.path.getFunctionParent();
  if (!functionPath) return null;
  const call = functionPath.parentPath;
  if (!call?.isCallExpression()) return null;
  const callee = call.get('callee');
  if (!callee.isMemberExpression()) return null;
  const property = callee.get('property');
  if (!property.isIdentifier({ name: 'addEventListener' })) return null;
  const eventName = call.get('arguments.0');
  if (!eventName?.isStringLiteral({ value: 'message' })) return null;
  let validated = state.messageOriginValidation.get(functionPath.node);
  if (validated === undefined) {
    const parameter = binding.identifier.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const code = babelGenerate(functionPath.node, { minified: true, comments: false }).code;
    validated = new RegExp(
      `(?:${parameter}\\.origin(?:===|!==|==|!=)|(?:includes|has|test)\\([^)]*${parameter}\\.origin)`,
    ).test(code);
    state.messageOriginValidation.set(functionPath.node, validated);
  }
  return {
    source: 'postMessage.data',
    confidence: validated ? 'low' : 'medium',
    path: [step(usePath, 'source', validated ? 'postMessage event data (origin checked)' : 'postMessage event data')],
  };
}

function resolveIdentifier(path: AnyPath, before: number, state: ResolverState): Taint | null {
  const binding = path.scope.getBinding(path.node.name);
  if (!binding) return null;
  if (state.overrides.has(binding)) return state.overrides.get(binding) ?? null;
  const message = messageEventSource(binding, path, state);
  if (message) return message;

  const key = `${bindingID(binding, state)}:${before}`;
  if (state.resolving.has(key)) return null;
  state.resolving.add(key);
  try {
    for (const write of writesBefore(binding, before)) {
      let taint = resolveExpression(write.value, write.path.node.start ?? before, state);
      if (!taint && write.operator !== '=') {
        taint = resolveIdentifier(path, write.path.node.start ?? before, state);
      }
      if (taint) {
        return {
          ...taint,
          path: [...taint.path, step(write.path, 'assignment', path.node.name)],
        };
      }
      // An unconditional clean write kills earlier taint; a branch-local clean
      // write does not prove every path was sanitized.
      if (!write.conditional) return null;
    }
    return null;
  } finally {
    state.resolving.delete(key);
  }
}

function functionPathForCall(path: AnyPath): AnyPath | null {
  const callee = path.get('callee') as AnyPath;
  if (!callee.isIdentifier()) return null;
  const binding = callee.scope.getBinding(callee.node.name);
  if (!binding) return null;
  if (binding.path.isFunctionDeclaration()) return binding.path;
  if (binding.path.isVariableDeclarator()) {
    const init = binding.path.get('init');
    if (init?.isFunctionExpression() || init?.isArrowFunctionExpression()) return init as AnyPath;
  }
  return null;
}

function functionOverrides(callPath: AnyPath, functionPath: AnyPath, state: ResolverState): Map<Binding, Taint | null> {
  const overrides = new Map(state.overrides);
  const params = functionPath.get('params') as AnyPath[];
  const args = callPath.get('arguments') as AnyPath[];
  for (let index = 0; index < params.length; index++) {
    const parameter = params[index];
    if (!parameter.isIdentifier()) continue;
    const binding = functionPath.scope.getBinding(parameter.node.name);
    if (!binding) continue;
    const argument = args[index];
    overrides.set(binding, argument?.node
      ? resolveExpression(argument, callPath.node.start ?? Number.MAX_SAFE_INTEGER, state)
      : null);
  }
  return overrides;
}

function resolveFunctionReturn(callPath: AnyPath, state: ResolverState): Taint | null {
  if (state.depth >= state.maxFunctionDepth) return null;
  const functionPath = functionPathForCall(callPath);
  if (!functionPath || state.functionStack.has(functionPath.node)) return null;
  const overrides = functionOverrides(callPath, functionPath, state);
  const nested = childState(state, overrides);
  nested.depth++;
  nested.functionStack.add(functionPath.node);
  let resolved: Taint | null = null;
  functionPath.traverse({
    Function(path) {
      if (path.node !== functionPath.node) path.skip();
    },
    ReturnStatement(path) {
      if (resolved) return;
      const argument = path.get('argument');
      if (!argument?.node) return;
      const taint = resolveExpression(argument as AnyPath, path.node.start ?? Number.MAX_SAFE_INTEGER, nested);
      if (taint) {
        resolved = {
          ...taint,
          path: [...taint.path, step(path as AnyPath, 'return', functionPath.node.id?.name ?? 'local function')],
        };
      }
    },
  });
  return resolved;
}

function resolveExpression(path: AnyPath | null | undefined, before: number, state: ResolverState): Taint | null {
  if (!path?.node || state.depth > state.maxResolutionDepth) return null;
  const direct = directSource(path);
  if (direct) return direct;

  if (path.isIdentifier()) return resolveIdentifier(path, before, state);
  if (path.isMemberExpression() || path.isOptionalMemberExpression()) {
    const object = path.get('object') as AnyPath;
    const objectTaint = resolveExpression(object, before, state);
    if (objectTaint) return objectTaint;
    if (path.node.computed) return resolveExpression(path.get('property') as AnyPath, before, state);
    return null;
  }
  if (path.isCallExpression() || path.isOptionalCallExpression() || path.isNewExpression()) {
    const callee = path.get('callee') as AnyPath;
    const calleeName = memberPath(callee.node as Node)?.toLowerCase() ?? '';
    const globalCallee = unshadowedGlobalPath(callee)?.toLowerCase();
    if (globalCallee && STORAGE_GETTERS.has(globalCallee)) {
      return { source: globalCallee, confidence: 'high', path: [step(path, 'source', globalCallee)] };
    }
    if (STRONG_SANITIZERS.has(calleeName)) return null;

    const localReturn = path.isCallExpression() ? resolveFunctionReturn(path, state) : null;
    if (localReturn) return localReturn;

    if (callee.isMemberExpression() || callee.isOptionalMemberExpression()) {
      const receiver = callee.get('object') as AnyPath;
      const receiverTaint = resolveExpression(receiver, before, state);
      if (receiverTaint) {
        return { ...receiverTaint, path: [...receiverTaint.path, step(path, 'call', calleeName || 'method')] };
      }
    }
    const args = path.get('arguments') as AnyPath[];
    for (const argument of args) {
      if (!argument?.node || argument.isFunction()) continue;
      const taint = resolveExpression(argument, before, state);
      if (taint) {
        const confidence: Confidence = PASS_THROUGH_CALLS.has(calleeName) ? taint.confidence : 'medium';
        return {
          ...weaken(taint, confidence),
          path: [...taint.path, step(path, 'call', calleeName || 'call')],
        };
      }
    }
    return null;
  }
  if (path.isBinaryExpression() || path.isLogicalExpression()) {
    return resolveExpression(path.get('left') as AnyPath, before, state) ??
      resolveExpression(path.get('right') as AnyPath, before, state);
  }
  if (path.isConditionalExpression()) {
    return resolveExpression(path.get('consequent') as AnyPath, before, state) ??
      resolveExpression(path.get('alternate') as AnyPath, before, state);
  }
  if (path.isTemplateLiteral()) {
    for (const expression of path.get('expressions') as AnyPath[]) {
      const taint = resolveExpression(expression, before, state);
      if (taint) return taint;
    }
    return null;
  }
  if (path.isSequenceExpression()) {
    const expressions = path.get('expressions') as AnyPath[];
    return expressions.length ? resolveExpression(expressions[expressions.length - 1], before, state) : null;
  }
  if (path.isAwaitExpression() || path.isTSAsExpression() || path.isTypeCastExpression()) {
    return resolveExpression(path.get('argument') as AnyPath, before, state);
  }
  return null;
}

interface SinkHit {
  label: string;
  argument: AnyPath;
  path: AnyPath;
  confidence: Confidence;
  flowType: DomFlow['flowType'];
}

function isScriptObject(path: AnyPath): boolean {
  if (path.isIdentifier()) {
    if (/script/i.test(path.node.name)) return true;
    const binding = path.scope.getBinding(path.node.name);
    if (binding?.path.isVariableDeclarator()) {
      const init = binding.path.get('init');
      if (init?.isCallExpression()) {
        const callee = init.get('callee') as AnyPath;
        const args = init.get('arguments') as AnyPath[];
        return memberPath(callee.node)?.toLowerCase().endsWith('document.createelement') === true &&
          args[0]?.isStringLiteral({ value: 'script' });
      }
    }
  }
  return false;
}

function isXHRObject(path: AnyPath): boolean {
  if (!path.isIdentifier()) return false;
  const binding = path.scope.getBinding(path.node.name);
  if (!binding?.path.isVariableDeclarator()) return false;
  const init = binding.path.get('init');
  return !!init?.isNewExpression() && (init.get('callee') as AnyPath).isIdentifier({ name: 'XMLHttpRequest' });
}

function isDOMParserObject(path: AnyPath): boolean {
  if (path.isNewExpression()) {
    return (path.get('callee') as AnyPath).isIdentifier({ name: 'DOMParser' });
  }
  if (!path.isIdentifier()) return false;
  const binding = path.scope.getBinding(path.node.name);
  if (!binding?.path.isVariableDeclarator()) return false;
  const init = binding.path.get('init');
  return !!init?.isNewExpression() && (init.get('callee') as AnyPath).isIdentifier({ name: 'DOMParser' });
}

function objectPropertyValue(path: AnyPath, propertyName: string): AnyPath | null {
  if (!path.isObjectExpression()) return null;
  for (const property of path.get('properties') as AnyPath[]) {
    if (!property.isObjectProperty()) continue;
    const key = property.get('key') as AnyPath;
    const name = key.isIdentifier() ? key.node.name : key.isStringLiteral() ? key.node.value : '';
    if (name === propertyName) return property.get('value') as AnyPath;
  }
  return null;
}

function classifySink(path: AnyPath): SinkHit | null {
  if (path.isAssignmentExpression({ operator: '=' })) {
    const left = path.get('left') as AnyPath;
    const right = path.get('right') as AnyPath;
    if (left.isMemberExpression() || left.isOptionalMemberExpression()) {
      const property = left.get('property') as AnyPath;
      const name = property.isIdentifier() ? property.node.name : property.isStringLiteral() ? property.node.value : '';
      if (name === 'innerHTML' || name === 'outerHTML' || name === 'srcdoc') {
        return { label: name, argument: right, path, confidence: 'high', flowType: 'domXss' };
      }
      if (name === 'href' && isLocationObject(left.get('object') as AnyPath)) {
        return { label: 'location.href', argument: right, path, confidence: 'high', flowType: 'openRedirect' };
      }
      if (name === 'src' && isScriptObject(left.get('object') as AnyPath)) {
        return { label: 'script.src', argument: right, path, confidence: 'high', flowType: 'scriptUrlInjection' };
      }
	  if (left.node.computed && (left.get('object') as AnyPath).matchesPattern('Object.prototype')) {
		return { label: 'Object.prototype[dynamicKey]', argument: left.get('property') as AnyPath, path, confidence: 'high', flowType: 'prototypePollution' };
	  }
    }
    if (isLocationObject(left)) return { label: 'location', argument: right, path, confidence: 'high', flowType: 'openRedirect' };
  }

  if (path.isCallExpression()) {
    const callee = path.get('callee') as AnyPath;
    const args = path.get('arguments') as AnyPath[];
    if (callee.isIdentifier() && !callee.scope.getBinding(callee.node.name)) {
      if (callee.node.name === 'eval' && args[0]) return { label: 'eval', argument: args[0], path, confidence: 'high', flowType: 'dynamicExecution' };
      if ((callee.node.name === 'setTimeout' || callee.node.name === 'setInterval') && args[0] && !args[0].isFunction()) {
        return { label: callee.node.name, argument: args[0], path, confidence: 'high', flowType: 'dynamicExecution' };
      }
      if (callee.node.name === 'fetch' && args[0]) return { label: 'network.fetch', argument: args[0], path, confidence: 'medium', flowType: 'clientRequestInjection' };
    }
	if (callee.isImport() && args[0]) {
	  return { label: 'dynamic import', argument: args[0], path, confidence: 'high', flowType: 'scriptUrlInjection' };
	}
    if (callee.isMemberExpression() || callee.isOptionalMemberExpression()) {
      const property = callee.get('property') as AnyPath;
      const method = property.isIdentifier() ? property.node.name : property.isStringLiteral() ? property.node.value : '';
      const object = callee.get('object') as AnyPath;
      if ((method === 'write' || method === 'writeln') && isDocumentObject(object) && args[0]) {
        return { label: 'document.write', argument: args[0], path, confidence: 'high', flowType: 'domXss' };
      }
      if (method === 'insertAdjacentHTML' && args[1]) return { label: method, argument: args[1], path, confidence: 'high', flowType: 'domXss' };
      if (method === 'createContextualFragment' && args[0]) return { label: 'Range.createContextualFragment', argument: args[0], path, confidence: 'high', flowType: 'domXss' };
	  if (['html', 'append', 'prepend', 'before', 'after', 'replaceWith'].includes(method) && isJQueryObject(object) && args[0]) {
		return { label: `jquery.${method}`, argument: args[0], path, confidence: 'high', flowType: 'domXss' };
	  }
	  if (method === 'parseFromString' && isDOMParserObject(object) && args[0] && args[1]?.isStringLiteral() && /html/i.test(args[1].node.value)) {
		return { label: 'DOMParser.parseFromString(text/html)', argument: args[0], path, confidence: 'high', flowType: 'domXss' };
	  }
      if ((method === 'assign' || method === 'replace') && isLocationObject(object) && args[0]) {
        return { label: `location.${method}`, argument: args[0], path, confidence: 'high', flowType: 'openRedirect' };
      }
      if (method === 'setAttribute' && args[0]?.isStringLiteral({ value: 'srcdoc' }) && args[1]) {
        return { label: 'setAttribute(srcdoc)', argument: args[1], path, confidence: 'high', flowType: 'domXss' };
      }
	  if (method === 'setAttribute' && args[0]?.isStringLiteral({ value: 'src' }) && args[1] && isScriptObject(object)) {
		return { label: 'script.setAttribute(src)', argument: args[1], path, confidence: 'high', flowType: 'scriptUrlInjection' };
	  }
	  if (method === 'open' && args[1] && isXHRObject(object)) {
		return { label: 'XMLHttpRequest.open', argument: args[1], path, confidence: 'medium', flowType: 'clientRequestInjection' };
	  }
	  if (['set', 'setWith'].includes(method) && args[1] && (memberPath(callee.node)?.startsWith('_.') || /lodash/i.test(memberPath(callee.node) ?? ''))) {
		return { label: `${memberPath(callee.node)}(dynamicPath)`, argument: args[1], path, confidence: 'low', flowType: 'prototypePollution' };
	  }
    }
  }
	if (path.isObjectProperty()) {
	  const key = path.get('key') as AnyPath;
	  const name = key.isIdentifier() ? key.node.name : key.isStringLiteral() ? key.node.value : '';
	  const value = path.get('value') as AnyPath;
	  if (name === 'dangerouslySetInnerHTML') {
		const html = objectPropertyValue(value, '__html');
		if (html) return { label: 'React.dangerouslySetInnerHTML', argument: html, path, confidence: 'high', flowType: 'domXss' };
	  }
	  if (name === 'innerHTML' && path.parentPath?.parentPath?.isObjectProperty()) {
		const parentKey = path.parentPath.parentPath.get('key') as AnyPath;
		if (parentKey.isIdentifier({ name: 'domProps' }) || parentKey.isStringLiteral({ value: 'domProps' })) {
		  return { label: 'Vue.domProps.innerHTML', argument: value, path, confidence: 'high', flowType: 'domXss' };
		}
	  }
	}
	if (path.isJSXAttribute() && path.get('name').isJSXIdentifier({ name: 'dangerouslySetInnerHTML' })) {
	  const value = path.get('value') as AnyPath;
	  if (value?.isJSXExpressionContainer()) {
		const html = objectPropertyValue(value.get('expression') as AnyPath, '__html');
		if (html) return { label: 'React.dangerouslySetInnerHTML', argument: html, path, confidence: 'high', flowType: 'domXss' };
	  }
	}
  if (path.isNewExpression()) {
    const callee = path.get('callee');
    const args = path.get('arguments') as AnyPath[];
    if (callee.isIdentifier({ name: 'Function' }) && !callee.scope.getBinding('Function') && args.length) {
      return { label: 'Function', argument: args[args.length - 1], path, confidence: 'high', flowType: 'dynamicExecution' };
    }
    if ((callee.isIdentifier({ name: 'Worker' }) || callee.isIdentifier({ name: 'SharedWorker' })) && args[0]) {
      return { label: `${callee.node.name}.url`, argument: args[0], path, confidence: 'high', flowType: 'scriptUrlInjection' };
    }
	if ((callee.isIdentifier({ name: 'WebSocket' }) || callee.isIdentifier({ name: 'EventSource' })) && args[0]) {
	  return { label: `${callee.node.name}.url`, argument: args[0], path, confidence: 'medium', flowType: 'clientRequestInjection' };
	}
  }
  return null;
}

function snippetFor(path: AnyPath, code: string): string {
  const start = path.node.start;
  const end = path.node.end;
  const snippet = typeof start === 'number' && typeof end === 'number' && end > start
    ? code.slice(start, end).replace(/\s+/g, ' ').trim()
    : '';
  return snippet.length > SNIPPET_MAX ? `${snippet.slice(0, SNIPPET_MAX)}…` : snippet;
}

function collectFunctionBody(functionPath: AnyPath): { sinks: SinkHit[]; calls: AnyPath[] } {
  const sinks: SinkHit[] = [];
  const calls: AnyPath[] = [];
  functionPath.traverse({
    Function(path) {
      if (path.node !== functionPath.node) path.skip();
    },
    enter(path) {
      const sink = classifySink(path as AnyPath);
      if (sink) sinks.push(sink);
      if (path.isCallExpression() && functionPathForCall(path as AnyPath)) calls.push(path as AnyPath);
    },
  });
  return { sinks, calls };
}

/** Analyze the pristine AST for browser-controlled source to dangerous sink flows. */
export function analyzeDomXss(
  ast: Node,
  code: string,
  limits: { maxFlows?: number; maxFunctionDepth?: number; maxResolutionDepth?: number } = {},
): DomFlow[] {
  const sinks: SinkHit[] = [];
  const localCalls: AnyPath[] = [];
  traverse(ast, {
    enter(path) {
      const sink = classifySink(path as AnyPath);
      if (sink) sinks.push(sink);
      if (path.isCallExpression() && functionPathForCall(path as AnyPath)) localCalls.push(path as AnyPath);
    },
  });

  const base: ResolverState = {
    overrides: new Map(), bindingIDs: new WeakMap(), nextBindingID: 1,
    resolving: new Set(), functionStack: new Set(), depth: 0,
    maxFunctionDepth: limits.maxFunctionDepth ?? MAX_FUNCTION_DEPTH,
    maxResolutionDepth: limits.maxResolutionDepth ?? MAX_DEPTH,
    messageOriginValidation: new WeakMap(),
  };
  const flows: DomFlow[] = [];
  const seen = new Set<string>();

  const emit = (sink: SinkHit, state: ResolverState) => {
    const taint = resolveExpression(sink.argument, sink.path.node.start ?? Number.MAX_SAFE_INTEGER, state);
    if (!taint) return;
    const line = sink.path.node.loc?.start.line ?? 0;
    const snippet = snippetFor(sink.path, code);
    const key = `${taint.source}|${sink.label}|${sink.path.node.start ?? line}`;
    if (seen.has(key) || flows.length >= (limits.maxFlows ?? MAX_FLOWS)) return;
    seen.add(key);
    const flowType = sink.flowType === 'clientRequestInjection' &&
      /cookie|storage\.getitem/i.test(taint.source) ? 'sensitiveExfiltration' : sink.flowType;
    flows.push({
      type: 'domFlow', source: taint.source, sink: sink.label, snippet, line,
      confidence: confidenceMin(taint.confidence, sink.confidence),
      path: [...taint.path, step(sink.path, 'sink', sink.label)],
      flowType,
    });
  };

  for (const sink of sinks) emit(sink, base);

  const analyzeCall = (callPath: AnyPath, parentState: ResolverState, depth: number) => {
    if (depth >= base.maxFunctionDepth || flows.length >= (limits.maxFlows ?? MAX_FLOWS)) return;
    const functionPath = functionPathForCall(callPath);
    if (!functionPath || parentState.functionStack.has(functionPath.node)) return;
    const overrides = functionOverrides(callPath, functionPath, parentState);
    const state = childState(parentState, overrides);
    state.functionStack.add(functionPath.node);
    state.depth = depth + 1;
    const body = collectFunctionBody(functionPath);
    for (const sink of body.sinks) emit(sink, state);
    for (const nestedCall of body.calls) analyzeCall(nestedCall, state, depth + 1);
  };
  for (const call of localCalls) analyzeCall(call, base, 0);

  return flows;
}
