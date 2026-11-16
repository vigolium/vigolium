import { createHash } from 'node:crypto';
import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import { generate } from '../ast-utils';
import { traverse, type NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import type {
  BodyTemplate,
  ClientRouteFact,
  ClientRouteMeta,
  Confidence,
  EventSourceFact,
  HeaderTemplate,
  Provenance,
  RouteMetaValue,
  ValueTemplate,
  WebSocketFact,
} from '../protocol';
import { valueTemplate } from '../protocol';

function hashId(prefix: string, ...parts: string[]): string {
  return `${prefix}-${createHash('sha256').update(parts.join('\0')).digest('hex').slice(0, 20)}`;
}

function memberName(node: t.Node): string {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const object = memberName(node.object as t.Node);
    const property = t.isIdentifier(node.property) ? node.property.name : t.isStringLiteral(node.property) ? node.property.value : '';
    return object && property ? `${object}.${property}` : property;
  }
  return '';
}

function stringValue(node: t.Node | null | undefined): string | undefined {
  if (!node) return undefined;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node)) {
    let rendered = '';
    for (let index = 0; index < node.quasis.length; index++) {
      rendered += node.quasis[index].value.cooked ?? node.quasis[index].value.raw;
      if (node.expressions[index]) rendered += `\${${generate(node.expressions[index])}}`;
    }
    return rendered;
  }
  if (t.isNewExpression(node) && t.isIdentifier(node.callee, { name: 'URL' })) {
    return stringValue(node.arguments[0] as t.Node);
  }
  return undefined;
}

function locationProvenance(path: NodePath, context: AnalysisContext, extractor: string, confidence: Confidence): Provenance {
  const start = path.node.loc?.start;
  return {
    extractor, confidence,
    ...(start ? { start: { line: start.line, column: start.column, offset: path.node.start ?? undefined } } : {}),
    ...(typeof path.node.start === 'number' && typeof path.node.end === 'number'
      ? { evidence: context.source.slice(path.node.start, Math.min(path.node.end, path.node.start + 400)) }
      : {}),
  };
}

function protocols(node: t.Node | null | undefined): string[] {
  if (!node) return [];
  if (t.isStringLiteral(node)) return [node.value];
  if (t.isArrayExpression(node)) return node.elements.flatMap((element) =>
    element && !t.isSpreadElement(element) && t.isStringLiteral(element) ? [element.value] : []);
  return [];
}

function body(node: t.Node | null | undefined): BodyTemplate | undefined {
  if (!node) return undefined;
  const rendered = t.isStringLiteral(node) ? node.value : generate(node);
  return { kind: /^[\[{]/.test(rendered.trim()) ? 'json' : 'text', value: valueTemplate(rendered) };
}

function objectFields(node: t.Node | null | undefined): Map<string, t.Node> {
  const fields = new Map<string, t.Node>();
  if (!node || !t.isObjectExpression(node)) return fields;
  for (const property of node.properties) {
    if (!t.isObjectProperty(property)) continue;
    const name = t.isIdentifier(property.key) ? property.key.name : t.isStringLiteral(property.key) ? property.key.value : '';
    if (name) fields.set(name, property.value);
  }
  return fields;
}

function headerTemplates(node: t.Node | null | undefined): HeaderTemplate[] {
  const headers: HeaderTemplate[] = [];
  for (const [name, value] of objectFields(node)) {
    const rendered = stringValue(value) ?? generate(value);
    headers.push({
      name: valueTemplate(name), value: valueTemplate(rendered),
      ...(/^(?:authorization|cookie|x-api-key)$/i.test(name) ? { sensitive: true } : {}),
    });
  }
  return headers;
}

function messageHandlerNode(path: NodePath, node: t.Node | null | undefined): t.Function | undefined {
  if (!node) return undefined;
  if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node) || t.isFunctionDeclaration(node)) return node;
  if (!t.isIdentifier(node)) return undefined;
  const binding = path.scope.getBinding(node.name);
  if (binding?.path.isFunctionDeclaration()) return binding.path.node;
  if (binding?.path.isVariableDeclarator() && (t.isFunctionExpression(binding.path.node.init) || t.isArrowFunctionExpression(binding.path.node.init))) {
    return binding.path.node.init;
  }
  return undefined;
}

function unsafeInboundMessage(path: NodePath, handler: t.Function, context: AnalysisContext): void {
  const parameter = handler.params[0];
  if (!t.isIdentifier(parameter)) return;
  const code = generate(handler);
  const escaped = parameter.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const usesData = new RegExp(`\\b${escaped}\\s*\\.\\s*data\\b`).test(code);
  if (!usesData) return;
  const validatesOrigin = new RegExp(
    `(?:${escaped}\\s*\\.\\s*(?:origin|source)\\s*(?:===|!==|==|!=)|(?:includes|has|test)\\s*\\([^)]*${escaped}\\s*\\.\\s*origin)`,
  ).test(code);
  if (validatesOrigin) return;
  context.addBrowserSecurityFlow({
    kind: 'browserSecurityFlow', id: hashId('browser-flow', 'unsafePostMessage-handler', String(path.node.start)),
    flowType: 'unsafePostMessage', source: `${parameter.name}.data`, sink: 'message handler without origin/source validation',
    confidence: 'high', evidence: code.slice(0, 500), path: [],
    provenance: locationProvenance(path, context, 'postmessage-handler-policy', 'high'),
  });
}

function looksSensitiveMessage(node: t.Node | null | undefined): boolean {
  if (!node) return false;
  return /(?:token|secret|auth|cookie|session|password|credential|apiKey|user|account|profile|personal)/i.test(generate(node));
}

interface RouteShape {
  /** Raw `path` as written (may be relative or empty). */
  raw: string;
  routeType: ClientRouteFact['routeType'];
  properties: Map<string, t.ObjectProperty>;
}

function routeShape(node: t.ObjectExpression): RouteShape | undefined {
  const properties = new Map<string, t.ObjectProperty>();
  for (const property of node.properties) {
    if (!t.isObjectProperty(property)) continue;
    const name = t.isIdentifier(property.key) ? property.key.name : t.isStringLiteral(property.key) ? property.key.value : '';
    if (name) properties.set(name, property);
  }
  const pathProperty = properties.get('path') ?? properties.get('id');
  if (!pathProperty) return undefined;
  // React Router data routes declare `Component`, `loader` or `lazy` and may
  // carry no `element`.
  const hasRouterSignal = [
    'component', 'element', 'children', 'loadChildren', 'loadComponent', 'redirectTo',
    ...ROUTE_GUARD_KEYS, 'Component', 'loader', 'lazy',
  ].some((name) => properties.has(name)) ||
    (properties.has('id') && ['pattern', 'page', 'endpoint'].some((name) => properties.has(name)));
  if (!hasRouterSignal) return undefined;
  const raw = stringValue(pathProperty.value);
  if (raw === undefined || raw === '*' || raw === '**') return undefined;
  let routeType: ClientRouteFact['routeType'] = raw.startsWith('/api/') ? 'api' : 'page';
  if (properties.has('redirectTo')) routeType = 'redirect';
  if (properties.has('loadChildren') || properties.has('loadComponent') || properties.has('lazy')) routeType = 'lazy';
  return { raw, routeType, properties };
}

/**
 * Route-record keys that gate navigation: Angular `canActivate`,
 * `canActivateChild`, `canMatch` and `canLoad`, Vue Router `beforeEnter`.
 * `canDeactivate` is left out: it guards leaving a view, not reaching it.
 */
const ROUTE_GUARD_KEYS = ['canActivate', 'canActivateChild', 'canMatch', 'canLoad', 'beforeEnter'];

/** Placeholder for a guard or loader written as an anonymous function. */
const INLINE_FUNCTION = '<inline>';
const MAX_REFERENCE_LENGTH = 120;

/**
 * Renders a call chain as written, arguments included when they are
 * identifiers or literals: `inject(AuthService).isLoggedIn`,
 * `hasRole("admin")`. Undefined for any other shape.
 */
function callChainName(node: t.Node, depth = 0): string | undefined {
  if (depth > 6) return undefined;
  if (t.isIdentifier(node)) return node.name;
  if (t.isThisExpression(node)) return 'this';
  if ((t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) && !node.computed && t.isIdentifier(node.property)) {
    const object = callChainName(node.object as t.Node, depth + 1);
    return object ? `${object}.${node.property.name}` : undefined;
  }
  if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
    const callee = callChainName(node.callee as t.Node, depth + 1);
    if (!callee) return undefined;
    const args = node.arguments.map((argument) => {
      if (t.isIdentifier(argument)) return argument.name;
      if (t.isStringLiteral(argument) || t.isNumericLiteral(argument) || t.isBooleanLiteral(argument)) {
        return JSON.stringify(argument.value);
      }
      return '…';
    });
    return `${callee}(${args.join(', ')})`;
  }
  if (t.isAwaitExpression(node) || t.isUnaryExpression(node)) return callChainName(node.argument, depth + 1);
  return undefined;
}

function boundedReference(name: string): string {
  return name.length > MAX_REFERENCE_LENGTH ? `${name.slice(0, MAX_REFERENCE_LENGTH - 1)}…` : name;
}

/**
 * Names a guard or loader reference. A named function is its identifier
 * (or dotted member), an injection token its string; a call such as a guard factory is its call chain; an
 * anonymous function whose body is a single call is that call (an Angular
 * functional guard `() => inject(Auth).check()`), any other anonymous
 * function is `<inline>`.
 */
function functionReference(node: t.Node): string | undefined {
  if (t.isIdentifier(node)) return node.name;
  // Angular's deprecated string-token guards: `canActivate: ['authToken']`.
  if (t.isStringLiteral(node)) return node.value ? boundedReference(node.value) : undefined;
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const name = memberName(node);
    return name ? boundedReference(name) : undefined;
  }
  if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
    const name = callChainName(node);
    return name ? boundedReference(name) : INLINE_FUNCTION;
  }
  if (t.isArrowFunctionExpression(node) || t.isFunctionExpression(node)) {
    let expression: t.Node | undefined;
    if (t.isExpression(node.body)) expression = node.body;
    else if (node.body.body.length === 1 && t.isReturnStatement(node.body.body[0])) expression = node.body.body[0].argument ?? undefined;
    const name = expression && (t.isCallExpression(expression) || t.isOptionalCallExpression(expression) || t.isAwaitExpression(expression))
      ? callChainName(expression)
      : undefined;
    return name ? boundedReference(name) : INLINE_FUNCTION;
  }
  return undefined;
}

/** Guard names from every gating key of a route record, in key order, deduplicated. */
function routeGuards(properties: Map<string, t.ObjectProperty>): string[] {
  const guards: string[] = [];
  for (const key of ROUTE_GUARD_KEYS) {
    const property = properties.get(key);
    if (!property) continue;
    const elements = t.isArrayExpression(property.value) ? property.value.elements : [property.value];
    for (const element of elements) {
      if (!element || t.isSpreadElement(element)) continue;
      const name = functionReference(element);
      if (name && !guards.includes(name)) guards.push(name);
    }
  }
  return guards;
}

// Bounds on the emitted metadata object, so a route record holding a large
// table cannot inflate every route fact.
const MAX_META_DEPTH = 4;
const MAX_META_KEYS = 32;
const MAX_META_ITEMS = 32;
const MAX_META_STRING = 512;

/**
 * The literal value of `node`, or null when it is not a literal. Minified
 * `!0`, `!1` and `void 0` are the literals `true`, `false` and null: a
 * minifier emits them for the constants a developer wrote.
 */
function metaValue(node: t.Node, depth: number): RouteMetaValue {
  if (t.isStringLiteral(node)) return node.value.length <= MAX_META_STRING ? node.value : null;
  if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
    const value = node.quasis[0]?.value.cooked ?? '';
    return value.length <= MAX_META_STRING ? value : null;
  }
  if (t.isNumericLiteral(node)) return node.value;
  if (t.isBooleanLiteral(node)) return node.value;
  if (t.isNullLiteral(node)) return null;
  if (t.isUnaryExpression(node)) {
    if (node.operator === '!' && t.isNumericLiteral(node.argument)) return !node.argument.value;
    if (node.operator === '-' && t.isNumericLiteral(node.argument)) return -node.argument.value;
    return null;
  }
  if (depth >= MAX_META_DEPTH) return null;
  if (t.isArrayExpression(node)) {
    return node.elements.slice(0, MAX_META_ITEMS).map((element) =>
      element && !t.isSpreadElement(element) ? metaValue(element, depth + 1) : null);
  }
  if (t.isObjectExpression(node)) return metaObject(node, depth + 1);
  return null;
}

function metaObject(node: t.ObjectExpression, depth: number): ClientRouteMeta {
  const out: ClientRouteMeta = {};
  let keys = 0;
  for (const property of node.properties) {
    if (keys >= MAX_META_KEYS) break;
    if (!t.isObjectProperty(property) && !t.isObjectMethod(property)) continue;
    if (property.computed) continue;
    const key = property.key;
    const name = t.isIdentifier(key) ? key.name : t.isStringLiteral(key) ? key.value : t.isNumericLiteral(key) ? String(key.value) : '';
    if (!name) continue;
    out[name] = t.isObjectProperty(property) ? metaValue(property.value, depth) : null;
    keys++;
  }
  return out;
}

/**
 * The literal metadata object of a route record: Vue Router `meta`, else
 * Angular `data`. A value naming a `const` object in scope is followed once.
 */
function routeMeta(path: NodePath, properties: Map<string, t.ObjectProperty>): ClientRouteMeta | undefined {
  const property = properties.get('meta') ?? properties.get('data');
  if (!property) return undefined;
  let value: t.Node = property.value;
  if (t.isIdentifier(value)) {
    const binding = path.scope.getBinding(value.name);
    const init = binding?.kind === 'const' && binding.path.isVariableDeclarator() ? binding.path.node.init : undefined;
    if (!init) return undefined;
    value = init;
  }
  if (!t.isObjectExpression(value)) return undefined;
  const meta = metaObject(value, 1);
  return Object.keys(meta).length ? meta : undefined;
}

interface RouteLineage {
  full: string;
  /** True when the parent route lives in another module (forChild, lazy). */
  unknownParent: boolean;
  /** Nearest emitted ancestor route id. */
  parentId?: string;
  /** Id this route is emitted under. */
  id: string;
}

const MAX_ROUTE_DEPTH = 12;

function joinRoute(parent: string, child: string): string {
  const joined = `${parent}/${child}`.replace(/\/{2,}/g, '/');
  return joined.length > 1 ? joined.replace(/\/$/, '') : joined;
}

/** True for `RouterModule.forChild(...)` and minified `x.forChild(...)`. */
function isForChildCall(node: t.Node | null | undefined): boolean {
  return t.isCallExpression(node) && t.isMemberExpression(node.callee) &&
    t.isIdentifier(node.callee.property, { name: 'forChild' });
}

/**
 * The route object enclosing `array` through a `children` property, directly
 * or through a binding (`children: adminRoutes`). `lazy` when the array is a
 * forChild table, whose parent is the lazy route in another module.
 */
function enclosingRoute(array: NodePath): { parent?: NodePath<t.ObjectExpression>; lazy: boolean } {
  const viaChildren = (holder: NodePath | null): NodePath<t.ObjectExpression> | undefined => {
    if (!holder?.isObjectProperty()) return undefined;
    const key = holder.node.key;
    const name = t.isIdentifier(key) ? key.name : t.isStringLiteral(key) ? key.value : '';
    const owner = holder.parentPath;
    return name === 'children' && owner?.isObjectExpression() ? owner : undefined;
  };
  const direct = viaChildren(array.parentPath);
  if (direct) return { parent: direct, lazy: false };
  if (isForChildCall(array.parentPath?.node)) return { lazy: true };
  const declarator = array.parentPath;
  if (declarator?.isVariableDeclarator() && t.isIdentifier(declarator.node.id)) {
    const binding = declarator.scope.getBinding(declarator.node.id.name);
    for (const ref of binding?.referencePaths ?? []) {
      const parent = viaChildren(ref.parentPath);
      if (parent) return { parent, lazy: false };
      if (isForChildCall(ref.parentPath?.node)) return { lazy: true };
    }
  }
  return { lazy: false };
}

function routeLineage(
  path: NodePath<t.ObjectExpression>,
  shape: RouteShape,
  memo: WeakMap<object, RouteLineage | null>,
  depth = 0,
): RouteLineage {
  const cached = memo.get(path.node);
  if (cached) return cached;
  let parent: RouteLineage | undefined;
  let parentShape: RouteShape | undefined;
  let unknownParent = false;
  const array = path.parentPath;
  if (array?.isArrayExpression() && depth < MAX_ROUTE_DEPTH) {
    const enclosing = enclosingRoute(array);
    unknownParent = enclosing.lazy;
    parentShape = enclosing.parent ? routeShape(enclosing.parent.node) : undefined;
    if (enclosing.parent && parentShape) parent = routeLineage(enclosing.parent, parentShape, memo, depth + 1);
  }
  let full: string;
  if (shape.raw.startsWith('/')) full = shape.raw;
  else if (parent) full = shape.raw ? joinRoute(parent.full, shape.raw) : parent.full;
  else if (unknownParent) full = joinRoute('${parent}', shape.raw);
  else full = joinRoute('', shape.raw);
  if (shape.raw.startsWith('/')) unknownParent = false;
  else if (parent) unknownParent = parent.unknownParent;
  // A route emitted under its absolute path keeps its historical id; nested
  // ones hash the full path so siblings named alike under different parents
  // stay distinct.
  const id = hashId('route', full === shape.raw ? shape.raw : full, shape.routeType);
  // An empty-path parent is never emitted, so point at its own parent instead.
  const parentId = parent ? (parentShape?.raw ? parent.id : parent.parentId) : undefined;
  const lineage: RouteLineage = { full, unknownParent, id, ...(parentId ? { parentId } : {}) };
  memo.set(path.node, lineage);
  return lineage;
}

function routeObject(
  path: NodePath<t.ObjectExpression>,
  context: AnalysisContext,
  memo: WeakMap<object, RouteLineage | null>,
): ClientRouteFact | undefined {
  const shape = routeShape(path.node);
  // An empty path only contributes to its children's full path.
  if (!shape || !shape.raw) return undefined;
  const { raw: rendered, routeType, properties } = shape;
  const lineage = routeLineage(path, shape, memo);
  const guards = routeGuards(properties);
  const meta = routeMeta(path, properties);
  const loaderProperty = properties.get('loader');
  const loader = loaderProperty ? functionReference(loaderProperty.value) : undefined;
  const lazyProperty = properties.get('loadChildren') ?? properties.get('loadComponent') ?? properties.get('lazy');
  let lazyAsset: ValueTemplate | undefined;
  if (lazyProperty) {
    const generated = generate(lazyProperty.value);
    const match = generated.match(/import\(["']([^"']+)["']\)/);
    if (match) lazyAsset = valueTemplate(match[1]);
  }
  return {
    kind: 'clientRoute', id: lineage.id, path: valueTemplate(rendered), routeType,
    ...(guards.length ? { guards } : {}), ...(lazyAsset ? { lazyAsset } : {}),
    ...(meta ? { meta } : {}), ...(loader ? { loader } : {}),
    fullPath: valueTemplate(lineage.full),
    ...(lineage.parentId ? { parentId: lineage.parentId } : {}),
    provenance: locationProvenance(path, context, 'router-config', 'high'),
  };
}

export function analyzeBrowserCapabilities(ast: ParseResult<t.File>, context: AnalysisContext): void {
  const socketBindings = new Map<string, WebSocketFact>();
  const routeMemo = new WeakMap<object, RouteLineage | null>();
  const eventSourceBindings = new Map<string, EventSourceFact>();

  traverse(ast, {
	AssignmentExpression(path) {
	  if (context.has('clientRoutes') && t.isMemberExpression(path.node.left) && t.isObjectExpression(path.node.right)) {
		const property = t.isIdentifier(path.node.left.property) ? path.node.left.property.name : '';
		if (/BUILD_MANIFEST|ROUTES_MANIFEST/.test(property)) {
		  for (const item of path.node.right.properties) {
			if (!t.isObjectProperty(item)) continue;
			const route = t.isStringLiteral(item.key) ? item.key.value : t.isIdentifier(item.key) ? item.key.name : '';
			if (!route.startsWith('/')) continue;
			let lazyAsset: ValueTemplate | undefined;
			if (t.isArrayExpression(item.value)) {
			  const asset = item.value.elements.find((element) => t.isStringLiteral(element) && /\.js(?:\?|$)/.test(element.value));
			  if (asset && t.isStringLiteral(asset)) lazyAsset = valueTemplate(asset.value);
			}
			context.addClientRoute({
			  kind: 'clientRoute', id: hashId('route', route, property), path: valueTemplate(route),
			  routeType: lazyAsset ? 'lazy' : 'page', ...(lazyAsset ? { lazyAsset } : {}),
			  provenance: locationProvenance(path, context, 'next-route-manifest', 'high'),
			});
		  }
		}
	  }
	  if (!t.isMemberExpression(path.node.left)) return;
	  const property = t.isIdentifier(path.node.left.property) ? path.node.left.property.name : '';
	  if (context.has('realtimeProtocols') && property === 'onmessage' && t.isIdentifier(path.node.left.object)) {
		const eventSource = eventSourceBindings.get(path.node.left.object.name);
		if (eventSource && !eventSource.eventNames.includes('message')) eventSource.eventNames.push('message');
	  }
	  if (context.has('browserSecurityFlows') && property === 'onmessage') {
		const handler = messageHandlerNode(path, path.node.right);
		if (handler) unsafeInboundMessage(path, handler, context);
	  }
	},
	VariableDeclarator(path) {
	  if (!context.has('clientRoutes') || !t.isIdentifier(path.node.id, { name: 'config' }) || !t.isObjectExpression(path.node.init)) return;
	  const matcher = objectFields(path.node.init).get('matcher');
	  const routes = t.isStringLiteral(matcher)
		? [matcher.value]
		: t.isArrayExpression(matcher)
		  ? matcher.elements.flatMap((element) => element && t.isStringLiteral(element) ? [element.value] : [])
		  : [];
	  for (const route of routes) if (route.startsWith('/')) context.addClientRoute({
		kind: 'clientRoute', id: hashId('route', route, 'middleware'), path: valueTemplate(route), routeType: 'page',
		provenance: locationProvenance(path, context, 'middleware-matcher', 'high'),
	  });
	},
    ObjectExpression(path) {
      if (context.has('clientRoutes')) {
        const route = routeObject(path, context, routeMemo);
        if (route) context.addClientRoute(route);
      }
    },
    JSXOpeningElement(path) {
	  if (!context.has('clientRoutes') || !t.isJSXIdentifier(path.node.name)) return;
	  const component = path.node.name.name;
	  if (!['Route', 'Link', 'NavLink', 'IonRouterLink'].includes(component)) return;
      const attribute = path.node.attributes.find((item): item is t.JSXAttribute =>
		t.isJSXAttribute(item) && t.isJSXIdentifier(item.name) && ['path', 'to', 'href', 'routerLink'].includes(item.name.name));
      const rendered = attribute && t.isStringLiteral(attribute.value) ? attribute.value.value : undefined;
      if (!rendered || rendered === '*') return;
      context.addClientRoute({
        kind: 'clientRoute', id: hashId('route', rendered, 'jsx'), path: valueTemplate(rendered),
        routeType: rendered.startsWith('/api/') ? 'api' : 'page',
		provenance: locationProvenance(path, context, component === 'IonRouterLink' ? 'ionic-router-jsx' : 'react-router-jsx', 'high'),
      });
    },
    NewExpression(path) {
      if (!context.has('realtimeProtocols')) return;
      const name = memberName(path.node.callee);
      const rendered = stringValue(path.node.arguments[0] as t.Node);
      if (!rendered) return;
      if (name === 'WebSocket' || name.endsWith('.WebSocket') || name === 'SockJS') {
        const library: WebSocketFact['library'] = name === 'SockJS' ? 'sockjs' : 'native';
        const fact: WebSocketFact = {
          kind: 'websocket', id: hashId('websocket', rendered, library), url: valueTemplate(rendered),
          subprotocols: protocols(path.node.arguments[1] as t.Node), outboundMessages: [], inboundEventNames: [],
          library, provenance: locationProvenance(path, context, library === 'sockjs' ? 'sockjs' : 'native-websocket', 'high'),
        };
        context.addWebSocket(fact);
        if (path.parentPath?.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id)) {
          socketBindings.set(`${path.scope.uid}:${path.parentPath.node.id.name}`, fact);
          socketBindings.set(path.parentPath.node.id.name, fact);
        }
      } else if (name === 'EventSource' || name.endsWith('.EventSource')) {
        const options = path.node.arguments[1];
        const withCredentials = t.isObjectExpression(options) && options.properties.some((property) =>
          t.isObjectProperty(property) && t.isIdentifier(property.key, { name: 'withCredentials' }) && t.isBooleanLiteral(property.value, { value: true }));
        const fact: EventSourceFact = {
          kind: 'eventSource', id: hashId('eventsource', rendered), url: valueTemplate(rendered),
          withCredentials, eventNames: [], library: 'native',
          provenance: locationProvenance(path, context, 'native-eventsource', 'high'),
        };
        context.addEventSource(fact);
        if (path.parentPath?.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id)) {
          eventSourceBindings.set(path.parentPath.node.id.name, fact);
        }
      }
    },
    CallExpression(path) {
      const name = memberName(path.node.callee);
	  if (context.has('browserSecurityFlows') && name.endsWith('addEventListener')) {
		const eventName = stringValue(path.node.arguments[0] as t.Node);
		if (eventName === 'message') {
		  const handlerArg = path.node.arguments[1];
		  const handler = handlerArg && !t.isSpreadElement(handlerArg) ? messageHandlerNode(path, handlerArg) : undefined;
		  if (handler) unsafeInboundMessage(path, handler, context);
		}
	  }
      if (context.has('clientRoutes')) {
        const routeArg = name.endsWith('pushState') || name.endsWith('replaceState')
          ? path.node.arguments[2]
          : /(?:^|\.)(?:navigate|push|replace)$/.test(name)
            ? path.node.arguments[0]
            : undefined;
        const rendered = routeArg && !t.isSpreadElement(routeArg) ? stringValue(routeArg) : undefined;
        if (rendered && rendered.startsWith('/') && rendered !== '/*') {
          context.addClientRoute({
            kind: 'clientRoute', id: hashId('route', rendered, name), path: valueTemplate(rendered), routeType: 'page',
            provenance: locationProvenance(path, context, 'router-navigation', 'medium'),
          });
        }
      }

      if (context.has('realtimeProtocols')) {
        if (name === 'io' || name.endsWith('.io')) {
          const rendered = stringValue(path.node.arguments[0] as t.Node);
		  const config = path.node.arguments[1];
		  const fields = objectFields(config as t.Node);
		  if (rendered) {
			const options: Record<string, ValueTemplate> = {};
			for (const option of ['path', 'transports', 'reconnection', 'withCredentials']) {
			  const value = fields.get(option);
			  if (value) options[option] = valueTemplate(stringValue(value) ?? generate(value));
			}
			const fact: WebSocketFact = {
			  kind: 'websocket', id: hashId('websocket', rendered, 'socket.io'), url: valueTemplate(rendered),
			  subprotocols: [], outboundMessages: [], inboundEventNames: [], library: 'socket.io',
			  ...(fields.get('extraHeaders') ? { headers: headerTemplates(fields.get('extraHeaders')) } : {}),
			  ...(Object.keys(options).length ? { options } : {}),
			  provenance: locationProvenance(path, context, 'socket.io', 'high'),
			};
			context.addWebSocket(fact);
			if (path.parentPath?.isVariableDeclarator() && t.isIdentifier(path.parentPath.node.id)) socketBindings.set(path.parentPath.node.id.name, fact);
		  }
        }
		if (name === 'fetch') {
		  const rendered = stringValue(path.node.arguments[0] as t.Node);
		  const config = path.node.arguments[1];
		  const fields = objectFields(config as t.Node);
		  const headers = headerTemplates(fields.get('headers'));
		  if (rendered && headers.some((header) => header.name.rendered.toLowerCase() === 'accept' && /text\/event-stream/i.test(header.value.rendered))) {
			const lastEvent = headers.find((header) => header.name.rendered.toLowerCase() === 'last-event-id');
			context.addEventSource({
			  kind: 'eventSource', id: hashId('eventsource', rendered, 'fetch-stream'), url: valueTemplate(rendered),
			  withCredentials: fields.get('credentials') !== undefined, eventNames: [], library: 'fetch-stream', headers,
			  ...(lastEvent ? { lastEventId: lastEvent.value } : {}),
			  provenance: locationProvenance(path, context, 'fetch-sse', 'high'),
			});
		  }
		}
        if (name.endsWith('createClient') && t.isObjectExpression(path.node.arguments[0])) {
          const config = path.node.arguments[0];
          const urlProperty = config.properties.find((property): property is t.ObjectProperty =>
            t.isObjectProperty(property) && t.isIdentifier(property.key, { name: 'url' }));
          const rendered = urlProperty ? stringValue(urlProperty.value) : undefined;
          if (rendered && /^wss?:/i.test(rendered)) context.addWebSocket({
            kind: 'websocket', id: hashId('websocket', rendered, 'graphql-ws'), url: valueTemplate(rendered),
            subprotocols: ['graphql-transport-ws'], outboundMessages: [], inboundEventNames: [], library: 'graphql-ws',
            provenance: locationProvenance(path, context, 'graphql-ws', 'high'),
          });
        }
        if (t.isMemberExpression(path.node.callee) && t.isIdentifier(path.node.callee.object)) {
          const receiver = path.node.callee.object.name;
          const method = t.isIdentifier(path.node.callee.property) ? path.node.callee.property.name : '';
          const socket = socketBindings.get(`${path.scope.uid}:${receiver}`) ?? socketBindings.get(receiver);
          const eventSource = eventSourceBindings.get(receiver);
          if (socket && method === 'send') {
            const message = body(path.node.arguments[0] as t.Node);
            if (message && !socket.outboundMessages.some((item) => item.value.rendered === message.value.rendered)) socket.outboundMessages.push(message);
          }
		  if (socket && method === 'emit') {
			const event = stringValue(path.node.arguments[0] as t.Node) ?? 'event';
			const payload = path.node.arguments[1];
			const message = body(payload && !t.isSpreadElement(payload) ? payload : undefined);
			if (message) {
			  message.value = valueTemplate(JSON.stringify({ event, payload: message.value.rendered }));
			  if (!socket.outboundMessages.some((item) => item.value.rendered === message.value.rendered)) socket.outboundMessages.push(message);
			}
		  }
          if (method === 'addEventListener' || method === 'on') {
            const event = stringValue(path.node.arguments[0] as t.Node);
            if (event && socket && !socket.inboundEventNames.includes(event)) socket.inboundEventNames.push(event);
            if (event && eventSource && !eventSource.eventNames.includes(event)) eventSource.eventNames.push(event);
          }
        }
      }

      if (context.has('browserSecurityFlows') && name.endsWith('postMessage')) {
        const target = stringValue(path.node.arguments[1] as t.Node);
        const message = path.node.arguments[0];
        if (target === '*' && message && !t.isSpreadElement(message) && looksSensitiveMessage(message)) {
          const evidence = typeof path.node.start === 'number' && typeof path.node.end === 'number'
            ? context.source.slice(path.node.start, path.node.end)
            : 'postMessage(..., "*")';
          context.addBrowserSecurityFlow({
            kind: 'browserSecurityFlow', id: hashId('browser-flow', 'unsafePostMessage', String(path.node.start)),
            flowType: 'unsafePostMessage', source: 'application data', sink: 'postMessage targetOrigin=*',
            confidence: 'high', evidence, path: [],
            provenance: locationProvenance(path, context, 'postmessage-policy', 'high'),
          });
        }
      }
    },
  });
}
