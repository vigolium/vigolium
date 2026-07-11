import { createHash } from 'node:crypto';
import * as t from '@babel/types';
import type { ParseResult } from '@babel/parser';
import { traverse, type NodePath } from '../ast-utils/babel';
import type { AnalysisContext } from '../context';
import type { AssetReferenceFact, AssetType, Confidence, Provenance } from '../protocol';
import { getTrackedVariablesMap } from '../requestpattern/globalVariableTracking';
import { createResolutionContext, findContainingFunction, resolveValue } from '../requestpattern/extractRequest';

const SOURCE_MAP_REFERENCE = /\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/g;
const FETCHED_ASSET = /\.(?:m?js|cjs|json|wasm|webmanifest)(?:[?#]|$)/i;

function stableId(kind: AssetType, rendered: string, parent: string): string {
  return `asset-${createHash('sha256').update(`${kind}\0${rendered}\0${parent}`).digest('hex').slice(0, 20)}`;
}

function memberPath(node: t.Node): string {
  const parts: string[] = [];
  let current: t.Node = node;
  while (t.isMemberExpression(current) || t.isOptionalMemberExpression(current)) {
    const property = current.property;
    if (t.isIdentifier(property)) parts.unshift(property.name);
    else if (t.isStringLiteral(property)) parts.unshift(property.value);
    else return '';
    current = current.object as t.Node;
  }
  if (t.isIdentifier(current)) parts.unshift(current.name);
  return parts.join('.');
}

function directAssetArgument(node: t.Node | null | undefined): t.Node | undefined {
  if (!node) return undefined;
  if (t.isNewExpression(node) && t.isIdentifier(node.callee, { name: 'URL' })) {
    const first = node.arguments[0];
    return first && !t.isSpreadElement(first) ? first : undefined;
  }
  return node;
}

function provenance(path: NodePath, extractor: string, confidence: Confidence, source: string): Provenance {
  const node = path.node;
  const start = node.loc?.start;
  const end = node.loc?.end;
  const evidence = typeof node.start === 'number' && typeof node.end === 'number'
    ? source.slice(node.start, Math.min(node.end, node.start + 300))
    : undefined;
  const functionName = findContainingFunction(path);
  return {
    extractor, confidence,
    ...(functionName ? { functionName } : {}),
    ...(start ? { start: { line: start.line, column: start.column, offset: node.start ?? undefined } } : {}),
    ...(end ? { end: { line: end.line, column: end.column, offset: node.end ?? undefined } } : {}),
    ...(evidence ? { evidence } : {}),
  };
}

function addResolved(
  context: AnalysisContext,
  path: NodePath,
  node: t.Node | null | undefined,
  assetType: AssetType,
  eager: boolean,
  extractor: string,
  confidence: Confidence,
): void {
  const valueNode = directAssetArgument(node);
  if (!valueNode) return;
  const values = resolveValue(
    valueNode,
    getTrackedVariablesMap(),
    createResolutionContext(findContainingFunction(path), { callSiteIndex: 0 }, path),
  ).filter((value) => value && value !== '${unknown}' && value !== '${X}');
  if (!values.length) return;
  const [rendered, ...alternatives] = [...new Set(values)];
  if (!/^(?:https?:)?\/\//.test(rendered) && !/^(?:\.{0,2}\/)/.test(rendered) &&
      !rendered.startsWith('data:') && !FETCHED_ASSET.test(rendered)) return;
  const parent = context.sourceUrl ?? '';
  context.addAssetReference({
    kind: 'assetReference', id: stableId(assetType, rendered, parent), assetType,
    url: {
      rendered, static: !rendered.includes('${'),
      variables: [...rendered.matchAll(/\$\{([^}]+)\}/g)].map((match) => ({ name: match[1], placeholder: match[0] })),
      ...(alternatives.length ? { alternatives } : {}),
    },
    ...(parent ? { parentSourceUrl: parent } : {}), eager,
    provenance: provenance(path, extractor, confidence, context.source),
  });
}

export function extractAssetReferences(
  ast: ParseResult<t.File>,
  context: AnalysisContext,
): AssetReferenceFact[] {
  for (const match of context.source.matchAll(SOURCE_MAP_REFERENCE)) {
    const raw = match[1].replace(/["']/g, '');
    const inline = raw.startsWith('data:');
    const rendered = inline ? 'inline:source-map' : raw;
    context.addAssetReference({
      kind: 'assetReference', id: stableId('source-map', rendered, context.sourceUrl ?? ''),
      assetType: 'source-map', url: { rendered, static: true, variables: [] },
      ...(context.sourceUrl ? { parentSourceUrl: context.sourceUrl } : {}),
      eager: false, ...(inline ? { inline: true } : {}),
      provenance: {
        extractor: 'source-map-comment', confidence: 'high',
        start: { offset: match.index },
        evidence: inline ? 'inline source map data URL' : match[0].slice(0, 300),
      },
    });
  }

  traverse(ast, {
    ImportDeclaration(path) {
      addResolved(context, path, path.node.source, 'script', true, 'static-import', 'high');
    },
    ExportNamedDeclaration(path) {
      if (path.node.source) addResolved(context, path, path.node.source, 'script', true, 're-export', 'high');
    },
    ExportAllDeclaration(path) {
      addResolved(context, path, path.node.source, 'script', true, 're-export-all', 'high');
    },
    NewExpression(path) {
      const name = t.isIdentifier(path.node.callee) ? path.node.callee.name : memberPath(path.node.callee);
      if (name === 'Worker' || name.endsWith('.Worker')) {
        addResolved(context, path, path.node.arguments[0] as t.Node, 'worker', false, 'worker-constructor', 'high');
      } else if (name === 'SharedWorker' || name.endsWith('.SharedWorker')) {
        addResolved(context, path, path.node.arguments[0] as t.Node, 'shared-worker', false, 'shared-worker-constructor', 'high');
      }
    },
    AssignmentExpression(path) {
      if (t.isMemberExpression(path.node.left) && t.isIdentifier(path.node.left.property, { name: 'src' })) {
        addResolved(context, path, path.node.right, 'script', false, 'script-src-assignment', 'medium');
      }
    },
    CallExpression(path) {
      const callee = path.node.callee;
      if (t.isImport(callee)) {
        addResolved(context, path, path.node.arguments[0] as t.Node, 'dynamic-import', false, 'dynamic-import', 'high');
        return;
      }
      const name = t.isIdentifier(callee) ? callee.name : memberPath(callee);
      if (name === 'importScripts' || name.endsWith('.importScripts')) {
        for (const arg of path.node.arguments) {
          if (!t.isSpreadElement(arg)) addResolved(context, path, arg, 'script', true, 'import-scripts', 'high');
        }
      } else if (name.endsWith('serviceWorker.register')) {
        addResolved(context, path, path.node.arguments[0] as t.Node, 'service-worker', false, 'service-worker-register', 'high');
      } else if (/precacheAndRoute$/.test(name)) {
        const first = path.node.arguments[0];
        if (t.isArrayExpression(first)) {
          for (const element of first.elements) {
            if (!element || t.isSpreadElement(element)) continue;
            const value = t.isObjectExpression(element)
              ? element.properties.find((prop): prop is t.ObjectProperty =>
                  t.isObjectProperty(prop) && ((t.isIdentifier(prop.key) && prop.key.name === 'url') || (t.isStringLiteral(prop.key) && prop.key.value === 'url')))?.value
              : element;
            addResolved(context, path, value as t.Node, 'manifest', true, 'workbox-precache', 'medium');
          }
        }
      } else if (name === 'fetch' || name.endsWith('.fetch')) {
        const first = path.node.arguments[0];
        if (first && !t.isSpreadElement(first)) {
          const direct = directAssetArgument(first);
          const literal = t.isStringLiteral(direct) ? direct.value : '';
          if (/\.wasm(?:[?#]|$)/i.test(literal)) {
            addResolved(context, path, first, 'wasm', false, 'wasm-fetch', 'high');
          } else if (/\.(?:json|webmanifest)(?:[?#]|$)/i.test(literal)) {
            addResolved(context, path, first, literal.includes('manifest') ? 'manifest' : 'config', false, 'config-fetch', 'medium');
          }
        }
      }
    },
  });
  return context.assetReferences;
}
