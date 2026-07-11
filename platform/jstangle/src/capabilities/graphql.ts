import { createHash } from 'node:crypto';
import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import {
  Kind,
  parse as parseGraphQL,
  print,
  stripIgnoredCharacters,
  type DocumentNode,
  type OperationDefinitionNode,
} from 'graphql';
import { traverse, type NodePath } from '../ast-utils/babel';
import { generate } from '../ast-utils';
import type { AnalysisContext } from '../context';
import type { Confidence, GraphQLOperationFact, Provenance, ValueTemplate } from '../protocol';
import { valueTemplate } from '../protocol';

const MAX_DOCUMENT_BYTES = 100 * 1024;
const MAX_DOCUMENT_DEPTH = 25;

interface DocumentCandidate {
  document: string;
  parsed: DocumentNode;
  path: NodePath;
  confidence: Confidence;
  endpoint?: string;
  persistedQueryHash?: string;
  transport?: GraphQLOperationFact['transport'];
  variableValues?: Record<string, ValueTemplate>;
}

function propertyName(node: t.ObjectProperty | t.ObjectMethod): string {
  if (t.isIdentifier(node.key)) return node.key.name;
  if (t.isStringLiteral(node.key)) return node.key.value;
  return '';
}

function objectProperty(object: t.ObjectExpression | null | undefined, name: string): t.Node | undefined {
  if (!object) return undefined;
  const property = object.properties.find((item): item is t.ObjectProperty =>
    t.isObjectProperty(item) && propertyName(item) === name);
  return property?.value;
}

function stringFromNode(node: t.Node | null | undefined, path: NodePath, depth = 0): string | undefined {
  if (!node || depth > 8) return undefined;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('');
  }
  if (t.isTaggedTemplateExpression(node)) return stringFromNode(node.quasi, path, depth + 1);
  if (t.isIdentifier(node)) {
    const binding = path.scope.getBinding(node.name);
    if (binding?.path.isVariableDeclarator()) return stringFromNode(binding.path.node.init, binding.path as NodePath, depth + 1);
  }
  return undefined;
}

function parseDocument(document: string): DocumentNode | undefined {
  if (!document || Buffer.byteLength(document) > MAX_DOCUMENT_BYTES) return undefined;
  try {
    const parsed = parseGraphQL(document, { noLocation: false, maxTokens: 20_000 });
    if (!parsed.definitions.some((definition) => definition.kind === Kind.OPERATION_DEFINITION)) return undefined;
    if (documentDepth(parsed) > MAX_DOCUMENT_DEPTH) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

function documentDepth(document: DocumentNode): number {
  const selectionDepth = (selectionSet: OperationDefinitionNode['selectionSet'], depth: number): number => {
    let maximum = depth;
    for (const selection of selectionSet.selections) {
      if ('selectionSet' in selection && selection.selectionSet) {
        maximum = Math.max(maximum, selectionDepth(selection.selectionSet, depth + 1));
      }
    }
    return maximum;
  };
  let maximum = 0;
  for (const definition of document.definitions) {
    if (definition.kind === Kind.OPERATION_DEFINITION) maximum = Math.max(maximum, selectionDepth(definition.selectionSet, 1));
  }
  return maximum;
}

function pathEvidence(path: NodePath, context: AnalysisContext, extractor: string, confidence: Confidence): Provenance {
  const node = path.node;
  const start = node.loc?.start;
  return {
    extractor, confidence,
    ...(start ? { start: { line: start.line, column: start.column, offset: node.start ?? undefined } } : {}),
    ...(typeof node.start === 'number' && typeof node.end === 'number'
      ? { evidence: context.source.slice(node.start, Math.min(node.end, node.start + 500)) }
      : {}),
  };
}

function calleeName(node: t.Node): string {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const property = t.isIdentifier(node.property) ? node.property.name : t.isStringLiteral(node.property) ? node.property.value : '';
    const object = t.isIdentifier(node.object) ? node.object.name : '';
    return object && property ? `${object}.${property}` : property;
  }
  return '';
}

function findGraphQLNodes(node: t.Node | null | undefined): t.Node[] {
  if (!node) return [];
  if (t.isCallExpression(node) && calleeName(node.callee).endsWith('stringify')) {
    const arg = node.arguments[0];
    return arg && !t.isSpreadElement(arg) ? findGraphQLNodes(arg) : [];
  }
  if (t.isObjectExpression(node)) {
    const direct = objectProperty(node, 'query') ?? objectProperty(node, 'document');
    const found: t.Node[] = direct ? [direct] : [];
    for (const nestedName of ['body', 'data', 'extensions']) {
      const nested = objectProperty(node, nestedName);
      found.push(...findGraphQLNodes(nested));
    }
    return found;
  }
  if (t.isArrayExpression(node)) {
    const found: t.Node[] = [];
    for (const element of node.elements) {
      if (element && !t.isSpreadElement(element)) {
        found.push(...findGraphQLNodes(element));
      }
    }
    return found;
  }
  return [node];
}

function persistedHashes(node: t.Node | null | undefined): string[] {
  if (!node) return [];
  if (t.isCallExpression(node) && calleeName(node.callee).endsWith('stringify')) {
    const argument = node.arguments[0];
    return argument && !t.isSpreadElement(argument) ? persistedHashes(argument) : [];
  }
  if (t.isArrayExpression(node)) {
    const hashes: string[] = [];
    for (const element of node.elements) {
      if (!element || t.isSpreadElement(element)) continue;
      hashes.push(...persistedHashes(element));
    }
    return hashes;
  }
  if (!t.isObjectExpression(node)) return [];
  const hashes: string[] = [];
  for (const property of node.properties) {
    if (!t.isObjectProperty(property)) continue;
    if (propertyName(property) === 'sha256Hash' && t.isStringLiteral(property.value)) hashes.push(property.value.value);
    hashes.push(...persistedHashes(property.value));
  }
  return [...new Set(hashes)];
}

function variableValues(node: t.Node | null | undefined): Record<string, ValueTemplate> | undefined {
  if (!node) return undefined;
  if (t.isCallExpression(node) && calleeName(node.callee).endsWith('stringify')) {
    const argument = node.arguments[0];
    return argument && !t.isSpreadElement(argument) ? variableValues(argument) : undefined;
  }
  if (t.isArrayExpression(node)) {
    for (const element of node.elements) {
      if (!element || t.isSpreadElement(element)) continue;
      const values = variableValues(element);
      if (values) return values;
    }
    return undefined;
  }
  if (!t.isObjectExpression(node)) return undefined;
  const variables = objectProperty(node, 'variables');
  if (t.isObjectExpression(variables)) {
    const values: Record<string, ValueTemplate> = {};
    for (const property of variables.properties) {
      if (!t.isObjectProperty(property)) continue;
      const name = propertyName(property);
      if (name) values[name] = valueTemplate(generate(property.value));
    }
    return Object.keys(values).length ? values : undefined;
  }
  for (const property of node.properties) {
    if (!t.isObjectProperty(property)) continue;
    const nested = variableValues(property.value);
    if (nested) return nested;
  }
  return undefined;
}

function endpointTemplate(value: string | undefined): ValueTemplate | undefined {
  return value ? valueTemplate(value) : undefined;
}

function emitCandidate(context: AnalysisContext, candidate: DocumentCandidate): void {
  const normalized = stripIgnoredCharacters(candidate.document);
  for (const definition of candidate.parsed.definitions) {
    if (definition.kind !== Kind.OPERATION_DEFINITION) continue;
    const operation = definition.operation;
    const operationName = definition.name?.value;
    const endpoint = endpointTemplate(candidate.endpoint);
    const identity = [normalized, operation, operationName ?? '', candidate.endpoint ?? '', candidate.persistedQueryHash ?? ''].join('\0');
    context.addGraphQLOperation({
      kind: 'graphqlOperation',
      id: `graphql-${createHash('sha256').update(identity).digest('hex').slice(0, 20)}`,
      ...(endpoint ? { endpoint } : {}),
      operationType: operation,
      ...(operationName ? { operationName } : {}),
      document: normalized,
      ...(candidate.persistedQueryHash ? { persistedQueryHash: candidate.persistedQueryHash } : {}),
      variables: (definition.variableDefinitions ?? []).map((variable) => ({
        name: variable.variable.name.value,
        type: print(variable.type),
        required: variable.type.kind === Kind.NON_NULL_TYPE,
        ...(variable.defaultValue ? { defaultValue: print(variable.defaultValue) } : {}),
        ...(candidate.variableValues?.[variable.variable.name.value]
          ? { value: candidate.variableValues[variable.variable.name.value] }
          : {}),
      })),
      transport: candidate.transport ?? (operation === 'subscription' ? 'websocket' : candidate.endpoint ? 'http' : 'unknown'),
      provenance: pathEvidence(candidate.path, context, 'graphql-document', candidate.endpoint ? 'high' : candidate.confidence),
    });
  }
}

export function analyzeGraphQL(ast: ParseResult<t.File>, context: AnalysisContext): void {
  if (!/(?:\bgql\b|graphql|Apollo|urql|Relay|useQuery|useMutation|persistedQuery|sha256Hash|subscription\s+[A-Za-z_{])/i.test(context.source)) return;

  const clientEndpoints = new Map<string, string>();
  const knownEndpoints: string[] = [];
  const candidates: DocumentCandidate[] = [];

  traverse(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id) || !path.node.init) return;
      const init = path.node.init;
      if (t.isNewExpression(init) && t.isIdentifier(init.callee, { name: 'GraphQLClient' })) {
        const endpoint = stringFromNode(init.arguments[0] as t.Node, path);
        if (endpoint) clientEndpoints.set(path.node.id.name, endpoint);
      }
      if (t.isCallExpression(init) && /(?:createClient|createUrqlClient)$/.test(calleeName(init.callee))) {
        const config = init.arguments[0];
        const endpoint = t.isObjectExpression(config) ? stringFromNode(objectProperty(config, 'url'), path) : undefined;
        if (endpoint) clientEndpoints.set(path.node.id.name, endpoint);
      }
      if (t.isNewExpression(init) && /(?:HttpLink|WebSocketLink|GraphQLWsLink)$/.test(calleeName(init.callee))) {
        const config = init.arguments[0];
        const endpoint = t.isObjectExpression(config)
          ? stringFromNode(objectProperty(config, 'uri') ?? objectProperty(config, 'url'), path)
          : undefined;
        if (endpoint) {
          clientEndpoints.set(path.node.id.name, endpoint);
          knownEndpoints.push(endpoint);
        }
      }
	  if (t.isNewExpression(init) && /(?:ApolloClient|Environment)$/.test(calleeName(init.callee))) {
		const config = init.arguments[0];
		if (t.isObjectExpression(config)) {
		  const direct = stringFromNode(objectProperty(config, 'uri') ?? objectProperty(config, 'url'), path);
		  const link = objectProperty(config, 'link') ?? objectProperty(config, 'network');
		  let endpoint = direct;
		  if (!endpoint && t.isIdentifier(link)) endpoint = clientEndpoints.get(link.name);
		  if (!endpoint && t.isNewExpression(link) && /(?:HttpLink|WebSocketLink|GraphQLWsLink)$/.test(calleeName(link.callee))) {
			const linkConfig = link.arguments[0];
			endpoint = t.isObjectExpression(linkConfig)
			  ? stringFromNode(objectProperty(linkConfig, 'uri') ?? objectProperty(linkConfig, 'url'), path)
			  : undefined;
		  }
		  if (endpoint) {
			clientEndpoints.set(path.node.id.name, endpoint);
			knownEndpoints.push(endpoint);
		  }
		}
	  }
      const raw = stringFromNode(init, path);
      const parsed = raw ? parseDocument(raw) : undefined;
      if (raw && parsed) candidates.push({ document: raw, parsed, path, confidence: 'medium' });
    },
    TaggedTemplateExpression(path) {
      const tag = calleeName(path.node.tag);
      if (!/(?:^|\.)(?:gql|graphql)$/.test(tag)) return;
      const raw = stringFromNode(path.node, path);
      const parsed = raw ? parseDocument(raw) : undefined;
      if (raw && parsed) candidates.push({ document: raw, parsed, path, confidence: 'high' });
    },
    CallExpression(path) {
      const name = calleeName(path.node.callee);
      let endpoint: string | undefined;
	  let documentNodes: t.Node[] = [];
	  let hashes: string[] = [];
	  let values: Record<string, ValueTemplate> | undefined;
      if (name === 'fetch' || name === 'axios.post' || name.endsWith('.post')) {
        endpoint = stringFromNode(path.node.arguments[0] as t.Node, path);
        const configOrBody = path.node.arguments[name === 'fetch' ? 1 : 1];
		documentNodes = findGraphQLNodes(configOrBody as t.Node);
		hashes = persistedHashes(configOrBody as t.Node);
		values = variableValues(configOrBody as t.Node);
		if (endpoint && (documentNodes.length || hashes.length) && !knownEndpoints.includes(endpoint)) knownEndpoints.push(endpoint);
      } else if (/(?:useQuery|useMutation|useSubscription|\.request|\.query|\.mutate)$/.test(name)) {
		const documentNode = path.node.arguments[0];
		if (documentNode && !t.isSpreadElement(documentNode)) documentNodes = findGraphQLNodes(documentNode);
		const hookOptions = path.node.arguments[1];
		if (hookOptions && !t.isSpreadElement(hookOptions)) values = variableValues(hookOptions);
		if (!values && documentNode && !t.isSpreadElement(documentNode)) values = variableValues(documentNode);
        const receiver = name.includes('.') ? name.split('.')[0] : '';
        endpoint = clientEndpoints.get(receiver) ?? (knownEndpoints.length === 1 ? knownEndpoints[0] : undefined);
      }
	  let parsedAny = false;
	  for (const documentNode of documentNodes) {
		const raw = stringFromNode(documentNode, path);
		const parsed = raw ? parseDocument(raw) : undefined;
		if (!raw || !parsed) continue;
		parsedAny = true;
		candidates.push({
		  document: raw, parsed, path, confidence: 'high', endpoint,
		  ...(hashes[0] ? { persistedQueryHash: hashes[0] } : {}),
		  ...(values ? { variableValues: values } : {}),
		  transport: /subscription/i.test(name) ? 'websocket' : undefined,
		});
	  }
	  if (!parsedAny) for (const hash of hashes) {
        const identity = [hash, endpoint ?? '', name].join('\0');
        context.addGraphQLOperation({
          kind: 'graphqlOperation', id: `graphql-${createHash('sha256').update(identity).digest('hex').slice(0, 20)}`,
          ...(endpoint ? { endpoint: valueTemplate(endpoint) } : {}), operationType: 'unknown',
          persistedQueryHash: hash, variables: [], transport: endpoint ? 'http' : 'unknown',
          provenance: pathEvidence(path, context, 'graphql-persisted-query', endpoint ? 'high' : 'medium'),
        });
      }
    },
  });

  for (const candidate of candidates) emitCandidate(context, candidate);
}
