import type { ParseResult } from '@babel/parser';
import * as t from '@babel/types';
import { traverse, type Binding, type NodePath } from '../ast-utils/babel';

export interface IndexedPropertyAssignment {
  line: number;
  offset: number;
  propName: string;
  value: t.Node;
  declarationLine: number;
  binding: Binding;
}

export interface StructuralIndexStats {
  fullTreePasses: number;
  calls: number;
  functions: number;
  propertyAssignments: number;
  xhrOperations: number;
  xhrLifecycleQueries: number;
  xhrFallbackTraversals: number;
}

/**
 * Post-transform index shared by function mapping, request extraction, and XHR
 * lifecycle correlation. Binding identity is used wherever Babel can resolve
 * one; scope-qualified structural keys are the bounded fallback.
 */
export class StructuralIndex {
  readonly callExpressions: Array<NodePath<t.CallExpression>> = [];
  readonly functionPaths: Array<NodePath<t.Function>> = [];
  readonly variableDeclarators: Array<NodePath<t.VariableDeclarator>> = [];
  readonly objectProperties: Array<NodePath<t.ObjectProperty>> = [];
  readonly assignmentExpressions: Array<NodePath<t.AssignmentExpression>> = [];
  readonly propertyAssignments = new Map<Binding, IndexedPropertyAssignment[]>();
  readonly xhrOperations = new Map<string, Array<NodePath<t.CallExpression>>>();
  readonly stats: StructuralIndexStats = {
    fullTreePasses: 1, calls: 0, functions: 0, propertyAssignments: 0, xhrOperations: 0,
    xhrLifecycleQueries: 0, xhrFallbackTraversals: 0,
  };
  private readonly bindingIds = new WeakMap<object, number>();
  private nextBindingId = 1;

  bindingID(binding: Binding): number {
    let id = this.bindingIds.get(binding as object);
    if (id === undefined) {
      id = this.nextBindingId++;
      this.bindingIds.set(binding as object, id);
    }
    return id;
  }

  receiverKey(path: NodePath, node: t.Node | null | undefined): string | null {
    if (!node) return null;
    if (t.isIdentifier(node)) {
      const binding = path.scope.getBinding(node.name);
      return binding ? `binding:${this.bindingID(binding)}` : `scope:${path.scope.uid}:id:${node.name}`;
    }
    if (t.isThisExpression(node)) return `scope:${path.getFunctionParent()?.scope.uid ?? path.scope.uid}:this`;
    if (t.isMemberExpression(node) && !node.computed) {
      const object = this.receiverKey(path, node.object);
      const property = t.isIdentifier(node.property) ? node.property.name : undefined;
      return object && property ? `${object}.${property}` : null;
    }
    return null;
  }

  operationsForReceiver(path: NodePath, node: t.Node): Array<NodePath<t.CallExpression>> {
    const key = this.receiverKey(path, node);
    return key ? this.xhrOperations.get(key) ?? [] : [];
  }
}

function memberProperty(node: t.MemberExpression): string | undefined {
  if (t.isIdentifier(node.property) && !node.computed) return node.property.name;
  if (t.isStringLiteral(node.property)) return node.property.value;
  return undefined;
}

export function buildStructuralIndex(ast: ParseResult<t.File>): StructuralIndex {
  const index = new StructuralIndex();
  traverse(ast, {
    Function(path) {
      index.functionPaths.push(path as NodePath<t.Function>);
      index.stats.functions++;
    },
    VariableDeclarator(path) {
      index.variableDeclarators.push(path);
    },
    ObjectProperty(path) {
      index.objectProperties.push(path);
    },
    AssignmentExpression(path) {
      index.assignmentExpressions.push(path);
      const left = path.node.left;
      if (!t.isMemberExpression(left) || !t.isIdentifier(left.object)) return;
      const propName = memberProperty(left);
      const binding = path.scope.getBinding(left.object.name);
      if (!propName || !binding) return;
      const assignments = index.propertyAssignments.get(binding) ?? [];
      assignments.push({
        line: path.node.loc?.start.line ?? 0,
        offset: path.node.start ?? 0,
        propName,
        value: path.node.right,
        declarationLine: binding.path.node.loc?.start.line ?? 0,
        binding,
      });
      index.propertyAssignments.set(binding, assignments);
      index.stats.propertyAssignments++;
    },
    CallExpression(path) {
      index.callExpressions.push(path);
      index.stats.calls++;
      const callee = path.node.callee;
      if (!t.isMemberExpression(callee)) return;
      const method = memberProperty(callee);
      if (method !== 'open' && method !== 'setRequestHeader' && method !== 'send') return;
      const key = index.receiverKey(path, callee.object);
      if (!key) return;
      const operations = index.xhrOperations.get(key) ?? [];
      operations.push(path);
      index.xhrOperations.set(key, operations);
      index.stats.xhrOperations++;
    },
  });
  for (const assignments of index.propertyAssignments.values()) {
    assignments.sort((a, b) => a.offset - b.offset);
  }
  for (const operations of index.xhrOperations.values()) {
    operations.sort((a, b) => (a.node.start ?? 0) - (b.node.start ?? 0));
  }
  return index;
}
