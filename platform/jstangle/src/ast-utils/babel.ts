/**
 * Babel imports that work with both normal runtime and bun compile.
 * Handles the ESM/CJS interop issue where default exports get nested.
 */

import * as _traverse from '@babel/traverse';
import * as _generator from '@babel/generator';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const traverseModule = _traverse as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const generatorModule = _generator as any;

// Handle nested default exports from CJS modules bundled as ESM
export const traverse: typeof _traverse.default =
  typeof traverseModule.default === 'function'
    ? traverseModule.default
    : traverseModule.default?.default ?? traverseModule;

export const visitors: typeof _traverse.visitors =
  traverseModule.visitors ?? traverseModule.default?.visitors;

export const babelGenerate: typeof _generator.default =
  typeof generatorModule.default === 'function'
    ? generatorModule.default
    : generatorModule.default?.default ?? generatorModule;

// Re-export types
export type { Node, NodePath, Scope, Binding, TraverseOptions, Visitor } from '@babel/traverse';
export type { GeneratorOptions } from '@babel/generator';
