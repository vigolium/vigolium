import debug from 'debug';
import type { Node, TraverseOptions, Visitor } from './babel';
import { traverse, visitors } from './babel';

const logger = debug('jstangle:transforms');

export async function applyTransformAsync<TOptions>(
  ast: Node,
  transform: AsyncTransform<TOptions>,
  options?: TOptions,
): Promise<TransformState> {
  logger(`${transform.name}: started`);
  const state: TransformState = { changes: 0 };

  await transform.run?.(ast, state, options);
  if (transform.visitor)
    traverse(ast, transform.visitor(options), undefined, state);

  logger(`${transform.name}: finished with ${state.changes} changes`);
  return state;
}

export function applyTransform<TOptions>(
  ast: Node,
  transform: Transform<TOptions>,
  options?: TOptions,
): TransformState {
  logger(`${transform.name}: started`);
  const state: TransformState = { changes: 0 };
  transform.run?.(ast, state, options);

  if (transform.visitor) {
    const visitor = transform.visitor(
      options,
    ) as TraverseOptions<TransformState>;
    visitor.noScope = !transform.scope;
    traverse(ast, visitor, undefined, state);
  }

  logger(`${transform.name}: finished with ${state.changes} changes`);
  return state;
}

export function applyTransforms(
  ast: Node,
  transforms: Transform[],
  options: { noScope?: boolean; name?: string; log?: boolean } = {},
): TransformState {
  options.log ??= true;
  const name = options.name ?? transforms.map((t) => t.name).join(', ');
  if (options.log) logger(`${name}: started`);
  const state: TransformState = { changes: 0 };

  for (const transform of transforms) {
    transform.run?.(ast, state);
  }

  const traverseOptions = transforms.flatMap((t) => t.visitor?.() ?? []);
  if (traverseOptions.length > 0) {
    const visitor: TraverseOptions<TransformState> =
      visitors.merge(traverseOptions);
    visitor.noScope = options.noScope || transforms.every((t) => !t.scope);
    traverse(ast, visitor, undefined, state);
  }

  if (options.log) logger(`${name}: finished with ${state.changes} changes`);
  return state;
}

export interface FixpointState extends TransformState {
  /** Change count for each pass, in order. Length is the number of passes run. */
  passes: number[];
}

/**
 * Run an ordered list of transforms repeatedly until a full pass produces no
 * changes (a fixpoint), the pass budget is exhausted, or the deadline passes.
 *
 * Unlike {@link applyTransforms} — which merges every visitor into a single
 * traversal — this re-runs the whole list each pass, so a change made by one
 * transform can be picked up by an earlier transform on the next pass (e.g.
 * `concat-to-plus` exposes a `+` chain that `merge-strings` can then fold).
 */
export function applyTransformsToFixpoint(
  ast: Node,
  transforms: Transform[],
  options: {
    maxPasses?: number;
    /** Absolute `performance.now()` timestamp after which no new pass starts. */
    deadline?: number;
    noScope?: boolean;
    name?: string;
  } = {},
): FixpointState {
  const maxPasses = Math.max(1, options.maxPasses ?? 5);
  const name = options.name ?? transforms.map((t) => t.name).join(', ');
  const passes: number[] = [];
  let total = 0;

  for (let pass = 0; pass < maxPasses; pass++) {
    if (options.deadline !== undefined && performance.now() > options.deadline) {
      break;
    }
    const { changes } = applyTransforms(ast, transforms, {
      noScope: options.noScope,
      name,
      log: false,
    });
    passes.push(changes);
    total += changes;
    if (changes === 0) break;
  }

  logger(`${name}: fixpoint reached after ${passes.length} pass(es), ${total} changes [${passes.join(', ')}]`);
  return { changes: total, passes };
}

export function mergeTransforms(options: {
  name: string;
  tags: Tag[];
  transforms: Transform[];
}): Transform {
  return {
    name: options.name,
    tags: options.tags,
    scope: options.transforms.some((t) => t.scope),
    visitor() {
      return visitors.merge(
        options.transforms.flatMap((t) => t.visitor?.() ?? []),
      );
    },
  };
}

export interface TransformState {
  changes: number;
}

export interface Transform<TOptions = unknown> {
  name: string;
  tags: Tag[];
  scope?: boolean;
  /**
   * Least-permissive rewrite level at which this transform runs. Defaults to
   * `standard`. `strict` transforms have binding/mutation/purity proofs;
   * `aggressive` transforms may affect obscure semantics for readability.
   */
  minLevel?: RewriteLevel;
  run?: (ast: Node, state: TransformState, options?: TOptions) => void;
  visitor?: (options?: TOptions) => Visitor<TransformState>;
}

export type RewriteLevel = 'strict' | 'standard' | 'aggressive';

export const REWRITE_LEVELS: readonly RewriteLevel[] = [
  'strict',
  'standard',
  'aggressive',
] as const;

const LEVEL_RANK: Record<RewriteLevel, number> = {
  strict: 0,
  standard: 1,
  aggressive: 2,
};

export function isRewriteLevel(value: unknown): value is RewriteLevel {
  return (REWRITE_LEVELS as readonly unknown[]).includes(value);
}

/**
 * True when a transform whose minimum level is `min` should run under the
 * `active` rewrite level. `min` defaults to `standard`.
 */
export function levelAllows(
  active: RewriteLevel,
  min: RewriteLevel = 'standard',
): boolean {
  return LEVEL_RANK[active] >= LEVEL_RANK[min];
}

export interface AsyncTransform<TOptions = unknown>
  extends Transform<TOptions> {
  run?: (ast: Node, state: TransformState, options?: TOptions) => Promise<void>;
}

export type Tag = 'safe' | 'unsafe';
