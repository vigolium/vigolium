import { AsyncLocalStorage } from 'node:async_hooks';
import type { FunctionMap } from '../mapping/types';
import type { WebpackBundleState } from '../mapping/extractors/webpackExtractor';

export interface AxiosInstanceState {
  baseURL: string;
  headers: string[];
}

/** All mutable analyzer state owned by one analysis job. */
export interface EngineState {
  functionMap: FunctionMap;
  maxResolutionDepth: number;
  webpackBundle: WebpackBundleState;
  endpointDictionary: Map<string, string>;
  trackedVariables: Map<string, Set<string>>;
  trackedVariablesFinalized: boolean;
  axiosInstances: Map<string, AxiosInstanceState>;
  limits: {
    maxAlternativesPerValue: number;
    maxTemplateCombinations: number;
    maxTrackedVariables: number;
    maxValuesPerVariable: number;
  };
  limitHits: Set<string>;
  reportLimit?: (code: string, message: string) => void;
}

export function createEngineState(): EngineState {
  return {
    functionMap: {
      framework: 'unknown',
      functions: new Map(),
      callSites: new Map(),
    },
    maxResolutionDepth: 5,
    webpackBundle: {
      modules: new Map(),
      importResolution: new Map(),
    },
    endpointDictionary: new Map(),
    trackedVariables: new Map(),
    trackedVariablesFinalized: false,
    axiosInstances: new Map(),
    limits: {
      maxAlternativesPerValue: 16,
      maxTemplateCombinations: 64,
      maxTrackedVariables: 10_000,
      maxValuesPerVariable: 16,
    },
    limitHits: new Set(),
  };
}

const engineStateStorage = new AsyncLocalStorage<EngineState>();

/** Run an analysis with isolated state, including across awaited stages. */
export function runWithEngineState<T>(state: EngineState, run: () => T): T {
  return engineStateStorage.run(state, run);
}

/**
 * Return the current state. Low-level compatibility tests that call extractors
 * directly receive an async-context-local state rather than a module singleton.
 */
export function getEngineState(): EngineState {
  const current = engineStateStorage.getStore();
  if (current) return current;
  const standalone = createEngineState();
  engineStateStorage.enterWith(standalone);
  return standalone;
}
