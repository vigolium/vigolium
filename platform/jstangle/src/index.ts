import type { ParseResult } from '@babel/parser';
import { parse, type ParserPlugin } from '@babel/parser';
import * as t from '@babel/types';
import debug from 'debug';
import {
  applyTransforms,
  applyTransformsToFixpoint,
  generate,
  levelAllows,
  type RewriteLevel,
  type Transform,
} from './ast-utils';
import { beautifyBundle, looksWorthBeautifying, unpackBundle, type BeautifyResult, type UnpackedBundle } from './beautify';
import concatToPlus from './deobfuscate/concat-to-plus';
import controlFlowObject from './deobfuscate/control-flow-object';
import mergeStrings from './deobfuscate/merge-strings';
import { staticEval } from './staticeval';
import { analyzeDomXss, type DomFlow } from './domxss/taint';
import {
  AnalysisContext,
  runWithEngineState,
  type AnalysisLimits,
  type RequestPatternRecord,
} from './context';
import { buildFunctionMap, clearFunctionMap, getWebpackExtractedRequests } from './mapping';
import { collectTrackedVariablesFromIndex, createGlobalVariableTracking, clearTrackedVariables, getTrackedVariablesMap } from './requestpattern/globalVariableTracking';
import { createFetchRequestTransform } from './requestpattern/fetchRequest';
import { createAxiosRequestTransform, clearAxiosInstances } from './requestpattern/axiosRequest';
import { createProtocolRequestTransform } from './requestpattern/protocolRequest';
import { createGenericRequestPattern1Transform } from './requestpattern/genericRequestPattern1';
import { createGenericRequestPattern2Transform } from './requestpattern/genericRequestPattern2';
import { createGenericRequestPattern3Transform } from './requestpattern/genericRequestPattern3';
import { createGenericRequestPattern4Transform } from './requestpattern/genericRequestPattern4';
import { createJqueryAjaxTransform } from './requestpattern/jqueryAjax';
import { createJqueryMethodTransform } from './requestpattern/jqueryMethod';
import type { ExtractedRequest } from './requestpattern/types';
import { appendExtractedRequest, flushPendingPatterns, getExtractedRequests } from './requestpattern/utils';
import { createVariableContainsURLTransform } from './requestpattern/variableContainsURL';
import { createXhrRequestTransform } from './requestpattern/xhrRequest';
import { createModernClientTransform } from './requestpattern/modernClients';
import type {
  AnalysisCapability,
  AnalysisProfile,
  Diagnostic,
  ScanStatus,
  StageMetric,
} from './protocol';
import { sha256 } from './protocol';
import { buildStagePlan, type StageName } from './stages';
import { extractAssetReferences } from './assets';
import { analyzeBrowserCapabilities, analyzeGraphQL } from './capabilities';
import { buildStructuralIndex } from './structure';

// Re-export tracking utilities for testing
export { getTrackedVariablesMap, clearTrackedVariables } from './requestpattern/globalVariableTracking';
// Re-export the rewrite-level surface so transports (CLI, worker) share one type.
export { isRewriteLevel, type RewriteLevel } from './ast-utils';

export interface JstangleResult {
  code: string;
  extractedRequests: ExtractedRequest[];
  domFlows: DomFlow[];
  requestPatterns: RequestPatternRecord[];
  assetReferences: import('./protocol').AssetReferenceFact[];
  graphqlOperations: import('./protocol').GraphQLOperationFact[];
  webSockets: import('./protocol').WebSocketFact[];
  eventSources: import('./protocol').EventSourceFact[];
  clientRoutes: import('./protocol').ClientRouteFact[];
  browserSecurityFlows: import('./protocol').BrowserSecurityFlowFact[];
  diagnostics: Diagnostic[];
  stageMetrics: StageMetric[];
  profile: AnalysisProfile;
  status: ScanStatus;
  beautified?: BeautifyResult;
  /** Per-run state used to construct the typed v2 envelope. */
  analysisContext: AnalysisContext;
}

export interface Options {
  /**
   * @param progress Progress in percent (0-100)
   */
  onProgress?: (progress: number) => void;
  /** Optional instrumentation hook, awaited after each planned stage. */
  onStageComplete?: (stage: string) => void | Promise<void>;
  /**
   * When true, also unminify and (if a bundle) unpack the script into a single
   * readable, module-annotated document via webcrack. Off by default so the
   * discovery pipeline's per-script scans stay fast; enabled by the passive
   * js-beautify module. See ./beautify.
   */
  beautify?: boolean;
  /**
   * When true (and endpoints are requested), unpack a detected bundle with
   * webcrack and re-scan each recovered module independently, merging endpoints
   * with module-path provenance. Off by default: it adds a webcrack pass to the
   * endpoints path, so callers opt in. See the `bundleModuleScan` stage.
   */
  unpackModules?: boolean;
  /** Named preset. The legacy profile preserves the historical API behavior. */
  profile?: AnalysisProfile;
  /**
   * Deobfuscation aggressiveness. `strict` runs only provably-safe transforms;
   * `standard` (default) matches historical behavior; `aggressive` additionally
   * inlines wrappers that may change obscure evaluation-order semantics.
   */
  rewriteLevel?: RewriteLevel;
  /** Explicit capabilities override the selected profile. */
  capabilities?: Iterable<AnalysisCapability>;
  /** Per-analysis resource and expansion limits. */
  limits?: Partial<AnalysisLimits>;
  /** Correlation identifier supplied by a transport, otherwise generated. */
  scanId?: string;
  /** URL and media metadata for source-aware provenance and replay. */
  sourceUrl?: string;
  filename?: string;
  mediaType?: string;
}

interface NormalizedOptions {
  onProgress: (progress: number) => void;
  onStageComplete: (stage: string) => void | Promise<void>;
  beautify: boolean;
  unpackModules: boolean;
  profile: AnalysisProfile;
  rewriteLevel: RewriteLevel;
  capabilities?: Iterable<AnalysisCapability>;
  limits?: Partial<AnalysisLimits>;
  scanId: string;
  sourceUrl?: string;
  filename?: string;
  mediaType?: string;
}

function normalizeOptions(options: Options): NormalizedOptions {
  return {
    onProgress: () => { },
    onStageComplete: () => { },
    beautify: false,
    unpackModules: false,
    profile: 'legacy',
    rewriteLevel: 'standard',
    scanId: crypto.randomUUID(),
    ...options,
  };
}

class AnalysisLimitError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'AnalysisLimitError';
  }
}

// Count nodes without building Babel scopes. This cheap iterative gate runs
// once immediately after parsing and prevents all later traversal-heavy stages
// from starting on adversarially dense ASTs.
function enforceAstBudget(ast: ParseResult<t.File>, context: AnalysisContext): void {
  const stack: t.Node[] = [ast];
  let count = 0;
  while (stack.length > 0) {
    const node = stack.pop()!;
    count++;
    if (count > context.limits.maxAstNodes) {
      context.astNodeCount = count;
      throw new AnalysisLimitError(
        'ast_node_limit_reached',
        `AST exceeds the configured ${context.limits.maxAstNodes} node limit`,
      );
    }
    if ((count & 0x7ff) === 0 && performance.now() > context.deadline) {
      context.astNodeCount = count;
      throw new AnalysisLimitError(
        'analysis_time_budget_reached',
        'Analysis deadline reached while admitting the parsed AST',
      );
    }
    for (const key of t.VISITOR_KEYS[node.type] ?? []) {
      const child = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(child)) {
        for (let i = child.length - 1; i >= 0; i--) {
          if (t.isNode(child[i])) stack.push(child[i]);
        }
      } else if (t.isNode(child)) {
        stack.push(child);
      }
    }
  }
  context.astNodeCount = count;
}

/**
 * Filter a transform list by the context's rewrite level, then run it to a
 * bounded fixpoint. Shared by the deobfuscate and staticEval stages so
 * `minLevel` gating is applied uniformly.
 */
function runLeveledFixpoint(
  ast: ParseResult<t.File>,
  context: AnalysisContext,
  candidates: Transform[],
): void {
  const transforms = candidates.filter((tr) => levelAllows(context.rewriteLevel, tr.minLevel));
  applyTransformsToFixpoint(ast, transforms, {
    maxPasses: context.limits.maxDeobfuscatePasses,
    deadline: context.deadline,
  });
}

/**
 * Unpack a detected bundle and re-scan each recovered module independently. Each
 * module is analyzed by a fresh nested jstangle run (its own isolated engine
 * state); its endpoints are merged into `context` with module-path provenance.
 */
async function scanBundleModules(
  context: AnalysisContext,
  normalized: NormalizedOptions,
  unpacked: UnpackedBundle,
): Promise<void> {
  if (unpacked.format === 'none' || unpacked.modules.length === 0) return;

  const cap = context.limits.maxBundleModules;
  const scanned = unpacked.modules.slice(0, cap);
  if (unpacked.modules.length > cap) {
    context.partial = true;
    context.addDiagnostic({
      type: 'diagnostic', severity: 'warning', stage: 'bundleModuleScan',
      code: 'bundle_module_limit_reached',
      message: `Bundle had ${unpacked.modules.length} modules; re-scanned the first ${cap}`,
      recoverable: true,
    });
  }

  for (const mod of scanned) {
    const remainingMs = context.deadline - performance.now();
    if (remainingMs <= 0) {
      context.partial = true;
      break;
    }
    let sub: JstangleResult;
    try {
      sub = await jstangle(mod.content, {
        profile: 'endpoints',
        rewriteLevel: normalized.rewriteLevel,
        unpackModules: false, // never recurse
        sourceUrl: normalized.sourceUrl,
        filename: mod.path,
        limits: { ...normalized.limits, deadlineMs: remainingMs },
      });
    } catch (err) {
      debug('jstangle:bundle-module')('module scan failed: %s', mod.path, err);
      continue;
    }
    for (const request of sub.extractedRequests) {
      appendExtractedRequest(context, request, {
        extractor: 'bundle-module', modulePath: mod.path, client: 'bundle', confidence: 'medium',
      });
    }
  }
}

export async function jstangle(
  code: string,
  options: Options = {},
): Promise<JstangleResult> {
  const normalized = normalizeOptions(options);
  normalized.onProgress(0);

  const requestedCapabilities = normalized.capabilities
    ? new Set(normalized.capabilities)
    : undefined;
  if (normalized.beautify) requestedCapabilities?.add('beautifiedCode');
  const context = new AnalysisContext({
    scanId: normalized.scanId,
    profile: normalized.profile,
    source: code,
    sourceUrl: normalized.sourceUrl,
    filename: normalized.filename,
    mediaType: normalized.mediaType,
    capabilities: requestedCapabilities,
    limits: normalized.limits,
    rewriteLevel: normalized.rewriteLevel,
  });
  return runWithEngineState(context.engineState, async () => {
  // Backward compatibility: `{ beautify: true }` historically meant the full
  // legacy analysis plus Webcrack.
  if (normalized.beautify && !context.capabilities.has('beautifiedCode')) {
    (context.capabilities as Set<AnalysisCapability>).add('beautifiedCode');
  }

  // Clear state from previous runs
  if (context.has('endpoints')) {
    clearTrackedVariables();
    clearFunctionMap();
    clearAxiosInstances();
  }

  const isBookmarklet = /^javascript:./.test(code);
  if (isBookmarklet) {
    code = code
      .replace(/^javascript:/, '')
      .split(/%(?![a-f\d]{2})/i)
      .map(decodeURIComponent)
      .join('%');
  }

  let ast: ParseResult<t.File> | null = null;
  let outputCode = '';
  let domFlows: DomFlow[] = [];
  let beautified: BeautifyResult | undefined;

  // Unpack the bundle at most once per run: the bundleModuleScan and beautify
  // stages both need it, and webcrack is the single heaviest operation.
  let unpackedBundle: Promise<UnpackedBundle> | undefined;
  const unpackShared = () => (unpackedBundle ??= unpackBundle(code));

  interface Stage {
    name: StageName;
    enabled: boolean;
    fatal: boolean;
    mutatesAst: boolean;
    costClass: 'light' | 'medium' | 'heavy';
    run: () => void | Promise<void>;
  }

  const stageRuns: Record<StageName, () => void | Promise<void>> = {
    parse: () => {
      const filename = normalized.filename?.toLowerCase() ?? '';
      const plugins: ParserPlugin[] = filename.endsWith('.tsx')
        ? ['jsx', 'typescript']
        : filename.endsWith('.ts')
          ? ['typescript']
          : ['jsx'];
      ast = parse(code, {
        sourceType: 'unambiguous',
        allowReturnOutsideFunction: true,
        errorRecovery: true,
        plugins,
      });
      if (ast.errors?.length) {
        debug('jstangle:parse')('Errors', ast.errors);
        context.addDiagnostic({
          type: 'diagnostic', severity: 'warning', stage: 'parse',
          code: 'parse_recovery_used',
          message: `Babel recovered from ${ast.errors.length} parse error(s)`,
          recoverable: true,
        });
      }
      enforceAstBudget(ast, context);
    },
    // DOM-XSS taint analysis on the pristine AST, so snippet offsets and line
    // numbers line up with the original source. Isolated in try/catch: this
    // stage runs before request extraction/deobfuscation, so a failure here
    // must never abort the rest of the pipeline.
    domFlows: () => {
      if (!ast) return;
      try {
        domFlows = analyzeDomXss(ast, code, {
          maxFlows: context.limits.maxDomFlows,
          maxFunctionDepth: context.limits.maxTaintFunctionDepth,
          maxResolutionDepth: context.limits.maxTaintResolutionDepth,
        });
        if (context.has('browserSecurityFlows')) {
          for (const flow of domFlows) {
            if (flow.flowType === 'domXss') continue;
            context.addBrowserSecurityFlow({
              kind: 'browserSecurityFlow',
              id: `browser-flow-${sha256([flow.flowType, flow.source, flow.sink, flow.line].join('|')).slice(0, 20)}`,
              flowType: flow.flowType,
              source: flow.source,
              sink: flow.sink,
              confidence: flow.confidence,
              evidence: flow.snippet,
              path: flow.path,
              provenance: {
                extractor: 'binding-aware-browser-taint', confidence: flow.confidence,
                ...(flow.line ? { start: { line: flow.line } } : {}), evidence: flow.snippet,
              },
            });
          }
        }
        if (domFlows.length > context.limits.maxDomFlows) {
          domFlows = domFlows.slice(0, context.limits.maxDomFlows);
          context.partial = true;
        }
      } catch (err) {
        debug('jstangle:domxss')('analysis failed', err);
        domFlows = [];
        throw err;
      }
    },
    // Essential deobfuscation (concat->plus, string merging, control flow object
    // inlining). Run as a bounded fixpoint so a change made by one transform can
    // be picked up by an earlier one on the next pass (e.g. concat->plus exposes
    // a `+` chain that merge-strings then folds). control-flow-object is a
    // `standard`+ transform and opts into impure-arg inlining only at aggressive.
    deobfuscate: () => {
      if (ast) runLeveledFixpoint(ast, context, [
        concatToPlus,
        mergeStrings,
        controlFlowObject({ allowImpureArgs: context.rewriteLevel === 'aggressive' }),
      ]);
    },
    // Bounded static value recovery: fold pure decoder chains (fromCharCode,
    // atob, reversed strings, literal string methods, JSON.parse) and parse
    // eval/Function payloads so recovered endpoint strings feed extraction.
    // Runs a small fixpoint with merge-strings so folded fragments coalesce.
    staticEval: () => {
      if (ast) runLeveledFixpoint(ast, context, [staticEval, mergeStrings]);
    },
    structuralIndex: () => {
      if (ast) context.structuralIndex = buildStructuralIndex(ast);
    },
    // Build function map (framework-aware mapping) BEFORE request extraction
    functionMapping: () => {
      if (ast) buildFunctionMap(ast, code, context.structuralIndex);
    },
    // Global variable tracking
    valueTracking: () => {
      if (context.structuralIndex) collectTrackedVariablesFromIndex(context.structuralIndex);
      else if (ast) applyTransforms(ast, [createGlobalVariableTracking()]);
    },
    assetDiscovery: () => {
      if (ast) extractAssetReferences(ast, context);
    },
    capabilityPacks: () => {
      if (!ast) return;
      if (context.has('graphqlOperations')) analyzeGraphQL(ast, context);
      if (context.has('realtimeProtocols') || context.has('clientRoutes') || context.has('browserSecurityFlows')) {
        analyzeBrowserCapabilities(ast, context);
      }
    },
    // Request patterns (XHR, Fetch, axios, jQuery)
    requestClients: () => {
      if (!ast) return;
      applyTransforms(ast, [
        createXhrRequestTransform(context, ast, code),
        createFetchRequestTransform(context, ast, code),
        createAxiosRequestTransform(context, ast, code),
        createModernClientTransform(context, ast, code),
        createProtocolRequestTransform(context, ast, code),
        createJqueryAjaxTransform(context, ast, code),
        createJqueryMethodTransform(context, ast, code)] as Transform<unknown>[]);
    },
    // Request patterns (Generic)
    requestFallbacks: () => {
      if (!ast) return;
      applyTransforms(ast, [
        createGenericRequestPattern1Transform(context, ast, code),
        createGenericRequestPattern2Transform(context, ast, code),
        createGenericRequestPattern3Transform(context, ast, code),
        createGenericRequestPattern4Transform(context, ast, code),
        createVariableContainsURLTransform(context, ast, code),
      ] as Transform<unknown>[]);
    },
    // Unpack the bundle and re-scan each recovered module independently, merging
    // endpoints with module-path provenance. Non-fatal and opt-in (unpackModules).
    bundleModuleScan: async () => {
      await scanBundleModules(context, normalized, await unpackShared());
    },
    // Generate code
    generateCode: () => {
      if (ast) outputCode = generate(ast);
    },
    beautify: async () => {
      beautified = await beautifyBundle(code, await unpackShared());
    },
  };

  // Extra runtime gates for stages whose enablement depends on the source or
  // options (which the capability-only planner cannot see).
  const stageGates: Partial<Record<StageName, () => boolean>> = {
    beautify: () => looksWorthBeautifying(code),
    bundleModuleScan: () => normalized.unpackModules && looksWorthBeautifying(code),
  };

  const stages: Stage[] = buildStagePlan(context.capabilities).map((planned) => ({
    ...planned,
    enabled: planned.enabled && (stageGates[planned.name]?.() ?? true),
    run: stageRuns[planned.name],
  }));

  for (let i = 0; i < stages.length; i++) {
    const stage = stages[i];
    if (!stage.enabled || (context.failed && stage.name !== 'beautify')) {
      context.stageMetrics.push({
        stage: stage.name, durationMs: 0, status: 'skipped',
        costClass: stage.costClass, mutatesAst: stage.mutatesAst,
      });
      await normalized.onStageComplete(stage.name);
      normalized.onProgress((100 / stages.length) * (i + 1));
      continue;
    }
    const started = performance.now();
    try {
      if (!context.checkBudget(stage.name)) break;
      const stageResult = stage.run();
      // Do not yield between synchronous AST stages. The current Babel engine
      // is single-threaded; yielding here allowed a second library call to
      // clear and mutate legacy mapping state mid-analysis. Async stages (today
      // only beautification) are awaited normally.
      if (stageResult instanceof Promise) await stageResult;
      context.stageMetrics.push({
        stage: stage.name, durationMs: performance.now() - started, status: 'complete',
        costClass: stage.costClass, mutatesAst: stage.mutatesAst,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const limitError = err instanceof AnalysisLimitError;
      context.addDiagnostic({
        type: 'diagnostic', severity: stage.fatal ? 'error' : 'warning',
        stage: stage.name,
        code: limitError ? err.code : stage.name === 'parse' ? 'parse_unrecoverable' : 'internal_analysis_error',
        message,
        recoverable: limitError || !stage.fatal,
      });
      context.stageMetrics.push({
        stage: stage.name, durationMs: performance.now() - started, status: 'failed',
        costClass: stage.costClass, mutatesAst: stage.mutatesAst,
      });
      if (stage.fatal) context.failed = true;
      else context.partial = true;
    }
    await normalized.onStageComplete(stage.name);
    normalized.onProgress((100 / stages.length) * (i + 1));
  }

  if (context.has('endpoints') && !context.failed) {
    // Merge bundle-derived facts through the same canonical candidate store.
    // Pass the *full* multi-value tracked-variable map so branch alternatives
    // (e.g. a base URL that is /api/v1 or /api/v2) each expand into a distinct
    // endpoint instead of being truncated to the first value.
    const trackedVars = getTrackedVariablesMap();
    const webpackRequests = getWebpackExtractedRequests(trackedVars, {
      maxAlternativesPerValue: context.limits.maxAlternativesPerValue,
      maxTemplateCombinations: context.limits.maxTemplateCombinations,
    });
    for (const request of webpackRequests) {
      appendExtractedRequest(context, request, {
        extractor: 'webpack-cross-module', client: 'bundle', confidence: 'medium',
      });
    }
  }

  if (context.has('requestEvidence') && !context.failed) flushPendingPatterns(context);

  const status: ScanStatus = context.failed
    ? 'failed'
    : context.partial
      ? 'partial'
      : 'complete';

  return {
    code: outputCode,
    extractedRequests: getExtractedRequests(context),
    domFlows,
    requestPatterns: [...context.requestPatterns],
    assetReferences: [...context.assetReferences],
    graphqlOperations: [...context.graphqlOperations],
    webSockets: [...context.webSockets],
    eventSources: [...context.eventSources],
    clientRoutes: [...context.clientRoutes],
    browserSecurityFlows: [...context.browserSecurityFlows],
    diagnostics: [...context.diagnostics],
    stageMetrics: [...context.stageMetrics],
    profile: context.profile,
    status,
    beautified,
    analysisContext: context,
  };
  });
}
