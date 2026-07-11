import type { ExtractedRequest } from '../requestpattern/types';
import type { TracebackResult } from '../traceback/tracebackVariables';
import type {
  AnalysisCapability,
  AnalysisProfile,
  HttpClientKind,
  Provenance,
  Diagnostic,
  StageMetric,
  AssetReferenceFact,
  GraphQLOperationFact,
  WebSocketFact,
  EventSourceFact,
  ClientRouteFact,
  BrowserSecurityFlowFact,
} from '../protocol';
import { createEngineState, type EngineState } from './engine-state';
import type { StructuralIndex } from '../structure';
import type { RewriteLevel } from '../ast-utils';

export interface RequestOrigin {
  client: HttpClientKind;
  provenance: Provenance;
  extractors: string[];
  alternatives: {
    url: string[];
    method: string[];
    params: string[];
    body: string[];
  };
}

export interface AnalysisLimits {
  maxRequests: number;
  maxDomFlows: number;
  maxDiagnostics: number;
  maxEvidenceRecords: number;
  maxOutputBytes: number;
  maxAlternativesPerValue: number;
  maxTemplateCombinations: number;
  maxTrackedVariables: number;
  maxValuesPerVariable: number;
  maxResolutionDepth: number;
  maxAstNodes: number;
  maxAssetReferences: number;
  maxTaintFunctionDepth: number;
  maxTaintResolutionDepth: number;
  /** Max passes of the deobfuscation transform list before stopping short of a fixpoint. */
  maxDeobfuscatePasses: number;
  /** Max unpacked bundle modules independently re-scanned for endpoints. */
  maxBundleModules: number;
  deadlineMs: number;
}

export const DEFAULT_LIMITS: AnalysisLimits = {
  maxRequests: 1_000,
  maxDomFlows: 100,
  maxDiagnostics: 100,
  maxEvidenceRecords: 500,
  maxOutputBytes: 16 * 1024 * 1024,
  maxAlternativesPerValue: 16,
  maxTemplateCombinations: 64,
  maxTrackedVariables: 10_000,
  maxValuesPerVariable: 16,
  maxResolutionDepth: 5,
  maxAstNodes: 500_000,
  maxAssetReferences: 256,
  maxTaintFunctionDepth: 8,
  maxTaintResolutionDepth: 80,
  maxDeobfuscatePasses: 5,
  maxBundleModules: 64,
  deadlineMs: 60_000,
};

const PROFILE_CAPABILITIES: Record<AnalysisProfile, AnalysisCapability[]> = {
  legacy: [
    'endpoints',
    'domFlows',
    'transformedCode',
    'requestEvidence',
    'diagnostics',
    'stageMetrics',
  ],
  endpoints: ['endpoints', 'diagnostics', 'stageMetrics'],
  'dom-security': ['domFlows', 'browserSecurityFlows', 'diagnostics', 'stageMetrics'],
  beautify: ['beautifiedCode', 'diagnostics', 'stageMetrics'],
  discovery: [
    'endpoints', 'transformedCode', 'assetReferences', 'graphqlOperations',
    'realtimeProtocols', 'clientRoutes', 'diagnostics', 'stageMetrics',
  ],
  'discovery-lite': [
    'endpoints', 'assetReferences', 'graphqlOperations', 'realtimeProtocols',
    'clientRoutes', 'diagnostics', 'stageMetrics',
  ],
  full: [
    'endpoints',
    'domFlows',
    'transformedCode',
    'beautifiedCode',
    'requestEvidence',
    'diagnostics',
    'stageMetrics',
    'assetReferences',
    'graphqlOperations',
    'realtimeProtocols',
    'clientRoutes',
    'browserSecurityFlows',
  ],
  inspect: [
    'endpoints',
    'domFlows',
    'transformedCode',
    'beautifiedCode',
    'requestEvidence',
    'diagnostics',
    'stageMetrics',
    'assetReferences',
    'graphqlOperations',
    'realtimeProtocols',
    'clientRoutes',
    'browserSecurityFlows',
  ],
};

export interface RequestPatternRecord {
  type: 'requestPattern';
  patternType: string;
  code: string;
  functionName: string;
  paramCount: number;
  literals: string[];
  callSites: TracebackResult['callSites'];
  tracedVariables: string[];
}

export interface AnalysisContextOptions {
  scanId: string;
  profile: AnalysisProfile;
  source: string;
  sourceUrl?: string;
  filename?: string;
  mediaType?: string;
  capabilities?: Iterable<AnalysisCapability>;
  limits?: Partial<AnalysisLimits>;
  rewriteLevel?: RewriteLevel;
}

export class AnalysisContext {
  readonly scanId: string;
  readonly profile: AnalysisProfile;
  readonly source: string;
  readonly sourceUrl?: string;
  readonly filename?: string;
  readonly mediaType?: string;
  readonly capabilities: ReadonlySet<AnalysisCapability>;
  readonly limits: AnalysisLimits;
  readonly rewriteLevel: RewriteLevel;
  readonly startedAt = performance.now();
  readonly engineState: EngineState = createEngineState();
  readonly deadline: number;
  readonly diagnostics: Diagnostic[] = [];
  readonly stageMetrics: StageMetric[] = [];
  readonly requests: ExtractedRequest[] = [];
  readonly requestOrigins: RequestOrigin[] = [];
  readonly requestPatterns: RequestPatternRecord[] = [];
  readonly pendingRequestEvidence: Array<{
    patternType: string;
    node?: object;
    build: () => TracebackResult;
  }> = [];
  readonly pendingEvidenceNodes = new WeakSet<object>();
  readonly retainedEvidenceNodes = new WeakSet<object>();
  evidenceBuilds = 0;
  readonly assetReferences: AssetReferenceFact[] = [];
  readonly graphqlOperations: GraphQLOperationFact[] = [];
  readonly webSockets: WebSocketFact[] = [];
  readonly eventSources: EventSourceFact[] = [];
  readonly clientRoutes: ClientRouteFact[] = [];
  readonly browserSecurityFlows: BrowserSecurityFlowFact[] = [];
  structuralIndex?: StructuralIndex;
  astNodeCount = 0;
  readonly assetDedup = new Set<string>();
  readonly factDedup = new Set<string>();
  readonly requestDedup = new Map<string, number>();
  readonly patternDedup = new Set<string>();
  readonly claimedRequestNodes = new WeakSet<object>();
  private cachedSourceLines?: string[];
  partial = false;
  failed = false;

  constructor(options: AnalysisContextOptions) {
    this.scanId = options.scanId;
    this.profile = options.profile;
    this.source = options.source;
    this.sourceUrl = options.sourceUrl;
    this.filename = options.filename;
    this.mediaType = options.mediaType;
    this.capabilities = new Set(
      options.capabilities ?? PROFILE_CAPABILITIES[options.profile],
    );
    this.rewriteLevel = options.rewriteLevel ?? 'standard';
    this.limits = { ...DEFAULT_LIMITS, ...options.limits };
    this.deadline = this.startedAt + this.limits.deadlineMs;
    this.engineState.maxResolutionDepth = this.limits.maxResolutionDepth;
    this.engineState.limits = {
      maxAlternativesPerValue: this.limits.maxAlternativesPerValue,
      maxTemplateCombinations: this.limits.maxTemplateCombinations,
      maxTrackedVariables: this.limits.maxTrackedVariables,
      maxValuesPerVariable: this.limits.maxValuesPerVariable,
    };
    this.engineState.reportLimit = (code, message) => {
      this.partial = true;
      this.addDiagnostic({
        type: 'diagnostic', severity: 'warning', stage: 'resolution',
        code, message, recoverable: true,
      });
    };
  }

  has(capability: AnalysisCapability): boolean {
    return this.capabilities.has(capability);
  }

  checkBudget(stage: string): boolean {
    if (performance.now() <= this.deadline) return true;
    this.partial = true;
    this.addDiagnostic({
      type: 'diagnostic',
      severity: 'warning',
      stage,
      code: 'analysis_time_budget_reached',
      message: `Analysis deadline reached during ${stage}`,
      recoverable: true,
    });
    return false;
  }

  addDiagnostic(diagnostic: Diagnostic): void {
    if (!this.has('diagnostics')) return;
    if (this.diagnostics.length >= this.limits.maxDiagnostics) {
      this.partial = true;
      return;
    }
    this.diagnostics.push(diagnostic);
  }

  claimRequestNode(node: object): void {
    this.claimedRequestNodes.add(node);
  }

  isRequestNodeClaimed(node: object): boolean {
    return this.claimedRequestNodes.has(node);
  }

  get sourceLines(): string[] {
    this.cachedSourceLines ??= this.source.split('\n');
    return this.cachedSourceLines;
  }

  defaultOrigin(): RequestOrigin {
    return {
      client: 'generic',
      provenance: {
        extractor: 'legacy-unknown',
        confidence: 'low',
      },
      extractors: ['legacy-unknown'],
      alternatives: { url: [], method: [], params: [], body: [] },
    };
  }

  addAssetReference(reference: AssetReferenceFact): void {
    const key = `${reference.assetType}\u0000${reference.url.rendered}`;
    if (this.assetDedup.has(key)) return;
    if (this.assetReferences.length >= this.limits.maxAssetReferences) {
      this.partial = true;
      this.addDiagnostic({
        type: 'diagnostic', severity: 'warning', stage: 'assetDiscovery',
        code: 'asset_reference_limit_reached',
        message: `Asset references were limited to ${this.limits.maxAssetReferences}`,
        recoverable: true,
      });
      return;
    }
    this.assetDedup.add(key);
    this.assetReferences.push(reference);
  }

  private addBoundedFact<T extends { id: string }>(fact: T, target: T[], stage: string): void {
    if (this.factDedup.has(fact.id)) return;
    const total = this.graphqlOperations.length + this.webSockets.length + this.eventSources.length +
      this.clientRoutes.length + this.browserSecurityFlows.length;
    if (total >= this.limits.maxEvidenceRecords) {
      this.partial = true;
      this.addDiagnostic({
        type: 'diagnostic', severity: 'warning', stage,
        code: 'analysis_record_limit_reached',
        message: `Additional analysis records were limited to ${this.limits.maxEvidenceRecords}`,
        recoverable: true,
      });
      return;
    }
    this.factDedup.add(fact.id);
    target.push(fact);
  }

  addGraphQLOperation(fact: GraphQLOperationFact): void {
    this.addBoundedFact(fact, this.graphqlOperations, 'graphql');
  }
  addWebSocket(fact: WebSocketFact): void {
    this.addBoundedFact(fact, this.webSockets, 'realtimeProtocols');
  }
  addEventSource(fact: EventSourceFact): void {
    this.addBoundedFact(fact, this.eventSources, 'realtimeProtocols');
  }
  addClientRoute(fact: ClientRouteFact): void {
    this.addBoundedFact(fact, this.clientRoutes, 'clientRoutes');
  }
  addBrowserSecurityFlow(fact: BrowserSecurityFlowFact): void {
    this.addBoundedFact(fact, this.browserSecurityFlows, 'browserSecurityFlows');
  }
}

export function capabilitiesForProfile(
  profile: AnalysisProfile,
): ReadonlySet<AnalysisCapability> {
  return new Set(PROFILE_CAPABILITIES[profile]);
}
