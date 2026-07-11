export const PROTOCOL_VERSION = 2;
export const RESULT_SCHEMA_VERSION = 2;

export type AnalysisProfile =
  | 'legacy'
  | 'endpoints'
  | 'dom-security'
  | 'beautify'
  | 'discovery'
  | 'discovery-lite'
  | 'full'
  | 'inspect';

export type AnalysisCapability =
  | 'endpoints'
  | 'domFlows'
  | 'transformedCode'
  | 'beautifiedCode'
  | 'requestEvidence'
  | 'diagnostics'
  | 'stageMetrics'
  | 'assetReferences'
  | 'graphqlOperations'
  | 'realtimeProtocols'
  | 'clientRoutes'
  | 'browserSecurityFlows';

export type ScanStatus = 'complete' | 'partial' | 'failed' | 'cancelled';

export interface Diagnostic {
  type: 'diagnostic';
  severity: 'info' | 'warning' | 'error';
  stage: string;
  code: string;
  message: string;
  recoverable: boolean;
  location?: {
    line?: number;
    column?: number;
    offset?: number;
  };
}

export interface StageMetric {
  stage: string;
  durationMs: number;
  status: 'complete' | 'skipped' | 'failed';
  costClass?: 'light' | 'medium' | 'heavy';
  mutatesAst?: boolean;
}

export type Confidence = 'high' | 'medium' | 'low';

export interface SourceLocation {
  line?: number;
  column?: number;
  offset?: number;
}

export interface SourceDescriptor {
  url?: string;
  filename?: string;
  mediaType?: string;
  contentSha256: string;
  byteLength: number;
  bundleFormat?: string;
  sourceMapUrl?: string;
}

export interface ResolutionStep {
  kind: string;
  name?: string;
  value?: string;
  module?: string;
  export?: string;
}

export interface Provenance {
  extractor: string;
  confidence: Confidence;
  moduleId?: string;
  modulePath?: string;
  functionName?: string;
  start?: SourceLocation;
  end?: SourceLocation;
  evidence?: string;
  resolutionSteps?: ResolutionStep[];
}

export interface TemplateVariable {
  name: string;
  placeholder: string;
}

export interface ValueTemplate {
  rendered: string;
  static: boolean;
  variables: TemplateVariable[];
  alternatives?: string[];
}

export interface FieldTemplate {
  name: ValueTemplate;
  value: ValueTemplate;
}

export interface HeaderTemplate extends FieldTemplate {
  sensitive?: boolean;
}

export interface BodyTemplate {
  kind: 'json' | 'form' | 'text' | 'unknown';
  value: ValueTemplate;
  contentType?: string;
}

export type HttpClientKind =
  | 'fetch'
  | 'xhr'
  | 'axios'
  | 'jquery'
  | 'angular'
  | 'ky'
  | 'ofetch'
  | 'superagent'
  | 'openapi'
  | 'graphql'
  | 'protocol'
  | 'generic'
  | 'bundle';

export interface HttpRequestFact {
  kind: 'httpRequest';
  id: string;
  url: ValueTemplate;
  method: ValueTemplate;
  query: FieldTemplate[];
  queryAlternatives?: ValueTemplate[];
  headers: HeaderTemplate[];
  cookies: FieldTemplate[];
  body?: BodyTemplate;
  credentialsMode?: string;
  client: HttpClientKind;
  provenance: Provenance;
  alternateExtractors?: string[];
}

export interface DomFlowFact {
  kind: 'domFlow';
  id: string;
  source: string;
  sink: string;
  snippet: string;
  line: number;
  confidence: Confidence;
  provenance: Provenance;
  path?: Array<{ kind: string; label: string; location?: SourceLocation }>;
  flowType?: 'domXss' | 'openRedirect' | 'scriptUrlInjection' | 'sensitiveExfiltration' | 'clientRequestInjection' | 'dynamicExecution' | 'prototypePollution';
}

export type AssetType =
  | 'script'
  | 'dynamic-import'
  | 'worker'
  | 'shared-worker'
  | 'service-worker'
  | 'source-map'
  | 'wasm'
  | 'manifest'
  | 'config';

export interface AssetReferenceFact {
  kind: 'assetReference';
  id: string;
  assetType: AssetType;
  url: ValueTemplate;
  parentSourceUrl?: string;
  eager: boolean;
  inline?: boolean;
  provenance: Provenance;
}

export interface GraphQLVariableTemplate {
  name: string;
  type?: string;
  required?: boolean;
  defaultValue?: string;
  value?: ValueTemplate;
}

export interface GraphQLOperationFact {
  kind: 'graphqlOperation';
  id: string;
  endpoint?: ValueTemplate;
  operationType: 'query' | 'mutation' | 'subscription' | 'unknown';
  operationName?: string;
  document?: string;
  persistedQueryHash?: string;
  variables: GraphQLVariableTemplate[];
  transport: 'http' | 'websocket' | 'sse' | 'unknown';
  provenance: Provenance;
}

export interface WebSocketFact {
  kind: 'websocket';
  id: string;
  url: ValueTemplate;
  subprotocols: string[];
  outboundMessages: BodyTemplate[];
  inboundEventNames: string[];
  library: 'native' | 'socket.io' | 'sockjs' | 'graphql-ws' | 'unknown';
  headers?: HeaderTemplate[];
  options?: Record<string, ValueTemplate>;
  provenance: Provenance;
}

export interface EventSourceFact {
  kind: 'eventSource';
  id: string;
  url: ValueTemplate;
  withCredentials: boolean;
  eventNames: string[];
  library: 'native' | 'fetch-stream' | 'unknown';
  headers?: HeaderTemplate[];
  lastEventId?: ValueTemplate;
  provenance: Provenance;
}

export interface ClientRouteFact {
  kind: 'clientRoute';
  id: string;
  path: ValueTemplate;
  routeType: 'page' | 'api' | 'redirect' | 'lazy' | 'unknown';
  guards?: string[];
  lazyAsset?: ValueTemplate;
  provenance: Provenance;
}

export interface BrowserSecurityFlowFact {
  kind: 'browserSecurityFlow';
  id: string;
  flowType: 'openRedirect' | 'scriptUrlInjection' | 'unsafePostMessage' | 'sensitiveExfiltration' | 'clientRequestInjection' | 'dynamicExecution' | 'prototypePollution';
  source: string;
  sink: string;
  confidence: Confidence;
  evidence: string;
  path: Array<{ kind: string; label: string; location?: SourceLocation }>;
  provenance: Provenance;
}

export interface ArtifactDescriptor {
  kind: 'artifact';
  artifactType: 'transformedSource' | 'beautifiedSource' | 'sourceMap' | 'originalSource';
  path: string;
  sha256: string;
  byteLength: number;
  mediaType?: string;
  filename?: string;
  format?: string;
  moduleCount?: number;
  modulePaths?: string[];
}

export type AnalysisRecord =
  | HttpRequestFact
  | DomFlowFact
  | AssetReferenceFact
  | GraphQLOperationFact
  | WebSocketFact
  | EventSourceFact
  | ClientRouteFact
  | BrowserSecurityFlowFact;

export interface AnalysisStats {
  status: ScanStatus;
  inputBytes: number;
  durationMs: number;
  recordCounts: Record<string, number>;
  stageMetrics: StageMetric[];
}

export interface AnalysisResultV2 {
  type: 'analysisResult';
  schemaVersion: typeof RESULT_SCHEMA_VERSION;
  jobId: string;
  profile: AnalysisProfile;
  tool: {
    version: string;
    sourceHash: string;
  };
  source: SourceDescriptor;
  stats: AnalysisStats;
  diagnostics: Diagnostic[];
  records: AnalysisRecord[];
  artifacts: ArtifactDescriptor[];
}

export interface ScanStartedRecord {
  type: 'scanStarted';
  protocolVersion: number;
  schemaVersion: number;
  scanId: string;
  profile: AnalysisProfile;
  inputBytes: number;
}

export interface ScanCompletedRecord {
  type: 'scanCompleted';
  protocolVersion: number;
  schemaVersion: number;
  scanId: string;
  profile: AnalysisProfile;
  status: ScanStatus;
  reasonCode?: string;
  counts: {
    requests: number;
    domFlows: number;
    diagnostics: number;
    artifacts: number;
  };
  outputBytes?: number;
  stageMetrics?: StageMetric[];
}

export interface CapabilitiesRecord {
  type: 'capabilities';
  protocolVersion: number;
  toolVersion: string;
  sourceHash: string;
  schemaVersions: Record<string, number>;
  capabilities: AnalysisCapability[];
  profiles: AnalysisProfile[];
  /** Supported deobfuscation aggressiveness levels for the rewriteLevel option. */
  rewriteLevels?: Array<'strict' | 'standard' | 'aggressive'>;
  framing: Array<'length-prefixed-v2'>;
  runtime: {
    name: 'bun' | 'node' | 'unknown';
    version: string;
  };
  build: {
    timestamp?: string;
    commit?: string;
    dependencies: Record<string, string>;
  };
}

export interface WorkerLimits {
  maxRequests?: number;
  maxAstNodes?: number;
  maxOutputBytes?: number;
  maxArtifactBytes?: number;
  deadlineMs?: number;
}

export interface WorkerAnalyzeRequest {
  type: 'analyze';
  id: string;
  profile: AnalysisProfile;
  /** Deobfuscation aggressiveness. Omitted defaults to `standard`. */
  rewriteLevel?: 'strict' | 'standard' | 'aggressive';
  sourceUrl?: string;
  filename?: string;
  mediaType?: string;
  artifactDir: string;
  beautify?: boolean;
  /** Unpack detected bundles and re-scan each module for endpoints. */
  unpackModules?: boolean;
  contentLength: number;
  limits?: WorkerLimits;
}

export interface WorkerShutdownRequest {
  type: 'shutdown';
}

export interface WorkerHelloRecord {
  type: 'workerHello';
  workerId: string;
  pid: number;
  capabilities: CapabilitiesRecord;
}

export interface WorkerResultRecord {
  type: 'workerResult';
  id: string;
  result?: AnalysisResultV2;
  completion: ScanCompletedRecord;
  error?: Diagnostic;
}

export type WorkerRequest = WorkerAnalyzeRequest | WorkerShutdownRequest;
