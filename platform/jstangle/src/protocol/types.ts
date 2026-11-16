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
  | 'browserSecurityFlows'
  | 'pathLiterals';

/**
 * Additive record features advertised next to the analysis capabilities so a
 * consumer can gate on them (Go: `Capabilities.Has`) without a protocol bump.
 * A helper that predates a feature simply does not list it.
 */
export type FeatureCapability =
  | 'facts.pathLiteral'
  | 'facts.httpRequest.auth'
  | 'facts.httpRequest.callSite'
  | 'facts.httpRequest.suppressed'
  | 'facts.httpRequest.urlModel'
  | 'facts.httpRequest.queryFromUrl'
  | 'facts.clientRoute.fullPath'
  | 'facts.clientRoute.meta'
  | 'completion.truncated'
  | 'loader.webpack-chunk'
  | 'loader.vite-preload';

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

/**
 * Where a request's credential comes from. Never carries the credential value:
 * `literal` only says the bundle hard-codes one (secret scanning reports it).
 */
export interface AuthContext {
  kind: 'bearer' | 'basic' | 'apikey-header' | 'apikey-query' | 'cookie' | 'custom';
  /** Header carrying the credential, for header-borne kinds. */
  header?: string;
  /** Query parameter carrying the credential, for `apikey-query`. */
  query?: string;
  /** Authorization scheme (`Bearer`, `Basic`, `Token`, ...) when one is prefixed. */
  scheme?: string;
  /** `<sourceKind>:<key>`, e.g. `localStorage:jwt` or `state:auth.token`. */
  source: string;
  sourceKind: 'localStorage' | 'sessionStorage' | 'cookie' | 'state' | 'literal' | 'unknown';
}

/** A lower-confidence fact dropped in favour of the one that carries it. */
export interface SuppressedFact {
  id: string;
  url: string;
  reason: 'prefix' | 'suffix';
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
  /** Credential source feeding this request, when the bundle shows one. */
  auth?: AuthContext;
  /** Stable id of the call expression that produced the canonical fact. */
  callSite?: string;
  /** Noise facts from the same call site folded into this one. */
  suppressed?: SuppressedFact[];
}

export type PathLiteralReason =
  | 'object-value'
  | 'array-element'
  | 'const-init'
  | 'default-param'
  | 'return'
  | 'assignment';

/**
 * A path-shaped string that never reached a request call. Always low
 * confidence: a wordlist and discovery hint, never a replay template.
 */
export interface PathLiteralFact {
  kind: 'pathLiteral';
  id: string;
  value: ValueTemplate;
  reason: PathLiteralReason;
  /** Object key, variable or parameter name the literal was bound to. */
  key?: string;
  provenance: Provenance;
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
  | 'config'
  | 'chunk';

/**
 * Runtime that loads an asset the bundle never names literally:
 * - `webpack-chunk` / `webpack-css-chunk`: rendered from the webpack runtime's
 *   chunk-filename function (`__webpack_require__.u` / `.miniCssF`) over its
 *   chunk-id set, prefixed with a static `.p` publicPath.
 * - `vite-preload`: a dependency listed in a Vite `__vitePreload` call.
 * - `template-import`: an `import(`...${x}...`)` whose alternatives were
 *   enumerated from a literal map.
 */
export type AssetLoader = 'webpack-chunk' | 'webpack-css-chunk' | 'vite-preload' | 'template-import';

export interface AssetReferenceFact {
  kind: 'assetReference';
  id: string;
  assetType: AssetType;
  url: ValueTemplate;
  parentSourceUrl?: string;
  eager: boolean;
  inline?: boolean;
  loader?: AssetLoader;
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

/** A literal route-metadata value; null stands for any non-literal value. */
export type RouteMetaValue = string | number | boolean | null | RouteMetaValue[] | { [key: string]: RouteMetaValue };

export type ClientRouteMeta = { [key: string]: RouteMetaValue };

export interface ClientRouteFact {
  kind: 'clientRoute';
  id: string;
  path: ValueTemplate;
  routeType: 'page' | 'api' | 'redirect' | 'lazy' | 'unknown';
  /**
   * Gates on the route record (`canActivate`, `canActivateChild`, `canMatch`,
   * `canLoad`, `beforeEnter`): a guard's identifier, a guard factory's call
   * (`hasRole("admin")`), a functional guard's single call
   * (`inject(AuthService).isLoggedIn()`), or `<inline>`.
   */
  guards?: string[];
  lazyAsset?: ValueTemplate;
  /**
   * The literal metadata object on the route record: Vue Router `meta`, else
   * Angular `data`. Bounded in depth and size; non-literal values are null.
   */
  meta?: ClientRouteMeta;
  /** React Router data-route `loader`: its function name, or `<inline>`. */
  loader?: string;
  /**
   * Absolute route: parent paths joined, leading `/`, `//` collapsed. Not
   * static (variable `parent`) when the parent lives in another module.
   */
  fullPath?: ValueTemplate;
  /** Id of the enclosing route record for nested `children`. */
  parentId?: string;
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
  | BrowserSecurityFlowFact
  | PathLiteralFact;

/** Records dropped by a per-kind cap or the output budget, keyed by record kind. */
export type TruncationCounts = Record<string, number>;

export interface AnalysisStats {
  status: ScanStatus;
  inputBytes: number;
  durationMs: number;
  recordCounts: Record<string, number>;
  stageMetrics: StageMetric[];
  truncated?: TruncationCounts;
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
    truncated?: TruncationCounts;
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
  capabilities: Array<AnalysisCapability | FeatureCapability>;
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
  /** Max unpacked bundle modules independently re-scanned for endpoints. */
  maxBundleModules?: number;
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
