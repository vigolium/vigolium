// vigolium.d.ts — TypeScript type declarations for the vigolium extension API.
// This file provides IDE autocompletion for extension authors.
// It is NOT loaded by the runtime.

declare namespace vigolium {
  namespace log {
    function info(msg: string): void;
    function warn(msg: string): void;
    function error(msg: string): void;
    function debug(msg: string): void;
  }

  namespace utils {
    function base64Encode(s: string): string;
    function base64Decode(s: string): string;
    function urlEncode(s: string): string;
    function urlDecode(s: string): string;
    function htmlEncode(s: string): string;
    function htmlDecode(s: string): string;
    function sha1(s: string): string;
    function sha256(s: string): string;
    function md5(s: string): string;
    function randomString(len: number): string;
    function sleep(ms: number): void;
    function exec(cmd: string): { stdout: string; stderr: string; exitCode: number };
    function glob(pattern: string): string[];
    function readFile(path: string): string;
    function readLines(path: string): string[];
    function writeFile(path: string, data: string): boolean;
    function mkdir(path: string): boolean;
    function getEnv(name: string): string;
    function setEnv(name: string, value: string): boolean;
    function jsonExtract(json: string, path: string): any;
    function regexMatch(str: string, pattern: string): boolean;
    function regexExtract(str: string, pattern: string): string | string[] | null;
    function detectAnomaly(responses: AnomalyInput[]): AnomalyResult[];
    function parse_url(url: string, format: string): string;
    function parse_url_file(input: string, format: string, output: string): boolean;
    /** Normalize a URL path by replacing dynamic segments (IDs, UUIDs, tokens) with "*". */
    function pathToTemplate(path: string): string;
    /** Returns true if the path contains at least one dynamic segment (numeric ID, UUID, token). */
    function hasDynamicSegment(path: string): boolean;
    /** Convert a comma-separated string into a {key: true} object for fast lookups. */
    function toSet(csv: string): Record<string, boolean>;
    /** Extract deduplicated, lowercased parameter names from a query/body string. */
    function extractParamNames(str: string): string[];
    /** Compare two strings line-by-line and return added/removed lines with a similarity score. */
    function diff(a: string, b: string): DiffResult;
    /** Compute Jaccard similarity (0.0–1.0) between two strings on word-level tokens. */
    function similarity(a: string, b: string): number;
    /**
     * Compare two HTTP responses structurally: status codes, headers, body similarity, and length.
     * Returns null if either response is invalid.
     */
    function diffResponses(a: HttpResponse, b: HttpResponse): ResponseDiffResult | null;
    /**
     * Run a CSS selector query against an HTML string and return matching elements.
     */
    function cssSelect(html: string, selector: string): CSSSelectResult[];
    /**
     * Extract tokens from an HTTP response using configurable rules.
     * Returns a map of extracted values keyed by rule name/path/index.
     */
    function extractToken(response: HttpResponse, rules: TokenExtractRule[]): Record<string, string>;

    /** Decode a JWT token without verification. Returns null if the token is malformed. */
    function jwtDecode(token: string): JWTDecoded | null;
    /** Forge a JWT with the given payload. Supports HS256/HS384/HS512/none algorithms. */
    function jwtEncode(payload: object, opts?: JWTEncodeOpts): string;
    /** Check if a JWT token is expired based on the "exp" claim. Returns true if expired or malformed. */
    function jwtExpired(token: string): boolean;

    /**
     * Build a multipart/form-data body from an array of fields.
     * Returns the encoded body and the Content-Type header (with boundary).
     */
    function multipart(fields: MultipartField[]): MultipartResult;
  }

  namespace parse {
    /** Parse a URL string into its components. Returns null on parse error. */
    function url(urlStr: string): ParsedURL | null;
    /** Parse a raw HTTP request into its components. Returns null on empty input. */
    function request(raw: string): ParsedRequest | null;
    /** Parse a raw HTTP response into its components. Returns null on empty input. */
    function response(raw: string): ParsedResponse | null;
    /** Parse a newline-separated header block into a flat name→value map. */
    function headers(str: string): Record<string, string>;
    /** Parse a Cookie header value (semicolon-delimited name=value pairs) into a map. */
    function cookies(str: string): Record<string, string>;
    /** Parse a URL query string (with or without leading "?") into a flat map. */
    function query(str: string): Record<string, string>;
    /** Parse a JSON string into a native JS value. Returns null on parse error. */
    function json(str: string): any | null;
    /** Parse a URL-encoded form body into a flat name→value map. */
    function form(body: string): Record<string, string>;
    /** Parse HTML and extract forms, links, scripts, and meta tags. Returns null on parse error. */
    function html(htmlStr: string): HTMLParseResult | null;
  }

  namespace http {
    function get(url: string, opts?: RequestOptions): HttpResponse;
    function post(url: string, body: string, opts?: RequestOptions): HttpResponse;
    function request(opts: FullRequestOptions): HttpResponse;
    function send(rawRequest: string): HttpResponse;
    /** Clone and modify a raw HTTP request. Override method, path, headers, body, or query params. */
    function buildRequest(rawRequest: string, overrides: RequestOverrides): string;

    /**
     * Create a persistent HTTP session with shared cookie jar and default headers.
     * Cookies from Set-Cookie responses are automatically stored and sent on subsequent requests.
     */
    function session(opts?: SessionOptions): HttpSession;

    /**
     * Execute a login flow: send credentials, extract auth tokens from the response,
     * and return an authenticated session ready to use.
     */
    function login(opts: LoginOptions): HttpSession;

    /**
     * Send multiple HTTP requests in parallel and return all responses.
     * Useful for IDOR/BOLA testing or race condition checks.
     */
    function batch(requests: FullRequestOptions[], opts?: BatchOptions): HttpResponse[];

    /**
     * Replay a raw HTTP request with multiple variations (header overrides, body swaps, etc.).
     * Returns one response per variation, in order.
     */
    function replay(rawRequest: string, variations: ReplayVariation[]): HttpResponse[];

    /**
     * Execute a sequence of HTTP requests where each step can extract variables
     * (from response body, headers, cookies) for use in subsequent steps via {{varName}} placeholders.
     * Steps support conditional execution, fallback steps, and repeat loops.
     */
    function sequence(steps: SequenceStep[]): SequenceResult;

    /**
     * Test for IDOR/BOLA vulnerabilities by replaying requests across multiple sessions
     * with different privilege levels and comparing responses.
     */
    function authTest(opts: AuthTestOptions): AuthTestResult[];

    /**
     * Create a pool of named HTTP sessions from a config map.
     * Each entry can be LoginOptions (auto-login), SessionOptions (manual), or {} (empty session).
     */
    function sessionPool(configs: Record<string, LoginOptions | SessionOptions | {}>): SessionPool;

    /**
     * Fetch a CSRF token from a page by parsing forms, meta tags, headers, or cookies.
     * Returns null if no token is found.
     */
    function csrf(url: string, opts?: CSRFOptions): CSRFResult | null;

    /**
     * Execute an OAuth2 authentication flow and return an authenticated session.
     */
    function followAuth(opts: FollowAuthOptions): HttpSession;

    /**
     * Send an HTTP request with automatic retries and configurable backoff.
     * Returns null if all retries are exhausted.
     */
    function retry(request: FullRequestOptions | string, opts?: RetryOptions): HttpResponse | null;

    /**
     * Send a GraphQL query or mutation and return the parsed result.
     * Returns null on network or parse error.
     */
    function graphql(url: string, opts: GraphQLOptions): GraphQLResult | null;

    /**
     * Fetch a GraphQL introspection schema from the given endpoint.
     * Returns null if introspection is disabled or the request fails.
     */
    function graphqlSchema(url: string, opts?: GraphQLSchemaOptions): object | null;

    /**
     * Enable response caching for subsequent requests. Cached responses are returned
     * for identical request signatures within the TTL window.
     */
    function cache(opts?: CacheOptions): void;

    /** Clear all cached HTTP responses. */
    function clearCache(): void;

    /** Perform a GET request, returning a cached response if available. */
    function cachedGet(url: string, opts?: RequestOptions): HttpResponse;

    /** Perform an HTTP request, returning a cached response if available. */
    function cachedRequest(opts: FullRequestOptions): HttpResponse;
  }

  namespace scan {
    function listModules(): ModuleInfo[];
    /** Returns all unique tags across all registered modules (lowercased). */
    function listModuleTags(): string[];
    /** Returns all modules that have the given tag (case-insensitive). */
    function listModulesByTag(tag: string): ModuleInfo[];
    function isInScope(host: string, path: string): boolean;
    function getScope(): ScopeConfig;
    function setScope(scope: Partial<ScopeConfig>): boolean;
    function createFinding(finding: FindingInput): boolean;
    function getCurrentScan(): ScanInfo;
    function startNewScan(opts: StartScanInput): StartScanResult;
    /** Queue a scan for existing database records by their UUIDs. */
    function scanRecords(opts: ScanRecordsInput): ScanRecordsResult;
  }

  namespace ingest {
    function url(url: string): IngestResult;
    function urls(content: string): IngestBatchResult;
    function curl(command: string): IngestResult;
    function raw(rawRequest: string, rawResponse?: string): IngestResult;
    function openapi(spec: string, opts?: { base_url?: string }): IngestBatchResult;
    function postman(collection: string): IngestBatchResult;
  }

  namespace source {
    function list(hostname?: string): SourceRepo[];
    function get(id: number): SourceRepo | null;
    function getByHostname(hostname: string): SourceRepo[];
    function readFile(hostname: string, path: string): string;
    function listFiles(hostname: string, glob?: string): string[];
    function searchFiles(hostname: string, pattern: string): SearchMatch[];
  }

  namespace agent {
    /** Low-level: full control over model, messages, schema, and temperature. */
    function complete(opts: AgentCompleteOpts): AgentCompleteResult;
    /** Mid-level: send a single user prompt, receive a text response. */
    function ask(prompt: string, opts?: AgentAskOpts): string;
    /** Mid-level: send a message array, receive a text response. */
    function chat(messages: AgentMessage[], opts?: AgentChatOpts): string;
    /** High-level: generate security test payloads for a given vulnerability type. */
    function generatePayloads(opts: GeneratePayloadsOpts): string[];
    /** High-level: analyze an HTTP exchange for a specific vulnerability. */
    function analyzeResponse(opts: AnalyzeResponseOpts): AnalyzeResponseResult;
    /** High-level: confirm whether a scanner finding is a true positive. */
    function confirmFinding(opts: ConfirmFindingOpts): ConfirmFindingResult;
    /** Subprocess: run a full agent backend (claude, opencode, gemini, etc.). */
    function run(opts: AgentRunOpts): AgentRunResult;
  }

  namespace oast {
    /** Returns true if the OAST service is active and available. */
    function enabled(): boolean;
    /** Generate a unique OAST callback URL for out-of-band testing. Returns null if OAST is unavailable. */
    function payload(targetURL?: string, paramName?: string, injectionType?: string): OASTPayload | null;
    /** Wait for the specified timeout then return all OAST interactions from the current scan. */
    function poll(timeoutMs?: number): OASTInteraction[];
  }

  namespace db {
    namespace records {
      /** Query HTTP records with optional filters. Returns up to limit results. */
      function query(filters?: DBQueryFilters): DBRecord[];
      /** Get a single HTTP record by UUID. Returns null if not found. */
      function get(uuid: string): DBRecord | null;
      /** Get HTTP records with the same path template and hostname as the given UUID's record. */
      function getRelated(uuid: string, opts?: DBGetRelatedOpts): DBRecord[];
      /** Update risk_score and/or remarks on an HTTP record. Returns true on success. */
      function annotate(uuid: string, patch: DBAnnotatePatch): boolean;
      /**
       * Group records by path template (dynamic segments replaced with "*").
       * Returns groups with at least min_group_size records, useful for finding IDOR candidates.
       */
      function grouped(opts?: DBGroupedOpts): RecordGroup[];
    }
    namespace findings {
      /** Query findings with optional filters. Returns up to limit results. */
      function query(filters?: DBQueryFilters): DBFinding[];
      /** Get a single finding by numeric ID. Returns null if not found. */
      function get(id: number): DBFinding | null;
      /** Get findings that reference the given HTTP record UUID. */
      function getByRecord(uuid: string): DBFinding[];
      /** Persist a new finding directly. Returns true on success. */
      function create(finding: DBFindingInput): boolean;
    }
    /**
     * Compare a set of HTTP records for response anomalies.
     * Uses the anomaly engine to rank records by how much they diverge from the majority.
     * Useful for IDOR/BOLA detection: pass records from the same endpoint with different IDs
     * and check if some responses differ unexpectedly.
     */
    function compareResponses(records: DBRecord[]): DBCompareResult;
  }

  const config: Record<string, string>;

  /**
   * Return built-in payload wordlists by vulnerability type.
   * Types: "xss", "sqli", "ssti", "ssrf", "lfi", "path_traversal", "xxe", "cmdi", "open_redirect", "crlf"
   */
  function payloads(type: PayloadType): string[];

  /**
   * Current HTTP record context (alias for ctx.record).
   * Set per scan invocation — only available inside scanPerRequest / scanPerHost / scanPerInsertionPoint.
   */
  const record: RecordContext;
}

type PayloadType = "xss" | "sqli" | "ssti" | "ssrf" | "lfi" | "path_traversal" | "xxe" | "cmdi" | "open_redirect" | "crlf";

interface AnomalyInput {
  status: number;
  body: string;
  headers?: Record<string, string>;
}

interface AnomalyResult {
  index: number;
  score: number;
}

interface DiffResult {
  /** Lines present in b but not in a. */
  added: string[];
  /** Lines present in a but not in b. */
  removed: string[];
  /** Dice coefficient similarity (0.0–1.0) on unique lines. */
  similarity: number;
}

interface RequestOptions {
  headers?: Record<string, string>;
}

interface FullRequestOptions {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

interface RequestOverrides {
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  body?: string;
  query?: Record<string, string>;
}

interface HttpResponse {
  status: number;
  body: string;
  raw: string;
  headers: Record<string, string>;
  /** Response time in milliseconds. */
  elapsed_ms: number;
}

interface OASTPayload {
  /** The unique OAST callback URL to inject. */
  url: string;
}

interface OASTInteraction {
  protocol: string;
  unique_id: string;
  full_id: string;
  remote_address: string;
  target_url: string;
  parameter_name: string;
  module_id: string;
  interacted_at: string;
}

interface HTMLParseResult {
  forms: HTMLForm[];
  links: HTMLLink[];
  scripts: HTMLScript[];
  meta: HTMLMeta[];
}

interface HTMLForm {
  action: string;
  method: string;
  inputs: HTMLFormInput[];
}

interface HTMLFormInput {
  name: string;
  type: string;
  value: string;
}

interface HTMLLink {
  href: string;
  text: string;
}

interface HTMLScript {
  src: string;
  content: string;
}

interface HTMLMeta {
  name: string;
  content: string;
}

interface ModuleInfo {
  id: string;
  name: string;
  type: "active" | "passive";
  severity: string;
  description: string;
  tags: string[];
}

interface ScopeRule {
  include?: string[];
  exclude?: string[];
}

interface ScopeConfig {
  host?: ScopeRule;
  path?: ScopeRule;
  status_code?: ScopeRule;
  request_content_type?: ScopeRule;
  response_content_type?: ScopeRule;
  request_string?: ScopeRule;
  response_string?: ScopeRule;
}

interface FindingInput {
  url: string;
  matched?: string;
  name: string;
  description?: string;
  severity?: string;
  request?: string;
  response?: string;
  additional_evidence?: string[];
}

interface ScanInfo {
  uuid: string;
}

interface StartScanInput {
  targets: string[];
  modules?: string[];
  name?: string;
}

interface StartScanResult {
  scan_uuid: string;
  queued: number;
  errors: string[];
}

interface ScanRecordsInput {
  uuids: string[];
  modules?: string[];
  tags?: string[];
  name?: string;
}

interface ScanRecordsResult {
  scan_uuid: string;
  record_count: number;
  errors: string[];
}

interface IngestResult {
  imported: number;
  skipped: number;
  uuid: string;
  error: string;
}

interface IngestBatchResult {
  imported: number;
  skipped: number;
  errors: string[];
}

interface SourceRepo {
  id: number;
  hostname: string;
  name: string;
  root_path: string;
  repo_type: string;
  language?: string;
  framework?: string;
  scan_uuid?: string;
  endpoints?: string[];
  route_params?: string[];
  sinks?: string[];
  tags?: string[];
}

interface SearchMatch {
  path: string;
  line: number;
  match: string;
}

// ── vigolium.agent types ────────────────────────────────────────────────────

interface AgentMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface AgentCompleteOpts {
  messages: AgentMessage[];
  model?: string;
  max_tokens?: number;
  temperature?: number;
  /** JSON Schema string for structured output. When set, content is raw JSON. */
  json_schema?: string;
}

interface AgentCompleteResult {
  content: string;
  model: string;
  tokens_in: number;
  tokens_out: number;
}

interface AgentAskOpts {
  system?: string;
  model?: string;
  max_tokens?: number;
}

interface AgentChatOpts {
  model?: string;
  max_tokens?: number;
}

interface GeneratePayloadsOpts {
  /** Vulnerability type: xss, sqli, ssrf, lfi, ssti, cmdi, xxe, open_redirect */
  type: string;
  parameter?: string;
  context?: string;
  technology?: string;
  waf?: string;
  count?: number;
}

interface AnalyzeResponseOpts {
  request: string;
  response: string;
  vulnerability_type: string;
  payload?: string;
  baseline_response?: string;
}

interface AnalyzeResponseResult {
  vulnerable: boolean;
  confidence: "high" | "medium" | "low";
  evidence: string;
  details: string;
}

interface ConfirmFindingOpts {
  name: string;
  request: string;
  response: string;
  matched?: string;
  baseline_response?: string;
}

interface ConfirmFindingResult {
  confirmed: boolean;
  confidence: "high" | "medium" | "low";
  reasoning: string;
  false_positive_indicators: string[];
}

interface AgentRunOpts {
  /** Agent backend name (claude, opencode, gemini, etc.) */
  agent: string;
  prompt: string;
  /** Timeout in seconds. Default: 60. */
  timeout?: number;
}

interface AgentRunResult {
  output: string;
  findings: any[];
  http_records: any[];
}

// ── vigolium.db types ────────────────────────────────────────────────────────

interface DBQueryFilters {
  hostname?: string;
  path?: string;
  methods?: string[];
  status_codes?: number[];
  source?: string;
  search?: string;
  fuzzy?: string;
  min_risk_score?: number;
  limit?: number;
  offset?: number;
  sort_by?: string;
  sort_asc?: boolean;
  /** Findings-only: filter by severity array, e.g. ["high","critical"] */
  severity?: string[];
  /** Findings-only: filter by module name substring */
  module_name?: string;
  /** Findings-only: filter by scan UUID */
  scan_uuid?: string;
}

interface DBRecord {
  uuid: string;
  scheme: string;
  hostname: string;
  port: number;
  method: string;
  path: string;
  url: string;
  http_version: string;
  status_code: number;
  status_phrase?: string;
  has_response: boolean;
  response_body: string;
  response_content_type?: string;
  request_content_type?: string;
  response_time_ms?: number;
  response_title?: string;
  response_headers?: Record<string, string[]>;
  request_headers?: Record<string, string[]>;
  request_body?: string;
  risk_score: number;
  remarks?: string[];
  source: string;
  sent_at: string;
}

interface DBFinding {
  id: number;
  module_id: string;
  module_name: string;
  severity: string;
  confidence: string;
  finding_hash: string;
  found_at: string;
  description?: string;
  request?: string;
  response?: string;
  tags?: string[];
  matched_at?: string[];
  extracted_results?: string[];
  http_record_uuids?: string[];
  scan_uuid?: string;
}

interface DBFindingInput {
  module_id: string;
  module_name: string;
  severity: string;
  confidence?: string;
  description?: string;
  request?: string;
  response?: string;
  matched_at?: string[];
  extracted_results?: string[];
  additional_evidence?: string[];
  tags?: string[];
  finding_hash?: string;
  http_record_uuids?: string[];
  scan_uuid?: string;
}

interface DBAnnotatePatch {
  risk_score?: number;
  remarks?: string[];
}

interface DBGetRelatedOpts {
  /** Maximum number of related records to return. Default: 10. */
  limit?: number;
}

interface DBScoreEntry {
  uuid: string;
  score: number;
}

interface DBCompareResult {
  /** True when all records have the same response fingerprint (score == 0 for all). */
  all_similar: boolean;
  /** Anomaly scores per record, sorted descending (highest divergence first). */
  scores: DBScoreEntry[];
  /** Number of records with a non-zero anomaly score. */
  variant_count: number;
  /** Human-readable summary, e.g. "2/5 responses differ (scores: 40500, 12000)". */
  summary: string;
}

// ── vigolium.parse types ─────────────────────────────────────────────────────

interface ParsedURL {
  scheme: string;
  host: string;
  hostname: string;
  port: string;
  path: string;
  query: string;
  fragment: string;
  /** Parsed query parameters (first value per key). */
  params: Record<string, string>;
  /** Non-empty path segments, e.g. ["api", "users", "123"]. */
  segments: string[];
  /** Path with dynamic segments replaced by "*", e.g. "/api/users/*". */
  template: string;
}

interface ParsedRequest {
  method: string;
  /** Path without query string. */
  path: string;
  /** Raw query string (without leading "?"). */
  query: string;
  /** HTTP version, e.g. "1.1". */
  version: string;
  /** Flat header map (last value wins for duplicates). */
  headers: Record<string, string>;
  body: string;
  /** Value of the Host header. */
  host: string;
  /** Parsed query parameters (first value per key). */
  params: Record<string, string>;
  /** Request cookies from the Cookie header. */
  cookies: Record<string, string>;
}

interface ParsedResponse {
  status: number;
  statusText: string;
  /** HTTP version, e.g. "1.1". */
  version: string;
  /** Flat header map (last value wins for duplicates). */
  headers: Record<string, string>;
  body: string;
  /** Cookies from Set-Cookie headers, keyed by name. */
  cookies: Record<string, string>;
  /** Value of the Content-Type header. */
  contentType: string;
}

/** Record context for the current HTTP record being processed by the extension. */
interface RecordContext {
  /** Database UUID of the current HTTP record. Empty string if not persisted. */
  uuid: string;
  /** Replace annotations on the current HTTP record. Returns true on success. */
  annotate(patch: DBAnnotatePatch): boolean;
  /** Increment risk_score by delta (can be negative, clamped to 0). Returns true on success. */
  addRiskScore(delta: number): boolean;
  /** Append remarks with deduplication (existing remarks are preserved). Returns true on success. */
  addRemarks(remarks: string[]): boolean;
}

// ── vigolium.http session types ───────────────────────────────────────────────

interface SessionOptions {
  /** Default headers applied to every request in this session. */
  headers?: Record<string, string>;
  /** Initial cookies (name=value) seeded into the session. */
  cookies?: Record<string, string>;
}

interface HttpSession {
  get(url: string, opts?: RequestOptions): HttpResponse;
  post(url: string, body: string, opts?: RequestOptions): HttpResponse;
  request(opts: FullRequestOptions): HttpResponse;
  send(rawRequest: string): HttpResponse;
  /** Set or update a default header for this session. */
  setHeader(name: string, value: string): void;
  /** Remove a default header by name (case-insensitive). */
  removeHeader(name: string): void;
  /** Get all current default headers (including Cookie). */
  getHeaders(): Record<string, string>;
  /** Get all cookies currently stored in this session. */
  getCookies(): Record<string, string>;
  /** Set or update a cookie in this session. */
  setCookie(name: string, value: string): void;
  /** Create a deep copy of this session with independent cookie jar and headers. */
  cloneAs(): HttpSession;

  /** Register a callback to run before every request. Return a modified RequestInfo to alter the request. */
  onRequest(fn: (req: RequestInfo) => RequestInfo | void): void;
  /** Register a callback to run after every response. */
  onResponse(fn: (resp: HttpResponse, req: RequestInfo) => void): void;
  /** Configure automatic token refresh when a trigger status code (e.g. 401) is received. */
  setAutoRefresh(opts: AutoRefreshOptions): void;
}

interface LoginOptions {
  /** Login endpoint URL. */
  url: string;
  /** HTTP method. Default: "POST". */
  method?: string;
  /** Request headers for the login request. */
  headers?: Record<string, string>;
  /** Request body (form data or JSON). */
  body?: string;
  /** Content-Type override. Auto-detected from body if omitted. */
  content_type?: string;
  /** Rules for extracting auth tokens from the login response. */
  extract: LoginExtractRule[];
}

interface LoginExtractRule {
  /** Where to extract from: "cookie", "json", or "header". */
  source: "cookie" | "json" | "header";
  /** Cookie name or header name to extract. */
  name?: string;
  /** JSON dot-path for json source (e.g. "data.access_token"). */
  path?: string;
  /** Header template for applying the extracted value, e.g. "Authorization: Bearer {value}". */
  apply_as?: string;
}

interface BatchOptions {
  /** Maximum parallel requests. Default: 5, max: 20. */
  concurrency?: number;
}

interface ReplayVariation extends RequestOverrides {
  /** Headers to remove from the original request before applying overrides. */
  remove_headers?: string[];
}

interface SequenceStep {
  /** Raw HTTP request template. Supports {{varName}} substitution. */
  request?: string;
  /** HTTP method (alternative to raw request). Supports {{varName}}. */
  method?: string;
  /** URL (alternative to raw request). Supports {{varName}}. */
  url?: string;
  /** Request headers. Values support {{varName}}. */
  headers?: Record<string, string>;
  /** Request body. Supports {{varName}}. */
  body?: string;
  /** Variable extraction rules. Keys become variable names for subsequent steps. */
  extract?: Record<string, SequenceExtractRule>;
  /** Skip this step if the condition evaluates to false. Supports "{{var}} != ''" and "{{var}} == 'value'". */
  condition?: string;
  /** Fallback step to execute if this step's request fails. */
  fallback?: SequenceStep;
  /** Repeat this step multiple times, optionally with a delay and until-condition. */
  repeat?: SequenceRepeatOpts;
}

interface SequenceExtractRule {
  /** Where to extract from. */
  source: "json" | "header" | "cookie" | "regex" | "body";
  /** JSON dot-path (for json source). */
  path?: string;
  /** Header or cookie name (for header/cookie source). */
  name?: string;
  /** Regex pattern with capture group (for regex source). */
  pattern?: string;
}

interface SequenceResult {
  /** Array of responses, one per step. Undefined entries indicate failed requests. */
  responses: HttpResponse[];
  /** All extracted variables accumulated across steps. */
  variables: Record<string, string>;
  /** True if all steps completed with valid responses. */
  success: boolean;
}

// ── vigolium.utils token extraction types ────────────────────────────────────

interface TokenExtractRule {
  /** Where to extract from. */
  source: "json" | "header" | "cookie" | "regex";
  /** Header or cookie name. */
  name?: string;
  /** JSON dot-path (for json source). */
  path?: string;
  /** Regex pattern with capture group (for regex source). */
  pattern?: string;
}

// ── vigolium.utils JWT types ──────────────────────────────────────────────────

interface JWTDecoded {
  header: object;
  payload: object;
  signature: string;
}

interface JWTEncodeOpts {
  /** Signing algorithm. Default: "HS256". Use "none" for unsigned tokens. */
  algorithm?: string;
  /** HMAC secret for HS256/HS384/HS512. */
  secret?: string;
}

// ── vigolium.utils multipart types ───────────────────────────────────────────

interface MultipartField {
  /** Form field name. */
  name: string;
  /** Text value for non-file fields. */
  value?: string;
  /** Filename — triggers file upload mode when set. */
  filename?: string;
  /** Content-Type for the part. Default: "application/octet-stream" for files. */
  contentType?: string;
  /** Raw content for file uploads. */
  data?: string;
}

interface MultipartResult {
  /** The encoded multipart body. */
  body: string;
  /** The Content-Type header value (includes boundary). */
  contentType: string;
}

// ── vigolium.http authTest types ─────────────────────────────────────────────

interface AuthTestOptions {
  /** Sessions with different privilege levels to test. Each session should have a "label" property. */
  sessions: (HttpSession & { label?: string })[];
  /** Records to test — string UUIDs or DBRecord objects with request data. */
  records: (string | DBRecord)[];
  /** Test method: "replay" (default) replays same request with different auth headers. */
  method?: "replay" | "swap";
}

interface AuthTestResult {
  record_uuid: string;
  url: string;
  results: AuthTestSessionResult[];
  vulnerability: "idor" | "bola" | "none";
  confidence: number;
}

interface AuthTestSessionResult {
  session_label: string;
  status: number;
  /** Jaccard similarity of response body vs original response. */
  body_similarity: number;
  /** Heuristic: true if same status class + high similarity to original. */
  accessible: boolean;
}

// ── vigolium.http session interceptor types ───────────────────────────────────

interface RequestInfo {
  method?: string;
  url?: string;
  body?: string;
  headers?: Record<string, string>;
  raw?: string;
}

interface AutoRefreshOptions {
  /** Status code that triggers a refresh (e.g. 401). */
  trigger: number;
  /** Function that returns a new token string. */
  refresh: () => string;
  /** Header name to set with the new token. Default: "Authorization" with "Bearer" prefix. */
  header?: string;
  /** Maximum refresh retries per request. Default: 1. */
  maxRetries?: number;
}

// ── vigolium.http sequence conditional types ─────────────────────────────────

interface SequenceRepeatOpts {
  /** Number of times to repeat. Max: 100. */
  times: number;
  /** Delay in milliseconds between repetitions. Max: 30000. */
  delay_ms?: number;
  /** Stop repeating when this condition becomes true. Same syntax as step conditions. */
  until?: string;
}

// ── vigolium.db grouped types ────────────────────────────────────────────────

interface DBGroupedOpts {
  /** Filter records by hostname. */
  hostname?: string;
  /** Minimum group size to include. Default: 2. */
  min_group_size?: number;
  /** Filter by HTTP methods (e.g. ["GET", "POST"]). */
  methods?: string[];
}

interface RecordGroup {
  /** Path template with dynamic segments replaced by "*", e.g. "/api/users/*/profile". */
  template: string;
  method: string;
  records: DBRecord[];
  /** Dynamic segment values per record, in order of appearance in the path. */
  param_values: string[][];
}

/** Context object passed to extension scanPerRequest / scanPerHost / scanPerInsertionPoint. */
interface ExtensionContext {
  request: {
    raw: string;
    method: string;
    url: string;
    headers: Record<string, string>;
  };
  response: {
    status: number;
    body: string;
    raw: string;
    headers: Record<string, string>;
  };
  /** Current HTTP record with UUID and annotate shortcut. */
  record: RecordContext;
}

// ── vigolium.http session pool types ──────────────────────────────────────────

interface SessionPool {
  /** Get a named session from the pool. */
  get(name: string): HttpSession;
  /** Return all session names in the pool. */
  names(): string[];
  /** Iterate over all sessions in the pool. */
  forEach(fn: (name: string, session: HttpSession) => void): void;
  /** Send the same request from every session and return a map of name → response. */
  broadcast(request: FullRequestOptions | string): Record<string, HttpResponse>;
}

// ── vigolium.http CSRF types ─────────────────────────────────────────────────

interface CSRFOptions {
  /** Session to use for fetching the page. */
  session?: HttpSession;
  /** Custom field names to look for (e.g. ["_token", "csrf"]). */
  field_names?: string[];
  /** Where to look for the token. */
  source?: "form" | "meta" | "header" | "cookie";
}

interface CSRFResult {
  /** The extracted CSRF token value. */
  token: string;
  /** The field/header/cookie name where the token was found. */
  field_name: string;
  /** Where the token was extracted from. */
  source: string;
}

// ── vigolium.http OAuth/auth flow types ──────────────────────────────────────

interface FollowAuthOptions {
  /** OAuth2 grant type. */
  type: "oauth2_client_credentials" | "oauth2_password" | "oauth2_code";
  /** Token endpoint URL. */
  token_url: string;
  /** OAuth2 client ID. */
  client_id: string;
  /** OAuth2 client secret. */
  client_secret?: string;
  /** Username for password grant. */
  username?: string;
  /** Password for password grant. */
  password?: string;
  /** OAuth2 scope. */
  scope?: string;
  /** Redirect URI for authorization code grant. */
  redirect_uri?: string;
  /** Authorization code for code grant. */
  code?: string;
}

// ── vigolium.http retry types ────────────────────────────────────────────────

interface RetryOptions {
  /** Maximum number of retries. Default: 3. */
  max_retries?: number;
  /** Base backoff delay in milliseconds. Default: 1000. */
  backoff_ms?: number;
  /** Status codes that trigger a retry (e.g. [429, 502, 503]). */
  retry_on?: number[];
  /** Custom predicate: keep retrying until this returns true. */
  until?: (resp: HttpResponse) => boolean;
}

// ── vigolium.http GraphQL types ──────────────────────────────────────────────

interface GraphQLOptions {
  /** GraphQL query or mutation string. */
  query: string;
  /** Query variables. */
  variables?: Record<string, any>;
  /** Operation name for multi-operation documents. */
  operation?: string;
  /** Session to use for the request. */
  session?: HttpSession;
  /** Additional request headers. */
  headers?: Record<string, string>;
}

interface GraphQLResult {
  /** Parsed response data. */
  data: any;
  /** GraphQL errors array. */
  errors: any[];
  /** The raw HTTP response. */
  raw: HttpResponse;
}

interface GraphQLSchemaOptions {
  /** Session to use for the introspection request. */
  session?: HttpSession;
  /** Additional request headers. */
  headers?: Record<string, string>;
}

// ── vigolium.http cache types ────────────────────────────────────────────────

interface CacheOptions {
  /** Time-to-live for cached entries in milliseconds. */
  ttl_ms?: number;
  /** Maximum number of cached entries. */
  max_entries?: number;
}

// ── vigolium.utils response diff types ───────────────────────────────────────

interface ResponseDiffResult {
  /** True if both responses have the same status code. */
  status_match: boolean;
  /** Body similarity score (0.0–1.0). */
  body_similarity: number;
  /** Header-level differences. */
  header_diff: { added: string[]; removed: string[]; changed: string[] };
  /** Body-level line differences. */
  body_diff: { added: string[]; removed: string[] };
  /** Difference in Content-Length (b - a). */
  length_diff: number;
  /** Heuristic: true if status matches and body similarity is high. */
  likely_same_content: boolean;
}

// ── vigolium.utils CSS select types ──────────────────────────────────────────

interface CSSSelectResult {
  /** Text content of the matched element. */
  text: string;
  /** Element attributes as a flat map. */
  attrs: Record<string, string>;
  /** Outer HTML of the matched element. */
  html: string;
}
