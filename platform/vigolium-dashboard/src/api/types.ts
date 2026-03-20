// Types mirroring backend Go structs (pkg/server/types.go + pkg/database/models.go)

export interface PaginatedResponse<T> {
  project_uuid?: string;
  data: T[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface StatsResponse {
  http_records: { total: number };
  modules: {
    active: { total: number; enabled: number };
    passive: { total: number; enabled: number };
  };
  findings: {
    total: number;
    by_severity: Record<string, number>;
  };
}

export interface ServerInfoResponse {
  name: string;
  version: string;
  author: string;
  docs: string;
  build_time?: string;
  commit?: string;
  uptime: string;
  service_addr: string;
  proxy_addr?: string;
  db_driver?: string;
  queue_depth: number;
  total_records: number;
  total_findings: number;
}

export interface Finding {
  id: number;
  http_record_uuids: string[];
  scan_uuid?: string;
  module_id: string;
  module_name: string;
  module_type?: string;
  module_short?: string;
  finding_source?: string;
  description?: string;
  severity: string;
  confidence: string;
  tags?: string[];
  matched_at?: string[];
  extracted_results?: string[];
  additional_evidence?: string[];
  request?: string;
  response?: string;
  finding_hash: string;
  found_at: string;
  created_at: string;
}

export interface HTTPRecord {
  uuid: string;
  scheme: string;
  hostname: string;
  port: number;
  ip?: string;
  method: string;
  path: string;
  url: string;
  http_version: string;
  request_headers?: Record<string, string[]>;
  request_content_type?: string;
  request_content_length: number;
  request_hash: string;
  status_code: number;
  status_phrase?: string;
  response_content_type?: string;
  response_content_length: number;
  response_time_ms: number;
  response_words: number;
  has_response: boolean;
  response_title?: string;
  parameters?: EmbeddedParam[];
  sent_at: string;
  received_at?: string;
  created_at: string;
  source?: string;
  remarks?: string[];
  risk_score: number;
  // Detail-only fields (returned by GET /api/http-records/:uuid)
  raw_request?: string;
  raw_response?: string;
  request_body?: string;
  response_body?: string;
  response_hash?: string;
  response_http_version?: string;
  response_headers?: Record<string, string[]>;
}

export interface EmbeddedParam {
  name: string;
  value?: string;
  type: string;
}

export interface ModuleInfo {
  id: string;
  name: string;
  description: string;
  short_description: string;
  confirmation_criteria: string;
  severity: string;
  confidence: string;
  scan_scope: string[];
  tags?: string[];
  type: string;
}

export interface ModulesResponse {
  modules: ModuleInfo[];
  total: number;
}

export interface ScanStatusResponse {
  project_uuid?: string;
  scan_id?: string;
  running: boolean;
  status: string;
  message?: string;
}

export interface ScanResponse {
  project_uuid?: string;
  scan_id: string;
  running?: boolean;
  status: string;
  message?: string;
  records_to_scan?: number;
  targets_count?: number;
  scan_mode?: string;
  repo_path?: string;
}

export interface ErrorResponse {
  error: string;
  code?: number;
  details?: string;
}

export interface FindingsQueryParams {
  limit?: number;
  offset?: number;
  severity?: string;
  module_name?: string;
  module_type?: string;
  finding_source?: string;
  domain?: string;
  scan_id?: string;
  search?: string;
  sort?: string;
  order?: string;
}

export interface HttpRecordsQueryParams {
  limit?: number;
  offset?: number;
  hostname?: string;
  method?: string;
  path?: string;
  status_code?: number;
  content_type?: string;
  source?: string;
  min_risk?: number;
  remark?: string;
  search?: string;
  sort?: string;
  order?: string;
}

export interface OASTInteraction {
  id: number;
  scan_uuid?: string;
  unique_id: string;
  full_id: string;
  protocol: string;
  q_type?: string;
  raw_request?: string;
  raw_response?: string;
  remote_address?: string;
  interacted_at: string;
  target_url?: string;
  parameter_name?: string;
  injection_type?: string;
  module_id?: string;
  created_at: string;
}

export interface OASTInteractionsQueryParams {
  limit?: number;
  offset?: number;
  scan_id?: string;
  protocol?: string;
  module_id?: string;
  search?: string;
  sort?: string;
  order?: string;
}

// Scope types
export interface ScopeRule {
  include: string[];
  exclude: string[];
}

export interface ScopeConfig {
  host: ScopeRule;
  path: ScopeRule;
  status_code: ScopeRule;
  request_content_type: ScopeRule;
  response_content_type: ScopeRule;
  request_string: ScopeRule;
  response_string: ScopeRule;
}

export interface ScopeUpdateResponse {
  message: string;
}

// Config types
export interface ConfigEntry {
  key: string;
  value: string;
  sensitive?: boolean;
}

export interface ConfigResponse {
  entries: ConfigEntry[];
  total: number;
}

export interface ConfigUpdateResponse {
  message: string;
  updated: number;
  errors?: string[];
}

// Scan history types
export interface Scan {
  uuid: string;
  project_uuid?: string;
  name?: string;
  status: string;
  scan_source?: string;
  scan_mode?: string;
  modules?: string;
  total_findings: number;
  processed_count: number;
  started_at: string;
  finished_at?: string;
  created_at: string;
}

export interface ScansQueryParams {
  limit?: number;
  offset?: number;
}

export interface ScanRecordsRequest {
  record_uuids: string[];
  enable_modules?: string[];
}

export interface DeleteFindingsRequest {
  severity?: string;
  module_name?: string;
  scan_uuid?: string;
  domain?: string;
  date_from?: string;
  date_to?: string;
  search?: string;
  dry_run?: boolean;
}

export interface DeleteRecordsRequest {
  domain?: string;
  method?: string;
  path?: string;
  source?: string;
  status_code?: string;
  date_from?: string;
  date_to?: string;
  search?: string;
  dry_run?: boolean;
}

export interface DeleteResponse {
  deleted: number;
  dry_run: boolean;
  message: string;
}

export interface DeleteScanResponse {
  project_uuid?: string;
  message: string;
  uuid: string;
}

export interface DeleteOASTInteractionResponse {
  message: string;
  id: number;
}

export interface SourceRepo {
  id: number;
  hostname: string;
  name: string;
  root_path: string;
  repo_type: string;
  language: string;
  framework: string;
  endpoints: string[];
  route_params: string[];
  sinks: string[];
  tags: string[];
  third_party_scan_status: string;
  third_party_scan_at: string;
  scan_uuid?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface SourceReposQueryParams {
  limit?: number;
  offset?: number;
  hostname?: string;
  search?: string;
  sort?: string;
  order?: string;
}

export interface DeleteSourceRepoResponse {
  message: string;
  id: number;
}

export interface DeleteFindingResponse {
  message: string;
  id: number;
}

export interface DeleteHttpRecordResponse {
  message: string;
  uuid: string;
}

// Scan request types
export interface ScanURLRequest {
  url: string;
  method?: string;
  body?: string;
  headers?: Record<string, string>;
  modules?: string;
  no_passive?: boolean;
}

export interface ScanRequestRequest {
  raw_request: string; // base64-encoded
  target_url?: string;
  modules?: string;
  no_passive?: boolean;
}

// POST /api/scans/run
export interface RunScanRequest {
  targets?: string[];
  urls?: string[];
  dry_run?: boolean;
  strategy?: string;
  only?: string;
  skip?: string[];
  modules?: string[];
  module_tags?: string[];
  concurrency?: number;
  timeout?: string;
  max_per_host?: number;
  rate_limit?: number;
  scanning_max_duration?: string;
  scope_origin?: string;
  heuristics_check?: string;
  headers?: Record<string, string>;
  scanning_profile?: string;
  repo_path?: string;
  repo_url?: string;
}

// POST /api/scan-all-records
export interface ScanAllRecordsRequest {
  hostname?: string;
  methods?: string[];
  path?: string;
  status_codes?: number[];
  source?: string;
  search?: string;
  min_risk_score?: number;
  remark?: string;
  force?: boolean;
  dry_run?: boolean;
  modules?: string[];
  module_tags?: string[];
  concurrency?: number;
  timeout?: string;
  max_per_host?: number;
  rate_limit?: number;
  scanning_max_duration?: string;
  heuristics_check?: string;
  headers?: Record<string, string>;
  scanning_profile?: string;
}

// POST /api/repos/upload
export interface RepoUploadResponse {
  repo_path: string;
  message: string;
}

// Ingest types
export interface IngestRequest {
  input_mode: string;
  url?: string;
  content?: string;
  content_base64?: string;
  http_request_base64?: string;
  http_response_base64?: string;
}

export interface IngestResponse {
  imported: number;
  skipped: number;
  errors: number;
  message: string;
}

// Extension types
export interface Extension {
  id: string;
  name: string;
  language: string;
  type: string;
  severity: string;
  confidence: string;
  scan_types: string[];
  tags?: string[];
  description: string;
  file: string;
  file_name: string;
  raw_content?: string;
}

export interface ExtensionsResponse {
  extensions: Extension[];
  total: number;
  extensions_enabled: number;
}

export interface ExtensionEditResponse {
  message: string;
  file: string;
  file_name: string;
}

export interface ExtensionApiFunction {
  category: string;
  namespace: string;
  name: string;
  full_name: string;
  signature: string;
  returns: string;
  description: string;
  example?: string;
}

export interface ExtensionDocsResponse {
  functions: ExtensionApiFunction[];
  total: number;
  namespaces: string[];
}

// Agent types

// POST /api/agent/run/query
export interface AgentQueryRequest {
  agent?: string;
  prompt_template?: string;
  prompt_file?: string;
  prompt?: string;
  repo_path?: string;
  files?: string[];
  append?: string;
  source?: string;
  scan_uuid?: string;
  stream?: boolean;
}

// POST /api/agent/run/autopilot
export interface AgentAutopilotRequest {
  target: string;
  agent?: string;
  repo_path?: string;
  files?: string[];
  focus?: string;
  system_prompt?: string;
  timeout?: string;
  max_commands?: number;
  dry_run?: boolean;
  stream?: boolean;
  scan_uuid?: string;
}

// POST /api/agent/run/pipeline
export interface AgentPipelineRequest {
  target: string;
  agent?: string;
  repo_path?: string;
  files?: string[];
  focus?: string;
  profile?: string;
  timeout?: string;
  max_rescan_rounds?: number;
  skip_phases?: string[];
  start_from?: string;
  dry_run?: boolean;
  stream?: boolean;
  scan_uuid?: string;
  project_uuid?: string;
}

// POST /api/agent/chat/completions
export interface ChatCompletionRequest {
  model: string;
  messages: { role: string; content: string }[];
}

export interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: {
    index: number;
    message: { role: string; content: string };
    finish_reason: string;
  }[];
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

// POST /api/agent/run/swarm
export interface AgentSwarmRequest {
  input?: string;
  inputs?: string[];
  http_request_base64?: string;
  http_response_base64?: string;
  url?: string;
  vuln_type?: string;
  module_names?: string[];
  scanning_phase?: string;
  max_iterations?: number;
  agent?: string;
  source?: string;
  project_uuid?: string;
  scan_uuid?: string;
  stream?: boolean;
  timeout?: string;
  dry_run?: boolean;
}

/** @deprecated Use AgentQueryRequest instead */
export interface AgentRunRequest {
  agent_name?: string;
  prompt_template?: string;
  prompt?: string;
  repo_path?: string;
  files?: string[];
  append?: string;
  source?: string;
  scan_uuid?: string;
  stream?: boolean;
}

export interface AgentRunResponse {
  run_id: string;
  status: string;
  message: string;
}

export interface AgentRunStatusResponse {
  run_id: string;
  status: string;
  agent_name: string;
  template_id?: string;
  mode?: string;
  current_phase?: string;
  phases_run?: string[];
  finding_count: number;
  record_count: number;
  saved_count: number;
  error?: string;
  completed_at?: string;
  result?: AgentResult;
  pipeline_result?: Record<string, unknown>;
}

export interface AgentResult {
  agent_name: string;
  raw_output: string;
  findings?: AgentFinding[];
  http_records?: AgentHTTPRecord[];
  saved_count: number;
  skipped_count: number;
}

export interface AgentFinding {
  title: string;
  description: string;
  severity: string;
  confidence?: string;
  file?: string;
  line?: number;
  snippet?: string;
  cwe?: string;
  tags?: string[];
}

export interface AgentHTTPRecord {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  notes?: string;
}

export interface AgentRunListResponse {
  runs: AgentRunStatusResponse[];
  total: number;
}

// Agent session types (GET /api/agent/sessions)
export interface AgentSession {
  uuid: string;
  mode: string;
  status: string;
  agent_name: string;
  template_id?: string;
  target_url?: string;
  input_type?: string;
  current_phase?: string;
  phases_run?: string[];
  finding_count: number;
  record_count: number;
  saved_count: number;
  duration_ms: number;
  started_at: string;
  completed_at?: string;
  created_at: string;
}

// GET /api/agent/sessions/:id
export interface AgentSessionDetail extends AgentSession {
  input_raw?: string;
  module_names?: string[];
  session_id?: string;
  prompt_sent?: string;
  agent_raw_output?: string;
  attack_plan?: string;
  triage_result?: string;
  result_json?: string;
}

export interface AgentSessionsQueryParams {
  mode?: string;
  limit?: number;
  offset?: number;
}

// GitHub integration types
export interface GitHubConnectionStatus {
  configured: boolean;
  connected: boolean;
  github_login?: string;
  connected_at?: string;
}

export interface GitHubRepo {
  id: number;
  full_name: string;
  name: string;
  owner: string;
  private: boolean;
  default_branch: string;
  language: string | null;
  description: string | null;
  html_url: string;
  clone_url: string;
  updated_at: string;
}

export interface GitHubBranch {
  name: string;
}

export interface GitHubCloneRequest {
  clone_url: string;
  branch?: string;
  hostname?: string;
}

export interface GitHubCloneResponse {
  path: string;
  source_repo_id?: number;
}

// Project types
export interface Project {
  uuid: string;
  name: string;
  description: string;
  owner_uuid: string;
  created_at: string;
  updated_at: string;
}

export interface CreateProjectRequest {
  name: string;
  description?: string;
  owner_uuid?: string;
}

export interface UpdateProjectRequest {
  name?: string;
  description?: string;
  owner_uuid?: string;
}

export interface DeleteProjectResponse {
  message: string;
  uuid: string;
}

// Scan log types
export interface ScanLog {
  id: number;
  scan_uuid: string;
  level: string;
  phase?: string;
  message: string;
  metadata?: string;
  created_at: string;
}

export interface ScanLogsResponse {
  project_uuid?: string;
  logs: ScanLog[];
  total: number;
}

export interface ScanLogsQueryParams {
  limit?: number;
  offset?: number;
  level?: string;
  phase?: string;
}
