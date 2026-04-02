package server

import (
	"time"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// ServerConfig holds configuration for the API server.
type ServerConfig struct {
	ServiceAddr          string   // e.g. "0.0.0.0:9002"
	IngestProxyAddr      string   // e.g. "0.0.0.0:9003" (empty = disabled)
	APIKeys              []string // Valid Bearer tokens
	NoAuth               bool     // If true, skip auth
	ScanOnReceive        bool
	DisableFetchResponse bool
	Concurrency          int // Worker concurrency for API-triggered scans
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	ShutdownTimeout      time.Duration
	CORSAllowedOrigins   string
	UserStore            *UserStore // File-based user store (nil = legacy auth only)
	ScanQueueCapacity    int        // 0 = reject with 409 when busy (default), >0 = per-project queue depth
	NoAgent              bool       // If true, disable all agent endpoints and warm sessions
	ViewOnly             bool       // If true, only serve GET/viewer routes (no scanning, ingestion, or agent)
	EnableMetrics        bool       // Enable Prometheus /metrics endpoint
	Debug                bool       // Log raw request body, query params, and headers
	Version              string     // Injected version string for /server-info
	Author               string
	Commit               string
	BuildTime            string
}

// DefaultServerConfig returns sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ServiceAddr:     ":9002",
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    60 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		CORSAllowedOrigins: "",
	}
}

// --- Auth Types ---

// LoginRequest is the request body for POST /api/auth/login.
type LoginRequest struct {
	Username   string `json:"username"`
	AccessCode string `json:"access_code"`
}

// LoginResponse is the response for POST /api/auth/login.
type LoginResponse struct {
	Token string    `json:"token"`
	User  LoginUser `json:"user"`
}

// LoginUser is the user info returned in a login response.
type LoginUser struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// --- Request / Response Types ---

// RunScanRequest is the request body for POST /api/scans/run.
// This route only accepts target URLs — use /api/scan-all-records to scan DB records.
type RunScanRequest struct {
	// Target URLs to scan (like -t). At least one target or url is required.
	Targets []string `json:"targets,omitempty"`
	// URLs is an alias for Targets.
	URLs []string `json:"urls,omitempty"`

	// DryRun validates params and creates scan record but does not launch the runner
	DryRun bool `json:"dry_run"`

	// Strategy preset: lite, balanced, deep, whitebox
	Strategy string `json:"strategy,omitempty"`
	// Single phase isolation (like --only)
	Only string `json:"only,omitempty"`
	// Skip specific phases (like --skip)
	Skip []string `json:"skip,omitempty"`

	// Module IDs with fuzzy match (like -m)
	Modules []string `json:"modules,omitempty"`
	// Filter modules by tag (like --module-tag)
	ModuleTags []string `json:"module_tags,omitempty"`

	// Performance tuning
	Concurrency int    `json:"concurrency,omitempty"`
	Timeout     string `json:"timeout,omitempty"` // Go duration e.g. "30s"
	MaxPerHost  int    `json:"max_per_host,omitempty"`
	RateLimit   int    `json:"rate_limit,omitempty"`

	// Max scan duration (like --scanning-max-duration)
	ScanningMaxDuration string `json:"scanning_max_duration,omitempty"`

	// Scope origin mode: all, relaxed, balanced, strict
	ScopeOrigin string `json:"scope_origin,omitempty"`

	// Heuristics check level: none, basic, advanced
	HeuristicsCheck string `json:"heuristics_check,omitempty"`

	// Custom HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// Scanning profile name or path
	ScanningProfile string `json:"scanning_profile,omitempty"`

	// SAST repo fields (like --repo / --repo-url)
	RepoPath string `json:"repo_path,omitempty"` // Local path to source repo for SAST scan
	RepoURL  string `json:"repo_url,omitempty"`  // Git URL to clone for SAST scan
}

// ScanAllRecordsRequest is the request body for POST /api/scan-all-records.
// Scans existing HTTP records from the database with optional filtering.
type ScanAllRecordsRequest struct {
	// Record selection filters (all optional — omit all to scan everything)
	Hostname   string   `json:"hostname,omitempty"`     // hostname filter (supports * wildcards)
	Methods    []string `json:"methods,omitempty"`      // HTTP methods filter
	Path       string   `json:"path,omitempty"`         // path filter (supports * wildcards)
	StatusCodes []int   `json:"status_codes,omitempty"` // status code filter
	Source     string   `json:"source,omitempty"`       // record source filter
	Search     string   `json:"search,omitempty"`       // search across URL/path
	MinRiskScore int    `json:"min_risk_score,omitempty"` // minimum risk score
	Remark     string   `json:"remark,omitempty"`       // remark substring filter

	// Force full rescan (ignore cursor, scan all matching records)
	Force bool `json:"force"`

	// DryRun validates params, counts matching records, but does not launch the runner
	DryRun bool `json:"dry_run"`

	// Module IDs with fuzzy match (like -m)
	Modules []string `json:"modules,omitempty"`
	// Filter modules by tag (like --module-tag)
	ModuleTags []string `json:"module_tags,omitempty"`

	// Performance tuning
	Concurrency int    `json:"concurrency,omitempty"`
	Timeout     string `json:"timeout,omitempty"` // Go duration e.g. "30s"
	MaxPerHost  int    `json:"max_per_host,omitempty"`
	RateLimit   int    `json:"rate_limit,omitempty"`

	// Max scan duration (like --scanning-max-duration)
	ScanningMaxDuration string `json:"scanning_max_duration,omitempty"`

	// Heuristics check level: none, basic, advanced
	HeuristicsCheck string `json:"heuristics_check,omitempty"`

	// Custom HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// Scanning profile name or path
	ScanningProfile string `json:"scanning_profile,omitempty"`
}

// ScanURLRequest is the request body for POST /api/scan-url.
type ScanURLRequest struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`     // default GET
	Body      string            `json:"body"`
	Headers   map[string]string `json:"headers"`
	Modules   string            `json:"modules"`    // comma-separated module IDs
	NoPassive bool              `json:"no_passive"`
}

// ScanRequestRequest is the request body for POST /api/scan-request.
type ScanRequestRequest struct {
	RawRequest string `json:"raw_request"` // base64-encoded raw HTTP request
	TargetURL  string `json:"target_url"`  // scheme://host override
	Modules    string `json:"modules"`     // comma-separated module IDs
	NoPassive  bool   `json:"no_passive"`
}

// ScanResponse is the response for POST /api/scans/run.
type ScanResponse struct {
	ProjectUUID   string `json:"project_uuid,omitempty"`
	ScanID        string `json:"scan_id"`
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	RecordsToScan int64  `json:"records_to_scan,omitempty"`
	TargetsCount  int    `json:"targets_count,omitempty"`
	ScanMode      string `json:"scan_mode,omitempty"` // "target", "full", "incremental", "sast"
	RepoPath      string `json:"repo_path,omitempty"`
}

// RepoUploadResponse is the response for POST /api/repos/upload.
type RepoUploadResponse struct {
	RepoID   string `json:"repo_id"`
	RepoPath string `json:"repo_path"`
	Message  string `json:"message"`
}

// RepoDeleteResponse is the response for DELETE /api/repos/:id.
type RepoDeleteResponse struct {
	RepoID  string `json:"repo_id"`
	Message string `json:"message"`
}

// ScanStatusResponse is the response for GET /api/scan/status.
type ScanStatusResponse struct {
	ProjectUUID string `json:"project_uuid,omitempty"`
	ScanID      string `json:"scan_id,omitempty"`
	Running     bool   `json:"running"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
}

// HealthResponse is the response for GET /health.
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// ErrorResponse is returned for error conditions.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// IngestHTTPRequest is the request body for POST /api/ingest-http.
type IngestHTTPRequest struct {
	InputMode          string `json:"input_mode"`
	URL                string `json:"url,omitempty"`
	Content            string `json:"content,omitempty"`
	ContentBase64      string `json:"content_base64,omitempty"`
	HTTPRequestBase64  string `json:"http_request_base64,omitempty"`
	HTTPResponseBase64 string `json:"http_response_base64,omitempty"`
}

// IngestHTTPResponse is the response for POST /api/ingest-http.
type IngestHTTPResponse struct {
	ProjectUUID string   `json:"project_uuid,omitempty"`
	Imported    int      `json:"imported"`
	Skipped     int      `json:"skipped,omitempty"`
	Errors      []string `json:"errors,omitempty"`
	Message     string   `json:"message"`
}

// PaginatedResponse wraps paginated results.
type PaginatedResponse struct {
	ProjectUUID string      `json:"project_uuid,omitempty"`
	Data        interface{} `json:"data"`
	Total       int64       `json:"total"`
	Limit       int         `json:"limit"`
	Offset      int         `json:"offset"`
	HasMore     bool        `json:"has_more"`
}

// ModuleInfo is the response type for module listing.
type ModuleInfo struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	ShortDescription     string   `json:"short_description"`
	ConfirmationCriteria string   `json:"confirmation_criteria"`
	Severity             string   `json:"severity"`
	Confidence           string   `json:"confidence"`
	ScanScope            []string `json:"scan_scope"`
	Tags                 []string `json:"tags"`
	Type                 string   `json:"type"` // "active" or "passive"
}

// AppInfoResponse is the response for GET /api/info.
type AppInfoResponse struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Author    string `json:"author"`
	Docs      string `json:"docs"`
	BuildTime string `json:"build_time,omitempty"`
	Commit    string `json:"commit,omitempty"`
}

// ServerInfoResponse is the response for GET /server-info.
type ServerInfoResponse struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Author        string `json:"author"`
	Docs          string `json:"docs"`
	BuildTime     string `json:"build_time,omitempty"`
	Commit        string `json:"commit,omitempty"`
	Uptime        string `json:"uptime"`
	ServiceAddr   string `json:"service_addr"`
	ProxyAddr     string `json:"proxy_addr,omitempty"`
	DBDriver      string `json:"db_driver,omitempty"`
	QueueDepth    int64  `json:"queue_depth"`
	TotalRecords  int64  `json:"total_records"`
	TotalFindings int64  `json:"total_findings"`
}

// StatsResponse is the response for GET /api/stats.
type StatsResponse struct {
	ProjectUUID string          `json:"project_uuid,omitempty"`
	HTTPRecords HTTPRecordStats `json:"http_records"`
	Modules     ModuleStats     `json:"modules"`
	Findings    FindingStats    `json:"findings"`
}

// HTTPRecordStats holds HTTP record counts.
type HTTPRecordStats struct {
	Total int64 `json:"total"`
}

// ModuleStats holds module counts.
type ModuleStats struct {
	Active  ModuleCount `json:"active"`
	Passive ModuleCount `json:"passive"`
}

// ModuleCount holds total and enabled counts for a module type.
type ModuleCount struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
}

// FindingStats holds finding counts.
type FindingStats struct {
	Total      int64            `json:"total"`
	BySeverity map[string]int64 `json:"by_severity"`
}

// ScopeUpdateResponse is the response for POST /api/scope.
type ScopeUpdateResponse struct {
	Message string      `json:"message"`
	Scope   interface{} `json:"scope"`
}

// ConfigListResponse is the response for GET /api/config.
type ConfigListResponse struct {
	Entries []ConfigEntryResponse `json:"entries"`
	Total   int                   `json:"total"`
}

// ConfigEntryResponse is a single config entry in API responses.
type ConfigEntryResponse struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

// ConfigUpdateRequest is the request body for POST /api/config.
// Keys are dot-notation paths, values are string representations.
type ConfigUpdateRequest map[string]string

// ProjectStats holds aggregated statistics for a project.
type ProjectStats struct {
	HTTPRecords      ProjectHTTPRecordStats `json:"http_records"`
	Findings         ProjectFindingStats    `json:"findings"`
	Scans            int64                  `json:"scans"`
	AgentRuns        int64                  `json:"agent_runs"`
	SourceRepos      int64                  `json:"source_repos"`
	OASTInteractions int64                  `json:"oast_interactions"`
}

// ProjectHTTPRecordStats holds HTTP record counts with status breakdown.
type ProjectHTTPRecordStats struct {
	Total     int64 `json:"total"`
	Success   int64 `json:"success"`    // 2xx
	Redirect  int64 `json:"redirect"`   // 3xx
	ClientErr int64 `json:"client_err"` // 4xx
	ServerErr int64 `json:"server_err"` // 5xx
}

// ProjectFindingStats holds finding counts with severity breakdown.
type ProjectFindingStats struct {
	Total    int64            `json:"total"`
	Critical int64            `json:"critical"`
	High     int64            `json:"high"`
	Medium   int64            `json:"medium"`
	Low      int64            `json:"low"`
	Info     int64            `json:"info"`
}

// ProjectWithStats wraps a Project with its aggregated stats.
type ProjectWithStats struct {
	*database.Project
	Stats ProjectStats `json:"stats"`
}

// ProjectRequest is the request body for POST/PUT /api/projects.
type ProjectRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	OwnerUUID      string   `json:"owner_uuid"`
	AllowedDomains []string `json:"allowed_domains"`
	AllowedEmails  []string `json:"allowed_emails"`
}

// SourceRepoRequest is the request body for POST/PUT /api/source-repos.
type SourceRepoRequest struct {
	Hostname    string                 `json:"hostname"`
	Name        string                 `json:"name"`
	RootPath    string                 `json:"root_path"`
	RepoType    string                 `json:"repo_type,omitempty"`
	Language    string                 `json:"language,omitempty"`
	Framework   string                 `json:"framework,omitempty"`
	ScanUUID    string                 `json:"scan_uuid,omitempty"`
	Endpoints   []string               `json:"endpoints,omitempty"`
	RouteParams []string               `json:"route_params,omitempty"`
	Sinks       []string               `json:"sinks,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ConfigUpdateResponse is the response for POST /api/config.
type ConfigUpdateResponse struct {
	Message string                `json:"message"`
	Updated []ConfigEntryResponse `json:"updated"`
	Errors  []string              `json:"errors,omitempty"`
}

// AgentRunRequest is the request body for POST /api/agent/run/query.
type AgentRunRequest struct {
	Agent          string   `json:"agent,omitempty"`
	PromptTemplate string   `json:"prompt_template,omitempty"`
	PromptFile     string   `json:"prompt_file,omitempty"`
	Prompt         string   `json:"prompt,omitempty"`
	SourcePath     string   `json:"source,omitempty"`          // path to source code
	Files          []string `json:"files,omitempty"`
	Append         string   `json:"append,omitempty"`
	Instruction    string   `json:"instruction,omitempty"`     // custom instruction appended to the prompt
	Source         string   `json:"source_label,omitempty"`
	ScanUUID       string   `json:"scan_uuid,omitempty"`
	Stream         bool     `json:"stream,omitempty"`
}

// AgentAutopilotRequest is the request body for POST /api/agent/run/autopilot.
type AgentAutopilotRequest struct {
	Prompt      string   `json:"prompt,omitempty"`              // natural language scan prompt (parsed into target/source/focus when explicit fields are empty)
	Target      string   `json:"target,omitempty"`              // target URL (derived from input if not set)
	Input       string   `json:"input,omitempty"`               // raw input (curl, raw HTTP, Burp XML, URL) — target extracted automatically
	Agent       string   `json:"agent,omitempty"`               // agent backend name
	SourcePath  string   `json:"source,omitempty"`              // path to application source code
	Files       []string `json:"files,omitempty"`               // specific files to include
	Focus       string   `json:"focus,omitempty"`               // focus area hint
	Instruction string   `json:"instruction,omitempty"`         // custom instruction appended to the prompt
	Timeout     string   `json:"timeout,omitempty"`             // Go duration string, default "6h"
	MaxCommands int      `json:"max_commands,omitempty"`        // max CLI commands, default 100
	DryRun      bool     `json:"dry_run,omitempty"`             // render prompt without executing
	Stream      bool     `json:"stream,omitempty"`              // enable SSE streaming
	ScanUUID    string   `json:"scan_uuid,omitempty"`           // optional scan UUID
	ProjectUUID string   `json:"project_uuid,omitempty"`        // project UUID for data scoping
	Archon      string   `json:"archon,omitempty"`              // DEPRECATED: use no_archon + archon_mode instead. Legacy values: "lite", "scan", "deep", "off"
	NoArchon    bool     `json:"no_archon,omitempty"`           // disable automatic archon-audit (enabled by default when source is set)
	ArchonMode  string   `json:"archon_mode,omitempty"`         // archon audit mode: "lite" (default), "scan", "deep"
	Diff        string   `json:"diff,omitempty"`                // focus on changed code: PR URL, git ref range, or HEAD~N
	LastCommits int      `json:"last_commits,omitempty"`        // focus on last N commits (shorthand for diff HEAD~N)
}

// ResolvedNoArchon returns true when archon should be disabled, handling backward
// compatibility with the legacy Archon field.
func (r AgentAutopilotRequest) ResolvedNoArchon() bool {
	if r.Archon == "off" {
		return true
	}
	return r.NoArchon
}

// ResolvedArchonMode returns the effective archon mode, handling backward
// compatibility with the legacy Archon field.
func (r AgentAutopilotRequest) ResolvedArchonMode() string {
	if r.ArchonMode != "" {
		return r.ArchonMode
	}
	// Legacy: "archon": "deep" means mode=deep
	if r.Archon != "" && r.Archon != "off" {
		return r.Archon
	}
	return "lite"
}

// AgentSwarmRequest is the request body for POST /api/agent/run/swarm.
type AgentSwarmRequest struct {
	// Natural language prompt (parsed into structured fields when explicit fields are empty)
	Prompt string `json:"prompt,omitempty"`

	// Inputs
	Input              string   `json:"input,omitempty"`                // single input (URL, curl, raw HTTP, Burp XML, record UUID)
	Inputs             []string `json:"inputs,omitempty"`               // multiple inputs (for auth flows)
	HTTPRequestBase64  string   `json:"http_request_base64,omitempty"`  // base64-encoded raw HTTP request (ingested into DB, UUID used as input)
	HTTPResponseBase64 string   `json:"http_response_base64,omitempty"` // base64-encoded raw HTTP response (attached to the request above)
	URL                string   `json:"url,omitempty"`                  // optional URL hint for parsing the base64 request

	// Source analysis
	SourcePath         string   `json:"source_path,omitempty"`          // path to source code for route discovery (triggers source analysis phase)
	Files              []string `json:"files,omitempty"`                // specific source files to include (relative to source_path)
	SourceAnalysisOnly bool     `json:"source_analysis_only,omitempty"` // run only source analysis phase and exit
	SkipSAST           bool     `json:"skip_sast,omitempty"`            // skip native SAST tools during source analysis

	// Scanning parameters
	VulnType           string   `json:"vuln_type,omitempty"`            // vulnerability type focus
	Focus              string   `json:"focus,omitempty"`                // broad focus area hint (e.g. "API injection", "auth bypass")
	Instruction        string   `json:"instruction,omitempty"`          // custom instruction appended to agent prompts
	ModuleNames        []string `json:"module_names,omitempty"`         // explicit module IDs
	OnlyPhase          string   `json:"only_phase,omitempty"`           // isolate a single phase
	SkipPhases         []string `json:"skip_phases,omitempty"`          // skip specific phases
	StartFrom          string   `json:"start_from,omitempty"`           // resume from a specific phase
	MaxIterations      int      `json:"max_iterations,omitempty"`       // max triage-rescan rounds (default 3)
	Discover           bool     `json:"discover,omitempty"`             // run discovery+spidering before master agent planning
	CodeAudit          bool     `json:"code_audit,omitempty"`           // enable AI security code audit phase
	Triage             bool     `json:"triage,omitempty"`               // enable AI triage and rescan phases (disabled by default)
	Profile            string   `json:"profile,omitempty"`              // scanning profile name (e.g. "light", "thorough")

	// Agent selection
	Agent              string   `json:"agent,omitempty"`                // agent backend name

	// Concurrency tuning
	BatchConcurrency    int           `json:"batch_concurrency,omitempty"`     // max parallel master agent batches (0 = auto)
	MaxMasterRetries    int           `json:"max_master_retries,omitempty"`    // max master agent retries on parse failure (0 = default 3)
	SAMaxConcurrency    int           `json:"sa_max_concurrency,omitempty"`    // max parallel source analysis sub-agents (0 = default 3)
	MaxPlanRecords      int           `json:"max_plan_records,omitempty"`      // max records sent to plan agent (0 = default 10)
	MasterBatchSize     int    `json:"master_batch_size,omitempty"`     // max records per master agent batch (0 = default 5)
	ProbeConcurrency    int    `json:"probe_concurrency,omitempty"`     // max parallel probe requests (0 = default 10)
	ProbeTimeout        string `json:"probe_timeout,omitempty"`         // per-request probe timeout as Go duration e.g. "10s" (0 = default 10s)
	MaxProbeBodySize    int    `json:"max_probe_body,omitempty"`        // max response body size in bytes during probing (0 = default 2MB)

	// Output control
	DryRun      bool   `json:"dry_run,omitempty"`      // render prompts without executing
	ShowPrompt  bool   `json:"show_prompt,omitempty"`   // include rendered prompts in output
	Stream      bool   `json:"stream,omitempty"`        // enable SSE streaming
	Timeout     string `json:"timeout,omitempty"`       // Go duration string

	// Project/scan scoping
	ProjectUUID string `json:"project_uuid,omitempty"` // optional project UUID
	ScanUUID    string `json:"scan_uuid,omitempty"`    // optional scan UUID

	// Background archon-audit
	Archon string `json:"archon,omitempty"` // run background archon-audit: "lite" (3-phase), "scan" (6-phase), "deep" (11-phase), "off" to disable

	// Diff context
	Diff        string `json:"diff,omitempty"`          // focus on changed code: PR URL, git ref range, or HEAD~N
	LastCommits int    `json:"last_commits,omitempty"`  // focus on last N commits (shorthand for diff HEAD~N)
}

// ResolvedNoArchon returns true when archon should be disabled.
// Swarm uses opt-in archon: empty string means disabled.
func (r AgentSwarmRequest) ResolvedNoArchon() bool {
	return r.Archon == "" || r.Archon == "off"
}

// ResolvedArchonMode returns the effective archon mode.
// Returns empty string when archon is disabled.
func (r AgentSwarmRequest) ResolvedArchonMode() string {
	if r.Archon == "" || r.Archon == "off" {
		return ""
	}
	return r.Archon
}

// EffectiveInputs returns all inputs as a slice, merging Input and Inputs.
func (r AgentSwarmRequest) EffectiveInputs() []string {
	var result []string
	if r.Input != "" {
		result = append(result, r.Input)
	}
	result = append(result, r.Inputs...)
	return result
}

// AgentRunResponse is the response for POST /api/agent/run/*.
type AgentRunResponse struct {
	RunID   string `json:"run_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// ChatCompletionRequest is an OpenAI-compatible chat completion request.
type ChatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
}

// ChatMessage represents a single message in a chat completion request/response.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionResponse is an OpenAI-compatible chat completion response.
type ChatCompletionResponse struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   *ChatUsage  `json:"usage,omitempty"`
}

// ChatChoice represents a single completion choice.
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ChatUsage reports token usage for a chat completion.
type ChatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ExtensionInfo is the metadata summary of a loaded extension, returned in list responses.
type ExtensionInfo struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Language             string   `json:"language"` // "js" or "yaml"
	Type                 string   `json:"type"`     // "active", "passive", "pre_hook", "post_hook"
	Severity             string   `json:"severity,omitempty"`
	Confidence           string   `json:"confidence,omitempty"` // tentative, firm, certain
	ScanTypes            []string `json:"scan_types,omitempty"`
	Tags                 []string `json:"tags,omitempty"`
	Scope                string   `json:"scope,omitempty"`
	Description          string   `json:"description,omitempty"`
	ConfirmationCriteria string   `json:"confirmation_criteria,omitempty"`
	File                 string   `json:"file"`
	FileName             string   `json:"file_name"`
}

// ExtensionDetail is the full extension response including raw file content,
// returned by GET /api/extensions/:name.
type ExtensionDetail struct {
	ExtensionInfo
	RawContent string `json:"raw_content"`
}

// ExtensionEditRequest is the request body for PUT /api/extensions/:name.
type ExtensionEditRequest struct {
	Content string `json:"content"`
}

// ExtensionAPIFunction is a single JS utility function entry.
type ExtensionAPIFunction struct {
	Category    string `json:"category"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Signature   string `json:"signature"`
	Returns     string `json:"returns"`
	Description string `json:"description"`
	Example     string `json:"example,omitempty"`
}

// ScanRecordsRequest is the request body for POST /api/scan-records.
type ScanRecordsRequest struct {
	RecordUUIDs   []string `json:"record_uuids"`
	EnableModules []string `json:"enable_modules,omitempty"`
}

// AgentRunStatusResponse is the response for GET /api/agent/status/:id and GET /api/agent/status/list.
type AgentRunStatusResponse struct {
	RunID        string       `json:"run_id"`
	Mode         string       `json:"mode"`   // "query", "autopilot", "pipeline"
	Status       string       `json:"status"` // "running", "completed", "failed"
	AgentName    string       `json:"agent_name,omitempty"`
	TemplateID   string       `json:"template_id,omitempty"`
	FindingCount int          `json:"finding_count,omitempty"`
	RecordCount  int          `json:"record_count,omitempty"`
	SavedCount   int          `json:"saved_count,omitempty"`
	Error        string       `json:"error,omitempty"`
	CompletedAt  *time.Time   `json:"completed_at,omitempty"`
	Result       *agent.Result `json:"result,omitempty"`

	// Phase progress fields
	CurrentPhase string   `json:"current_phase,omitempty"`
	PhasesRun    []string `json:"phases_run,omitempty"`

	// Swarm/pipeline result
	SwarmResult *agent.SwarmResult `json:"swarm_result,omitempty"`
}

// AgentSessionSummary is a lightweight representation of an agent run for list responses.
type AgentSessionSummary struct {
	UUID         string   `json:"uuid"`
	Mode         string   `json:"mode"`
	Status       string   `json:"status"`
	AgentName    string   `json:"agent_name,omitempty"`
	TemplateID   string   `json:"template_id,omitempty"`
	TargetURL    string   `json:"target_url,omitempty"`
	VulnType     string   `json:"vuln_type,omitempty"`
	InputType    string   `json:"input_type,omitempty"`
	CurrentPhase string   `json:"current_phase,omitempty"`
	PhasesRun    []string `json:"phases_run,omitempty"`
	FindingCount int      `json:"finding_count,omitempty"`
	RecordCount  int      `json:"record_count,omitempty"`
	SavedCount   int      `json:"saved_count,omitempty"`
	ErrorMessage string   `json:"error_message,omitempty"`
	DurationMs   int64    `json:"duration_ms,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AgentSessionDetail is the full representation of an agent run including debug fields.
type AgentSessionDetail struct {
	AgentSessionSummary
	InputRaw       string   `json:"input_raw,omitempty"`
	ModuleNames    []string `json:"module_names,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
	PromptSent     string   `json:"prompt_sent,omitempty"`
	AgentRawOutput string   `json:"agent_raw_output,omitempty"`
	AttackPlan     string   `json:"attack_plan,omitempty"`
	TriageResult   string   `json:"triage_result,omitempty"`
	ResultJSON     string   `json:"result_json,omitempty"`
}
