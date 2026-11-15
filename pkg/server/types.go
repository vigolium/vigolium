package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// ServerConfig holds configuration for the API server.
type ServerConfig struct {
	ServiceAddr          string     // e.g. "0.0.0.0:9002"
	BurpBridgeURL        string     // optional loopback Burp listener merged into GET /api/http-records
	IngestProxyAddr      string     // e.g. "0.0.0.0:9003" (empty = disabled)
	IngestProxyMITM      bool       // Intercept HTTPS via a generated CA (records + scans TLS traffic)
	IngestProxyInsecure  bool       // Skip upstream TLS verification when intercepting HTTPS
	IngestProxyCADir     string     // Directory holding the MITM CA (empty = ~/.vigolium/ca)
	IngestProxyAuth      *ProxyAuth // Token and/or client allow-list for the ingest proxy (nil = open; loopback only)
	APIKeys              []string   // Valid Bearer tokens
	NoAuth               bool       // If true, skip auth
	ScanOnReceive        bool
	DisableFetchResponse bool
	Concurrency          int // Worker concurrency for API-triggered scans
	ReadTimeout          time.Duration
	// WriteTimeout bounds how long the whole response may take to write. It must
	// be 0 (unlimited) for the SSE agent/audit streams this server hosts — a
	// finite cap severs a stream that outlives it. Non-streaming write protection
	// is provided by IdleTimeout and handler-level deadlines instead. 0 = default
	// (unlimited).
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	// MaxUploadBytes is the framework-level request body ceiling (Fiber BodyLimit).
	// It must exceed the ordinary DefaultBodyLimitMiddleware cap so the large-upload
	// routes (/api/import, /api/storage/upload-source) aren't rejected by the
	// framework before the route exemption runs. 0 = default (512 MiB).
	MaxUploadBytes     int
	CORSAllowedOrigins string
	UserStore          *UserStore    // File-based user store (nil = legacy auth only)
	ScanQueueCapacity  int           // 0 = reject with 409 when busy (default), >0 = per-project queue depth
	NoAgent            bool          // If true, disable all agent endpoints and warm sessions
	ViewOnly           bool          // If true, only serve GET/viewer routes (no scanning, ingestion, or agent)
	DemoOnly           bool          // If true, expose only the demo allowlist (subset of GET endpoints)
	License            string        // Optional license tag surfaced in /server-info (configured in server.license)
	EnableMetrics      bool          // Enable Prometheus /metrics endpoint
	NoSwagger          bool          // If true, disable Swagger UI and spec endpoint
	Debug              bool          // Log raw request body, query params, and headers
	AgentHeavyMax      int           // Max concurrent heavy agent runs (autopilot/swarm); 0 = default 5
	AgentLightMax      int           // Max concurrent light agent runs (query/chat); 0 = default 10
	AgentQueueTimeout  time.Duration // Max wait time when all agent slots busy; 0 = default 30s
	// AgentHeavyPerProject caps how many concurrent heavy agent runs a
	// single project can hold at once. 0 = default 2; negative = disable
	// the per-project cap (only the global AgentHeavyMax applies). Used
	// to prevent one tenant from draining the cluster's heavy slot pool.
	AgentHeavyPerProject int
	Version              string // Injected version string for /server-info
	Author               string
	Commit               string
	BuildTime            string
	// MirrorFSPath, when set, mirrors every ingested HTTP record and finding to
	// a flat filesystem tree under this directory (in addition to the database),
	// so an external agent can read live traffic as files. See --mirror-fs.
	MirrorFSPath string
	// ConfigPath is the effective config file the server loaded settings from
	// (honors the --config flag). The config watcher watches this file for
	// hot-reload. Empty falls back to config.ConfigFilePath() (the default
	// ~/.vigolium/vigolium-configs.yaml).
	ConfigPath string
	// ReportFormats are the post-scan report formats (html, report, …) that
	// RenderReport can produce. REST `output_formats` accepts "jsonl" (the live
	// stream the runner writes) plus exactly these; anything else is a 400, so a
	// format is never accepted and then silently not produced.
	ReportFormats []string
	// RenderReport renders one report file for a finished REST scan. Injected by
	// the CLI so REST output comes from the same generator `scan --format` uses
	// (pkg/server cannot import pkg/cli). Nil means no report formats.
	RenderReport ReportRenderFunc
	// APIVersionDefault is the REST response version a request gets when it
	// does not negotiate one (server.api_version_default). 0 or 1 = v1, 2 = v2.
	APIVersionDefault int
	// AutoCreateProjects creates the project an unknown X-Project-UUID names
	// instead of answering 404 project_not_found (server.auto_create_projects).
	AutoCreateProjects bool
}

// ReportRenderFunc renders one post-scan report file in format to outputPath
// from db, scoped to projectUUID and scanUUID.
type ReportRenderFunc func(ctx context.Context, db *database.DB, format, outputPath, projectUUID, scanUUID string) error

// DefaultServerConfig returns sensible defaults.
// defaultMaxUploadBytes is the framework-level request body ceiling applied when
// ServerConfig.MaxUploadBytes is unset. It must stay well above the 4 MB
// DefaultBodyLimitMiddleware cap so large-upload routes work; non-upload routes
// remain capped at 4 MB by that middleware.
const defaultMaxUploadBytes = 512 << 20 // 512 MiB

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ServiceAddr: ":9002",
		ReadTimeout: 10 * time.Second,
		// WriteTimeout stays 0 (unlimited) so SSE agent/audit streams aren't
		// severed mid-flight; see the ServerConfig.WriteTimeout doc.
		WriteTimeout:       0,
		IdleTimeout:        120 * time.Second,
		ShutdownTimeout:    30 * time.Second,
		MaxUploadBytes:     defaultMaxUploadBytes,
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

	// Strategy preset: lite, balanced, deep
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

	// Request budgets (like --max-requests / --max-requests-per-host): the scan
	// stops after max_requests requests to the targets (partial, stop_reason
	// request_budget), and sends at most max_requests_per_host to any one host.
	// 0 or absent = scanning_pace.max_requests / max_requests_per_host.
	MaxRequests        int64 `json:"max_requests,omitempty"`
	MaxRequestsPerHost int64 `json:"max_requests_per_host,omitempty"`

	// Scope origin mode: all, relaxed, balanced, strict
	ScopeOrigin string `json:"scope_origin,omitempty"`

	// Heuristics check level: none, basic, advanced
	HeuristicsCheck string `json:"heuristics_check,omitempty"`

	// Custom HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// Scanning profile name or path
	ScanningProfile string `json:"scanning_profile,omitempty"`

	// Intensity preset: quick, balanced, deep (resolves to scanning_profile + strategy)
	Intensity string `json:"intensity,omitempty"`

	// Upload results to cloud storage after scan completion
	UploadResults bool `json:"upload_results,omitempty"`

	// OutputFormats selects extra result formats to materialize on disk: "jsonl"
	// (written live during the scan) plus the report formats in
	// ServerConfig.ReportFormats — the REST surface of the output format table
	// (html, report, pdf, markdown, sarif, csv, junit; rendered after the
	// scan). Aliases and case are folded. Any other value is a 400. When set, files are
	// written to <sessions_dir>/<scan_uuid>/output.<ext> and — if
	// upload_results is also true — bundled into the uploaded tar.gz alongside
	// runtime.log.
	OutputFormats []string `json:"output_formats,omitempty"`

	// Pin scan UUID (for cross-node sync). When set, the scan record is
	// fetched-or-created with this UUID; if a record already exists, its
	// project_uuid must match.
	ScanUUID string `json:"scan_uuid,omitempty"`
}

// ScanAllRecordsRequest is the request body for POST /api/scan-all-records.
// Scans existing HTTP records from the database with optional filtering.
type ScanAllRecordsRequest struct {
	// Record selection filters (all optional — omit all to scan everything)
	Hostname     string   `json:"hostname,omitempty"`       // hostname filter (supports * wildcards)
	Methods      []string `json:"methods,omitempty"`        // HTTP methods filter
	Path         string   `json:"path,omitempty"`           // path filter (supports * wildcards)
	StatusCodes  []int    `json:"status_codes,omitempty"`   // status code filter
	Source       string   `json:"source,omitempty"`         // record source filter
	Search       string   `json:"search,omitempty"`         // search across URL/path
	MinRiskScore int      `json:"min_risk_score,omitempty"` // minimum risk score
	// MinSurfaceScore filters on the deterministic attack-surface score (0-100)
	// written by the surface_scoring passive module, which owns the scale.
	MinSurfaceScore int    `json:"min_surface_score,omitempty"`
	Remark          string `json:"remark,omitempty"` // remark substring filter

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

	// Request budgets (like --max-requests / --max-requests-per-host): the scan
	// stops after max_requests requests to the targets (partial, stop_reason
	// request_budget), and sends at most max_requests_per_host to any one host.
	// 0 or absent = scanning_pace.max_requests / max_requests_per_host.
	MaxRequests        int64 `json:"max_requests,omitempty"`
	MaxRequestsPerHost int64 `json:"max_requests_per_host,omitempty"`

	// Heuristics check level: none, basic, advanced
	HeuristicsCheck string `json:"heuristics_check,omitempty"`

	// Custom HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// Scanning profile name or path
	ScanningProfile string `json:"scanning_profile,omitempty"`

	// Intensity preset: quick, balanced, deep (resolves to scanning_profile + strategy)
	Intensity string `json:"intensity,omitempty"`
}

// ScanURLRequest is the request body for POST /api/scan-url.
type ScanURLRequest struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"` // default GET
	Body      string            `json:"body"`
	Headers   map[string]string `json:"headers"`
	Modules   string            `json:"modules"` // comma-separated module IDs
	NoPassive bool              `json:"no_passive"`
}

// ScanRequestRequest is the request body for POST /api/scan-request.
type ScanRequestRequest struct {
	// HTTPRequestBase64 is the preferred field name for the base64-encoded raw HTTP request.
	// RawRequest is accepted as an alias for backward compatibility.
	HTTPRequestBase64 string `json:"http_request_base64,omitempty"`
	RawRequest        string `json:"raw_request,omitempty"`
	// HTTPResponseBase64 is the preferred field name for the base64-encoded raw HTTP response
	// (optional, for Burp-style request+response pairs). RawResponse is accepted as an alias.
	HTTPResponseBase64 string `json:"http_response_base64,omitempty"`
	RawResponse        string `json:"raw_response,omitempty"`
	TargetURL          string `json:"target_url"` // scheme://host override
	Modules            string `json:"modules"`    // comma-separated module IDs
	NoPassive          bool   `json:"no_passive"`
	// NoSchemeProbe keeps the inferred https default for a request whose
	// scheme nothing in it settles, instead of probing the target first (the
	// CLI's --no-scheme-probe).
	NoSchemeProbe bool `json:"no_scheme_probe,omitempty"`
}

// ReqBase64 returns the base64-encoded raw request, preferring http_request_base64 over raw_request.
func (r *ScanRequestRequest) ReqBase64() string {
	if r.HTTPRequestBase64 != "" {
		return r.HTTPRequestBase64
	}
	return r.RawRequest
}

// RespBase64 returns the base64-encoded raw response, preferring http_response_base64 over raw_response.
func (r *ScanRequestRequest) RespBase64() string {
	if r.HTTPResponseBase64 != "" {
		return r.HTTPResponseBase64
	}
	return r.RawResponse
}

// ScanResponse is the response for POST /api/scans/run.
type ScanResponse struct {
	ProjectUUID   string `json:"project_uuid,omitempty"`
	ScanUUID      string `json:"scan_uuid"`
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	RecordsToScan int64  `json:"records_to_scan,omitempty"`
	TargetsCount  int    `json:"targets_count,omitempty"`
	ScanMode      string `json:"scan_mode,omitempty"` // "target", "full", "incremental"
	// Target is the URL a scan-request will send to, after scheme resolution.
	Target string `json:"target,omitempty"`
	// SchemeSource is what decided a scan-request's scheme: explicit, port,
	// origin, referer, probe or default (the CLI result's scheme_source).
	SchemeSource string `json:"scheme_source,omitempty"`
	// Resolved is the pace the scan will run with after profile, strategy and
	// scanning_pace resolution — the same values `vigolium scan` resolves for
	// the same inputs.
	Resolved *ScanResolved `json:"resolved,omitempty"`
}

// ScanResolved is the invocation-wide pace a submitted scan resolved to.
type ScanResolved struct {
	Strategy    string `json:"strategy"`
	Concurrency int    `json:"concurrency"`
	RateLimit   int    `json:"rate_limit"`
	MaxPerHost  int    `json:"max_per_host"`
}

// ScanStatusResponse is the response for GET /api/scan/status.
type ScanStatusResponse struct {
	ProjectUUID string `json:"project_uuid,omitempty"`
	ScanUUID    string `json:"scan_uuid,omitempty"`
	Running     bool   `json:"running"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
}

// HealthResponse is the response for GET /health.
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	// PID is the serving process's pid, so a controller holding a pidfile can
	// confirm it is talking to the process it recorded.
	PID int `json:"pid"`
}

// ErrorResponse is the v1 error body. Code is always the HTTP status;
// ErrorCode is the stable string classification (pkg/apicontract) a client
// branches on. v2 clients get apicontract.RESTErrorEnvelope instead. Build it
// only through respondError and friends (respond.go).
type ErrorResponse struct {
	Error     string `json:"error"`
	Code      int    `json:"code"`
	ErrorCode string `json:"error_code"`
	Details   string `json:"details,omitempty"`
}

// IngestHTTPRequest is the request body for POST /api/ingest-http.
//
// input_mode is one of the REST-only single-item modes (url, burp_base64,
// curl), "auto" (detect the format from content), or any input-format name or
// alias -I accepts (urls/url_file, har/http_archive, postman/postman_collection,
// openapi/swagger, wsdl, burpxml, burpraw, burpscope, nuclei, deparos).
type IngestHTTPRequest struct {
	InputMode          string `json:"input_mode"`
	URL                string `json:"url,omitempty"`
	Content            string `json:"content,omitempty"`
	ContentBase64      string `json:"content_base64,omitempty"`
	HTTPRequestBase64  string `json:"http_request_base64,omitempty"`
	HTTPResponseBase64 string `json:"http_response_base64,omitempty"`
	// Variables fill {{name}} placeholders in Postman collections and named
	// parameters / security credentials in OpenAPI and WSDL specs (the REST
	// equivalent of --spec-var), e.g. {"baseUrl": "https://api.example.com"}.
	Variables map[string]string `json:"variables,omitempty"`
}

// IngestHTTPResponse is the response for POST /api/ingest-http.
type IngestHTTPResponse struct {
	ProjectUUID string `json:"project_uuid,omitempty"`
	Imported    int    `json:"imported"`
	Skipped     int    `json:"skipped,omitempty"`
	// Format is the canonical input format the content was parsed as (empty
	// for the single-item url/burp_base64/curl modes).
	Format string `json:"format,omitempty"`
	// DetectedFormat is set when input_mode was "auto": the format the content
	// was detected as.
	DetectedFormat string `json:"detected_format,omitempty"`
	// SkippedReasons counts everything that did not become a stored record, by
	// reason (out_of_scope, unparsed_line, skipped_operation, …), so nothing
	// is dropped silently. Skipped is the out_of_scope count.
	SkippedReasons map[string]int `json:"skipped_reasons,omitempty"`
	// DerivedScope is the primary host a multi-host capture was scoped to;
	// records for other hosts were stored as context (ContextOnly
	// of them, source ingest-context) and are not scanned by scan-on-receive.
	DerivedScope string   `json:"derived_scope,omitempty"`
	ContextOnly  int      `json:"context_only,omitempty"`
	Errors       []string `json:"errors,omitempty"`
	Message      string   `json:"message"`
}

// PaginatedResponse is the v1 paginated list body. SchemaVersion (1) and
// Command are stamped by respondList; v2 clients get apicontract.RESTList,
// which carries the rows under items.
type PaginatedResponse struct {
	SchemaVersion int         `json:"schema_version"`
	Command       string      `json:"command"`
	ProjectUUID   string      `json:"project_uuid,omitempty"`
	Data          interface{} `json:"data"`
	Total         int64       `json:"total"`
	Limit         int         `json:"limit"`
	Offset        int         `json:"offset"`
	HasMore       bool        `json:"has_more"`
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
	Name        string `json:"name"`
	Version     string `json:"version"`
	Author      string `json:"author"`
	Docs        string `json:"docs"`
	LicenseSPDX string `json:"license_spdx"`
	Source      string `json:"source"`
	BuildTime   string `json:"build_time,omitempty"`
	Commit      string `json:"commit,omitempty"`
}

// ServerInfoResponse is the response for GET /server-info.
type ServerInfoResponse struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Author      string `json:"author"`
	Docs        string `json:"docs"`
	BuildTime   string `json:"build_time,omitempty"`
	Commit      string `json:"commit,omitempty"`
	Uptime      string `json:"uptime"`
	ServiceAddr string `json:"service_addr"`
	ProxyAddr   string `json:"proxy_addr,omitempty"`
	// ProxyAuth names the ingest proxy's access control: "token",
	// "allowlist", "token+allowlist" or "none". Omitted without a proxy.
	ProxyAuth     string `json:"proxy_auth,omitempty"`
	QueueDepth    int64  `json:"queue_depth"`
	TotalRecords  int64  `json:"total_records"`
	TotalFindings int64  `json:"total_findings"`
	License       string `json:"license,omitempty"`
	LicenseSPDX   string `json:"license_spdx"`
	Source        string `json:"source"`
	DemoOnly      bool   `json:"demo_only,omitempty"`
	ViewOnly      bool   `json:"view_only,omitempty"`
	// MirrorDropped counts --mirror-fs jobs dropped because the mirror writer
	// stayed saturated past its enqueue timeout. Present only with --mirror-fs.
	MirrorDropped *int64 `json:"mirror_dropped,omitempty"`
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
	AgenticScans     int64                  `json:"agentic_scans"`
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
	Total    int64 `json:"total"`
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Info     int64 `json:"info"`
}

// ProjectWithStats wraps a Project with its aggregated stats.
type ProjectWithStats struct {
	*database.Project
	Stats ProjectStats `json:"stats"`
}

// ProjectRequest is the request body for POST/PUT /api/projects.
//
// UUID is optional on POST. When the cloud console eagerly provisions a
// scanner row for a Convex-managed project, it sends the Convex-side UUID so
// both systems agree on the same key. When omitted, the scanner mints a fresh
// UUID — preserving the standalone-CLI behavior.
type ProjectRequest struct {
	UUID        string `json:"uuid,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
	OwnerUUID   string `json:"owner_uuid"`
}

// ConfigUpdateResponse is the response for POST /api/config.
type ConfigUpdateResponse struct {
	Message string                `json:"message"`
	Updated []ConfigEntryResponse `json:"updated"`
	Errors  []string              `json:"errors,omitempty"`
}

// AgenticScanRequest is the request body for POST /api/agent/run/query.
type AgenticScanRequest struct {
	Agent          string   `json:"agent,omitempty"`
	PromptTemplate string   `json:"prompt_template,omitempty"`
	PromptFile     string   `json:"prompt_file,omitempty"`
	Prompt         string   `json:"prompt,omitempty"`
	SourcePath     string   `json:"source,omitempty"` // path to source code
	Files          []string `json:"files,omitempty"`
	Append         string   `json:"append,omitempty"`
	Instruction    string   `json:"instruction,omitempty"` // custom instruction appended to the prompt
	Source         string   `json:"source_label,omitempty"`
	ScanUUID       string   `json:"scan_uuid,omitempty"`
	ProjectUUID    string   `json:"project_uuid,omitempty"` // project UUID for storage scoping (falls back to X-Project-UUID header)
	Stream         bool     `json:"stream,omitempty"`
	UploadResults  bool     `json:"upload_results,omitempty"` // upload session bundle to cloud storage on completion

	// AgentBYOK fields (api_key, oauth_token, oauth_cred_file, oauth_cred_json)
	// are accepted at the top level. When set, the in-process olium engine
	// for this request is built from a per-request OliumConfig overlay rather
	// than the server-wide agent.olium.* defaults.
	AgentBYOK
}

// AgentAutopilotRequest is the request body for POST /api/agent/run/autopilot.
type AgentAutopilotRequest struct {
	Prompt      string   `json:"prompt,omitempty"`       // natural language scan prompt (parsed into target/source/focus when explicit fields are empty)
	Intensity   string   `json:"intensity,omitempty"`    // scan intensity preset: quick, balanced (default), deep
	Target      string   `json:"target,omitempty"`       // target URL (derived from input if not set)
	Input       string   `json:"input,omitempty"`        // raw input (curl, raw HTTP, Burp XML, URL) — target extracted automatically
	Agent       string   `json:"agent,omitempty"`        // agent backend name
	SourcePath  string   `json:"source,omitempty"`       // path to application source code
	Files       []string `json:"files,omitempty"`        // specific files to include
	Focus       string   `json:"focus,omitempty"`        // focus area hint
	Instruction string   `json:"instruction,omitempty"`  // custom instruction appended to the prompt
	Timeout     string   `json:"timeout,omitempty"`      // Go duration string, default "6h"
	MaxCommands int      `json:"max_commands,omitempty"` // max CLI commands, default 100
	DryRun      bool     `json:"dry_run,omitempty"`      // render prompt without executing
	Stream      bool     `json:"stream,omitempty"`       // enable SSE streaming
	ScanUUID    string   `json:"scan_uuid,omitempty"`    // optional scan UUID
	ProjectUUID string   `json:"project_uuid,omitempty"` // project UUID for data scoping
	// Deprecated: use NoAudit + AuditDriverMode instead. Kept for backward
	// compatibility with older API clients; "off" maps to NoAudit=true and
	// any other value (e.g. "deep") maps to AuditDriverMode. Slated for removal.
	Audit           string                      `json:"audit,omitempty"`             // legacy values: "lite", "balanced", "deep", "off"
	NoAudit         bool                        `json:"no_audit,omitempty"`          // keep the nested vigolium-audit harness off (the default; kept for older clients)
	AuditDriverMode string                      `json:"audit_mode,omitempty"`        // run the nested vigolium-audit harness (needs source): "lite", "balanced", "deep", "mock"; empty = off
	Diff            string                      `json:"diff,omitempty"`              // focus on changed code: PR URL, git ref range, or HEAD~N
	LastCommits     int                         `json:"last_commits,omitempty"`      // focus on last N commits (shorthand for diff HEAD~N)
	Browser         bool                        `json:"browser,omitempty"`           // explicitly enable browser tooling
	Credentials     string                      `json:"credentials,omitempty"`       // compact credential hint for preflight auth setup
	CredentialSets  []agent.IntentCredentialSet `json:"credential_sets,omitempty"`   // structured roles/accounts for preflight auth setup
	AuthRequired    bool                        `json:"auth_required,omitempty"`     // authenticate before scan
	RequiresBrowser bool                        `json:"requires_browser,omitempty"`  // browser is required for login/auth setup
	BrowserStartURL string                      `json:"browser_start_url,omitempty"` // explicit login/start URL for browser-based flows
	FocusRoutes     []string                    `json:"focus_routes,omitempty"`      // protected/browser focus routes

	// Piolium runs the nested piolium audit harness (Pi runtime; needs
	// source) in this mode instead of vigolium-audit. Empty = off: an
	// installed piolium is never picked automatically.
	Piolium string `json:"piolium,omitempty"`

	// Triage, when true, runs an AI triage pass over the findings after the
	// scan completes — classifying each as confirmed or false positive and
	// writing the verdict back to finding status. Pure classification (no
	// native rescan).
	Triage bool `json:"triage,omitempty"`

	// NoPreflightDiscovery disables the pre-flight discovery + OpenAPI/Swagger
	// ingestion pass that seeds http_records before the operator agent
	// starts. Default false (pre-flight on). Set true to skip — useful when
	// the caller has already seeded the project via --input or a prior scan.
	NoPreflightDiscovery bool `json:"no_preflight_discovery,omitempty"`

	// NoPostHaltVerify disables the post-halt coverage verification loop —
	// the agent's halt_scan is accepted as final regardless of whether a
	// follow-up discovery probe would surface new routes. Default false
	// (verification on). Cap the cost via PostHaltGapThreshold rather than
	// disabling entirely when possible.
	NoPostHaltVerify bool `json:"no_post_halt_verify,omitempty"`

	// PostHaltGapThreshold sets the minimum number of new routes the
	// post-halt probe must turn up before the agent is re-entered. 0 falls
	// back to the autopilot's built-in default (5).
	PostHaltGapThreshold int `json:"post_halt_gap_threshold,omitempty"`

	// Upload results to cloud storage after scan completion
	UploadResults bool `json:"upload_results,omitempty"`

	// AgentBYOK fields (api_key, oauth_token, oauth_cred_file, oauth_cred_json)
	// are accepted at the top level of the request body. The in-process
	// olium engine for this run is built with these overlaid onto the
	// server-wide agent.olium.* defaults; the background audit (when
	// enabled via AuditDriverMode/Piolium) inherits the same overrides.
	AgentBYOK
}

// ResolvedNoAudit returns true when audit should be disabled, handling backward
// compatibility with the legacy Audit field.
func (r AgentAutopilotRequest) ResolvedNoAudit() bool {
	if r.Audit == "off" {
		return true
	}
	return r.NoAudit
}

// ResolvedAuditDriverMode returns the effective audit mode, handling backward
// compatibility with the legacy Audit field.
func (r AgentAutopilotRequest) ResolvedAuditDriverMode() string {
	if r.AuditDriverMode != "" {
		return r.AuditDriverMode
	}
	// Legacy: "audit": "deep" means mode=deep
	if r.Audit != "" && r.Audit != "off" {
		return r.Audit
	}
	return "lite"
}

// AgentBYOK is the shared shape of "bring your own key" credentials sent
// on agent endpoints. Embedded in every request type that runs an agent
// (audit/audit subprocess drivers, autopilot/swarm/query in-process
// olium) so callers get a uniform field surface regardless of which
// endpoint they target.
//
// Field semantics (mutually exclusive — at most one of APIKey /
// OAuthToken / OAuthCredFile / OAuthCredJSON may be non-empty):
//
//   - APIKey         — Anthropic or OpenAI API key. Routed to the right
//     env / x-api-key header by the receiving driver.
//   - OAuthToken     — Claude Code OAuth token (`sk-ant-oat01-…` from
//     `claude setup-token`). Claude-only.
//   - OAuthCredFile  — server-side path to a Codex auth.json. DEPRECATED:
//     server-supplied paths let any operator point the audit at any
//     readable file. New integrations should send the contents inline
//     via OAuthCredJSON.
//   - OAuthCredJSON  — raw contents of a Codex auth.json. Staged by the
//     server to a per-request 0600 temp file, used for one run, then
//     deleted.
//
// Values are treated as literals — unlike the CLI flags, REST does NOT
// honor $ENV / @path indirection. Doing so would let a network caller
// probe the server's environment or filesystem.
type AgentBYOK struct {
	APIKey        string `json:"api_key,omitempty"`
	OAuthToken    string `json:"oauth_token,omitempty"`
	OAuthCredFile string `json:"oauth_cred_file,omitempty"`
	OAuthCredJSON string `json:"oauth_cred_json,omitempty"`
}

// IsZero reports whether no BYOK fields are set. Used to short-circuit
// the resolver / staging path when the request doesn't carry any creds.
func (b AgentBYOK) IsZero() bool {
	return b.APIKey == "" && b.OAuthToken == "" && b.OAuthCredFile == "" && b.OAuthCredJSON == ""
}

// AgentAuditDriverRequest is the request body for POST /api/agent/run/audit.
// Mirrors the autopilot request shape for the fields audit actually consumes
// (source, intensity/mode, platform, timeout, diff context, scoping, streaming).
type AgentAuditDriverRequest struct {
	Source        string   `json:"source,omitempty"`         // local path, git URL, gs:// archive, or local archive (required)
	Target        string   `json:"target,omitempty"`         // optional target URL — stored on the run row for cross-referencing scans
	Intensity     string   `json:"intensity,omitempty"`      // quick | balanced (default) | deep — bundles mode + timeout + commit_depth
	Mode          string   `json:"mode,omitempty"`           // explicit audit mode: lite, balanced, scan, deep, mock, revisit, reinvest, confirm, merge, diff, status (overrides intensity)
	Modes         []string `json:"modes,omitempty"`          // mode chain run back-to-back via audit's native --modes (e.g. ["deep","refresh","confirm"]); overrides mode/intensity, stops on first non-complete
	Platform      string   `json:"platform,omitempty"`       // claude | codex (default: from settings, then claude)
	Agent         string   `json:"agent,omitempty"`          // alias for platform — accepted for parity with the CLI flag
	Timeout       string   `json:"timeout,omitempty"`        // Go duration string; overrides intensity preset (quick=1h, balanced=6h, deep=12h)
	Diff          string   `json:"diff,omitempty"`           // focus on changed code: PR URL, git ref range, or HEAD~N
	LastCommits   int      `json:"last_commits,omitempty"`   // focus on last N commits (shorthand for diff HEAD~N)
	CommitDepth   int      `json:"commit_depth,omitempty"`   // git clone --depth when source is a git URL; overrides intensity preset (quick/balanced=1, deep=0)
	Files         []string `json:"files,omitempty"`          // specific files to focus on
	Stream        bool     `json:"stream,omitempty"`         // enable SSE streaming of agent output
	UploadResults bool     `json:"upload_results,omitempty"` // upload session bundle to cloud storage on completion
	ProjectUUID   string   `json:"project_uuid,omitempty"`   // project UUID for data scoping
	ScanUUID      string   `json:"scan_uuid,omitempty"`      // optional scan UUID

	// AgentBYOK fields (api_key, oauth_token, oauth_cred_file, oauth_cred_json)
	// are accepted at the top level of the request body via JSON field
	// promotion. See AgentBYOK doc for resolution semantics.
	AgentBYOK
}

// EffectivePlatform resolves the platform field, accepting the legacy `agent`
// alias used by the CLI flag (`--agent claude|codex`).
func (r AgentAuditDriverRequest) EffectivePlatform() string {
	if r.Platform != "" {
		return r.Platform
	}
	return r.Agent
}

// AgentAuditRequest is the request body for POST /api/agent/run/audit.
//
// Mirrors the `vigolium agent audit` CLI: dispatches audit and/or piolium
// against a source tree (local path, git URL, gs:// archive, or local
// archive) under one AgenticScan. When driver=auto (default), audit
// runs first and piolium only runs as a fallback if audit fails — a
// clean audit run finishes the audit and piolium is never started.
// When driver=both, both drivers run sequentially (audit first, then
// piolium) unconditionally. Multi-driver runs use per-driver child
// AgenticScan rows. Same /agent/status, /agent/sessions/:id/logs, and
// /agent/sessions/:id/artifacts shape as the single-driver endpoints.
//
// Optional fields default to the same values as their CLI counterparts; in
// particular, the `pi_*` and `plm_*` knobs only fire when explicitly set.
type AgentAuditRequest struct {
	Source        string   `json:"source,omitempty"`         // local path, git URL, gs:// archive, or local archive (required)
	Target        string   `json:"target,omitempty"`         // optional target URL — stored on the run row for cross-referencing scans
	Intensity     string   `json:"intensity,omitempty"`      // quick | balanced (default) | deep — bundles mode + timeout + commit_depth
	Mode          string   `json:"mode,omitempty"`           // explicit audit mode (overrides intensity). With driver=auto or driver=both, restricted to: lite, balanced, deep, revisit, confirm, merge. With driver=piolium adds: diff, longshot, status, smoke. With driver=audit adds: reinvest, diff, status, mock.
	Modes         []string `json:"modes,omitempty"`          // mode chain run back-to-back (e.g. ["deep","refresh","confirm"]); overrides mode/intensity. audit runs it natively; piolium chains via sequential runs collapsed into one row; with driver=auto/both, modes a driver can't run are skipped on that driver's leg.
	Timeout       string   `json:"timeout,omitempty"`        // Go duration string; overrides intensity preset (quick=1h, balanced=6h, deep=12h)
	Diff          string   `json:"diff,omitempty"`           // focus on changed code: PR URL, git ref range, or HEAD~N
	LastCommits   int      `json:"last_commits,omitempty"`   // focus on last N commits (shorthand for diff HEAD~N)
	CommitDepth   int      `json:"commit_depth,omitempty"`   // git clone --depth when source is a git URL; overrides intensity preset (quick/balanced=1, deep=0)
	Files         []string `json:"files,omitempty"`          // specific files to focus on
	Stream        bool     `json:"stream,omitempty"`         // enable SSE streaming of agent output. With driver=auto/both, events are tagged with a "driver" field
	UploadResults bool     `json:"upload_results,omitempty"` // upload session bundle to cloud storage on completion
	ProjectUUID   string   `json:"project_uuid,omitempty"`   // project UUID for data scoping
	ScanUUID      string   `json:"scan_uuid,omitempty"`      // optional scan UUID

	// Driver picks which audit harnesses participate. One of:
	//   "auto"    — audit first; piolium runs only as a fallback if
	//               audit fails (a clean audit run finishes the audit
	//               and piolium is never started). Default when empty.
	//   "both"    — sequential audit-then-piolium under one parent
	//               AgenticScan, run unconditionally
	//   "audit"  — audit only (equivalent to /api/agent/run/audit)
	//   "piolium" — piolium only
	// "auto" and "both" run under one parent AgenticScan with per-driver
	// child rows, post-pass findings dedup, and multiplexed SSE.
	// Defaults to "auto" when empty.
	Driver string `json:"driver,omitempty"`

	// NoDedup skips the post-pass project-wide findings dedup that runs
	// after the audit completes. Only meaningful for driver=auto/both,
	// since single-driver runs already INSERT-time-dedup by finding_hash.
	NoDedup bool `json:"no_dedup,omitempty"`

	// KeepRaw maps to vigolium-audit's `--keep-raw`: opt out of the
	// deep/confirm auto-prune so raw scanner output, draft findings, and
	// intermediate workspaces stay under <source>/vigolium-results/ (and
	// the synced session copy) for manual review. Audit-only — ignored on
	// the piolium leg of driver=auto/both/piolium runs.
	KeepRaw bool `json:"keep_raw,omitempty"`

	// Agent picks the audit platform when audit participates. Accepts
	// claude (default) or codex. Ignored when driver=piolium.
	Agent string `json:"agent,omitempty"`

	// Pi provider/model overrides, forwarded as `pi --provider X --model Y`.
	// Empty values fall back to whatever the user has configured in
	// ~/.pi/agent/settings.json. Ignored when driver=audit.
	PiProvider string `json:"pi_provider,omitempty"`
	PiModel    string `json:"pi_model,omitempty"`

	// Piolium passthrough flags (`--plm-*`). Empty/zero values are dropped
	// so piolium's own defaults still apply. Ignored when driver=audit.
	PlmScanLimit       int    `json:"plm_scan_limit,omitempty"`       // cap commit-history scan to N commits
	PlmScanSince       string `json:"plm_scan_since,omitempty"`       // git --since window (e.g. "60 days ago")
	PlmPhaseRetries    int    `json:"plm_phase_retries,omitempty"`    // per-phase retry count
	PlmCommandRetries  int    `json:"plm_command_retries,omitempty"`  // per-command retry count
	PlmLongshotLimit   int    `json:"plm_longshot_limit,omitempty"`   // max files in longshot mode
	PlmLongshotTimeout int    `json:"plm_longshot_timeout,omitempty"` // per-file kill timer in ms (longshot)
	PlmLongshotLangs   string `json:"plm_longshot_langs,omitempty"`   // comma-separated language allowlist

	// AgentBYOK fields (api_key, oauth_token, oauth_cred_file, oauth_cred_json)
	// are accepted at the top level of the request body via JSON field
	// promotion. The audit dispatcher applies these to whichever driver(s)
	// actually run: audit receives them as --api-key / --oauth-token /
	// --oauth-cred-file flags; piolium receives them as env vars on the pi
	// subprocess (and, for codex cred files, a temporarily-staged auth.json
	// under the configured pi-agent-dir, restored on completion). See
	// AgentBYOK doc for full semantics.
	AgentBYOK

	// AuditDriverAuth, when set, OVERRIDES the top-level AgentBYOK for the
	// audit driver only. Used with driver=auto/both to give each driver
	// its own identity (e.g. one tenant's claude OAuth for the audit side,
	// another tenant's codex cred file for piolium). When unset, audit
	// inherits the top-level AgentBYOK. Ignored when driver=piolium.
	AuditDriverAuth *AgentBYOK `json:"audit_auth,omitempty"`

	// PioliumAuth, when set, OVERRIDES the top-level AgentBYOK for the
	// piolium driver only. Symmetric to AuditDriverAuth. Ignored when
	// driver=audit.
	PioliumAuth *AgentBYOK `json:"piolium_auth,omitempty"`
}

// AgentSwarmRequest is the request body for POST /api/agent/run/swarm.
type AgentSwarmRequest struct {
	// Natural language prompt (parsed into structured fields when explicit fields are empty)
	Prompt string `json:"prompt,omitempty"`

	// Scan intensity preset: quick, balanced (default), deep
	Intensity string `json:"intensity,omitempty"`

	// Inputs
	Input              string   `json:"input,omitempty"`                // single input (URL, curl, raw HTTP, Burp XML, record UUID)
	Inputs             []string `json:"inputs,omitempty"`               // multiple inputs (for auth flows)
	HTTPRequestBase64  string   `json:"http_request_base64,omitempty"`  // base64-encoded raw HTTP request (ingested into DB, UUID used as input)
	HTTPResponseBase64 string   `json:"http_response_base64,omitempty"` // base64-encoded raw HTTP response (attached to the request above)
	URL                string   `json:"url,omitempty"`                  // optional URL hint for parsing the base64 request

	// Source analysis
	SourcePath         string   `json:"source,omitempty"`               // path to source code for route discovery (triggers source analysis phase)
	Files              []string `json:"files,omitempty"`                // specific source files to include (relative to source)
	SourceAnalysisOnly bool     `json:"source_analysis_only,omitempty"` // run only source analysis phase and exit

	// Scanning parameters
	VulnType      string   `json:"vuln_type,omitempty"`      // vulnerability type focus
	Focus         string   `json:"focus,omitempty"`          // broad focus area hint (e.g. "API injection", "auth bypass")
	Instruction   string   `json:"instruction,omitempty"`    // custom instruction appended to agent prompts
	ModuleNames   []string `json:"module_names,omitempty"`   // explicit module IDs
	OnlyPhase     string   `json:"only_phase,omitempty"`     // isolate a single phase
	SkipPhases    []string `json:"skip_phases,omitempty"`    // skip specific phases
	StartFrom     string   `json:"start_from,omitempty"`     // resume from a specific phase
	MaxIterations int      `json:"max_iterations,omitempty"` // max triage-rescan rounds (default 3)
	Discover      bool     `json:"discover,omitempty"`       // run discovery+spidering before master agent planning
	CodeAudit     bool     `json:"code_audit,omitempty"`     // enable AI security code audit phase
	Triage        bool     `json:"triage,omitempty"`         // enable AI triage and rescan phases (disabled by default)
	Profile       string   `json:"profile,omitempty"`        // scanning profile name (e.g. "light", "thorough")

	// Agent selection
	Agent string `json:"agent,omitempty"` // agent backend name

	// Auth/browser intent
	Browser         bool                        `json:"browser,omitempty"`           // explicitly enable browser tooling
	Auth            bool                        `json:"auth,omitempty"`              // explicitly run browser auth phase
	Credentials     string                      `json:"credentials,omitempty"`       // compact credential hint
	CredentialSets  []agent.IntentCredentialSet `json:"credential_sets,omitempty"`   // structured roles/accounts
	AuthRequired    bool                        `json:"auth_required,omitempty"`     // authenticate before scan
	RequiresBrowser bool                        `json:"requires_browser,omitempty"`  // browser is required for login/auth setup
	BrowserStartURL string                      `json:"browser_start_url,omitempty"` // explicit login/start URL
	FocusRoutes     []string                    `json:"focus_routes,omitempty"`      // protected/browser focus routes

	// Concurrency tuning
	BatchConcurrency int    `json:"batch_concurrency,omitempty"`  // max parallel master agent batches (0 = auto)
	MaxMasterRetries int    `json:"max_master_retries,omitempty"` // max master agent retries on parse failure (0 = default 3)
	SAMaxConcurrency int    `json:"sa_max_concurrency,omitempty"` // max parallel source analysis sub-agents (0 = default 3)
	MaxPlanRecords   int    `json:"max_plan_records,omitempty"`   // max records sent to plan agent (0 = use intensity preset, which picks 10/25/50 for quick/balanced/deep)
	MasterBatchSize  int    `json:"master_batch_size,omitempty"`  // max records per master agent batch (0 = default 5)
	ProbeConcurrency int    `json:"probe_concurrency,omitempty"`  // max parallel probe requests (0 = default 10)
	ProbeTimeout     string `json:"probe_timeout,omitempty"`      // per-request probe timeout as Go duration e.g. "10s" (0 = default 10s)
	MaxProbeBodySize int    `json:"max_probe_body,omitempty"`     // max response body size in bytes during probing (0 = default 2MB)

	// Output control
	DryRun     bool   `json:"dry_run,omitempty"`     // render prompts without executing
	ShowPrompt bool   `json:"show_prompt,omitempty"` // include rendered prompts in output
	Stream     bool   `json:"stream,omitempty"`      // enable SSE streaming
	Timeout    string `json:"timeout,omitempty"`     // Go duration string

	// Project/scan scoping
	ProjectUUID string `json:"project_uuid,omitempty"` // optional project UUID
	ScanUUID    string `json:"scan_uuid,omitempty"`    // optional scan UUID

	// Nested vigolium-audit harness (launches a claude/codex CLI; needs
	// source): "lite" (3-phase), "balanced" (9-phase), "deep" (12-phase).
	// Empty or "off" = off; the intensity preset never turns it on.
	Audit string `json:"audit,omitempty"`

	// Nested piolium audit harness (Pi runtime; launches a pi CLI; needs
	// source). Empty = off: an installed piolium is never picked
	// automatically. Wins over audit when both are set.
	Piolium string `json:"piolium,omitempty"`

	// Diff context
	Diff        string `json:"diff,omitempty"`         // focus on changed code: PR URL, git ref range, or HEAD~N
	LastCommits int    `json:"last_commits,omitempty"` // focus on last N commits (shorthand for diff HEAD~N)

	// Upload results to cloud storage after scan completion
	UploadResults bool `json:"upload_results,omitempty"`

	// AgentBYOK fields (api_key, oauth_token, oauth_cred_file, oauth_cred_json)
	// are accepted at the top level. Master / triage / source-analysis
	// agents all run against the in-process olium engine; when set, the
	// engine for this run is built with these overlaid onto the server-wide
	// agent.olium.* defaults.
	AgentBYOK
}

// ResolvedNoAudit returns true when audit should be disabled.
// Swarm uses opt-in audit: empty string means disabled.
func (r AgentSwarmRequest) ResolvedNoAudit() bool {
	return r.Audit == "" || r.Audit == "off"
}

// ResolvedAuditDriverMode returns the effective audit mode.
// Returns empty string when audit is disabled.
func (r AgentSwarmRequest) ResolvedAuditDriverMode() string {
	if r.Audit == "" || r.Audit == "off" {
		return ""
	}
	return r.Audit
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

// UnmarshalJSON implements custom unmarshaling for AgentSwarmRequest to support
// the legacy "source_path" JSON key as a backward-compatible alias for "source".
func (r *AgentSwarmRequest) UnmarshalJSON(data []byte) error {
	type Alias AgentSwarmRequest
	aux := &struct {
		*Alias
		LegacySourcePath string `json:"source_path,omitempty"`
	}{Alias: (*Alias)(r)}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	// Legacy fallback: accept "source_path" when "source" is not set.
	if r.SourcePath == "" && aux.LegacySourcePath != "" {
		r.SourcePath = aux.LegacySourcePath
	}
	return nil
}

// AgenticScanResponse is the response for POST /api/agent/run/*.
type AgenticScanResponse struct {
	AgenticScanUUID string `json:"agentic_scan_uuid"`
	Status          string `json:"status"`
	Message         string `json:"message,omitempty"`
}

// ChatCompletionRequest is an OpenAI-compatible chat completion request.
type ChatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`

	// AgentBYOK fields (api_key, oauth_token, oauth_cred_file,
	// oauth_cred_json) are accepted at the top level. In no-auth server
	// mode, an `Authorization: Bearer <key>` header is also promoted into
	// AgentBYOK.APIKey for OpenAI-SDK compatibility.
	AgentBYOK
}

// ChatMessage represents a single message in a chat completion request/response.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionResponse is an OpenAI-compatible chat completion response.
type ChatCompletionResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   *ChatUsage   `json:"usage,omitempty"`
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

// AgenticScanStatusResponse is the response for GET /api/agent/status/:id and GET /api/agent/status/list.
type AgenticScanStatusResponse struct {
	AgenticScanUUID string        `json:"agentic_scan_uuid"`
	ProjectUUID     string        `json:"project_uuid,omitempty"` // owning project; scopes status/list/cancel to X-Project-UUID
	Mode            string        `json:"mode"`                   // "query", "autopilot", "pipeline"
	Status          string        `json:"status"`                 // "running", "completed", "failed"
	AgentName       string        `json:"agent_name,omitempty"`
	TemplateID      string        `json:"template_id,omitempty"`
	FindingCount    int           `json:"finding_count,omitempty"`
	RecordCount     int           `json:"record_count,omitempty"`
	SavedCount      int           `json:"saved_count,omitempty"`
	Error           string        `json:"error,omitempty"`
	CompletedAt     *time.Time    `json:"completed_at,omitempty"`
	Result          *agent.Result `json:"result,omitempty"`
	StorageURL      string        `json:"storage_url,omitempty"`

	// Phase progress fields
	CurrentPhase string   `json:"current_phase,omitempty"`
	PhasesRun    []string `json:"phases_run,omitempty"`

	// Swarm/pipeline result
	SwarmResult *agent.SwarmResult `json:"swarm_result,omitempty"`
}

// AgentSessionSummary is a lightweight representation of an agent run for list responses.
type AgentSessionSummary struct {
	UUID                  string     `json:"uuid"`
	Mode                  string     `json:"mode"`
	Status                string     `json:"status"`
	AgentName             string     `json:"agent_name,omitempty"`
	TemplateID            string     `json:"template_id,omitempty"`
	TargetURL             string     `json:"target_url,omitempty"`
	SourcePath            string     `json:"source_path,omitempty"`
	SessionDir            string     `json:"session_dir,omitempty"`
	VulnType              string     `json:"vuln_type,omitempty"`
	InputType             string     `json:"input_type,omitempty"`
	ParentAgenticScanUUID string     `json:"parent_agentic_scan_uuid,omitempty"`
	CurrentPhase          string     `json:"current_phase,omitempty"`
	PhasesRun             []string   `json:"phases_run,omitempty"`
	FindingCount          int        `json:"finding_count,omitempty"`
	RecordCount           int        `json:"record_count,omitempty"`
	SavedCount            int        `json:"saved_count,omitempty"`
	ErrorMessage          string     `json:"error_message,omitempty"`
	DurationMs            int64      `json:"duration_ms,omitempty"`
	StartedAt             *time.Time `json:"started_at,omitempty"`
	CompletedAt           *time.Time `json:"completed_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	StorageURL            string     `json:"storage_url,omitempty"`
}

// AgentSessionDetail is the full representation of an agent run including debug fields.
type AgentSessionDetail struct {
	AgentSessionSummary
	InputRaw       string                `json:"input_raw,omitempty"`
	ModuleNames    []string              `json:"module_names,omitempty"`
	SessionID      string                `json:"session_id,omitempty"`
	PromptSent     string                `json:"prompt_sent,omitempty"`
	AgentRawOutput string                `json:"agent_raw_output,omitempty"`
	AttackPlan     string                `json:"attack_plan,omitempty"`
	TriageResult   string                `json:"triage_result,omitempty"`
	ResultJSON     string                `json:"result_json,omitempty"`
	ChildRuns      []*AgentSessionDetail `json:"child_runs,omitempty"`
}

// AgentArtifact is one file under an agent session directory.
type AgentArtifact struct {
	Name       string    `json:"name"`        // path relative to session_dir
	Size       int64     `json:"size"`        // bytes
	ModifiedAt time.Time `json:"modified_at"` // mtime
	Kind       string    `json:"kind"`        // "log", "json", "markdown", "yaml", "jsonl", "text", "binary"
}

// AgentArtifactListResponse lists files under an agent session directory.
type AgentArtifactListResponse struct {
	AgenticScanUUID string          `json:"agentic_scan_uuid"`
	SessionDir      string          `json:"session_dir"`
	Artifacts       []AgentArtifact `json:"artifacts"`
	Truncated       bool            `json:"truncated,omitempty"` // true when the walk hit the file cap
}
