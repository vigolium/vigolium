package database

import (
	"time"

	"github.com/uptrace/bun"
)

// User represents a system user.
type User struct {
	bun.BaseModel `bun:"table:users,alias:u" json:"-"`

	UUID      string    `bun:"uuid,pk,notnull" json:"uuid"`
	Email     string    `bun:"email,nullzero" json:"email,omitempty"`
	Name      string    `bun:"name,nullzero" json:"name,omitempty"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// Project represents a logical grouping for all scan data.
type Project struct {
	bun.BaseModel `bun:"table:projects,alias:p" json:"-"`

	UUID        string `bun:"uuid,pk,notnull" json:"uuid"`
	Name        string `bun:"name,notnull" json:"name"`
	Description string `bun:"description,nullzero" json:"description,omitempty"`
	OwnerUUID   string `bun:"owner_uuid,nullzero" json:"owner_uuid,omitempty"` // soft FK → users
	ConfigPath  string `bun:"config_path,nullzero" json:"config_path,omitempty"`
	CreatedAt   time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt   time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// DefaultProjectUUID is the well-known UUID for the default project created during init.
const DefaultProjectUUID = "00000000-0000-0000-0000-000000000001"

// ModuleType constants classify the kind of module that created a finding.
const (
	ModuleTypeActive      = "active"
	ModuleTypePassive     = "passive"
	ModuleTypeNuclei      = "nuclei"
	ModuleTypeSecretScan  = "secret-scan"
	ModuleTypeAgent       = "agent"
	ModuleTypeSourceTools = "source-tools"
	ModuleTypeSAST        = "sast"
	ModuleTypeOAST        = "oast"
	ModuleTypeExtension   = "extension"
	ModuleTypeSPA         = "spa"
)

// FindingSource constants identify which phase/component produced a finding.
const (
	FindingSourceDynamicAssessment = "dynamic-assessment"
	FindingSourceSPA               = "spa"
	FindingSourceAgent             = "agent"
	FindingSourceOAST              = "oast"
	FindingSourceSourceTools       = "source-tools"
	FindingSourceExtension         = "extension"
)

// DefaultUserUUID is the well-known UUID for the default local user created during init.
const DefaultUserUUID = "00000000-0000-0000-0000-000000000001"

// Scan represents a scan session
type Scan struct {
	bun.BaseModel `bun:"table:scans,alias:sc" json:"-"`

	UUID        string `bun:"uuid,pk,notnull" json:"uuid"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	Name        string `bun:"name,nullzero" json:"name,omitempty"`
	Description string `bun:"description,nullzero" json:"description,omitempty"`
	Status      string `bun:"status,notnull,default:'running'" json:"status"` // running, paused, completed, failed, cancelled
	// Target can be a URL, domain, IP, CIDR, or file path (for imported requests)
	Target  string `bun:"target,nullzero" json:"target,omitempty"`
	Modules string `bun:"modules,nullzero" json:"modules,omitempty"`
	Threads int    `bun:"threads,default:0" json:"threads"`

	// Cursor-based scan tracking
	ScanSource      string    `bun:"scan_source,nullzero" json:"scan_source,omitempty"`         // "cli", "api", "scan-on-receive"
	ScanMode        string    `bun:"scan_mode,nullzero" json:"scan_mode,omitempty"`             // "incremental" or "full"
	StartCursorAt   time.Time `bun:"start_cursor_at,nullzero" json:"start_cursor_at,omitempty"` // cursor position at scan start
	StartCursorUUID string    `bun:"start_cursor_uuid,nullzero" json:"start_cursor_uuid,omitempty"`
	CursorAt        time.Time `bun:"cursor_at,nullzero" json:"cursor_at,omitempty"` // current cursor position
	CursorUUID      string    `bun:"cursor_uuid,nullzero" json:"cursor_uuid,omitempty"`
	ProcessedCount  int64     `bun:"processed_count,default:0" json:"processed_count"`

	StartedAt  time.Time `bun:"started_at,notnull,default:current_timestamp" json:"started_at"`
	FinishedAt time.Time `bun:"finished_at,nullzero" json:"finished_at,omitempty"`
	DurationMs int64     `bun:"duration_ms,default:0" json:"duration_ms"`
	// Summary fields (populated at end of scan)
	TotalRequests int64 `bun:"total_requests,default:0" json:"total_requests"`
	TotalFindings int64 `bun:"total_findings,default:0" json:"total_findings"`

	// Risk level counts (populated at end of scan)
	CriticalCount int64 `bun:"critical_count,default:0" json:"critical_count"`
	HighCount     int64 `bun:"high_count,default:0" json:"high_count"`
	MediumCount   int64 `bun:"medium_count,default:0" json:"medium_count"`
	LowCount      int64 `bun:"low_count,default:0" json:"low_count"`
	InfoCount     int64 `bun:"info_count,default:0" json:"info_count"`
	SuspectCount  int64 `bun:"suspect_count,default:0" json:"suspect_count"`
	// Error count (populated at end of scan)
	ErrorMessage string    `bun:"error_message,nullzero" json:"error_message,omitempty"`
	CreatedAt    time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt    time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// HTTPRecord represents a single HTTP request/response record (denormalized)
type HTTPRecord struct {
	bun.BaseModel `bun:"table:http_records,alias:r" json:"-"`

	UUID        string `bun:"uuid,pk,notnull" json:"uuid"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`

	// Host info (embedded, replaces hosts table)
	Scheme   string `bun:"scheme,notnull" json:"scheme"`
	Hostname string `bun:"hostname,notnull" json:"hostname"`
	Port     int    `bun:"port,notnull" json:"port"`
	IP       string `bun:"ip,nullzero" json:"ip,omitempty"`

	// Request fields
	Method               string              `bun:"method,notnull" json:"method"`
	Path                 string              `bun:"path,notnull" json:"path"`
	URL                  string              `bun:"url,notnull" json:"url"`
	HTTPVersion          string              `bun:"http_version,notnull" json:"http_version"`
	RequestHeaders       map[string][]string `bun:"request_headers,type:jsonb,nullzero" json:"request_headers,omitempty"`
	RequestContentType   string              `bun:"request_content_type,nullzero" json:"request_content_type,omitempty"`
	RequestContentLength int64               `bun:"request_content_length,default:0" json:"request_content_length"`
	RawRequest           []byte              `bun:"raw_request,type:bytea,nullzero" json:"raw_request,omitempty"`
	RequestBody          []byte              `bun:"request_body,type:bytea,nullzero" json:"request_body,omitempty"`
	RequestHash          string              `bun:"request_hash,notnull" json:"request_hash"`
	RequestAuthorization string              `bun:"request_authorization,nullzero" json:"request_authorization,omitempty"`

	// Response fields
	StatusCode            int                 `bun:"status_code,default:0" json:"status_code"`
	StatusPhrase          string              `bun:"status_phrase,nullzero" json:"status_phrase,omitempty"`
	ResponseHTTPVersion   string              `bun:"response_http_version,nullzero" json:"response_http_version,omitempty"`
	ResponseHeaders       map[string][]string `bun:"response_headers,type:jsonb,nullzero" json:"response_headers,omitempty"`
	ResponseContentType   string              `bun:"response_content_type,nullzero" json:"response_content_type,omitempty"`
	ResponseContentLength int64               `bun:"response_content_length,default:0" json:"response_content_length"`
	RawResponse           []byte              `bun:"raw_response,type:bytea,nullzero" json:"raw_response,omitempty"`
	ResponseBody          []byte              `bun:"response_body,type:bytea,nullzero" json:"response_body,omitempty"`
	ResponseHash          string              `bun:"response_hash,nullzero" json:"response_hash,omitempty"`
	ResponseTimeMs        int64               `bun:"response_time_ms,default:0" json:"response_time_ms"`
	ResponseWords         int64               `bun:"response_words,default:0" json:"response_words"`
	HasResponse           bool                `bun:"has_response,notnull,default:false" json:"has_response"`
	ResponseTitle         string              `bun:"response_title,nullzero" json:"response_title,omitempty"`

	// Parameters (JSON array, replaces http_parameters table)
	Parameters []EmbeddedParam `bun:"parameters,type:jsonb,nullzero" json:"parameters,omitempty"`

	// Timestamps
	SentAt     time.Time `bun:"sent_at,notnull,default:current_timestamp" json:"sent_at"`
	ReceivedAt time.Time `bun:"received_at,nullzero" json:"received_at,omitempty"`
	CreatedAt  time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`

	Source string `bun:"source,nullzero,default:''" json:"source,omitempty"`

	// Risk labeling (populated by background analysis)
	Remarks   []string `bun:"remarks,type:jsonb,nullzero" json:"remarks,omitempty"`
	RiskScore int      `bun:"risk_score,default:0" json:"risk_score"`
}

// EmbeddedParam represents a parameter stored as JSON within HTTPRecord
type EmbeddedParam struct {
	Name       string `json:"name"`
	Value      string `json:"value,omitempty"`
	Type       string `json:"type"`
	NameStart  int    `json:"name_start,omitempty"`
	NameEnd    int    `json:"name_end,omitempty"`
	ValueStart int    `json:"value_start,omitempty"`
	ValueEnd   int    `json:"value_end,omitempty"`
	Metadata   string `json:"metadata,omitempty"`
}

// Finding represents a vulnerability finding (no FK, soft UUID reference)
type Finding struct {
	bun.BaseModel `bun:"table:findings,alias:f" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`

	// UUID references to HTTPRecords (not FK, allows flexibility)
	HTTPRecordUUIDs []string `bun:"http_record_uuids,type:jsonb,notnull" json:"http_record_uuids"`

	// Scan reference (soft, no FK)
	ScanUUID string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`

	// Module info
	ModuleID      string   `bun:"module_id,notnull" json:"module_id"`
	ModuleName    string   `bun:"module_name,notnull" json:"module_name"`
	ModuleType    string   `bun:"module_type,nullzero" json:"module_type,omitempty"`
	FindingSource string   `bun:"finding_source,nullzero" json:"finding_source,omitempty"`
	ModuleShort   string   `bun:"module_short,nullzero" json:"module_short,omitempty"`
	Description string   `bun:"description,nullzero" json:"description,omitempty"`
	Severity    string   `bun:"severity,notnull" json:"severity"`
	Confidence  string   `bun:"confidence,notnull,default:'firm'" json:"confidence"`
	Tags        []string `bun:"tags,type:jsonb,nullzero" json:"tags,omitempty"`

	MatchedAt        []string `bun:"matched_at,type:jsonb,nullzero" json:"matched_at,omitempty"`
	ExtractedResults   []string `bun:"extracted_results,type:jsonb,nullzero" json:"extracted_results,omitempty"`
	AdditionalEvidence []string `bun:"additional_evidence,type:jsonb,nullzero" json:"additional_evidence,omitempty"`

	Request     string `bun:"request,nullzero" json:"request,omitempty"`
	Response    string `bun:"response,nullzero" json:"response,omitempty"`
	FindingHash string `bun:"finding_hash,notnull" json:"finding_hash"`

	FoundAt   time.Time `bun:"found_at,notnull,default:current_timestamp" json:"found_at"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// SourceRepo represents a link between a target hostname and its application source code on disk.
type SourceRepo struct {
	bun.BaseModel `bun:"table:source_repos,alias:sr" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	Hostname    string `bun:"hostname,notnull" json:"hostname"`
	ScanUUID    string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	Name      string `bun:"name,notnull" json:"name"`
	RootPath  string `bun:"root_path,notnull" json:"root_path"`
	RepoURL   string `bun:"repo_url,nullzero" json:"repo_url,omitempty"`
	RepoType  string `bun:"repo_type,notnull,default:'folder'" json:"repo_type"`
	Language  string `bun:"language,nullzero" json:"language,omitempty"`
	Framework string `bun:"framework,nullzero" json:"framework,omitempty"`

	Endpoints   []string               `bun:"endpoints,type:jsonb,nullzero" json:"endpoints,omitempty"`
	RouteParams []string               `bun:"route_params,type:jsonb,nullzero" json:"route_params,omitempty"`
	Sinks       []string               `bun:"sinks,type:jsonb,nullzero" json:"sinks,omitempty"`
	Tags        []string               `bun:"tags,type:jsonb,nullzero" json:"tags,omitempty"`
	Metadata    map[string]interface{} `bun:"metadata,type:jsonb,nullzero" json:"metadata,omitempty"`

	ThirdPartyScanStatus string    `bun:"third_party_scan_status,nullzero" json:"third_party_scan_status,omitempty"` // "", "running", "completed", "failed"
	ThirdPartyScanAt     time.Time `bun:"third_party_scan_at,nullzero" json:"third_party_scan_at,omitempty"`

	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// OASTInteraction records an out-of-band interaction received from an interactsh server.
type OASTInteraction struct {
	bun.BaseModel `bun:"table:oast_interactions,alias:oi" json:"-"`

	ID            int64     `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID   string    `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID      string    `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	UniqueID      string    `bun:"unique_id,notnull" json:"unique_id"`
	FullID        string    `bun:"full_id,notnull" json:"full_id"`
	Protocol      string    `bun:"protocol,notnull" json:"protocol"`
	QType         string    `bun:"q_type,nullzero" json:"q_type,omitempty"`
	RawRequest    string    `bun:"raw_request,nullzero" json:"raw_request,omitempty"`
	RawResponse   string    `bun:"raw_response,nullzero" json:"raw_response,omitempty"`
	RemoteAddress string    `bun:"remote_address,nullzero" json:"remote_address,omitempty"`
	InteractedAt  time.Time `bun:"interacted_at,notnull" json:"interacted_at"`

	// Correlated context from payload tracker
	TargetURL     string `bun:"target_url,nullzero" json:"target_url,omitempty"`
	ParameterName string `bun:"parameter_name,nullzero" json:"parameter_name,omitempty"`
	InjectionType string `bun:"injection_type,nullzero" json:"injection_type,omitempty"`
	ModuleID      string `bun:"module_id,nullzero" json:"module_id,omitempty"`

	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// ScanLog represents a log entry for a scan session.
type ScanLog struct {
	bun.BaseModel `bun:"table:scan_logs,alias:sl" json:"-"`

	ID          int64     `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string    `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string    `bun:"scan_uuid,notnull" json:"scan_uuid"`
	Level       string    `bun:"level,notnull" json:"level"`           // info, warn, error
	Phase     string    `bun:"phase,nullzero" json:"phase,omitempty"` // discovery, spidering, dynamic-assessment, etc.
	Message   string    `bun:"message,notnull" json:"message"`
	Metadata  string    `bun:"metadata,nullzero" json:"metadata,omitempty"` // JSON blob for extra context
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// AgentRun represents a single agent execution for debugging and status tracking.
// It replaces the in-memory agent run status map with persistent DB storage.
type AgentRun struct {
	bun.BaseModel `bun:"table:agent_runs,alias:ar" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	UUID        string `bun:"uuid,notnull,unique" json:"uuid"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`

	// Config
	Mode        string   `bun:"mode,notnull" json:"mode"`                                // query, autopilot, pipeline, scan
	AgentName   string   `bun:"agent_name,notnull" json:"agent_name"`
	InputRaw    string   `bun:"input_raw,nullzero" json:"input_raw,omitempty"`
	InputType   string   `bun:"input_type,nullzero" json:"input_type,omitempty"`          // url, curl, burp, raw, record_uuid
	TargetURL   string   `bun:"target_url,nullzero" json:"target_url,omitempty"`
	VulnType    string   `bun:"vuln_type,nullzero" json:"vuln_type,omitempty"`
	ModuleNames []string `bun:"module_names,type:jsonb,nullzero" json:"module_names,omitempty"`
	TemplateID  string   `bun:"template_id,nullzero" json:"template_id,omitempty"`

	// Execution
	Status       string   `bun:"status,notnull,default:'pending'" json:"status"` // pending, running, completed, failed, cancelled
	CurrentPhase string   `bun:"current_phase,nullzero" json:"current_phase,omitempty"`
	PhasesRun    []string `bun:"phases_run,type:jsonb,nullzero" json:"phases_run,omitempty"`

	// Results
	FindingCount int `bun:"finding_count,default:0" json:"finding_count"`
	RecordCount  int `bun:"record_count,default:0" json:"record_count"`
	SavedCount   int `bun:"saved_count,default:0" json:"saved_count"`

	// Agent session (ACP session ID for resume)
	SessionID string `bun:"session_id,nullzero" json:"session_id,omitempty"`

	// Debug (stored as JSON text blobs)
	AttackPlan     string `bun:"attack_plan,nullzero" json:"attack_plan,omitempty"`
	TriageResult   string `bun:"triage_result,nullzero" json:"triage_result,omitempty"`
	PromptSent     string `bun:"prompt_sent,nullzero" json:"prompt_sent,omitempty"`
	AgentRawOutput string `bun:"agent_raw_output,nullzero" json:"agent_raw_output,omitempty"`
	ErrorMessage   string `bun:"error_message,nullzero" json:"error_message,omitempty"`

	// Pipeline/scan result (JSON blob for full result objects)
	ResultJSON string `bun:"result_json,nullzero" json:"result_json,omitempty"`

	// Timing
	StartedAt   time.Time `bun:"started_at,nullzero" json:"started_at,omitempty"`
	CompletedAt time.Time `bun:"completed_at,nullzero" json:"completed_at,omitempty"`
	DurationMs  int64     `bun:"duration_ms,default:0" json:"duration_ms"`
	CreatedAt   time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// Scope defines URL/request scope rules (firewall-style: first match wins)
type Scope struct {
	bun.BaseModel `bun:"table:scopes,alias:s" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	Name        string `bun:"name,notnull" json:"name"`
	Description string `bun:"description,nullzero" json:"description,omitempty"`

	RuleType string `bun:"rule_type,notnull" json:"rule_type"` // "include" or "exclude"

	HostPattern string   `bun:"host_pattern,nullzero" json:"host_pattern,omitempty"`
	PathPattern string   `bun:"path_pattern,nullzero" json:"path_pattern,omitempty"`
	Methods     []string `bun:"methods,type:jsonb,nullzero" json:"methods,omitempty"`
	Ports       []int    `bun:"ports,type:jsonb,nullzero" json:"ports,omitempty"`
	Schemes     []string `bun:"schemes,type:jsonb,nullzero" json:"schemes,omitempty"`

	Priority int  `bun:"priority,notnull,default:100" json:"priority"`
	Enabled  bool `bun:"enabled,notnull,default:true" json:"enabled"`

	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}
