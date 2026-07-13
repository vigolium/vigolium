package database

import (
	"strings"
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

	Tags          []string  `bun:"tags,type:jsonb,nullzero" json:"tags,omitempty"`
	DefaultTarget string    `bun:"default_target,nullzero" json:"default_target,omitempty"`
	LastScanAt    time.Time `bun:"last_scan_at,nullzero" json:"last_scan_at,omitempty"`

	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// DefaultProjectUUID is the UUID for the default project created during init.
// Lowercased for consistency with uuid.New().String() output and byte-wise SQL comparisons.
const DefaultProjectUUID = "00000000-0000-0000-defa-c01001000001"

// ModuleType constants classify the kind of module that created a finding.
const (
	ModuleTypeActive         = "active"
	ModuleTypePassive        = "passive"
	ModuleTypeNuclei         = "nuclei"
	ModuleTypeAgent          = "agent"
	ModuleTypeOAST           = "oast"
	ModuleTypeExtension      = "extension"
	ModuleTypeKnownIssueScan = "known-issue-scan"
	ModuleTypeWhitebox       = "whitebox"
)

// FindingSource constants identify which phase/component produced a finding.
const (
	FindingSourceDynamicAssessment = "dynamic-assessment"
	FindingSourceKnownIssueScan    = "known-issue-scan"
	FindingSourceAgent             = "agent"
	FindingSourceOAST              = "oast"
	FindingSourceExtension         = "extension"
	FindingSourceAudit             = "audit"
	FindingSourceImport            = "import"
	FindingSourceSpidering         = "spidering"
)

// Record-kind constants distinguish reportable vulnerabilities from retained
// reconnaissance and unconfirmed hypotheses stored in the same table.
const (
	RecordKindFinding     = "finding"
	RecordKindCandidate   = "candidate"
	RecordKindObservation = "observation"
)

// Status constants represent the lifecycle state of a Finding.
//
// Lifecycle:
//
//	draft ──triage──▶ triaged ──fix──▶ fixed
//	             ╲──▶ false_positive
//	             ╲──▶ accepted_risk
//
// Trust model: deterministic engines (native scan, SAST tools) produce
// findings as `triaged`. LLM/agent-driven and externally imported findings
// land as `draft` and require triage to be promoted.
const (
	StatusDraft         = "draft"
	StatusTriaged       = "triaged"
	StatusFalsePositive = "false_positive"
	StatusAcceptedRisk  = "accepted_risk"
	StatusFixed         = "fixed"
)

// Severity constants represent the canonical severity strings stored on a
// Finding. They match the lowercase keys used by `vigolium finding --severity`
// and the severity counters on Scan.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
	SeveritySuspect  = "suspect"
)

// SourceType constants classify how source code was provided.
const (
	SourceTypeLocal  = "local"
	SourceTypeGitURL = "git-url"
	SourceTypeGCS    = "gcs"
)

// InferSourceType returns the source type for a given path or URL.
// Both "gs://" (canonical) and "gcs://" (alias) are recognized as cloud storage.
func InferSourceType(sourcePath string) string {
	if sourcePath == "" {
		return ""
	}
	if strings.HasPrefix(sourcePath, "gs://") || strings.HasPrefix(sourcePath, "gcs://") {
		return SourceTypeGCS
	}
	if strings.HasPrefix(sourcePath, "http://") || strings.HasPrefix(sourcePath, "https://") || strings.HasPrefix(sourcePath, "git@") {
		return SourceTypeGitURL
	}
	return SourceTypeLocal
}

// DefaultUserUUID is the well-known UUID for the default local user created during init.
const DefaultUserUUID = "00000000-0000-0000-0000-000000000001"

// Scan represents a scan session
type Scan struct {
	bun.BaseModel `bun:"table:scans,alias:sc" json:"-"`

	UUID        string `bun:"uuid,pk,notnull" json:"uuid"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	Name        string `bun:"name,nullzero" json:"name"`
	Description string `bun:"description,nullzero" json:"description"`
	Status      string `bun:"status,notnull,default:'running'" json:"status"` // running, paused, completed, failed, cancelled
	// Target can be a URL, domain, IP, CIDR, or file path (for imported requests)
	Target  string `bun:"target,nullzero" json:"target"`
	Modules string `bun:"modules,nullzero" json:"modules"`
	Threads int    `bun:"threads,default:0" json:"threads"`

	// Scan context
	Profile         string   `bun:"profile,nullzero" json:"profile"`                     // scanning profile used (light, full, api, etc.)
	SourcePath      string   `bun:"source_path,nullzero" json:"source_path"`             // source code path for audit/agent scans
	SourceType      string   `bun:"source_type,nullzero" json:"source_type"`             // local, git-url, gcs
	Tags            []string `bun:"tags,type:jsonb,nullzero" json:"tags"`                // arbitrary tags for filtering/grouping
	TriggeredBy     string   `bun:"triggered_by,nullzero" json:"triggered_by"`           // user, schedule, webhook, agent
	AgenticScanUUID string   `bun:"agentic_scan_uuid,nullzero" json:"agentic_scan_uuid"` // link to agentic_scan that spawned this scan

	// Soft reference to the HTTP record that triggered this scan (scan-on-receive)
	HTTPRecordUUID string `bun:"http_record_uuid,nullzero" json:"http_record_uuid"`

	// Cursor-based scan tracking
	ScanSource      string    `bun:"scan_source,nullzero" json:"scan_source"`         // "cli", "api", "scan-on-receive"
	ScanMode        string    `bun:"scan_mode,nullzero" json:"scan_mode"`             // "incremental" or "full"
	StartCursorAt   time.Time `bun:"start_cursor_at,nullzero" json:"start_cursor_at"` // cursor position at scan start
	StartCursorUUID string    `bun:"start_cursor_uuid,nullzero" json:"start_cursor_uuid"`
	CursorAt        time.Time `bun:"cursor_at,nullzero" json:"cursor_at"` // current cursor position
	CursorUUID      string    `bun:"cursor_uuid,nullzero" json:"cursor_uuid"`
	ProcessedCount  int64     `bun:"processed_count,default:0" json:"processed_count"`

	StartedAt  time.Time `bun:"started_at,notnull,default:current_timestamp" json:"started_at"`
	FinishedAt time.Time `bun:"finished_at,nullzero" json:"finished_at"`
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
	ErrorMessage string `bun:"error_message,nullzero" json:"error_message"`

	StorageURL string `bun:"storage_url,nullzero" json:"storage_url"`

	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}

// HTTPRecord represents a single HTTP request/response record (denormalized)
type HTTPRecord struct {
	bun.BaseModel `bun:"table:http_records,alias:r" json:"-"`

	UUID        string `bun:"uuid,pk,notnull" json:"uuid"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"` // link to scan that produced this record

	// Host info (embedded, replaces hosts table)
	Scheme   string `bun:"scheme,notnull" json:"scheme"`
	Hostname string `bun:"hostname,notnull" json:"hostname"`
	Port     int    `bun:"port,notnull" json:"port"`
	IP       string `bun:"ip,nullzero" json:"ip,omitempty"` // resolved IP address (cached per hostname)

	// Request fields
	Method               string `bun:"method,notnull" json:"method"`
	Path                 string `bun:"path,notnull" json:"path"`
	URL                  string `bun:"url,notnull" json:"url"`
	HTTPVersion          string `bun:"http_version,notnull" json:"http_version"`
	RequestContentType   string `bun:"request_content_type,nullzero" json:"request_content_type,omitempty"`
	RequestContentLength int64  `bun:"request_content_length,default:0" json:"request_content_length"`
	RawRequest           []byte `bun:"raw_request,type:bytea,nullzero" json:"raw_request,omitempty"`
	RequestHash          string `bun:"request_hash,notnull" json:"request_hash"`
	RequestAuthorization string `bun:"request_authorization,nullzero" json:"request_authorization,omitempty"`

	// Response fields
	StatusCode            int    `bun:"status_code,default:0" json:"status_code"`
	StatusPhrase          string `bun:"status_phrase,nullzero" json:"status_phrase,omitempty"`
	ResponseHTTPVersion   string `bun:"response_http_version,nullzero" json:"response_http_version,omitempty"`
	ResponseContentType   string `bun:"response_content_type,nullzero" json:"response_content_type,omitempty"`
	ResponseContentLength int64  `bun:"response_content_length,default:0" json:"response_content_length"`
	RawResponse           []byte `bun:"raw_response,type:bytea,nullzero" json:"raw_response,omitempty"`
	ResponseHash          string `bun:"response_hash,nullzero" json:"response_hash,omitempty"`
	ResponseNormHash      string `bun:"response_norm_hash,nullzero" json:"response_norm_hash,omitempty"` // hash of the body with reflected URL/path + dynamic runs stripped, for reflected-URL-robust dedup
	ResponseTimeMs        int64  `bun:"response_time_ms,default:0" json:"response_time_ms"`
	ResponseWords         int64  `bun:"response_words,default:0" json:"response_words"`
	HasResponse           bool   `bun:"has_response,notnull,default:false" json:"has_response"`
	ResponseTitle         string `bun:"response_title,nullzero" json:"response_title,omitempty"`

	// Parameters (JSON array, replaces http_parameters table)
	Parameters []EmbeddedParam `bun:"parameters,type:jsonb,nullzero" json:"parameters,omitempty"`

	// Timestamps
	SentAt     time.Time `bun:"sent_at,notnull,default:current_timestamp" json:"sent_at"`
	ReceivedAt time.Time `bun:"received_at,nullzero" json:"received_at,omitempty"`
	CreatedAt  time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`

	Source string `bun:"source,nullzero,default:''" json:"source,omitempty"`

	// Analysis & enrichment
	Technology      []string `bun:"technology,type:jsonb,nullzero" json:"technology,omitempty"`     // detected technologies/frameworks
	ContentHash     string   `bun:"content_hash,nullzero" json:"content_hash,omitempty"`            // hash of meaningful response content for change detection
	IsAuthenticated bool     `bun:"is_authenticated,notnull,default:false" json:"is_authenticated"` // whether request was sent with valid auth
	ParentUUID      string   `bun:"parent_uuid,nullzero" json:"parent_uuid,omitempty"`              // parent record UUID (crawl/spider parent)

	// Risk labeling (populated by background analysis)
	Remarks   []string `bun:"remarks,type:jsonb,nullzero" json:"remarks,omitempty"`
	RiskScore int      `bun:"risk_score,default:0" json:"risk_score"`
}

// AnalysisArtifact stores immutable derived content linked to an HTTP record.
// It deliberately lives beside, rather than inside, HTTPRecord so analysis can
// never replace the raw evidence captured from the target.
type AnalysisArtifact struct {
	bun.BaseModel `bun:"table:analysis_artifacts,alias:aa" json:"-"`

	ID             int64     `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID    string    `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID       string    `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	HTTPRecordUUID string    `bun:"http_record_uuid,notnull" json:"http_record_uuid"`
	Kind           string    `bun:"kind,notnull" json:"kind"`
	Filename       string    `bun:"filename,nullzero" json:"filename,omitempty"`
	MediaType      string    `bun:"media_type,nullzero" json:"media_type,omitempty"`
	SHA256         string    `bun:"sha256,notnull" json:"sha256"`
	ByteLength     int64     `bun:"byte_length,notnull" json:"byte_length"`
	Content        []byte    `bun:"content,type:bytea,notnull" json:"content,omitempty"`
	Metadata       string    `bun:"metadata,type:jsonb,nullzero" json:"metadata,omitempty"`
	CreatedAt      time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
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
	ScanUUID        string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	AgenticScanUUID string `bun:"agentic_scan_uuid,nullzero" json:"agentic_scan_uuid,omitempty"` // link to agentic_scan that produced this finding

	// Denormalized target info (for fast display/filtering without joining)
	URL      string `bun:"url,nullzero" json:"url,omitempty"`
	Hostname string `bun:"hostname,nullzero" json:"hostname,omitempty"`

	// Module info
	ModuleID      string   `bun:"module_id,notnull" json:"module_id"`
	ModuleName    string   `bun:"module_name,notnull" json:"module_name"`
	ModuleType    string   `bun:"module_type,nullzero" json:"module_type,omitempty"`
	FindingSource string   `bun:"finding_source,nullzero" json:"finding_source,omitempty"`
	RecordKind    string   `bun:"record_kind,notnull,default:'finding'" json:"record_kind,omitempty"`
	EvidenceGrade string   `bun:"evidence_grade,nullzero" json:"evidence_grade,omitempty"`
	ModuleShort   string   `bun:"module_short,nullzero" json:"module_short,omitempty"`
	Description   string   `bun:"description,nullzero" json:"description,omitempty"`
	Severity      string   `bun:"severity,notnull" json:"severity"`
	Confidence    string   `bun:"confidence,notnull,default:'firm'" json:"confidence"`
	Tags          []string `bun:"tags,type:jsonb,nullzero" json:"tags,omitempty"`

	// Finding lifecycle
	Status      string `bun:"status,nullzero,default:'triaged'" json:"status,omitempty"` // draft, triaged, false_positive, accepted_risk, fixed
	Remediation string `bun:"remediation,nullzero" json:"remediation,omitempty"`

	// Classification
	CWEID     string  `bun:"cwe_id,nullzero" json:"cwe_id,omitempty"`
	CVSSScore float64 `bun:"cvss_score,default:0" json:"cvss_score"`

	// Source info (for audit findings)
	SourceFile string `bun:"source_file,nullzero" json:"source_file,omitempty"`
	RepoName   string `bun:"repo_name,nullzero" json:"repo_name,omitempty"` // repository name or URL for audit findings

	MatchedAt          []string `bun:"matched_at,type:jsonb,nullzero" json:"matched_at,omitempty"`
	ExtractedResults   []string `bun:"extracted_results,type:jsonb,nullzero" json:"extracted_results,omitempty"`
	AdditionalEvidence []string `bun:"additional_evidence,type:jsonb,nullzero" json:"additional_evidence,omitempty"`

	Request     string `bun:"request,nullzero" json:"request,omitempty"`
	Response    string `bun:"response,nullzero" json:"response,omitempty"`
	FindingHash string `bun:"finding_hash,notnull" json:"finding_hash"`

	FoundAt   time.Time `bun:"found_at,notnull,default:current_timestamp" json:"found_at"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// AuthenticationHostname persists per-hostname session auth configs in the DB.
type AuthenticationHostname struct {
	bun.BaseModel `bun:"table:authentication_hostnames,alias:sh" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`

	Hostname string `bun:"hostname,notnull" json:"hostname"`

	SessionName string `bun:"session_name,notnull" json:"session_name"`
	SessionRole string `bun:"session_role,nullzero,default:''" json:"session_role,omitempty"`
	Position    int    `bun:"position,default:0" json:"position"`

	// Primary session token (JWT, cookie value, API key) for quick access.
	SessionToken string `bun:"session_token,nullzero" json:"session_token,omitempty"`

	// Static auth headers (JSON map)
	Headers map[string]string `bun:"headers,type:jsonb,nullzero" json:"headers,omitempty"`

	// Login flow fields (flat for queryability)
	LoginURL         string `bun:"login_url,nullzero" json:"login_url,omitempty"`
	LoginMethod      string `bun:"login_method,nullzero" json:"login_method,omitempty"`
	LoginContentType string `bun:"login_content_type,nullzero" json:"login_content_type,omitempty"`
	LoginBody        string `bun:"login_body,nullzero" json:"login_body,omitempty"`
	LoginRequest     string `bun:"login_request,nullzero" json:"login_request,omitempty"`
	LoginResponse    string `bun:"login_response,nullzero" json:"login_response,omitempty"`

	// Extract rules (JSON array)
	ExtractRules string `bun:"extract_rules,type:jsonb,nullzero" json:"extract_rules,omitempty"`

	Source     string     `bun:"source,nullzero,default:''" json:"source,omitempty"`
	HydratedAt *time.Time `bun:"hydrated_at,nullzero" json:"hydrated_at,omitempty"`
	CreatedAt  time.Time  `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt  time.Time  `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
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
	FindingID     int64  `bun:"finding_id,nullzero" json:"finding_id,omitempty"` // link to finding this interaction proves
	Payload       string `bun:"payload,nullzero" json:"payload,omitempty"`       // exact payload that triggered the interaction

	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// ScanLog represents a log entry for a scan session.
type ScanLog struct {
	bun.BaseModel `bun:"table:scan_logs,alias:sl" json:"-"`

	ID          int64     `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string    `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string    `bun:"scan_uuid,notnull" json:"scan_uuid"`
	Level       string    `bun:"level,notnull" json:"level"`            // trace, info, warn, error
	Phase       string    `bun:"phase,nullzero" json:"phase,omitempty"` // discovery, spidering, dynamic-assessment, etc.
	Message     string    `bun:"message,notnull" json:"message"`
	Metadata    string    `bun:"metadata,nullzero" json:"metadata,omitempty"` // JSON blob for extra context
	CreatedAt   time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// AgenticScan represents a single agent execution for debugging and status tracking.
// It replaces the in-memory agent run status map with persistent DB storage.
type AgenticScan struct {
	bun.BaseModel `bun:"table:agentic_scans,alias:ar" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	UUID        string `bun:"uuid,notnull,unique" json:"uuid"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`

	// Config
	Mode        string   `bun:"mode,notnull" json:"mode"` // query, autopilot, pipeline, scan
	AgentName   string   `bun:"agent_name,notnull" json:"agent_name"`
	Protocol    string   `bun:"protocol,nullzero" json:"protocol,omitempty"` // engine identifier — currently always "olium-engine" (subprocess SDK backends removed)
	Model       string   `bun:"model,nullzero" json:"model,omitempty"`       // model name used for this run (for cost audit)
	InputRaw    string   `bun:"input_raw,nullzero" json:"input_raw,omitempty"`
	InputType   string   `bun:"input_type,nullzero" json:"input_type,omitempty"` // url, curl, burp, raw, record_uuid
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

	// Agent context
	SourcePath            string                 `bun:"source_path,nullzero" json:"source_path,omitempty"`            // source code path used
	SourceType            string                 `bun:"source_type,nullzero" json:"source_type,omitempty"`            // local, git-url, gcs
	TokenUsage            map[string]interface{} `bun:"token_usage,type:jsonb,nullzero" json:"token_usage,omitempty"` // input/output token counts per phase
	TotalInputTokens      int64                  `bun:"total_input_tokens,default:0" json:"total_input_tokens"`
	TotalOutputTokens     int64                  `bun:"total_output_tokens,default:0" json:"total_output_tokens"`
	EstimatedCostUSD      float64                `bun:"estimated_cost_usd,default:0" json:"estimated_cost_usd"`
	RetryCount            int                    `bun:"retry_count,default:0" json:"retry_count"`
	ParentAgenticScanUUID string                 `bun:"parent_run_uuid,nullzero" json:"parent_agentic_scan_uuid,omitempty"` // for swarm sub-runs
	InputRecordCount      int                    `bun:"input_record_count,default:0" json:"input_record_count"`

	// Agent session ID (for resume)
	SessionID string `bun:"session_id,nullzero" json:"session_id,omitempty"`

	// Filesystem path to the session directory holding agent artifacts
	// (output.md, audit-stream.jsonl, extensions/, etc.). Populated by the
	// server handlers so API clients can locate run outputs.
	SessionDir string `bun:"session_dir,nullzero" json:"session_dir,omitempty"`

	// Debug (stored as JSON text blobs)
	AttackPlan     string `bun:"attack_plan,nullzero" json:"attack_plan,omitempty"`
	TriageResult   string `bun:"triage_result,nullzero" json:"triage_result,omitempty"`
	PromptSent     string `bun:"prompt_sent,nullzero" json:"prompt_sent,omitempty"`
	AgentRawOutput string `bun:"agent_raw_output,nullzero" json:"agent_raw_output,omitempty"`
	ErrorMessage   string `bun:"error_message,nullzero" json:"error_message,omitempty"`

	// Pipeline/scan result (JSON blob for full result objects)
	ResultJSON string `bun:"result_json,nullzero" json:"result_json,omitempty"`

	StorageURL string `bun:"storage_url,nullzero" json:"storage_url,omitempty"`

	// Timing
	StartedAt   time.Time `bun:"started_at,nullzero" json:"started_at,omitempty"`
	CompletedAt time.Time `bun:"completed_at,nullzero" json:"completed_at,omitempty"`
	DurationMs  int64     `bun:"duration_ms,default:0" json:"duration_ms"`
	CreatedAt   time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// AgentSection represents one bounded operator section within a durable
// autopilot run (an engine Reset() + reconstructed-brief cycle). Rows are only
// written when agent.olium.autopilot_mode != legacy; legacy runs never touch
// this table. Cascade-deleted with the parent agentic scan.
type AgentSection struct {
	bun.BaseModel `bun:"table:agent_sections,alias:asec" json:"-"`

	ID              int64  `bun:"id,pk,autoincrement" json:"id"`
	UUID            string `bun:"uuid,notnull,unique" json:"uuid"`
	AgenticScanUUID string `bun:"agentic_scan_uuid,nullzero" json:"agentic_scan_uuid,omitempty"`
	ProjectUUID     string `bun:"project_uuid,nullzero" json:"project_uuid,omitempty"`

	Seq            int    `bun:"seq,notnull,default:0" json:"seq"`
	Kind           string `bun:"kind,nullzero" json:"kind,omitempty"`
	Status         string `bun:"status,notnull,default:'running'" json:"status"` // running | completed | interrupted
	Task           string `bun:"task,nullzero" json:"task,omitempty"`
	ClosingSummary string `bun:"closing_summary,nullzero" json:"closing_summary,omitempty"`
	RotationReason string `bun:"rotation_reason,nullzero" json:"rotation_reason,omitempty"`
	TurnCount      int    `bun:"turn_count,notnull,default:0" json:"turn_count"`
	InputTokens    int64  `bun:"input_tokens,notnull,default:0" json:"input_tokens"`
	OutputTokens   int64  `bun:"output_tokens,notnull,default:0" json:"output_tokens"`
	ErrorMessage   string `bun:"error_message,nullzero" json:"error_message,omitempty"`

	StartedAt time.Time `bun:"started_at,nullzero" json:"started_at,omitempty"`
	EndedAt   time.Time `bun:"ended_at,nullzero" json:"ended_at,omitempty"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// AgentFindingCandidate is a proposed finding awaiting fresh-context
// verification in the durable-autopilot verify-before-promote pipeline. The
// operator's propose_candidate tool writes rows here (status=proposed); a
// skeptic verifier grades them, and confirmed ones are promoted into a real
// Finding (promoted_finding_id set, status=confirmed). Rows are only written
// when agent.olium.autopilot_mode != legacy. Cascade-deleted with the parent
// agentic scan.
type AgentFindingCandidate struct {
	bun.BaseModel `bun:"table:agent_finding_candidates,alias:acand" json:"-"`

	ID              int64  `bun:"id,pk,autoincrement" json:"id"`
	UUID            string `bun:"uuid,notnull,unique" json:"uuid"`
	AgenticScanUUID string `bun:"agentic_scan_uuid,nullzero" json:"agentic_scan_uuid,omitempty"`
	ProjectUUID     string `bun:"project_uuid,nullzero" json:"project_uuid,omitempty"`
	SectionUUID     string `bun:"section_uuid,nullzero" json:"section_uuid,omitempty"`

	Title       string `bun:"title,nullzero" json:"title,omitempty"`
	Severity    string `bun:"severity,nullzero" json:"severity,omitempty"`
	Description string `bun:"description,nullzero" json:"description,omitempty"`
	Remediation string `bun:"remediation,nullzero" json:"remediation,omitempty"`
	CWEID       string `bun:"cwe_id,nullzero" json:"cwe_id,omitempty"`
	SourceFile  string `bun:"source_file,nullzero" json:"source_file,omitempty"`
	URL         string `bun:"url,nullzero" json:"url,omitempty"`
	Hostname    string `bun:"hostname,nullzero" json:"hostname,omitempty"`
	Confidence  string `bun:"confidence,nullzero" json:"confidence,omitempty"`
	Class       string `bun:"class,nullzero" json:"class,omitempty"` // idor | xss | sqli | ssrf | rce | auth | other

	Status        string `bun:"status,notnull,default:'proposed'" json:"status"` // proposed | verifying | confirmed | rejected | needs_evidence
	VerdictReason string `bun:"verdict_reason,nullzero" json:"verdict_reason,omitempty"`
	EvidenceGrade string `bun:"evidence_grade,nullzero" json:"evidence_grade,omitempty"`

	RecordUUIDs []string `bun:"record_uuids,type:jsonb,nullzero" json:"record_uuids,omitempty"`
	OASTIDs     []string `bun:"oast_ids,type:jsonb,nullzero" json:"oast_ids,omitempty"`
	Request     string   `bun:"request,nullzero" json:"request,omitempty"`
	Response    string   `bun:"response,nullzero" json:"response,omitempty"`

	DedupHash         string   `bun:"dedup_hash,notnull,default:''" json:"dedup_hash"`
	PromotedFindingID int64    `bun:"promoted_finding_id,notnull,default:0" json:"promoted_finding_id"`
	Tags              []string `bun:"tags,type:jsonb,nullzero" json:"tags,omitempty"`

	CreatedAt  time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	VerifiedAt time.Time `bun:"verified_at,nullzero" json:"verified_at,omitempty"`
}

// Scope defines URL/request scope rules (firewall-style: first match wins)
type Scope struct {
	bun.BaseModel `bun:"table:scopes,alias:s" json:"-"`

	ID          int64  `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string `bun:"project_uuid,notnull" json:"project_uuid"`
	Name        string `bun:"name,notnull" json:"name"`
	Description string `bun:"description,nullzero" json:"description,omitempty"`

	RuleType string `bun:"rule_type,notnull" json:"rule_type"` // "include" or "exclude"

	HostPattern        string   `bun:"host_pattern,nullzero" json:"host_pattern,omitempty"`
	PathPattern        string   `bun:"path_pattern,nullzero" json:"path_pattern,omitempty"`
	ContentTypePattern string   `bun:"content_type_pattern,nullzero" json:"content_type_pattern,omitempty"` // e.g., "image/*" to exclude
	Methods            []string `bun:"methods,type:jsonb,nullzero" json:"methods,omitempty"`
	Ports              []int    `bun:"ports,type:jsonb,nullzero" json:"ports,omitempty"`
	Schemes            []string `bun:"schemes,type:jsonb,nullzero" json:"schemes,omitempty"`

	Priority      int       `bun:"priority,notnull,default:100" json:"priority"`
	Enabled       bool      `bun:"enabled,notnull,default:true" json:"enabled"`
	HitCount      int64     `bun:"hit_count,default:0" json:"hit_count"`
	LastMatchedAt time.Time `bun:"last_matched_at,nullzero" json:"last_matched_at,omitempty"`

	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updated_at"`
}
