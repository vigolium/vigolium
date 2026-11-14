package database

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/tlsprobe"
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
//	draft ──triage──▶ triaged ──verify──▶ confirmed ──fix──▶ fixed
//	             ╲──▶ false_positive
//	             ╲──▶ accepted_risk
//
// confirmed means a human or a re-verification reproduced the finding; it is a
// status, not a verification result (that is Finding.Verification, kept apart
// so re-running `finding verify` never silently rewrites a triage verdict).
//
// Trust model: deterministic engines (native scan, SAST tools) produce
// findings as `triaged`. LLM/agent-driven and externally imported findings
// land as `draft` and require triage to be promoted.
const (
	StatusDraft         = "draft"
	StatusTriaged       = "triaged"
	StatusConfirmed     = "confirmed"
	StatusFalsePositive = "false_positive"
	StatusAcceptedRisk  = "accepted_risk"
	StatusFixed         = "fixed"
)

// FindingStatuses is the closed finding-status vocabulary, in lifecycle order.
// IsValidFindingStatus, the REST validation message and any closed-enum
// consumer read this list rather than keeping their own.
var FindingStatuses = []string{
	StatusDraft, StatusTriaged, StatusConfirmed, StatusFalsePositive, StatusAcceptedRisk, StatusFixed,
}

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
	// ScopeOriginMode is the RESOLVED origin-scope mode the scan ran under (all,
	// relaxed, balanced, strict) — never the raw --scope-origin value, which is
	// empty on the common run that takes the default. Persisted because it is the
	// setting that decides which HOSTS the scan was allowed to touch: on a
	// database carrying traffic from earlier scans, "balanced" admits every
	// sibling subdomain of the target's eTLD+1, so a result set cannot be read
	// correctly without it. Written by the runner (the single owner of the
	// fallback chain) for CLI, server and scan-on-receive runs alike, and carried
	// out through the `scan` envelope of --format jsonl and the REST scan object.
	ScopeOriginMode string   `bun:"scope_origin_mode,nullzero" json:"scope_origin_mode"`
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

	// Scan completeness — whether the scan covered everything it was given, and
	// if not, why and where. Written by the runner's finalizer, which is the only
	// component that sees every phase's outcome.
	//
	// Status alone could never answer this: "completed" meant "the process
	// reached the end", so a scan whose total budget fired after two of seven
	// phases, or whose dynamic assessment was cut off at its own deadline, was
	// indistinguishable from one that finished the whole plan. That mattered
	// beyond reporting — scan-on-receive treats a completed scan as a valid
	// predecessor and inherits its cursor, so a curtailed run that looked clean
	// made the NEXT run skip the records the first one never processed.
	//
	// An EMPTY Completeness means unknown (an older binary, or an agent/server
	// caller with no outcome data) and must never be read as "complete".
	Completeness  string         `bun:"completeness,nullzero" json:"completeness,omitempty"`
	StopReason    string         `bun:"stop_reason,nullzero" json:"stop_reason,omitempty"`
	PhaseOutcomes []PhaseOutcome `bun:"phase_outcomes,type:jsonb,nullzero" json:"phase_outcomes,omitempty"`

	// Plan is the resolved scan plan (phases, budgets, pacing) as JSON, written
	// once when the run starts. Opaque here: the plan resolver owns its shape.
	Plan json.RawMessage `bun:"plan,type:jsonb,nullzero" json:"plan,omitempty"`

	// Run liveness, refreshed by the runner's heartbeat while the scan runs.
	// A row whose heartbeat stopped advancing while status is still "running"
	// belongs to a process that died; PID and RunnerHost let a reader on the
	// same host confirm that without waiting out the staleness window.
	HeartbeatAt  *time.Time `bun:"heartbeat_at,nullzero" json:"heartbeat_at,omitempty"`
	CurrentPhase string     `bun:"current_phase,nullzero" json:"current_phase,omitempty"`
	PID          int        `bun:"pid,nullzero" json:"pid,omitempty"`
	RunnerHost   string     `bun:"runner_host,nullzero" json:"runner_host,omitempty"`

	// ModuleErrors counts errors per module ID over the run; ExtensionsFailed
	// lists extensions that failed to load. scan.finished reads both back from
	// the row.
	ModuleErrors     map[string]int64 `bun:"module_errors,type:jsonb,nullzero" json:"module_errors,omitempty"`
	ExtensionsFailed []string         `bun:"extensions_failed,type:jsonb,nullzero" json:"extensions_failed,omitempty"`
	// ModuleStats is the per-module ledger (schema v6): calls, wire requests,
	// errors and skips by reason, so "why was this module not run / what did it
	// cost" has an answer on the row.
	ModuleStats map[string]ModuleStat `bun:"module_stats,type:jsonb,nullzero" json:"module_stats,omitempty"`

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
	IP       string `bun:"ip,nullzero" json:"ip,omitempty"` // resolved IP address the request went to (httpx: host_ip)

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
	// ResponseTimeMs is 0 when the exchange was never timed, which is not the
	// same as "it took no time". Only the requester measures, so every record
	// rebuilt from stored bytes — and every intermediate redirect hop, which
	// the transport followed inside one measurement — has nothing to report.
	//
	// omitempty so an unmeasured row omits the field entirely. A silent zero is
	// worse than an absent one: a consumer averaging over a chain gets a number
	// that is wrong rather than one it knows it cannot compute.
	ResponseTimeMs int64  `bun:"response_time_ms,default:0" json:"response_time_ms,omitempty"`
	ResponseWords  int64  `bun:"response_words,default:0" json:"response_words"`
	HasResponse    bool   `bun:"has_response,notnull,default:false" json:"has_response"`
	ResponseTitle  string `bun:"response_title,nullzero" json:"response_title,omitempty"`

	// ResponseLocation is the Location header of a 3xx response, stored verbatim
	// — relative values included, because rewriting them to absolute would be
	// this column asserting something the server did not say.
	//
	// It exists because the redirect tree needs exactly one header out of a
	// response whose body it has no use for. Without a column the destination is
	// only recoverable by reading raw_response back, which on a `--glob-db` read
	// means reopening every source file the selected redirects came from and
	// holding an 8 KiB prefix per row until rendering finishes. Parsing it once at
	// ingestion and storing ~30 bytes replaces all of that.
	//
	// Empty means "no Location", which for a record written by this version is
	// also the answer for a non-redirect. It does NOT distinguish "not backfilled"
	// on a record written before this column existed — see
	// redirectLocationsAreBackfilled for how the read path handles that.
	ResponseLocation string `bun:"response_location,nullzero" json:"response_location,omitempty"`

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

	// Target is the input line this record's chain started from, as it appears
	// in the run's target list (normalized to an absolute URL). Empty for
	// records that did not come from a submitted target — crawl discoveries,
	// ingest.
	//
	// It exists because hostname is THIS HOP's hostname, not the one that was
	// asked about. A followed redirect that leaves the host produces records
	// under names nobody submitted, and a consumer keying on hostname then
	// reports a host it invented. Recovering the input otherwise means walking
	// parent_uuid to the root, which no single record can answer and which a
	// truncated chain can break outright.
	Target string `bun:"target,nullzero" json:"target,omitempty"`
	// RootUUID is the first record of this record's redirect chain — itself for
	// a root. Redundant with walking ParentUUID, and deliberately so: the walk
	// is O(chain) and needs the whole stream, this is O(1) on one record and
	// survives the middle of a chain being dropped by the storage cap.
	RootUUID string `bun:"root_uuid,nullzero" json:"root_uuid,omitempty"`
	// ChainTruncated marks the last stored row of a redirect chain that did not
	// reach its destination — the follow cap was hit, or the storage cap
	// dropped hops after this one.
	//
	// Without it a 3xx at the end of a chain is ambiguous in a way that reads
	// as an answer: "this redirect pointed somewhere that never replied" and
	// "we stopped walking" produce an identical row, and the obvious consumer
	// reading ("the terminal hop is the row nothing claims as a parent") takes
	// the 3xx as final in both cases.
	ChainTruncated bool `bun:"chain_truncated,notnull,default:false" json:"chain_truncated,omitempty"`

	// Risk labeling (populated by background analysis)
	Remarks   []string `bun:"remarks,type:jsonb,nullzero" json:"remarks,omitempty"`
	RiskScore int      `bun:"risk_score,default:0" json:"risk_score"`

	// SurfaceScore is the deterministic attack-surface score (0-100) written by
	// the surface_scoring passive module, which owns the signal set and the
	// scale — see pkg/modules/passive/surface_scoring. It
	// answers "is this record worth attacking" from properties of the record
	// itself, and is reproducible across scans.
	//
	// Deliberately NOT merged into RiskScore: that column holds anomaly_ranking's
	// rank-within-batch percentile, which measures statistical rarity against
	// whichever records happened to be flushed alongside it. The two are different
	// scales from different inputs; sharing one column would mean whichever module
	// flushed last silently overwrote the other.
	SurfaceScore int `bun:"surface_score,default:0" json:"surface_score"`

	// BodyCompaction is set when `vigolium db compact` replaced a stored body
	// with its head, and records what the original was. Nil means RawRequest
	// and RawResponse hold the bodies exactly as captured. See BodyCompaction.
	BodyCompaction *BodyCompaction `bun:"body_compaction,type:jsonb,nullzero" json:"body_compaction,omitempty"`
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

// HostObservation is what one scan observed about one endpoint: the full DNS
// answer and, under --tls-probe, the handshake and leaf certificate.
//
// It is the durable counterpart to the process-local caches HostFacts reads.
// Those caches are bounded (8192 entries each) and evict in insertion order, so
// on a sweep larger than that the hosts resolved FIRST had their answers dropped
// before the export that wanted them - the work was done, the answer was known,
// and the output silently omitted it. A row here survives eviction, the process,
// and the run.
//
// One row per (scan, hostname, port). Re-probing a host adds an observation, it
// does not replace one: the addresses a host resolved to during an earlier scan
// are that scan's evidence, and an upsert keyed on the host alone would erase it.
type HostObservation struct {
	bun.BaseModel `bun:"table:host_observations,alias:ho" json:"-"`

	ID          int64     `bun:"id,pk,autoincrement" json:"id"`
	ProjectUUID string    `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string    `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	Hostname    string    `bun:"hostname,notnull" json:"hostname"`
	Port        int       `bun:"port,notnull" json:"port"`
	ObservedAt  time.Time `bun:"observed_at,notnull,default:current_timestamp" json:"observed_at"`

	// DNS answers as jsonb columns, the same way Finding.Tags and
	// HTTPRecord.Technology store their slices. Stored whole rather than as three
	// child tables: they are read as a whole or not at all, and never queried by
	// element.
	DNSA     []string `bun:"dns_a,type:jsonb,nullzero" json:"dns_a,omitempty"`
	DNSAAAA  []string `bun:"dns_aaaa,type:jsonb,nullzero" json:"dns_aaaa,omitempty"`
	DNSCNAME []string `bun:"dns_cname,type:jsonb,nullzero" json:"dns_cname,omitempty"`

	// The DNS record types beyond addresses and the CNAME chain, resolved by
	// `vigolium dns`. Stored on the host's port-0 row: they describe the name,
	// not an endpoint.
	DNSMX  []string `bun:"dns_mx,type:jsonb,nullzero" json:"dns_mx,omitempty"`
	DNSNS  []string `bun:"dns_ns,type:jsonb,nullzero" json:"dns_ns,omitempty"`
	DNSTXT []string `bun:"dns_txt,type:jsonb,nullzero" json:"dns_txt,omitempty"`
	DNSSOA []string `bun:"dns_soa,type:jsonb,nullzero" json:"dns_soa,omitempty"`
	DNSCAA []string `bun:"dns_caa,type:jsonb,nullzero" json:"dns_caa,omitempty"`

	// TLS is the handshake and leaf certificate, absent when the endpoint was not
	// handshaked (no --tls-probe, or a plaintext endpoint).
	TLS *tlsprobe.Info `bun:"tls,type:jsonb,nullzero" json:"tls,omitempty"`

	// Fingerprint is what the fingerprint phase concluded about the origin, and
	// NotFound its answer to a path no application serves. Absent when the
	// phase did not run against it.
	Fingerprint *recon.TechStackReport `bun:"fingerprint,type:jsonb,nullzero" json:"fingerprint,omitempty"`
	NotFound    *NotFoundBaseline      `bun:"not_found,type:jsonb,nullzero" json:"not_found,omitempty"`

	// Favicon is the origin's icon as the probe phase's --favicon fetched and
	// hashed it. Absent when the probe did not ask, or the origin serves no
	// icon. (The fingerprint phase keeps its own copy inside Fingerprint.)
	Favicon *recon.FaviconInfo `bun:"favicon,type:jsonb,nullzero" json:"favicon,omitempty"`

	// Complete reports that the lookup actually ran to an answer. False marks an
	// observation the run never finished - a cancelled or budget-limited
	// prefetch - which is a different fact from a host that genuinely resolves to
	// nothing, and the two are indistinguishable without it.
	Complete  bool      `bun:"complete,notnull" json:"complete"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
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
	// Hidden marks a parameter no observed request carried: the param-mining
	// phase found the endpoint acting on it (see pkg/parammine).
	Hidden bool `json:"hidden,omitempty"`
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
	Status      string `bun:"status,nullzero,default:'triaged'" json:"status,omitempty"` // one of FindingStatuses
	Remediation string `bun:"remediation,nullzero" json:"remediation,omitempty"`
	// Provenance of the current status: why, by whom, when. The full history is
	// finding_status_events.
	StatusNote      string     `bun:"status_note,nullzero" json:"status_note,omitempty"`
	StatusActor     string     `bun:"status_actor,nullzero" json:"status_actor,omitempty"`
	StatusUpdatedAt *time.Time `bun:"status_updated_at,nullzero" json:"status_updated_at,omitempty"`

	// Classification
	CWEID     string  `bun:"cwe_id,nullzero" json:"cwe_id,omitempty"`
	CVSSScore float64 `bun:"cvss_score,default:0" json:"cvss_score"`

	// Source info (for audit findings)
	SourceFile string `bun:"source_file,nullzero" json:"source_file,omitempty"`
	RepoName   string `bun:"repo_name,nullzero" json:"repo_name,omitempty"` // repository name or URL for audit findings

	MatchedAt          []string `bun:"matched_at,type:jsonb,nullzero" json:"matched_at,omitempty"`
	ExtractedResults   []string `bun:"extracted_results,type:jsonb,nullzero" json:"extracted_results,omitempty"`
	AdditionalEvidence []string `bun:"additional_evidence,type:jsonb,nullzero" json:"additional_evidence,omitempty"`

	Request  string `bun:"request,nullzero" json:"request,omitempty"`
	Response string `bun:"response,nullzero" json:"response,omitempty"`

	// Replay context, for re-verifying the finding: the baseline record the
	// module scanned (as opposed to the evidence records in HTTPRecordUUIDs),
	// the insertion point it mutated and the payload it sent. Empty on findings
	// written before schema v3 or by producers that do not know them.
	OriginRecordUUID string                 `bun:"origin_record_uuid,nullzero" json:"origin_record_uuid,omitempty"`
	InsertionPoint   *FindingInsertionPoint `bun:"insertion_point,type:jsonb,nullzero" json:"insertion_point,omitempty"`
	Payload          string                 `bun:"payload,nullzero" json:"payload,omitempty"`

	// Verification is the latest re-verification result, separate from Status.
	// VerifiedAt duplicates its timestamp as a column for sorting and filtering.
	Verification *FindingVerification `bun:"verification,type:jsonb,nullzero" json:"verification,omitempty"`
	VerifiedAt   *time.Time           `bun:"verified_at,nullzero" json:"verified_at,omitempty"`

	FindingHash string `bun:"finding_hash,notnull" json:"finding_hash"`

	FoundAt   time.Time `bun:"found_at,notnull,default:current_timestamp" json:"found_at"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
	// LastSeenAt is when a scan last detected the finding (schema v6). NULL on
	// rows no v6 binary has re-detected; FoundAt is then the best answer.
	LastSeenAt *time.Time `bun:"last_seen_at,nullzero" json:"last_seen_at,omitempty"`
}

// FindingInsertionPoint names the insertion point a module mutated, e.g.
// {type: "URL_PARAM", name: "id"}. Type uses the httpmsg insertion-point type
// names.
type FindingInsertionPoint struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// Verification verdicts recorded in FindingVerification.Verdict.
const (
	VerdictConfirmed     = "confirmed"
	VerdictNotReproduced = "not_reproduced"
	VerdictInconclusive  = "inconclusive"
	VerdictUnsupported   = "unsupported"
)

// FindingVerification is the result of re-running a finding's module against
// its target (`finding verify`).
type FindingVerification struct {
	Verdict       string    `json:"verdict"`
	At            time.Time `json:"at"`
	ModuleVersion string    `json:"module_version,omitempty"`
	ScanUUID      string    `json:"scan_uuid,omitempty"`
	Reason        string    `json:"reason,omitempty"`
}

// FindingObservation records that a scan observed a finding. One row per
// (finding, scan); see the finding_observations DDL for why findings.scan_uuid
// alone cannot answer it.
type FindingObservation struct {
	bun.BaseModel `bun:"table:finding_observations,alias:fo" json:"-"`

	ProjectUUID string    `bun:"project_uuid,notnull" json:"project_uuid"`
	FindingID   int64     `bun:"finding_id,pk" json:"finding_id"`
	FindingHash string    `bun:"finding_hash,notnull" json:"finding_hash"`
	ScanUUID    string    `bun:"scan_uuid,pk" json:"scan_uuid"`
	ObservedAt  time.Time `bun:"observed_at,notnull,default:current_timestamp" json:"observed_at"`
}

// FindingStatusEvent is one entry of a finding's append-only status history.
type FindingStatusEvent struct {
	bun.BaseModel `bun:"table:finding_status_events,alias:fse" json:"-"`

	ID          int64     `bun:"id,pk,autoincrement" json:"id"`
	FindingID   int64     `bun:"finding_id,notnull" json:"finding_id"`
	ProjectUUID string    `bun:"project_uuid,notnull" json:"project_uuid"`
	FromStatus  string    `bun:"from_status,nullzero" json:"from_status,omitempty"`
	ToStatus    string    `bun:"to_status,notnull" json:"to_status"`
	Note        string    `bun:"note,nullzero" json:"note,omitempty"`
	Actor       string    `bun:"actor,nullzero" json:"actor,omitempty"`
	CreatedAt   time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// OASTPayload is the context of one planted OAST payload, keyed by the nonce
// embedded in its callback host or path, so an interaction that arrives out of
// band can be attributed after the planting process is gone.
type OASTPayload struct {
	bun.BaseModel `bun:"table:oast_payloads,alias:op" json:"-"`

	Nonce       string    `bun:"nonce,pk" json:"nonce"`
	ProjectUUID string    `bun:"project_uuid,notnull" json:"project_uuid"`
	ScanUUID    string    `bun:"scan_uuid,nullzero" json:"scan_uuid,omitempty"`
	Class       string    `bun:"class,nullzero" json:"class,omitempty"`
	ModuleID    string    `bun:"module_id,nullzero" json:"module_id,omitempty"`
	TargetURL   string    `bun:"target_url,nullzero" json:"target_url,omitempty"`
	Param       string    `bun:"param,nullzero" json:"param,omitempty"`
	RequestHash string    `bun:"request_hash,nullzero" json:"request_hash,omitempty"`
	Payload     string    `bun:"payload,nullzero" json:"payload,omitempty"`
	CreatedAt   time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
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

// ModuleStat is one module's line in scans.module_stats.
type ModuleStat struct {
	Invocations int64 `json:"invocations,omitempty"`
	Requests    int64 `json:"requests,omitempty"`
	Findings    int64 `json:"findings,omitempty"`
	Errors      int64 `json:"errors,omitempty"`
	// Skips counts the module calls not made, by reason. Reasons (stable,
	// add-only): tech_filter, cannot_process, param_already_found, ip_type,
	// quarantined, timeout, method_policy, header_gated, inconclusive_throttled.
	Skips map[string]int64 `json:"skips,omitempty"`
}

// Module skip reasons recorded in ModuleStat.Skips.
const (
	SkipTechFilter            = "tech_filter"
	SkipCannotProcess         = "cannot_process"
	SkipParamAlreadyFound     = "param_already_found"
	SkipIPType                = "ip_type"
	SkipQuarantined           = "quarantined"
	SkipTimeout               = "timeout"
	SkipMethodPolicy          = "method_policy"
	SkipHeaderGated           = "header_gated"
	SkipInconclusiveThrottled = "inconclusive_throttled"
)

// ModuleSkipReasons lists every skip reason once.
var ModuleSkipReasons = []string{
	SkipTechFilter, SkipCannotProcess, SkipParamAlreadyFound, SkipIPType, SkipQuarantined,
	SkipTimeout, SkipMethodPolicy, SkipHeaderGated, SkipInconclusiveThrottled,
}
