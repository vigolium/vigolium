// Package jstangle provides a JavaScript analysis scanner that extracts endpoints,
// secrets, and other security-relevant information from JavaScript files.
//
// jstangle wraps an embedded binary tool, providing automatic extraction,
// caching, and a clean Go API. The binary is embedded at build time and
// extracted on first use. Checksum validation ensures the cached binary
// is updated when a new version is embedded.
//
// # Quick Start
//
//	service, err := jstangle.DefaultService()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result, err := service.Scan(ctx, jsContent)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, req := range result.Requests {
//	    fmt.Printf("Request: %s %s\n", req.Method, req.URL)
//	}
//
// # Binary Caching
//
// The jstangle binary is cached at ~/.cache/jstangle/ by default.
// The cache includes the binary and a checksum file. If the embedded
// binary's checksum differs from the cached version, the cache is
// automatically updated.
//
// # Thread Safety
//
// Service, Scanner, and Extractor are all thread-safe for concurrent use.
// Multiple goroutines can safely call Service.Scan() concurrently.
package jstangle

import (
	"encoding/json"
	"errors"
	"time"
)

const (
	// MaxScanTimeout is the maximum timeout for a single scan operation.
	MaxScanTimeout = 5 * time.Minute
	// ProtocolVersion is the framed/JSONL contract required by this Go client.
	ProtocolVersion = 2
	// DefaultMaxInputBytes prevents unexpectedly large AST jobs by default.
	DefaultMaxInputBytes = 10 * 1024 * 1024
	// DefaultMaxOutputBytes bounds helper transport amplification.
	DefaultMaxOutputBytes = 16 * 1024 * 1024
	// DefaultMaxArtifactBytes bounds each worker-produced derived file.
	DefaultMaxArtifactBytes = 32 * 1024 * 1024
	// DefaultMaxASTNodes prevents syntactically dense inputs from entering all
	// traversal-heavy stages after parsing.
	DefaultMaxASTNodes = 500_000
)

// Common errors for the jstangle package.
var (
	// ErrBinaryNotFound indicates the jstangle binary could not be extracted.
	ErrBinaryNotFound = errors.New("jstangle binary not found")

	// ErrExtractionFailed indicates binary extraction to cache failed.
	ErrExtractionFailed = errors.New("failed to extract jstangle binary")

	// ErrScanFailed indicates the jstangle scan command failed.
	ErrScanFailed = errors.New("jstangle scan failed")

	// ErrUnsupportedPlatform indicates the current OS/arch is not supported.
	ErrUnsupportedPlatform = errors.New("unsupported platform for jstangle")

	// ErrIncompatibleProtocol indicates a stale or unsupported embedded helper.
	ErrIncompatibleProtocol = errors.New("incompatible jstangle protocol")

	// ErrIncompleteOutput indicates the helper did not emit a valid completion record.
	ErrIncompleteOutput = errors.New("incomplete jstangle output")

	// ErrInputTooLarge indicates the configured input budget was exceeded.
	ErrInputTooLarge = errors.New("jstangle input exceeds configured limit")

	// ErrOutputTooLarge indicates the helper exceeded its output budget.
	ErrOutputTooLarge = errors.New("jstangle output exceeds configured limit")

	// ErrUnsupportedProfile indicates the embedded helper does not advertise the
	// requested analysis profile in its capability handshake. Callers should treat
	// this as a clean feature-unavailable skip rather than a scan failure, so a
	// stale embedded binary degrades to a no-op with a clear diagnostic instead of
	// an opaque per-job error.
	ErrUnsupportedProfile = errors.New("jstangle profile not supported by embedded binary")
)

// AnalysisProfile selects the smallest stage set needed by a caller.
type AnalysisProfile string

const (
	ProfileLegacy        AnalysisProfile = "legacy"
	ProfileEndpoints     AnalysisProfile = "endpoints"
	ProfileDOMSecurity   AnalysisProfile = "dom-security"
	ProfileBeautify      AnalysisProfile = "beautify"
	ProfileDiscovery     AnalysisProfile = "discovery"
	ProfileDiscoveryLite AnalysisProfile = "discovery-lite"
	ProfileFull          AnalysisProfile = "full"
	ProfileInspect       AnalysisProfile = "inspect"
)

// Capabilities is returned by `jstangle --capabilities` before any scan runs.
type Capabilities struct {
	Type            string         `json:"type"`
	ProtocolVersion int            `json:"protocolVersion"`
	ToolVersion     string         `json:"toolVersion"`
	SourceHash      string         `json:"sourceHash"`
	SchemaVersions  map[string]int `json:"schemaVersions"`
	Capabilities    []string       `json:"capabilities"`
	Profiles        []string       `json:"profiles"`
	Framing         []string       `json:"framing"`
	Runtime         struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"runtime"`
	Build struct {
		Timestamp    string            `json:"timestamp,omitempty"`
		Commit       string            `json:"commit,omitempty"`
		Dependencies map[string]string `json:"dependencies"`
	} `json:"build"`
}

// SupportsProfile reports whether the helper advertised the given analysis
// profile in its capability handshake. A helper that advertises no profiles at
// all (an older capability record that predates the profiles field) is treated
// as supporting everything, so this only ever rejects a profile a modern helper
// explicitly omits — turning "unknown option" style per-job failures into an
// up-front, actionable signal.
func (c *Capabilities) SupportsProfile(profile AnalysisProfile) bool {
	if c == nil || len(c.Profiles) == 0 {
		return true
	}
	for _, p := range c.Profiles {
		if p == string(profile) {
			return true
		}
	}
	return false
}

// Diagnostic describes a recoverable or fatal analysis degradation.
type Diagnostic struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Stage       string `json:"stage"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Recoverable bool   `json:"recoverable"`
}

// StageMetric reports one stage's duration and outcome.
type StageMetric struct {
	Stage      string  `json:"stage"`
	DurationMS float64 `json:"durationMs"`
	Status     string  `json:"status"`
	CostClass  string  `json:"costClass,omitempty"`
	MutatesAST bool    `json:"mutatesAst,omitempty"`
}

// SourceLocation identifies a byte/line span in the analyzed asset.
type SourceLocation struct {
	Line   int `json:"line,omitempty"`
	Column int `json:"column,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// SourceDescriptor binds facts to the exact asset bytes that produced them.
type SourceDescriptor struct {
	URL           string `json:"url,omitempty"`
	Filename      string `json:"filename,omitempty"`
	MediaType     string `json:"mediaType,omitempty"`
	ContentSHA256 string `json:"contentSha256"`
	ByteLength    int64  `json:"byteLength"`
	BundleFormat  string `json:"bundleFormat,omitempty"`
	SourceMapURL  string `json:"sourceMapUrl,omitempty"`
}

type TemplateVariable struct {
	Name        string `json:"name"`
	Placeholder string `json:"placeholder"`
}

// ValueTemplate preserves unresolved variables instead of flattening them away.
type ValueTemplate struct {
	Rendered     string             `json:"rendered"`
	Static       bool               `json:"static"`
	Variables    []TemplateVariable `json:"variables"`
	Alternatives []string           `json:"alternatives,omitempty"`
}

type FieldTemplate struct {
	Name  ValueTemplate `json:"name"`
	Value ValueTemplate `json:"value"`
}

type HeaderTemplate struct {
	Name      ValueTemplate `json:"name"`
	Value     ValueTemplate `json:"value"`
	Sensitive bool          `json:"sensitive,omitempty"`
}

type BodyTemplate struct {
	Kind        string        `json:"kind"`
	Value       ValueTemplate `json:"value"`
	ContentType string        `json:"contentType,omitempty"`
}

type ResolutionStep struct {
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
	Module string `json:"module,omitempty"`
	Export string `json:"export,omitempty"`
}

// Provenance explains the extractor and source span behind a fact.
type Provenance struct {
	Extractor       string           `json:"extractor"`
	Confidence      string           `json:"confidence"`
	ModuleID        string           `json:"moduleId,omitempty"`
	ModulePath      string           `json:"modulePath,omitempty"`
	FunctionName    string           `json:"functionName,omitempty"`
	Start           *SourceLocation  `json:"start,omitempty"`
	End             *SourceLocation  `json:"end,omitempty"`
	Evidence        string           `json:"evidence,omitempty"`
	ResolutionSteps []ResolutionStep `json:"resolutionSteps,omitempty"`
}

// HTTPRequestFact is the typed v2 endpoint record used for replay policy.
type HTTPRequestFact struct {
	Kind              string           `json:"kind"`
	ID                string           `json:"id"`
	URL               ValueTemplate    `json:"url"`
	Method            ValueTemplate    `json:"method"`
	Query             []FieldTemplate  `json:"query"`
	QueryAlternatives []ValueTemplate  `json:"queryAlternatives,omitempty"`
	Headers           []HeaderTemplate `json:"headers"`
	Cookies           []FieldTemplate  `json:"cookies"`
	Body              *BodyTemplate    `json:"body,omitempty"`
	CredentialsMode   string           `json:"credentialsMode,omitempty"`
	Client            string           `json:"client"`
	// OperationType carries the GraphQL verb (query/mutation/subscription) for
	// facts synthesized from a GraphQLOperationFact, so the replay safety policy
	// can treat a GraphQL query as read-only and a mutation as state-changing even
	// though both ride the same transport POST. Empty for non-GraphQL facts.
	OperationType       string     `json:"operationType,omitempty"`
	Provenance          Provenance `json:"provenance"`
	AlternateExtractors []string   `json:"alternateExtractors,omitempty"`
}

// DomFlowFact is the typed v2 browser security flow.
type DomFlowFact struct {
	Kind       string     `json:"kind"`
	ID         string     `json:"id"`
	FlowType   string     `json:"flowType,omitempty"`
	Source     string     `json:"source"`
	Sink       string     `json:"sink"`
	Snippet    string     `json:"snippet"`
	Line       int        `json:"line"`
	Confidence string     `json:"confidence"`
	Provenance Provenance `json:"provenance"`
	Path       []struct {
		Kind     string          `json:"kind"`
		Label    string          `json:"label"`
		Location *SourceLocation `json:"location,omitempty"`
	} `json:"path,omitempty"`
}

// GraphQLVariableTemplate describes an operation variable without requiring a
// concrete value to have been present in the bundle.
type GraphQLVariableTemplate struct {
	Name         string         `json:"name"`
	Type         string         `json:"type,omitempty"`
	Required     bool           `json:"required,omitempty"`
	DefaultValue string         `json:"defaultValue,omitempty"`
	Value        *ValueTemplate `json:"value,omitempty"`
}

// GraphQLOperationFact is a parsed, normalized GraphQL operation linked to a
// transport endpoint when the JavaScript contains enough evidence.
type GraphQLOperationFact struct {
	Kind               string                    `json:"kind"`
	ID                 string                    `json:"id"`
	Endpoint           *ValueTemplate            `json:"endpoint,omitempty"`
	OperationType      string                    `json:"operationType"`
	OperationName      string                    `json:"operationName,omitempty"`
	Document           string                    `json:"document,omitempty"`
	PersistedQueryHash string                    `json:"persistedQueryHash,omitempty"`
	Variables          []GraphQLVariableTemplate `json:"variables"`
	Transport          string                    `json:"transport"`
	Provenance         Provenance                `json:"provenance"`
}

// WebSocketFact preserves protocol metadata separately from ordinary HTTP
// request templates so discovery never accidentally replays it as HTTP.
type WebSocketFact struct {
	Kind              string                   `json:"kind"`
	ID                string                   `json:"id"`
	URL               ValueTemplate            `json:"url"`
	Subprotocols      []string                 `json:"subprotocols"`
	OutboundMessages  []BodyTemplate           `json:"outboundMessages"`
	InboundEventNames []string                 `json:"inboundEventNames"`
	Library           string                   `json:"library"`
	Headers           []HeaderTemplate         `json:"headers,omitempty"`
	Options           map[string]ValueTemplate `json:"options,omitempty"`
	Provenance        Provenance               `json:"provenance"`
}

// EventSourceFact describes an SSE endpoint and the client-visible event
// contract. It is metadata until a protocol-aware consumer opts in.
type EventSourceFact struct {
	Kind            string           `json:"kind"`
	ID              string           `json:"id"`
	URL             ValueTemplate    `json:"url"`
	WithCredentials bool             `json:"withCredentials"`
	EventNames      []string         `json:"eventNames"`
	Library         string           `json:"library"`
	Headers         []HeaderTemplate `json:"headers,omitempty"`
	LastEventID     *ValueTemplate   `json:"lastEventId,omitempty"`
	Provenance      Provenance       `json:"provenance"`
}

// ClientRouteFact is a typed client-side navigation candidate. Routes are
// deliberately distinct from replayable HTTP request templates.
type ClientRouteFact struct {
	Kind       string         `json:"kind"`
	ID         string         `json:"id"`
	Path       ValueTemplate  `json:"path"`
	RouteType  string         `json:"routeType"`
	Guards     []string       `json:"guards,omitempty"`
	LazyAsset  *ValueTemplate `json:"lazyAsset,omitempty"`
	Provenance Provenance     `json:"provenance"`
}

type FlowPathStep struct {
	Kind     string          `json:"kind"`
	Label    string          `json:"label"`
	Location *SourceLocation `json:"location,omitempty"`
}

// BrowserSecurityFlowFact carries non-DOM-XSS browser flow evidence for
// policy-aware passive modules and agent context.
type BrowserSecurityFlowFact struct {
	Kind       string         `json:"kind"`
	ID         string         `json:"id"`
	FlowType   string         `json:"flowType"`
	Source     string         `json:"source"`
	Sink       string         `json:"sink"`
	Confidence string         `json:"confidence"`
	Evidence   string         `json:"evidence"`
	Path       []FlowPathStep `json:"path"`
	Provenance Provenance     `json:"provenance"`
}

// AssetReferenceFact links lazy chunks, workers, maps, manifests, and related
// assets into Vigolium's bounded JavaScript asset graph.
type AssetReferenceFact struct {
	Kind            string        `json:"kind"`
	ID              string        `json:"id"`
	AssetType       string        `json:"assetType"`
	URL             ValueTemplate `json:"url"`
	ParentSourceURL string        `json:"parentSourceUrl,omitempty"`
	Eager           bool          `json:"eager"`
	Inline          bool          `json:"inline,omitempty"`
	Provenance      Provenance    `json:"provenance"`
}

// ArtifactDescriptor points at a worker-owned file. Content is populated only
// after Scanner validates containment, type, length, and SHA-256.
type ArtifactDescriptor struct {
	Kind         string   `json:"kind"`
	ArtifactType string   `json:"artifactType"`
	Path         string   `json:"path"`
	SHA256       string   `json:"sha256"`
	ByteLength   int64    `json:"byteLength"`
	MediaType    string   `json:"mediaType,omitempty"`
	Filename     string   `json:"filename,omitempty"`
	Format       string   `json:"format,omitempty"`
	ModuleCount  int      `json:"moduleCount,omitempty"`
	ModulePaths  []string `json:"modulePaths,omitempty"`
	Content      []byte   `json:"-"`
}

type AnalysisStats struct {
	Status       string         `json:"status"`
	InputBytes   int64          `json:"inputBytes"`
	DurationMS   float64        `json:"durationMs"`
	RecordCounts map[string]int `json:"recordCounts"`
	StageMetrics []StageMetric  `json:"stageMetrics"`
}

// AnalysisResultV2 is the compact typed result envelope.
type AnalysisResultV2 struct {
	Type          string          `json:"type"`
	SchemaVersion int             `json:"schemaVersion"`
	JobID         string          `json:"jobId"`
	Profile       AnalysisProfile `json:"profile"`
	Tool          struct {
		Version    string `json:"version"`
		SourceHash string `json:"sourceHash"`
	} `json:"tool"`
	Source      SourceDescriptor     `json:"source"`
	Stats       AnalysisStats        `json:"stats"`
	Diagnostics []Diagnostic         `json:"diagnostics"`
	Records     []json.RawMessage    `json:"records"`
	Artifacts   []ArtifactDescriptor `json:"artifacts"`
}

// ScanCompletion proves whether the emitted result set is complete.
type ScanCompletion struct {
	Type            string          `json:"type"`
	ProtocolVersion int             `json:"protocolVersion"`
	SchemaVersion   int             `json:"schemaVersion"`
	ScanID          string          `json:"scanId"`
	Profile         AnalysisProfile `json:"profile"`
	Status          string          `json:"status"`
	ReasonCode      string          `json:"reasonCode,omitempty"`
	Counts          struct {
		Requests    int `json:"requests"`
		DomFlows    int `json:"domFlows"`
		Diagnostics int `json:"diagnostics"`
		Artifacts   int `json:"artifacts"`
	} `json:"counts"`
	OutputBytes  int64         `json:"outputBytes,omitempty"`
	StageMetrics []StageMetric `json:"stageMetrics,omitempty"`
}

// ExtractedRequest represents an HTTP request extracted from JavaScript.
type ExtractedRequest struct {
	URL     string   `json:"url"`
	Method  string   `json:"method"`
	Params  string   `json:"params"`
	Body    string   `json:"body"`
	Headers []string `json:"headers"`
	Cookies []string `json:"cookies"`
}

// CodeRecord represents extracted/transformed JavaScript code.
type CodeRecord struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// DomFlow is a DOM-XSS source→sink taint flow reported by jstangle. Unlike a
// "source and sink both present" heuristic, each DomFlow means the analyzer
// traced the same data from a DOM-controlled source into a dangerous sink.
type DomFlow struct {
	FlowType string `json:"flow_type,omitempty"`
	Source   string `json:"source"`
	Sink     string `json:"sink"`
	Snippet  string `json:"snippet"`
	Line     int    `json:"line"`
}

// BeautifiedCode is the unminified + bundle-unpacked document jstangle produces
// under the --beautify flag (webcrack, no eval-based deobfuscation).
//
// When Format != "none" the script was a detected bundle (webpack, browserify,
// ...) and Content is a single module-annotated document — each section headed
// by its recovered path (e.g. ./src/api.js) — with ModulePaths listing those
// paths. When not a bundle, Content is the plain unminified source and
// ModuleCount is 0. Changed reports whether the document differs from the input
// (false means beautification was a no-op and callers should skip persisting it).
type BeautifiedCode struct {
	Filename    string   `json:"filename"`
	Format      string   `json:"format"`
	ModuleCount int      `json:"moduleCount"`
	ModulePaths []string `json:"modulePaths"`
	Changed     bool     `json:"changed"`
	Content     string   `json:"content"`
}

// ScanOptions tunes a single scan invocation.
type ScanOptions struct {
	// Beautify enables the unminify + bundle-unpack pass (jstangle --beautify),
	// populating ScanResult.Beautified. Off by default: it runs a heavier
	// webcrack pass, so only the passive js-beautify module opts in.
	Beautify bool
	// Profile requests only the analysis stages consumed by the caller.
	Profile AnalysisProfile
	// MaxInputBytes rejects oversized AST jobs before starting the helper.
	MaxInputBytes int
	// MaxOutputBytes bounds JSONL transport written by the helper.
	MaxOutputBytes int64
	// MaxArtifactBytes bounds each verified file returned by the helper.
	MaxArtifactBytes int64
	// MaxRequests bounds retained endpoint records.
	MaxRequests int
	// MaxASTNodes bounds the parsed tree before expensive analysis stages.
	MaxASTNodes int
	// Deadline bounds cooperative TypeScript analysis within the process timeout.
	Deadline time.Duration
	// SourceURL anchors relative endpoints to the script that emitted them.
	SourceURL string
	// Filename and MediaType are retained in the v2 source descriptor.
	Filename  string
	MediaType string
}

// ScanResult contains the complete output from a jstangle analysis.
type ScanResult struct {
	Requests          []ExtractedRequest        `json:"requests"`
	Code              *CodeRecord               `json:"code,omitempty"`
	DomFlows          []DomFlow                 `json:"dom_flows,omitempty"`
	Beautified        *BeautifiedCode           `json:"beautified,omitempty"`
	Diagnostics       []Diagnostic              `json:"diagnostics,omitempty"`
	Analysis          *AnalysisResultV2         `json:"analysis,omitempty"`
	RequestFacts      []HTTPRequestFact         `json:"request_facts,omitempty"`
	DomFlowFacts      []DomFlowFact             `json:"dom_flow_facts,omitempty"`
	AssetFacts        []AssetReferenceFact      `json:"asset_facts,omitempty"`
	GraphQLOperations []GraphQLOperationFact    `json:"graphql_operations,omitempty"`
	WebSockets        []WebSocketFact           `json:"websockets,omitempty"`
	EventSources      []EventSourceFact         `json:"event_sources,omitempty"`
	ClientRoutes      []ClientRouteFact         `json:"client_routes,omitempty"`
	BrowserFlows      []BrowserSecurityFlowFact `json:"browser_security_flows,omitempty"`
	Artifacts         []ArtifactDescriptor      `json:"artifacts,omitempty"`
	UnknownRecordData []json.RawMessage         `json:"unknown_records_data,omitempty"`
	Completion        *ScanCompletion           `json:"completion,omitempty"`
	MalformedRecords  int                       `json:"malformed_records,omitempty"`
	UnknownRecords    int                       `json:"unknown_records,omitempty"`
	ScanDuration      time.Duration             `json:"scan_duration"`
	BytesScanned      int                       `json:"bytes_scanned"`
}

// HasRequests returns true if any requests were extracted.
func (r *ScanResult) HasRequests() bool {
	return len(r.Requests) > 0
}

// HasCode returns true if code was extracted.
func (r *ScanResult) HasCode() bool {
	return r.Code != nil
}

// HasDomFlows returns true if any DOM-XSS taint flows were reported.
func (r *ScanResult) HasDomFlows() bool {
	return len(r.DomFlows) > 0
}

// HasBeautified returns true if a beautified document was produced and it
// actually differs from the input (a no-op beautification is not reported).
func (r *ScanResult) HasBeautified() bool {
	return r.Beautified != nil && r.Beautified.Changed && r.Beautified.Content != ""
}

// Config configures the jstangle scanner behavior.
type Config struct {
	// CacheDir overrides the default cache directory (~/.cache/jstangle/).
	// If empty, uses the default location.
	CacheDir string
	// MaxConcurrent bounds subprocesses owned by one Scanner. AST memory use is
	// too high for CPU-count-derived defaults.
	MaxConcurrent int
}

// DefaultConfig returns the default scanner configuration.
func DefaultConfig() *Config {
	return &Config{
		CacheDir:      "",
		MaxConcurrent: 1,
	}
}

// CachedBinary holds information about a cached jstangle binary.
type CachedBinary struct {
	Path        string
	Checksum    string
	ExtractedAt time.Time
}
