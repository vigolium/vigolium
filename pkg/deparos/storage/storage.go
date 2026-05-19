package storage

import (
	"net/url"
	"time"
)

// NodeCallback is called for each node during streaming iteration.
// Return error to stop iteration; use io.EOF for clean termination.
type NodeCallback func(node *DiscoveredNode) error

// Storage defines the interface for result storage implementations
type Storage interface {
	// Store adds or updates a result
	Store(result *Result) error

	// Get retrieves a node by URL
	Get(u *url.URL) (*DiscoveredNode, error)

	// WalkFiles traverses all file nodes (non-directory URLs)
	WalkFiles(fn NodeCallback) error

	// WalkDirectories traverses all directory nodes (URLs ending with /)
	WalkDirectories(fn NodeCallback) error

	// Count returns the total number of discovered URLs
	Count() int

	// StreamAllResults streams all results through callback.
	// This is memory-efficient as it processes one node at a time.
	StreamAllResults(fn NodeCallback) error

	// StreamResultsBySessionName streams results for a session through callback.
	StreamResultsBySessionName(sessionName string, fn NodeCallback) error

	// StreamNewNodesSince streams nodes in newSession not in oldSession.
	StreamNewNodesSince(oldSessionName, newSessionName string, fn NodeCallback) error

	// BatchUpdateKingfisherFindings updates kingfisher findings for nodes by URL.
	// Each map entry is a URL string → JSON-encoded findings string.
	BatchUpdateKingfisherFindings(urlFindings map[string]string) error

	// Close releases resources and ends the current session
	Close() error

	// SessionName returns the user-provided session name for grouping
	SessionName() string

	// SessionDBID returns the current session's database ID for foreign key references.
	SessionDBID() int64

	// GetNewDiscoveries returns URLs discovered in this session that weren't seen before
	GetNewDiscoveries() ([]*DiscoveredNode, error)

	// ListSessions returns all sessions in the database
	ListSessions() ([]*Session, error)

	// CompareSessions returns the differences between two sessions by name
	CompareSessions(session1Name, session2Name string) (*SessionDiff, error)

	// GetLatestRecordAt returns timestamp of most recently discovered record
	GetLatestRecordAt() *time.Time

	// Extractions returns the extraction repository for storing spider/jsscan/form extractions.
	Extractions() *ExtractionRepository

	// Observed returns the observed data repository for storing discovered filenames/extensions/paths.
	Observed() *ObservedRepository

	// Hostname returns the hostname associated with this storage.
	Hostname() string

	// GetSessionByName returns the session with a specific name (unique)
	GetSessionByName(name string) (*Session, error)
}

// KingfisherFinding represents a stored secret finding from kingfisher scanner.
type KingfisherFinding struct {
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	Snippet    string `json:"snippet"`
	Confidence string `json:"confidence"`
	Validated  bool   `json:"validated"`
}

// Result represents a complete discovery result
type Result struct {
	URL                *url.URL
	Request            *RequestData
	Response           *ResponseData
	Metadata           *DiscoveryMetadata
	FingerprintAttrs   map[uint8]uint32    // Fingerprint attribute ID → hash value
	Tags               []string            // Computed tags from tag analyzer
	KingfisherFindings []KingfisherFinding // Secret findings from kingfisher scanner
}

// NewResult creates a new Result
func NewResult(u *url.URL) *Result {
	return &Result{
		URL:      u,
		Request:  &RequestData{Headers: make(map[string]string)},
		Response: &ResponseData{Headers: make(map[string]string)},
		Metadata: &DiscoveryMetadata{},
	}
}

// ResultBuilder provides a fluent interface for constructing results
type ResultBuilder struct {
	result Result
}

// NewResultBuilder creates a new builder
func NewResultBuilder() *ResultBuilder {
	return &ResultBuilder{
		result: Result{
			Request:  &RequestData{Headers: make(map[string]string)},
			Response: &ResponseData{Headers: make(map[string]string)},
			Metadata: &DiscoveryMetadata{},
		},
	}
}

// WithURL sets the URL
func (b *ResultBuilder) WithURL(u *url.URL) *ResultBuilder {
	b.result.URL = u
	return b
}

// WithRequest sets request data
func (b *ResultBuilder) WithRequest(method string, headers map[string]string, body []byte) *ResultBuilder {
	b.result.Request.Method = method
	if headers != nil {
		b.result.Request.Headers = headers
	}
	b.result.Request.Body = body
	return b
}

// WithResponse sets response data
func (b *ResultBuilder) WithResponse(status int, headers map[string]string, body []byte, contentLength int64, mimeType string, location string, title string, words int64, lines int64) *ResultBuilder {
	b.result.Response.StatusCode = status
	if headers != nil {
		b.result.Response.Headers = headers
	}
	b.result.Response.Body = body
	b.result.Response.ContentLength = contentLength
	b.result.Response.MIMEType = mimeType
	b.result.Response.Location = location
	b.result.Response.Title = title
	b.result.Response.Words = words
	b.result.Response.Lines = lines
	return b
}

// WithMetadata sets discovery metadata
func (b *ResultBuilder) WithMetadata(foundBy string, depth uint16, timestamp time.Time) *ResultBuilder {
	b.result.Metadata.FoundBy = foundBy
	b.result.Metadata.Depth = depth
	b.result.Metadata.Timestamp = timestamp
	return b
}

// WithFingerprint sets fingerprint attributes
func (b *ResultBuilder) WithFingerprint(attrs map[uint8]uint32) *ResultBuilder {
	b.result.FingerprintAttrs = attrs
	return b
}

// Build returns the constructed result
func (b *ResultBuilder) Build() *Result {
	return &b.result
}
