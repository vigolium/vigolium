package storage

import (
	"database/sql"

	"github.com/uptrace/bun"
)

// SessionModel maps to the 'sessions' table.
// Each start creates a new session with unique ID.
// SessionName is optional metadata for grouping sessions when exporting.
type SessionModel struct {
	bun.BaseModel `bun:"table:sessions"`
	ID            int64          `bun:"id,pk,autoincrement"`
	SessionName   sql.NullString `bun:"session_name"`
	StartedAt     int64          `bun:"started_at,notnull"`
	EndedAt       sql.NullInt64  `bun:"ended_at"`
	TargetURL     string         `bun:"target_url"`
	Config        string         `bun:"config,type:text"`
	Stats         string         `bun:"stats,type:text"`
}

// NodeModel maps to the 'nodes' table
type NodeModel struct {
	bun.BaseModel `bun:"table:nodes,alias:nodes"`
	ID            int64         `bun:"id,pk,autoincrement"`
	URL           string        `bun:"url,notnull"` // Full URL including query string
	Depth         sql.NullInt64 `bun:"depth"`
	NodeType      int           `bun:"node_type,notnull"` // 0=Directory, 1=File

	// Request fields
	ReqMethod  sql.NullString `bun:"req_method"`
	ReqHeaders sql.NullString `bun:"req_headers,type:text"`
	ReqBody    []byte         `bun:"req_body"`

	// Response fields
	RespStatus        sql.NullInt64  `bun:"resp_status"`
	RespContentLength sql.NullInt64  `bun:"resp_content_length"`
	RespHeaders       sql.NullString `bun:"resp_headers,type:text"`
	RespBody          []byte         `bun:"resp_body"`
	RespMime          sql.NullString `bun:"resp_mime"`
	RespLocation      sql.NullString `bun:"resp_location"`
	RespTitle         sql.NullString `bun:"resp_title"`
	RespWords         sql.NullInt64  `bun:"resp_words"`
	RespLines         sql.NullInt64  `bun:"resp_lines"`

	// Metadata fields
	FoundBy            sql.NullString `bun:"found_by"`
	DiscoveredAt       sql.NullInt64  `bun:"discovered_at"`
	FingerprintAttrs   sql.NullString `bun:"fingerprint_attrs,type:text"`
	Tags               sql.NullString `bun:"tags,type:text"`
	KingfisherFindings sql.NullString `bun:"kingfisher_findings,type:text"`
	FirstSeenSession   sql.NullInt64  `bun:"first_seen_session"`
	LastSeenSession    sql.NullInt64  `bun:"last_seen_session"`

	// Hash for deduplication (FNV-1a 64-bit)
	Hash sql.NullString `bun:"hash"`
}

// SessionNodeModel maps to the 'session_nodes' junction table
type SessionNodeModel struct {
	bun.BaseModel `bun:"table:session_nodes"`
	SessionID     int64  `bun:"session_id,pk"`
	NodeID        int64  `bun:"node_id,pk"`
	Action        string `bun:"action,notnull"`
	Timestamp     int64  `bun:"timestamp,notnull"`
}

// ExtractionSource identifies where the extraction came from.
type ExtractionSource uint8

const (
	// SourceSpider - URL extracted by spider from HTML/JS/comments/headers/etc.
	SourceSpider ExtractionSource = iota
	// SourceJSScan - HTTP request extracted by jsscan from JavaScript analysis.
	SourceJSScan
	// SourceForm - HTML form request (params in URL for GET, body for POST).
	SourceForm
)

// String returns human-readable name for the extraction source.
func (s ExtractionSource) String() string {
	switch s {
	case SourceSpider:
		return "spider"
	case SourceJSScan:
		return "jsscan"
	case SourceForm:
		return "form"
	default:
		return "unknown"
	}
}

// ObservedType identifies the type of observed data.
type ObservedType uint8

const (
	// ObservedTypeName - Individual filenames like "admin", "config".
	ObservedTypeName ObservedType = iota
	// ObservedTypeExtension - File extensions like ".php", ".bak".
	ObservedTypeExtension
	// ObservedTypePath - Full URL paths like "/api/v1/users".
	ObservedTypePath
	// ObservedTypeFile - Complete filenames like "app.b5ca88ec.js".
	ObservedTypeFile
)

// String returns human-readable name for the observed type.
func (t ObservedType) String() string {
	switch t {
	case ObservedTypeName:
		return "name"
	case ObservedTypeExtension:
		return "extension"
	case ObservedTypePath:
		return "path"
	case ObservedTypeFile:
		return "file"
	default:
		return "unknown"
	}
}

// ObservedModel maps to the 'observed' table.
// Stores observed filenames, extensions, paths, and files with their frequencies.
type ObservedModel struct {
	bun.BaseModel `bun:"table:observed"`
	ID            int64  `bun:"id,pk,autoincrement"`
	Hostname      string `bun:"hostname,notnull"`            // Primary query field
	Type          uint8  `bun:"type,notnull"`                // ObservedType enum
	Value         string `bun:"value,notnull"`               // The observed item
	Frequency     int    `bun:"frequency,notnull,default:1"` // Match count
	UpdatedAt     int64  `bun:"updated_at,notnull"`          // Last update timestamp
}

// ExtractionModel maps to the 'extractions' table.
// Unified storage for all extracted data: spider links, jsscan requests, forms.
type ExtractionModel struct {
	bun.BaseModel `bun:"table:extractions"`
	ID            int64 `bun:"id,pk,autoincrement"`
	SourceNodeID  int64 `bun:"source_node_id,notnull"` // FK -> nodes.id
	SessionID     int64 `bun:"session_id,notnull"`     // FK -> sessions.id

	// Deduplication hash (FNV-1a of source+url+method+body)
	Hash string `bun:"hash"` // Unique constraint for dedup

	// Source identification
	Source    uint8 `bun:"source,notnull"`       // ExtractionSource enum
	SourceSub uint8 `bun:"source_sub,default:0"` // LinkSourceType for spider

	// Request data
	Hostname    string         `bun:"hostname,notnull"`     // Hostname for grouping queries
	URL         string         `bun:"url,notnull"`          // Full URL
	Method      string         `bun:"method,default:'GET'"` // HTTP method
	Body        sql.NullString `bun:"body,type:text"`       // Request body
	ContentType sql.NullString `bun:"content_type"`         // Content-Type header
	Headers     sql.NullString `bun:"headers,type:text"`    // JSON array
	Cookies     sql.NullString `bun:"cookies,type:text"`    // JSON array

	CreatedAt int64 `bun:"created_at,notnull"`
}
