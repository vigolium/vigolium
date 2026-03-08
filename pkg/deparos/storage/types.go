package storage

import "time"

// NodeType indicates what type of resource a discovered node represents.
// Uses flat storage model - each URL is stored as an independent node.
type NodeType int

const (
	// NodeTypeDirectory represents a directory path (URL ending with trailing slash).
	// Example: /api/, /admin/, /static/
	NodeTypeDirectory NodeType = iota

	// NodeTypeFile represents a file/resource endpoint (URL without trailing slash).
	// Example: /api/users, /index.html, /config.json
	NodeTypeFile
)

// String returns the string representation of NodeType
func (nt NodeType) String() string {
	switch nt {
	case NodeTypeDirectory:
		return "directory"
	case NodeTypeFile:
		return "file"
	default:
		return "unknown"
	}
}

// IsDirectory returns true if this is a directory node
func (nt NodeType) IsDirectory() bool {
	return nt == NodeTypeDirectory
}

// IsFile returns true if this is a file node
func (nt NodeType) IsFile() bool {
	return nt == NodeTypeFile
}

// ExportFormat defines supported export formats
type ExportFormat int

const (
	// ExportJSON exports as JSON array
	ExportJSON ExportFormat = iota
	// ExportCSV exports as CSV file
	ExportCSV
)

// String returns the string representation of ExportFormat
func (ef ExportFormat) String() string {
	switch ef {
	case ExportJSON:
		return "json"
	case ExportCSV:
		return "csv"
	default:
		return "unknown"
	}
}

// ParseExportFormat converts string to ExportFormat
func ParseExportFormat(s string) (ExportFormat, bool) {
	switch s {
	case "json":
		return ExportJSON, true
	case "csv":
		return ExportCSV, true
	default:
		return ExportJSON, false
	}
}

// Session represents a single scan session
type Session struct {
	DBID      int64  // Database primary key ID
	Name      string // User-provided session name (unique when set, empty for anonymous)
	StartedAt time.Time
	EndedAt   time.Time
	TargetURL string
	Config    string // JSON encoded config
	Stats     SessionStats
}

// SessionStats holds statistics for a session
type SessionStats struct {
	URLsFound    int
	URLsUpdated  int
	Errors       int
	Duration     time.Duration
	NewDiscovery int // URLs not seen in previous sessions
}

// SessionDiff represents differences between two sessions
type SessionDiff struct {
	Session1ID   string
	Session2ID   string
	NewURLs      []string // URLs in session2 not in session1
	RemovedURLs  []string // URLs in session1 not in session2
	UpdatedURLs  []string // URLs present in both but with different data
	UnchangedCnt int
}

// NodeAction represents what happened to a node in a session
type NodeAction string

const (
	NodeActionDiscovered NodeAction = "discovered"
	NodeActionUpdated    NodeAction = "updated"
	NodeActionRevisited  NodeAction = "revisited"
)
