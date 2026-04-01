package modules

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// ActiveModule is the interface for active scanning modules.
// Active modules send HTTP requests to detect vulnerabilities.
//
// Implementations must be thread-safe as scan methods will be called
// concurrently from multiple scanner goroutines.
type ActiveModule interface {
	Module

	// AllowedInsertionPointTypes returns which insertion point types this module supports.
	// Return AllInsertionPointTypes to accept all types.
	AllowedInsertionPointTypes() InsertionPointTypeSet

	// ScanPerInsertionPoint performs scanning for a specific insertion point.
	ScanPerInsertionPoint(
		ctx *httpmsg.HttpRequestResponse,
		ip httpmsg.InsertionPoint,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	// ScanPerRequest performs scanning once per unique request.
	ScanPerRequest(
		ctx *httpmsg.HttpRequestResponse,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	// ScanPerHost performs scanning once per unique host.
	ScanPerHost(
		ctx *httpmsg.HttpRequestResponse,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)
}

// Prioritized is an optional interface for modules that declare execution priority.
// Lower values indicate higher priority (0 = highest). Modules without this
// interface default to DefaultModulePriority (100).
// Higher priority modules are spawned first, getting earlier access to rate-limit slots.
type Prioritized interface {
	Priority() int
}

// VulnClassifier is an optional interface for modules that declare their
// vulnerability class for cross-module deduplication. When a module reports
// a finding, the executor marks the (URL, param, vuln_class) as found.
// Other modules with the same vuln class can check and skip redundant scanning.
type VulnClassifier interface {
	VulnClass() string // e.g., "xss", "sqli", "ssti"
}
