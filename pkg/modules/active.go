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
