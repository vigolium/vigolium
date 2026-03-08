package modules

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module is the base interface for all scanner modules.
// All modules must be thread-safe as scan methods will be called concurrently.
type Module interface {
	// ID returns unique identifier for the module (e.g., "active-sqli-error-based").
	ID() string

	// Name returns human-readable name (e.g., "SQLi Error Based Scanner").
	Name() string

	// Description returns detailed description (may contain markdown).
	Description() string

	// ShortDescription returns one-line summary for listings.
	ShortDescription() string

	// ConfirmationCriteria returns a description of how this module confirms a finding.
	ConfirmationCriteria() string

	// Severity returns the severity of issues found by this module.
	Severity() severity.Severity

	// Confidence returns the confidence level of findings produced by this module.
	Confidence() severity.Confidence

	// ScanScopes returns bitmask of supported scan scopes.
	// Must return at least one of: ScanScopeInsertionPoint, ScanScopeRequest, ScanScopeHost.
	ScanScopes() ScanScope

	// Tags returns classification tags for this module (e.g., "xss", "spring", "light").
	// Used for filtering modules via --module-tag flag.
	Tags() []string

	// CanProcess returns true if this module can process the given request.
	// Default implementations skip media files and certain HTTP methods.
	// Modules with special needs (like proxy_escape_detection) can override this.
	CanProcess(ctx *httpmsg.HttpRequestResponse) bool
}
