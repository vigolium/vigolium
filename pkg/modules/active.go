package modules

import (
	"context"

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

// ContextualActiveModule is an optional interface for active modules that support
// cancellation and timeout propagation through context. The executor prefers these
// methods when a module implements them, passing the per-call timeout/cancellation
// context so the module can thread it into cancellable HTTP requests
// (http.Requester.ExecuteContext). Modules can adopt this incrementally without
// breaking the legacy ActiveModule interface.
type ContextualActiveModule interface {
	ScanPerInsertionPointContext(
		ctx context.Context,
		item *httpmsg.HttpRequestResponse,
		ip httpmsg.InsertionPoint,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	ScanPerRequestContext(
		ctx context.Context,
		item *httpmsg.HttpRequestResponse,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	ScanPerHostContext(
		ctx context.Context,
		item *httpmsg.HttpRequestResponse,
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

// TechAware is an optional interface for modules that only make sense against
// certain technology stacks. Implement it on framework-specific modules
// (e.g. Spring, Rails, Django) to skip them on incompatible targets.
//
// Semantics (allowlist):
//   - Return an empty slice (or do not implement) → module always runs.
//   - Return ["spring", "java"] → module runs only if the request's host has
//     at least one of those tech tags detected by the *_fingerprint passive
//     modules earlier in the same scan.
//   - If no tech has been detected for the host yet, the executor fails open
//     and runs the module anyway, so first-request scans aren't pruned.
//
// Tech tags are lowercase strings that match the tag used by fingerprint
// modules (e.g. "spring", "rails", "django", "laravel", "express", "nextjs",
// "aspnet", "php", "wordpress").
type TechAware interface {
	RequiredTechs() []string
}
