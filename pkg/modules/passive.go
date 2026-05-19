package modules

import (
	"context"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// PassiveModule is the interface for passive scanning modules.
// Passive modules analyze existing HTTP traffic without sending additional requests.
//
// Implementations must be thread-safe as scan methods will be called
// concurrently from multiple goroutines.
type PassiveModule interface {
	Module

	// Scope returns what parts of the HTTP transaction to analyze.
	Scope() PassiveScanScope

	// ScanPerRequest performs passive analysis on each request/response.
	ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)

	// ScanPerHost performs passive analysis once per unique host.
	ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)
}

// ContextualPassiveModule is an optional interface for passive modules that
// support cancellation and timeout propagation through context.
// Modules can implement this incrementally without breaking the legacy
// PassiveModule interface.
type ContextualPassiveModule interface {
	ScanPerRequestContext(ctx context.Context, item *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)
	ScanPerHostContext(ctx context.Context, item *httpmsg.HttpRequestResponse, scanCtx *ScanContext) ([]*output.ResultEvent, error)
}

// Flusher is an optional interface for passive modules that buffer data
// and need end-of-scan finalization. The executor calls Flush after all
// workers have finished processing.
type Flusher interface {
	Flush(scanCtx *ScanContext)
}

// BatchFlusher is an optional interface for passive modules that buffer data
// and produce deferred findings at end-of-scan. Unlike Flusher (side-effects only),
// BatchFlusher returns result events that the executor emits through the normal
// result pipeline (post-hooks, DB storage, callbacks).
type BatchFlusher interface {
	FlushFindings(scanCtx *ScanContext) ([]*output.ResultEvent, error)
}

// TimeoutHinter is an optional interface for active or passive modules that
// need more time than the global per-module timeout (PassiveModuleTimeout for
// passive modules, ActiveModuleTimeout for active modules). The executor only
// honors the hint when it exceeds the applicable default; modules that do not
// implement this interface use the executor's default timeout.
type TimeoutHinter interface {
	TimeoutHint() time.Duration
}

// ScopeAwareModule is an optional interface for passive modules that should
// only run on in-scope records. Modules returning true will be skipped when
// the current item is out of scope. Default behavior (not implementing this
// interface) is to run on all records regardless of scope.
type ScopeAwareModule interface {
	ScopeAware() bool
}
