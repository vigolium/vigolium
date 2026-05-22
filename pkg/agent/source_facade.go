package agent

import "github.com/vigolium/vigolium/pkg/agent/source"

// Source resolution, source-tree filtering, and target detection live in
// pkg/agent/source. These facades expose them under the agent.* namespace.
//
// They are kept deliberately, not as transitional shims: the leaf package is
// named "source", which collides with the ubiquitous `source` local variable
// across pkg/cli and pkg/server. Calling these through agent.* keeps every call
// site readable; importing pkg/agent/source directly would force a per-file
// import alias (e.g. agentsrc.ResolveSourceAndDiff) at almost every call site.
//
// Only the symbols actually used by callers are re-exported.

var (
	// WithCloneDepth sets the git clone depth for remote sources.
	WithCloneDepth = source.WithCloneDepth
	// ResolveSourceAndDiff resolves a --source and optional --diff into a local
	// path, changed-file list, and diff context.
	ResolveSourceAndDiff = source.ResolveSourceAndDiff
	// DetectTargetFromSource infers a running app URL from a source tree.
	DetectTargetFromSource = source.DetectTargetFromSource
)

// shouldSkipDir reports whether a directory should be skipped during source walks.
func shouldSkipDir(name string) bool { return source.ShouldSkipDir(name) }

// shouldSkipFile reports whether a file should be excluded from source walks.
func shouldSkipFile(name string) bool { return source.ShouldSkipFile(name) }
