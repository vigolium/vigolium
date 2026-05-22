package agent

import "github.com/vigolium/vigolium/pkg/agent/source"

// Source resolution, source-tree filtering, and target detection live in
// pkg/agent/source. These facades preserve the agent.* public API consumed by
// pkg/cli and pkg/server, and keep the root orchestrators (engine.go,
// intent.go) calling the same unqualified names as before.

// SourceResolveOption configures source resolution (e.g. git clone depth).
type SourceResolveOption = source.SourceResolveOption

var (
	// WithCloneDepth sets the git clone depth for remote sources.
	WithCloneDepth = source.WithCloneDepth
	// ResolveSourceAndDiff resolves a --source and optional --diff into a local
	// path, changed-file list, and diff context.
	ResolveSourceAndDiff = source.ResolveSourceAndDiff
	// ResolveSource resolves a source argument into a local directory path.
	ResolveSource = source.ResolveSource
	// ResolveDiff resolves a --diff argument into changed files and patch content.
	ResolveDiff = source.ResolveDiff
	// DetectTargetFromSource infers a running app URL from a source tree.
	DetectTargetFromSource = source.DetectTargetFromSource
)

// shouldSkipDir reports whether a directory should be skipped during source walks.
func shouldSkipDir(name string) bool { return source.ShouldSkipDir(name) }

// shouldSkipFile reports whether a file should be excluded from source walks.
func shouldSkipFile(name string) bool { return source.ShouldSkipFile(name) }
