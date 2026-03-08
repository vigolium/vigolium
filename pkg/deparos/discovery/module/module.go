// Package module provides the discovery module system for context-aware task generation.
// Modules intercept directory/file discoveries and modify behavior based on patterns.
package module

import (
	"context"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
)

// Module defines the interface for discovery modules.
// Modules match directory/file patterns and control task generation behavior.
type Module interface {
	// Name returns the module's unique identifier.
	Name() string

	// Description returns a human-readable description.
	Description() string

	// Priority returns execution order (lower = first).
	Priority() int

	// Enabled returns whether the module is active.
	Enabled() bool

	// Patterns returns patterns this module matches against.
	Patterns() []Pattern

	// OnDirectoryMatch is called when a directory matches this module's patterns.
	// Returns actions to take for this directory.
	OnDirectoryMatch(ctx context.Context, event *DirectoryEvent) (*ModuleResult, error)

	// OnFileMatch is called when a file matches this module's patterns.
	// Returns actions to take for this file.
	OnFileMatch(ctx context.Context, event *FileEvent) (*ModuleResult, error)

	// ShouldAddTask is called by TaskFilter BEFORE task enters queue.
	// Return false to reject the task entirely.
	ShouldAddTask(task queue.TaskInfo) bool
}

// DirectoryEvent contains information about a discovered directory.
type DirectoryEvent struct {
	// URL is the full URL of the discovered directory.
	URL string

	// Path is the URL path component.
	Path string

	// Depth is the current recursion depth.
	Depth uint16

	// ParentPath is the parent directory path.
	ParentPath string

	// Segments are the path segments split by "/".
	Segments []string

	// ResponseFingerprint is the response fingerprint (for wildcard detection).
	ResponseFingerprint *fingerprint.Signature

	// ResponseStatusCode is the HTTP status code.
	ResponseStatusCode int

	// ResponseBodyHash is a hash of the response body.
	ResponseBodyHash uint64
}

// FileEvent contains information about a discovered file.
type FileEvent struct {
	// URL is the full URL of the discovered file.
	URL string

	// Path is the URL path component.
	Path string

	// Filename is the file name without path.
	Filename string

	// Extension is the file extension (including dot).
	Extension string

	// Depth is the current recursion depth.
	Depth uint16

	// ParentPath is the parent directory path.
	ParentPath string

	// ResponseFingerprint is the response fingerprint.
	ResponseFingerprint *fingerprint.Signature

	// ResponseStatusCode is the HTTP status code.
	ResponseStatusCode int
}

// BaseModule provides common implementation for modules.
// Embed this in concrete modules to get default behavior.
type BaseModule struct {
	name        string
	description string
	priority    int
	enabled     bool
	patterns    []Pattern
}

// NewBaseModule creates a new BaseModule with the given parameters.
func NewBaseModule(name, description string, priority int, patterns []Pattern) *BaseModule {
	return &BaseModule{
		name:        name,
		description: description,
		priority:    priority,
		enabled:     true,
		patterns:    patterns,
	}
}

func (b *BaseModule) Name() string        { return b.name }
func (b *BaseModule) Description() string { return b.description }
func (b *BaseModule) Priority() int       { return b.priority }
func (b *BaseModule) Enabled() bool       { return b.enabled }
func (b *BaseModule) Patterns() []Pattern { return b.patterns }

// SetEnabled enables or disables the module.
func (b *BaseModule) SetEnabled(enabled bool) { b.enabled = enabled }

// OnDirectoryMatch default implementation returns nil (no action).
func (b *BaseModule) OnDirectoryMatch(ctx context.Context, event *DirectoryEvent) (*ModuleResult, error) {
	return nil, nil
}

// OnFileMatch default implementation returns nil (no action).
func (b *BaseModule) OnFileMatch(ctx context.Context, event *FileEvent) (*ModuleResult, error) {
	return nil, nil
}

// ShouldAddTask default implementation allows all tasks.
func (b *BaseModule) ShouldAddTask(task queue.TaskInfo) bool {
	return true
}
