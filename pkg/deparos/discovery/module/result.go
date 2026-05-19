package module

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// TaskSpec defines a task to create when module matches.
type TaskSpec struct {
	// WordlistSource is where the wordlist comes from.
	WordlistSource config.WordlistSource

	// Extension is the extension to test. Empty means no extension.
	Extension string

	// Priority is the task priority (0-14).
	Priority uint8

	// CustomFile is path to custom wordlist file (for WordlistCustom).
	CustomFile string

	// CustomInline are inline words to use (for WordlistCustom).
	CustomInline []string
}

// ModuleResult contains actions to take after module execution.
type ModuleResult struct {
	// StopRecursion prevents recursive discovery into this directory.
	StopRecursion bool

	// StopProcessing prevents other modules from executing after this one.
	StopProcessing bool

	// SkipDefaultLogic skips default OnDirectoryDiscovered/OnFileDiscovered logic.
	SkipDefaultLogic bool

	// Tasks are the tasks to create when module matches.
	Tasks []TaskSpec

	// BlockTaskPatterns are regex patterns for tasks to reject in AddTask.
	// Tasks with BasePath matching these patterns will be blocked.
	BlockTaskPatterns []string

	// QueueCleanup requests queue cleanup (for wildcard scenarios).
	QueueCleanup *QueueCleanupRequest
}

// NormalizeExtension strips leading dot from an extension.
// This ensures consistency regardless of how extensions are specified.
func NormalizeExtension(ext string) string {
	return strings.TrimPrefix(ext, ".")
}

// QueueCleanupRequest requests queue cleanup operations.
type QueueCleanupRequest struct {
	// Pattern is regex pattern to match task BasePaths.
	Pattern string

	// Action is the cleanup action to take.
	Action QueueCleanupAction
}

// QueueCleanupAction defines queue cleanup operations.
type QueueCleanupAction int

const (
	// QueueActionRemoveMatching removes tasks matching pattern.
	QueueActionRemoveMatching QueueCleanupAction = iota

	// QueueActionRemoveKeepOne removes tasks matching pattern but keeps one.
	QueueActionRemoveKeepOne

	// QueueActionPauseMatching pauses tasks matching pattern.
	QueueActionPauseMatching
)

// MergeResult merges another result into this one.
// The other result's values take precedence where both are set.
func (r *ModuleResult) MergeResult(other *ModuleResult) {
	if other == nil {
		return
	}

	// Boolean OR for stop flags
	r.StopRecursion = r.StopRecursion || other.StopRecursion
	r.StopProcessing = r.StopProcessing || other.StopProcessing
	r.SkipDefaultLogic = r.SkipDefaultLogic || other.SkipDefaultLogic

	// Append tasks from other
	r.Tasks = append(r.Tasks, other.Tasks...)

	// Append block patterns
	r.BlockTaskPatterns = append(r.BlockTaskPatterns, other.BlockTaskPatterns...)

	// Take first non-nil queue cleanup
	if r.QueueCleanup == nil && other.QueueCleanup != nil {
		r.QueueCleanup = other.QueueCleanup
	}
}

// NewStopRecursionResult creates a result that stops recursion.
func NewStopRecursionResult() *ModuleResult {
	return &ModuleResult{
		StopRecursion:    true,
		SkipDefaultLogic: true,
	}
}

// NewBlockTaskResult creates a result that blocks tasks matching patterns.
func NewBlockTaskResult(patterns ...string) *ModuleResult {
	return &ModuleResult{
		BlockTaskPatterns: patterns,
	}
}

// NewQueueCleanupResult creates a result that requests queue cleanup.
func NewQueueCleanupResult(pattern string, action QueueCleanupAction) *ModuleResult {
	return &ModuleResult{
		QueueCleanup: &QueueCleanupRequest{
			Pattern: pattern,
			Action:  action,
		},
	}
}
