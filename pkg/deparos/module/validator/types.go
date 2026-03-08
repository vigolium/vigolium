package validator

import (
	"time"
)

// Severity indicates the severity of a validation issue.
type Severity int

const (
	SeverityError Severity = iota
	SeverityWarning
	SeverityInfo
)

func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// Issue represents a single validation problem.
type Issue struct {
	Severity   Severity `json:"severity"`
	Module     string   `json:"module,omitempty"`
	Field      string   `json:"field"`
	Message    string   `json:"message"`
	Suggestion string   `json:"suggestion,omitempty"`
}

// ValidationResult contains all validation results.
type ValidationResult struct {
	Valid    bool            `json:"valid"`
	Errors   int             `json:"errors"`
	Warnings int             `json:"warnings"`
	Issues   []Issue         `json:"issues,omitempty"`
	Modules  []ModuleSummary `json:"modules,omitempty"`
	Duration time.Duration   `json:"duration_ms"`
}

// ModuleSummary summarizes validation for one module.
type ModuleSummary struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	Priority     int    `json:"priority"`
	PatternCount int    `json:"pattern_count"`
	TaskCount    int    `json:"task_count"`
}

// DryRunResult contains simulation results for all test paths.
type DryRunResult struct {
	File     string        `json:"file"`
	Paths    []PathResult  `json:"paths"`
	Summary  DryRunSummary `json:"summary"`
	Duration time.Duration `json:"duration_ms"`
}

// PathResult contains simulation results for a single path.
type PathResult struct {
	Path           string        `json:"path"`
	MatchedModules []ModuleMatch `json:"matched_modules"`
	TotalTaskSpecs int           `json:"total_task_specs"`
	StopRecursion  bool          `json:"stop_recursion"`
	SkipDefault    bool          `json:"skip_default_logic"`
}

// ModuleMatch represents a module that matched a path.
type ModuleMatch struct {
	Name             string         `json:"name"`
	Priority         int            `json:"priority"`
	PatternsMatched  []PatternMatch `json:"patterns_matched"`
	TasksGenerated   []TaskInfo     `json:"tasks_generated"`
	BlockPatterns    []string       `json:"block_patterns,omitempty"`
	StopRecursion    bool           `json:"stop_recursion"`
	SkipDefaultLogic bool           `json:"skip_default_logic"`
}

// PatternMatch shows which pattern matched and how.
type PatternMatch struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Negated bool   `json:"negated,omitempty"`
}

// TaskInfo contains task spec details for display.
type TaskInfo struct {
	WordlistSource string   `json:"wordlist_source"`
	Extensions     []string `json:"extensions"`
	Priority       uint8    `json:"priority"`
	CustomFile     string   `json:"custom_file,omitempty"`
	InlineCount    int      `json:"inline_count,omitempty"`
	TaskSpecCount  int      `json:"task_spec_count"`
	SampleURLs     []string `json:"sample_urls,omitempty"`
}

// DryRunSummary provides aggregate statistics.
type DryRunSummary struct {
	TotalPaths       int            `json:"total_paths"`
	PathsWithMatches int            `json:"paths_with_matches"`
	PathsNoMatch     int            `json:"paths_no_match"`
	TotalTaskSpecs   int            `json:"total_task_specs"`
	TasksBySource    map[string]int `json:"tasks_by_source"`
	ModulesTriggered []string       `json:"modules_triggered"`
	StopRecursionAt  []string       `json:"stop_recursion_at,omitempty"`
}

// ValidateOptions configures validation behavior.
type ValidateOptions struct {
	Strict         bool // Treat warnings as errors
	CheckWordlists bool // Verify custom wordlist files exist
}

// DryRunOptions configures dry-run behavior.
type DryRunOptions struct {
	Paths       []string // Test paths to simulate
	ConfigPath  string   // Global config.yaml path for wordlist paths
	SampleCount int      // Number of sample URLs to show
}

// WordlistSamples holds sample words for each wordlist source.
type WordlistSamples struct {
	ShortFiles []string
	LongFiles  []string
	ShortDirs  []string
	LongDirs   []string
}
