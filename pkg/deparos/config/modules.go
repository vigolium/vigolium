package config

// WordlistSource defines where wordlist comes from.
type WordlistSource string

const (
	// WordlistObservedNames uses observed names collected during scan (dynamic).
	WordlistObservedNames WordlistSource = "observed_names"
	// WordlistObservedPaths uses observed paths collected during scan (dynamic).
	WordlistObservedPaths WordlistSource = "observed_paths"
	// WordlistShortFiles uses short file wordlist from global config.
	WordlistShortFiles WordlistSource = "short_files"
	// WordlistLongFiles uses long file wordlist from global config.
	WordlistLongFiles WordlistSource = "long_files"
	// WordlistShortDirs uses short directory wordlist from global config.
	WordlistShortDirs WordlistSource = "short_dirs"
	// WordlistLongDirs uses long directory wordlist from global config.
	WordlistLongDirs WordlistSource = "long_dirs"
	// WordlistCustom uses inline words or file path.
	WordlistCustom WordlistSource = "custom"
)

// ModuleConfig configures the discovery module system.
type ModuleConfig struct {
	// Enabled enables/disables the entire module system.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// BuiltIn lists which built-in modules to enable.
	// Available: wildcard
	// Empty slice means all built-in modules enabled.
	BuiltIn []string `json:"built_in" yaml:"built_in"`

	// Disabled lists modules to disable (overrides BuiltIn).
	Disabled []string `json:"disabled" yaml:"disabled"`

	// Custom defines user-defined modules.
	Custom []CustomModuleConfig `json:"custom" yaml:"custom"`
}

// CustomModuleConfig defines a user-configurable module.
type CustomModuleConfig struct {
	// Name is the module's unique identifier.
	Name string `json:"name" yaml:"name" validate:"required"`

	// Description is a human-readable description.
	Description string `json:"description" yaml:"description"`

	// Enabled controls whether module is active.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Priority is execution order (lower = first).
	Priority int `json:"priority" yaml:"priority"`

	// Patterns define what paths this module matches.
	Patterns []PatternConfig `json:"patterns" yaml:"patterns" validate:"required,min=1"`

	// Actions define what the module does when matched.
	Actions ActionConfig `json:"actions" yaml:"actions"`
}

// PatternConfig defines a matching pattern.
type PatternConfig struct {
	// Type is the pattern type.
	// Path-level: path_contains, path_prefix, path_suffix, path_exact, path_regex
	// Segment-level: segment_exact, segment_contains, segment_prefix, segment_suffix, segment_regex
	// File-level: file_extension, file_name, file_glob
	Type string `json:"type" yaml:"type" validate:"required,oneof=path_contains path_prefix path_suffix path_exact path_regex segment_exact segment_contains segment_prefix segment_suffix segment_regex file_extension file_name file_glob"`

	// Value is the pattern value.
	Value string `json:"value" yaml:"value" validate:"required"`

	// Negated inverts the match.
	Negated bool `json:"negated" yaml:"negated"`

	// MatchFiles if true also matches file paths.
	// Only relevant for file-level patterns (file_extension, file_name, file_glob).
	MatchFiles bool `json:"match_files" yaml:"match_files"`
}

// ActionConfig defines module actions when matched.
type ActionConfig struct {
	// StopRecursion prevents recursive discovery into matched directories.
	StopRecursion bool `json:"stop_recursion" yaml:"stop_recursion"`

	// SkipDefaultLogic skips default task generation.
	SkipDefaultLogic bool `json:"skip_default_logic" yaml:"skip_default_logic"`

	// Tasks defines tasks to create when module matches.
	Tasks []TaskActionConfig `json:"tasks" yaml:"tasks"`

	// BlockTaskPatterns are regex patterns for tasks to reject.
	BlockTaskPatterns []string `json:"block_task_patterns" yaml:"block_task_patterns"`
}

// TaskActionConfig defines a task to create when module matches.
type TaskActionConfig struct {
	// Wordlist is the wordlist source.
	Wordlist WordlistSource `json:"wordlist" yaml:"wordlist" validate:"required,oneof=observed_names observed_paths short_files long_files short_dirs long_dirs custom"`

	// Extensions are the extensions to test. Empty array means no extension.
	Extensions []string `json:"extensions" yaml:"extensions" validate:"required"`

	// Priority is the task priority (0-14). Default is 6 if not specified.
	Priority *uint8 `json:"priority" yaml:"priority"`

	// File is path to custom wordlist file (for Wordlist=custom).
	File string `json:"file" yaml:"file"`

	// Inline are inline words to use (for Wordlist=custom).
	Inline []string `json:"inline" yaml:"inline"`
}

// DefaultModuleConfig returns the default module configuration.
func DefaultModuleConfig() ModuleConfig {
	return ModuleConfig{
		Enabled: true,
		BuiltIn: []string{"wildcard"},
	}
}

// IsBuiltInEnabled checks if a built-in module should be enabled.
func (c *ModuleConfig) IsBuiltInEnabled(name string) bool {
	if !c.Enabled {
		return false
	}

	// Check if explicitly disabled
	for _, d := range c.Disabled {
		if d == name {
			return false
		}
	}

	// If BuiltIn is empty, all are enabled
	if len(c.BuiltIn) == 0 {
		return true
	}

	// Check if explicitly enabled
	for _, b := range c.BuiltIn {
		if b == name {
			return true
		}
	}

	return false
}
