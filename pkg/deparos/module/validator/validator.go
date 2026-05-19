package validator

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
)

// ValidateFile validates a module YAML file with enhanced checks.
func ValidateFile(path string, opts ValidateOptions) (*ValidationResult, error) {
	start := time.Now()

	cfg, err := config.LoadModuleConfig(path)
	if err != nil {
		//nolint:nilerr // intentional: validation errors returned as ValidationResult, not error
		return &ValidationResult{
			Valid:    false,
			Errors:   1,
			Issues:   []Issue{{Severity: SeverityError, Field: "file", Message: err.Error()}},
			Duration: time.Since(start),
		}, nil
	}

	result := ValidateConfig(cfg, opts)
	result.Duration = time.Since(start)
	return result, nil
}

// ValidateConfig validates a ModuleConfig struct with enhanced checks.
func ValidateConfig(cfg *config.ModuleConfig, opts ValidateOptions) *ValidationResult {
	result := &ValidationResult{
		Valid:   true,
		Issues:  []Issue{},
		Modules: []ModuleSummary{},
	}

	if cfg == nil {
		result.Valid = false
		result.Errors = 1
		result.Issues = append(result.Issues, Issue{
			Severity: SeverityError,
			Field:    "config",
			Message:  "module config is nil",
		})
		return result
	}

	// Track module names for duplicate detection
	moduleNames := make(map[string]int)

	for i, mod := range cfg.Custom {
		issues := validateCustomModule(mod, i, opts)
		result.Issues = append(result.Issues, issues...)

		// Count task specs
		taskCount := 0
		for _, task := range mod.Actions.Tasks {
			if len(task.Extensions) == 0 {
				taskCount++
			} else {
				taskCount += len(task.Extensions)
			}
		}

		result.Modules = append(result.Modules, ModuleSummary{
			Name:         mod.Name,
			Enabled:      mod.Enabled,
			Priority:     mod.Priority,
			PatternCount: len(mod.Patterns),
			TaskCount:    taskCount,
		})

		// Track duplicate names
		if mod.Name != "" {
			moduleNames[mod.Name]++
		}
	}

	// Check for duplicate module names
	for name, count := range moduleNames {
		if count > 1 {
			result.Issues = append(result.Issues, Issue{
				Severity:   SeverityError,
				Field:      "modules",
				Message:    fmt.Sprintf("duplicate module name %q appears %d times", name, count),
				Suggestion: "each module must have a unique name",
			})
		}
	}

	// Count errors and warnings
	for _, issue := range result.Issues {
		switch issue.Severity {
		case SeverityError:
			result.Errors++
		case SeverityWarning:
			result.Warnings++
		}
	}

	// Determine validity
	result.Valid = result.Errors == 0
	if opts.Strict && result.Warnings > 0 {
		result.Valid = false
	}

	return result
}

// validateCustomModule validates a single custom module.
func validateCustomModule(mod config.CustomModuleConfig, modIndex int, opts ValidateOptions) []Issue {
	var issues []Issue
	modName := mod.Name
	if modName == "" {
		modName = fmt.Sprintf("module[%d]", modIndex)
		issues = append(issues, Issue{
			Severity: SeverityError,
			Module:   modName,
			Field:    "name",
			Message:  "name is required",
		})
	}

	// Validate patterns
	if len(mod.Patterns) == 0 {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Module:   modName,
			Field:    "patterns",
			Message:  "at least one pattern is required",
		})
	}

	for i, p := range mod.Patterns {
		patternIssues := validatePattern(modName, i, p)
		issues = append(issues, patternIssues...)
	}

	// Validate actions
	actionIssues := validateActions(modName, mod.Actions, opts)
	issues = append(issues, actionIssues...)

	return issues
}

// validatePattern validates a single pattern config.
func validatePattern(modName string, idx int, p config.PatternConfig) []Issue {
	var issues []Issue
	field := fmt.Sprintf("patterns[%d]", idx)

	if p.Type == "" {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Module:   modName,
			Field:    field + ".type",
			Message:  "type is required",
		})
		return issues
	}

	if p.Value == "" {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Module:   modName,
			Field:    field + ".value",
			Message:  "value is required",
		})
		return issues
	}

	// Validate pattern type
	_, err := module.ParsePatternType(p.Type)
	if err != nil {
		issues = append(issues, Issue{
			Severity:   SeverityError,
			Module:     modName,
			Field:      field + ".type",
			Message:    fmt.Sprintf("invalid pattern type %q", p.Type),
			Suggestion: "valid types: " + strings.Join(module.ValidPatternTypes(), ", "),
		})
		return issues
	}

	// Validate regex patterns compile
	if p.Type == "path_regex" || p.Type == "segment_regex" {
		if _, err := regexp.Compile(p.Value); err != nil {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Module:   modName,
				Field:    field + ".value",
				Message:  fmt.Sprintf("invalid regex: %v", err),
			})
		}
	}

	// Validate glob patterns
	if p.Type == "file_glob" {
		// Basic glob validation - check for invalid patterns
		if strings.Contains(p.Value, "**") {
			issues = append(issues, Issue{
				Severity:   SeverityWarning,
				Module:     modName,
				Field:      field + ".value",
				Message:    "glob pattern contains '**' which is not supported by filepath.Match",
				Suggestion: "use single '*' for wildcard matching",
			})
		}
	}

	return issues
}

// validateActions validates action config.
func validateActions(modName string, actions config.ActionConfig, opts ValidateOptions) []Issue {
	var issues []Issue

	// Validate block_task_patterns regex
	for i, pattern := range actions.BlockTaskPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Module:   modName,
				Field:    fmt.Sprintf("actions.block_task_patterns[%d]", i),
				Message:  fmt.Sprintf("invalid regex pattern %q: %v", pattern, err),
			})
		}
	}

	// Validate tasks
	for i, task := range actions.Tasks {
		taskIssues := validateTaskAction(modName, i, task, opts)
		issues = append(issues, taskIssues...)
	}

	return issues
}

// validateTaskAction validates a single task action config.
func validateTaskAction(modName string, idx int, task config.TaskActionConfig, opts ValidateOptions) []Issue {
	var issues []Issue
	field := fmt.Sprintf("actions.tasks[%d]", idx)

	// Validate wordlist source
	validSources := map[config.WordlistSource]bool{
		config.WordlistObservedNames: true,
		config.WordlistObservedPaths: true,
		config.WordlistShortFiles:    true,
		config.WordlistLongFiles:     true,
		config.WordlistShortDirs:     true,
		config.WordlistLongDirs:      true,
		config.WordlistCustom:        true,
	}

	if !validSources[task.Wordlist] {
		issues = append(issues, Issue{
			Severity:   SeverityError,
			Module:     modName,
			Field:      field + ".wordlist",
			Message:    fmt.Sprintf("invalid wordlist source %q", task.Wordlist),
			Suggestion: "valid sources: observed_names, observed_paths, short_files, long_files, short_dirs, long_dirs, custom",
		})
	}

	// Validate priority range (0-14)
	if task.Priority != nil && *task.Priority > 14 {
		issues = append(issues, Issue{
			Severity:   SeverityError,
			Module:     modName,
			Field:      field + ".priority",
			Message:    fmt.Sprintf("priority %d exceeds maximum (14)", *task.Priority),
			Suggestion: "priority must be 0-14",
		})
	}

	// Validate custom wordlist
	if task.Wordlist == config.WordlistCustom {
		if task.File == "" && len(task.Inline) == 0 {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Module:   modName,
				Field:    field,
				Message:  "custom wordlist requires 'file' or 'inline'",
			})
		}

		if task.File != "" && len(task.Inline) > 0 {
			issues = append(issues, Issue{
				Severity:   SeverityWarning,
				Module:     modName,
				Field:      field,
				Message:    "both 'file' and 'inline' specified, 'file' takes precedence",
				Suggestion: "use only one of 'file' or 'inline'",
			})
		}

		// Check if custom file exists
		if opts.CheckWordlists && task.File != "" {
			if _, err := os.Stat(task.File); os.IsNotExist(err) {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Module:   modName,
					Field:    field + ".file",
					Message:  fmt.Sprintf("custom wordlist file not found: %s", task.File),
				})
			}
		}

		// Warn about empty inline
		if len(task.Inline) == 0 && task.File == "" {
			issues = append(issues, Issue{
				Severity: SeverityWarning,
				Module:   modName,
				Field:    field + ".inline",
				Message:  "inline wordlist is empty",
			})
		}
	}

	// Warn about extension format
	for i, ext := range task.Extensions {
		if strings.HasPrefix(ext, ".") {
			issues = append(issues, Issue{
				Severity:   SeverityWarning,
				Module:     modName,
				Field:      fmt.Sprintf("%s.extensions[%d]", field, i),
				Message:    fmt.Sprintf("extension %q has leading dot, will be normalized", ext),
				Suggestion: fmt.Sprintf("use %q instead", strings.TrimPrefix(ext, ".")),
			})
		}
	}

	return issues
}

// LoadSampleLines reads first n non-empty lines from a file.
func LoadSampleLines(path string, count int) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() && len(lines) < count {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}
