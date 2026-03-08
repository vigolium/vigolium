package validator

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// OutputFormat defines output format type.
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
)

// WriteValidationResult writes validation result in specified format.
func WriteValidationResult(w io.Writer, result *ValidationResult, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return writeValidationJSON(w, result)
	default:
		return writeValidationText(w, result)
	}
}

// WriteDryRunResult writes dry-run result in specified format.
func WriteDryRunResult(w io.Writer, result *DryRunResult, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return writeDryRunJSON(w, result)
	default:
		return writeDryRunText(w, result)
	}
}

// writeValidationJSON outputs validation result as JSON.
func writeValidationJSON(w io.Writer, result *ValidationResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// writeDryRunJSON outputs dry-run result as JSON.
func writeDryRunJSON(w io.Writer, result *DryRunResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// writeValidationText outputs validation result as human-readable text.
func writeValidationText(w io.Writer, result *ValidationResult) error {
	// Header
	_, _ = fmt.Fprintln(w, "Module Validation")
	_, _ = fmt.Fprintln(w, strings.Repeat("═", 70))
	_, _ = fmt.Fprintln(w)

	// Status
	status := "VALID"
	if !result.Valid {
		status = "INVALID"
	}
	_, _ = fmt.Fprintf(w, "Status: %s (%d errors, %d warnings)\n", status, result.Errors, result.Warnings)
	_, _ = fmt.Fprintf(w, "Modules: %d custom\n", len(result.Modules))
	_, _ = fmt.Fprintln(w)

	// Module summary table
	if len(result.Modules) > 0 {
		_, _ = fmt.Fprintln(w, "Module Summary:")
		_, _ = fmt.Fprintln(w, "┌──────────────────────┬─────────┬──────────┬──────────┬────────┐")
		_, _ = fmt.Fprintln(w, "│ Module               │ Enabled │ Priority │ Patterns │ Tasks  │")
		_, _ = fmt.Fprintln(w, "├──────────────────────┼─────────┼──────────┼──────────┼────────┤")

		for _, mod := range result.Modules {
			enabled := "✗"
			if mod.Enabled {
				enabled = "✓"
			}
			name := truncate(mod.Name, 20)
			_, _ = fmt.Fprintf(w, "│ %-20s │    %s    │ %8d │ %8d │ %6d │\n",
				name, enabled, mod.Priority, mod.PatternCount, mod.TaskCount)
		}
		_, _ = fmt.Fprintln(w, "└──────────────────────┴─────────┴──────────┴──────────┴────────┘")
		_, _ = fmt.Fprintln(w)
	}

	// Issues
	if len(result.Issues) > 0 {
		// Group by severity
		var errors, warnings, infos []Issue
		for _, issue := range result.Issues {
			switch issue.Severity {
			case SeverityError:
				errors = append(errors, issue)
			case SeverityWarning:
				warnings = append(warnings, issue)
			case SeverityInfo:
				infos = append(infos, issue)
			}
		}

		if len(errors) > 0 {
			_, _ = fmt.Fprintln(w, "Errors:")
			for _, issue := range errors {
				writeIssue(w, issue)
			}
			_, _ = fmt.Fprintln(w)
		}

		if len(warnings) > 0 {
			_, _ = fmt.Fprintln(w, "Warnings:")
			for _, issue := range warnings {
				writeIssue(w, issue)
			}
			_, _ = fmt.Fprintln(w)
		}

		if len(infos) > 0 {
			_, _ = fmt.Fprintln(w, "Info:")
			for _, issue := range infos {
				writeIssue(w, issue)
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	// Duration
	_, _ = fmt.Fprintf(w, "Validated in %s\n", result.Duration)

	return nil
}

// writeIssue writes a single issue.
func writeIssue(w io.Writer, issue Issue) {
	if issue.Module != "" {
		_, _ = fmt.Fprintf(w, "  [%s] %s: %s\n", issue.Module, issue.Field, issue.Message)
	} else {
		_, _ = fmt.Fprintf(w, "  %s: %s\n", issue.Field, issue.Message)
	}
	if issue.Suggestion != "" {
		_, _ = fmt.Fprintf(w, "    └─ suggestion: %s\n", issue.Suggestion)
	}
}

// writeDryRunText outputs dry-run result as human-readable text.
func writeDryRunText(w io.Writer, result *DryRunResult) error {
	// Header
	_, _ = fmt.Fprintln(w, "Dry-Run Simulation")
	_, _ = fmt.Fprintln(w, strings.Repeat("═", 70))
	_, _ = fmt.Fprintln(w)

	// Process each path
	for _, pathResult := range result.Paths {
		_, _ = fmt.Fprintf(w, "Path: %s\n", pathResult.Path)
		_, _ = fmt.Fprintln(w, strings.Repeat("─", 70))

		if len(pathResult.MatchedModules) == 0 {
			_, _ = fmt.Fprintln(w, "MATCHED MODULES: 0")
			_, _ = fmt.Fprintln(w, "(No modules matched this path)")
			_, _ = fmt.Fprintln(w)
			continue
		}

		_, _ = fmt.Fprintf(w, "MATCHED MODULES: %d\n", len(pathResult.MatchedModules))
		_, _ = fmt.Fprintln(w)

		for i, match := range pathResult.MatchedModules {
			_, _ = fmt.Fprintf(w, "%d. %s (priority: %d)\n", i+1, match.Name, match.Priority)

			// Patterns matched
			_, _ = fmt.Fprintln(w, "   Patterns matched:")
			for _, p := range match.PatternsMatched {
				negated := ""
				if p.Negated {
					negated = " (negated)"
				}
				_, _ = fmt.Fprintf(w, "   ├─ [%d] %s %q → MATCH%s\n", p.Index, p.Type, p.Value, negated)
			}

			// Tasks generated
			_, _ = fmt.Fprintln(w, "   Tasks generated:")
			if len(match.TasksGenerated) == 0 {
				_, _ = fmt.Fprintln(w, "   └─ (none)")
			} else {
				for j, task := range match.TasksGenerated {
					isLast := j == len(match.TasksGenerated)-1
					prefix := "├─"
					if isLast && len(match.BlockPatterns) == 0 {
						prefix = "└─"
					}

					extStr := "[]"
					if len(task.Extensions) > 0 {
						extStr = "[" + strings.Join(task.Extensions, ", ") + "]"
					}

					source := task.WordlistSource
					if task.InlineCount > 0 {
						source = fmt.Sprintf("%s (%d inline words)", source, task.InlineCount)
					} else if task.CustomFile != "" {
						source = fmt.Sprintf("%s (file: %s)", source, task.CustomFile)
					}

					_, _ = fmt.Fprintf(w, "   %s %s + %s @ priority %d\n", prefix, source, extStr, task.Priority)
					_, _ = fmt.Fprintf(w, "   │  → %d task spec(s)\n", task.TaskSpecCount)

					// Sample URLs
					if len(task.SampleURLs) > 0 {
						_, _ = fmt.Fprintln(w, "   │  Sample URLs:")
						for _, url := range task.SampleURLs {
							_, _ = fmt.Fprintf(w, "   │    • %s\n", url)
						}
					}
				}
			}

			// Actions
			_, _ = fmt.Fprintln(w, "   Actions:")
			if len(match.BlockPatterns) > 0 {
				_, _ = fmt.Fprintf(w, "   ├─ stop_recursion: %t\n", match.StopRecursion)
				_, _ = fmt.Fprintf(w, "   ├─ skip_default_logic: %t\n", match.SkipDefaultLogic)
				blockStr := formatBlockPatterns(match.BlockPatterns, 3)
				_, _ = fmt.Fprintf(w, "   └─ block_task_patterns: %s\n", blockStr)
			} else {
				_, _ = fmt.Fprintf(w, "   └─ stop_recursion: %t, skip_default_logic: %t\n",
					match.StopRecursion, match.SkipDefaultLogic)
			}

			_, _ = fmt.Fprintln(w)
		}
	}

	// Summary
	_, _ = fmt.Fprintln(w, strings.Repeat("═", 70))
	_, _ = fmt.Fprintln(w, "SUMMARY")
	_, _ = fmt.Fprintf(w, "Paths tested:        %d\n", result.Summary.TotalPaths)
	_, _ = fmt.Fprintf(w, "Paths with matches:  %d\n", result.Summary.PathsWithMatches)
	_, _ = fmt.Fprintf(w, "Paths without match: %d\n", result.Summary.PathsNoMatch)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "Total task specs:    %d\n", result.Summary.TotalTaskSpecs)

	if len(result.Summary.TasksBySource) > 0 {
		_, _ = fmt.Fprintln(w, "By wordlist source:")
		sources := sortedKeys(result.Summary.TasksBySource)
		for i, source := range sources {
			prefix := "├─"
			if i == len(sources)-1 {
				prefix = "└─"
			}
			_, _ = fmt.Fprintf(w, "  %s %s: %d\n", prefix, source, result.Summary.TasksBySource[source])
		}
	}
	_, _ = fmt.Fprintln(w)

	if len(result.Summary.ModulesTriggered) > 0 {
		_, _ = fmt.Fprintf(w, "Modules triggered: %s\n", strings.Join(result.Summary.ModulesTriggered, ", "))
	}

	if len(result.Summary.StopRecursionAt) > 0 {
		_, _ = fmt.Fprintf(w, "Would stop recursion: %s\n", strings.Join(result.Summary.StopRecursionAt, ", "))
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Simulated in %s\n", result.Duration)

	return nil
}

// truncate truncates a string to max length with ellipsis.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// formatBlockPatterns formats block patterns for display.
func formatBlockPatterns(patterns []string, maxShow int) string {
	if len(patterns) <= maxShow {
		return "[" + strings.Join(patterns, ", ") + "]"
	}
	shown := patterns[:maxShow]
	return fmt.Sprintf("[%s, ...+%d more]", strings.Join(shown, ", "), len(patterns)-maxShow)
}

// sortedKeys returns sorted keys from a map.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Sort by count descending
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if m[keys[i]] < m[keys[j]] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
