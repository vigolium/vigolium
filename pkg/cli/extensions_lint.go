package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/yamlext"
)

// errLintFailed is returned when lint finds errors, causing a non-zero exit without printing an error message.
var errLintFailed = errors.New("")

var lintStdin bool

var extensionsLintCmd = &cobra.Command{
	Use:   "lint [file-or-directory]",
	Short: "Validate extension files for syntax errors and unknown API calls",
	Long: `Lint extensions for common issues:
  - JavaScript/TypeScript: syntax errors, unknown API calls, metadata, handlers
  - YAML (.vgm.yaml): schema validation, regex, type-specific checks`,
	Args:          cobra.MaximumNArgs(1),
	SilenceErrors: true,
	RunE:          runExtensionsLint,
}

func init() {
	extensionsLintCmd.Flags().BoolVar(&lintStdin, "stdin", false, "Read extension source from stdin")
}

func runExtensionsLint(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	var results []*jsext.LintResult

	if lintStdin {
		if len(args) > 0 {
			return fmt.Errorf("cannot use both --stdin and a file argument")
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		source := string(data)
		result := jsext.LintSource(source, "<stdin>")
		results = append(results, result)
	} else if len(args) == 0 {
		return fmt.Errorf("provide a file, directory, or use --stdin")
	} else {
		path := args[0]
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("cannot access %s: %w", path, err)
		}

		if info.IsDir() {
			results, err = lintDirectory(path)
			if err != nil {
				return err
			}
		} else {
			result, err := lintFile(path)
			if err != nil {
				return err
			}
			results = append(results, result)
		}
	}

	// Print results
	hasErrors := printLintResults(results)
	if hasErrors {
		return errLintFailed
	}

	return nil
}

// lintFile reads, optionally transpiles, and lints a single file.
func lintFile(path string) (*jsext.LintResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	source := string(data)

	// YAML extensions
	if yamlext.IsYAMLExtension(path) {
		return lintYAMLFile(path, source), nil
	}

	filename := filepath.Base(path)

	// Transpile TypeScript
	if strings.EqualFold(filepath.Ext(path), ".ts") && !strings.HasSuffix(path, ".d.ts") {
		transpiled, err := jsext.TranspileTS(source, filename)
		if err != nil {
			// Return transpile error as a lint result
			result := &jsext.LintResult{
				Path: path,
				Issues: []jsext.LintIssue{{
					Severity: jsext.LintError,
					Message:  fmt.Sprintf("TypeScript transpile error: %v", err),
				}},
			}
			return result, nil
		}
		source = transpiled
	}

	result := jsext.LintSource(source, path)
	result.Path = path // ensure full path is set
	return result, nil
}

// lintYAMLFile lints a .vgm.yaml extension file and converts the result to jsext.LintResult.
func lintYAMLFile(path, source string) *jsext.LintResult {
	yamlResult := yamlext.LintYAML(source, path)

	result := &jsext.LintResult{
		Path:        path,
		SourceLines: strings.Split(source, "\n"),
	}
	for _, yi := range yamlResult.Issues {
		sev := jsext.LintWarning
		if yi.Severity == "error" {
			sev = jsext.LintError
		}
		result.Issues = append(result.Issues, jsext.LintIssue{
			Severity: sev,
			Line:     yi.Line,
			Message:  yi.Message,
		})
	}
	return result
}

// lintDirectory lints all .js, .ts, and .vgm.yaml files in a directory (non-recursive).
func lintDirectory(dir string) ([]*jsext.LintResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var results []*jsext.LintResult
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		isJS := strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts")
		isYAML := yamlext.IsYAMLExtension(name)
		if !isJS && !isYAML {
			continue
		}
		// Skip declaration files
		if strings.HasSuffix(name, ".d.ts") {
			continue
		}

		path := filepath.Join(dir, name)
		result, err := lintFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %s: %v\n", terminal.ErrorSymbol(), path, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// printLintResults formats and prints all lint results. Returns true if any errors were found.
func printLintResults(results []*jsext.LintResult) bool {
	totalErrors := 0
	totalWarnings := 0
	filesWithIssues := 0
	cleanFiles := 0

	for _, r := range results {
		if len(r.Issues) == 0 {
			cleanFiles++
			fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green(r.Path))
			continue
		}

		filesWithIssues++
		jsext.SortIssues(r.Issues)

		fmt.Printf("\n%s %s\n", terminal.ErrorSymbol(), terminal.BoldRed(r.Path))

		for _, issue := range r.Issues {
			var locStr string
			if issue.Line > 0 && issue.Col > 0 {
				locStr = fmt.Sprintf("%d:%d", issue.Line, issue.Col)
			} else if issue.Line > 0 {
				locStr = fmt.Sprintf("%d", issue.Line)
			}

			var symbol, sevLabel string
			switch issue.Severity {
			case jsext.LintError:
				symbol = terminal.ErrorSymbol()
				sevLabel = terminal.BoldRed("error")
				totalErrors++
			case jsext.LintWarning:
				symbol = terminal.WarningSymbol()
				sevLabel = terminal.BoldYellow("warning")
				totalWarnings++
			}

			if locStr != "" {
				fmt.Printf("  %s %s %s  %s\n", symbol, terminal.Gray(locStr), sevLabel, issue.Message)
			} else {
				fmt.Printf("  %s %s  %s\n", symbol, sevLabel, issue.Message)
			}

			// Show source context: 2 lines before and after the error line
			if issue.Line > 0 && len(r.SourceLines) > 0 {
				printSourceContext(r.SourceLines, issue.Line, issue.Col)
			} else if issue.Source != "" {
				fmt.Printf("    %s\n", terminal.Gray(issue.Source))
			}
		}
	}

	// Summary
	fmt.Println()
	totalFiles := len(results)
	if totalErrors == 0 && totalWarnings == 0 {
		fmt.Printf("%s %d file(s) checked, all clean\n", terminal.SuccessSymbol(), totalFiles)
	} else {
		parts := []string{fmt.Sprintf("%d file(s) checked", totalFiles)}
		if totalErrors > 0 {
			parts = append(parts, terminal.BoldRed(fmt.Sprintf("%d error(s)", totalErrors)))
		}
		if totalWarnings > 0 {
			parts = append(parts, terminal.BoldYellow(fmt.Sprintf("%d warning(s)", totalWarnings)))
		}
		if cleanFiles > 0 {
			parts = append(parts, terminal.Green(fmt.Sprintf("%d clean", cleanFiles)))
		}
		fmt.Printf("%s %s\n", terminal.InfoSymbol(), strings.Join(parts, ", "))
	}

	return totalErrors > 0
}

// printSourceContext prints source lines around an error with a column indicator.
// contextLines is the number of lines to show before and after the error line.
func printSourceContext(lines []string, errLine, errCol int) {
	const contextSize = 2
	total := len(lines)
	startLine := errLine - contextSize
	if startLine < 1 {
		startLine = 1
	}
	endLine := errLine + contextSize
	if endLine > total {
		endLine = total
	}

	// Width for line number gutter
	gutterWidth := len(fmt.Sprintf("%d", endLine))

	for ln := startLine; ln <= endLine; ln++ {
		lineContent := lines[ln-1]
		gutter := fmt.Sprintf("%*d", gutterWidth, ln)

		if ln == errLine {
			// Highlight the error line
			fmt.Printf("    %s %s %s\n", terminal.BoldRed(gutter), terminal.BoldRed("│"), lineContent)
			// Show column indicator
			if errCol > 0 {
				indicator := strings.Repeat(" ", errCol-1) + "^"
				fmt.Printf("    %s %s %s\n", strings.Repeat(" ", gutterWidth), terminal.BoldRed("│"), terminal.BoldRed(indicator))
			}
		} else {
			fmt.Printf("    %s %s %s\n", terminal.Gray(gutter), terminal.Gray("│"), terminal.Gray(lineContent))
		}
	}
}
