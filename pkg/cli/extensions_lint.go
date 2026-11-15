package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/yamlext"
)

var (
	lintStdin     bool
	lintStdinKind string
	lintStrict    bool
)

var extensionsLintCmd = &cobra.Command{
	Use:   "lint [file-or-directory]",
	Short: "Validate extension files for syntax errors and unknown API calls",
	Long: `Lint extensions for common issues:
  - JavaScript/TypeScript: syntax errors, unknown API calls, and — by running the
    top-level code in the same side-effect-free VM the scan loader uses —
    metadata, missing handlers, and effectful calls made at load time
  - YAML (.vgm.yaml): unknown keys (with a suggestion), schema, regex, and
    type-specific checks, with line numbers

Every file named on the command line, found in the directory, or read from
--stdin is held to extension rules: a file that does not load, or exports
nothing, is an error (mark a plain 'vigolium js' script with a
"// vigolium:script" line). A missing handler for a declared scan type is an
error, because the scan would load the extension and never call it.

Exits 1 (error.code lint_failed) when any file has an error; --strict counts
warnings as errors. With -j the result is one document: items are the files
({path, kind, issues:[{severity, line, col, message, rule}]}) and summary holds
{files, errors, warnings}; ok is false exactly when there are errors.`,
	Args:          cobra.MaximumNArgs(1),
	SilenceErrors: true,
	RunE:          runExtensionsLint,
}

func init() {
	extensionsLintCmd.Flags().BoolVar(&lintStdin, "stdin", false, "Read extension source from stdin")
	extensionsLintCmd.Flags().StringVar(&lintStdinKind, "stdin-kind", "", "Language of --stdin source: js, ts or yaml (default: sniffed — a top-level id:/type: YAML map without module.exports is yaml)")
	extensionsLintCmd.Flags().BoolVar(&lintStrict, "strict", false, "Treat warnings as errors (exit 1 on any issue)")
}

// lintedFile is one linted file and the language it was linted as.
type lintedFile struct {
	result *jsext.LintResult
	kind   string // js, ts or yaml
}

// extLintIssue and extLintFile are the -j shapes.
type extLintIssue struct {
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Message  string `json:"message"`
	Rule     string `json:"rule"`
}

type extLintFile struct {
	Path   string         `json:"path"`
	Kind   string         `json:"kind"`
	Issues []extLintIssue `json:"issues"`
}

type extLintSummary struct {
	Files    int `json:"files"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

// extLintExtras is the -j document's command-specific top-level keys
// (schema_registry.go).
type extLintExtras struct {
	Summary extLintSummary `json:"summary"`
}

func runExtensionsLint(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	var files []lintedFile

	switch {
	case lintStdin:
		if len(args) > 0 {
			return usageErrorf("cannot use both --stdin and a file argument")
		}
		kind := strings.ToLower(strings.TrimSpace(lintStdinKind))
		switch kind {
		case "", "js", "ts", "yaml":
		default:
			return usageErrorf("--stdin-kind must be js, ts or yaml, got %q", lintStdinKind)
		}
		data, err := readStdin()
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		if kind == "" {
			kind = sniffExtensionKind(string(data))
		}
		files = append(files, lintSource("<stdin>", string(data), kind))
	case lintStdinKind != "":
		return usageErrorf("--stdin-kind needs --stdin")
	case len(args) == 0:
		return usageErrorf("provide a file, directory, or use --stdin")
	default:
		path := args[0]
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("cannot access %s: %w", path, err)
		}
		if info.IsDir() {
			files, err = lintDirectory(path)
			if err != nil {
				return err
			}
		} else {
			files = append(files, lintFile(path))
		}
	}

	if lintStrict {
		for _, f := range files {
			for i := range f.result.Issues {
				f.result.Issues[i].Severity = jsext.LintError
			}
		}
	}

	summary := extLintSummary{Files: len(files)}
	for _, f := range files {
		jsext.SortIssues(f.result.Issues)
		for _, is := range f.result.Issues {
			if is.Severity == jsext.LintError {
				summary.Errors++
			} else {
				summary.Warnings++
			}
		}
	}

	var lintErr error
	if summary.Errors > 0 {
		filesWithErrors := 0
		for _, f := range files {
			if f.result.HasErrors() {
				filesWithErrors++
			}
		}
		lintErr = codedErrorf(apicontract.CodeLintFailed, "ext lint: %d error(s), %d warning(s) in %d of %d file(s)",
			summary.Errors, summary.Warnings, filesWithErrors, len(files))
	}

	if globalJSON {
		items := make([]extLintFile, 0, len(files))
		for _, f := range files {
			items = append(items, toExtLintFile(f))
		}
		var opts []envOpt
		opts = append(opts, withExtra("summary", summary))
		if err := emitRead(cmd, "", items, int64(len(items)), 0, len(items), opts...); err != nil {
			return err
		}
		return lintErr
	}

	printLintResults(files)
	return lintErr
}

func toExtLintFile(f lintedFile) extLintFile {
	out := extLintFile{Path: f.result.Path, Kind: f.kind, Issues: make([]extLintIssue, 0, len(f.result.Issues))}
	for _, is := range f.result.Issues {
		out.Issues = append(out.Issues, extLintIssue{
			Severity: string(is.Severity),
			Line:     is.Line,
			Col:      is.Col,
			Message:  is.Message,
			Rule:     is.Rule,
		})
	}
	return out
}

// reYAMLTopKey matches a top-level `id:` or `type:` key of a YAML map.
var reYAMLTopKey = regexp.MustCompile(`(?m)^(id|type)\s*:`)

// sniffExtensionKind guesses the language of --stdin source: a YAML map with a
// top-level id: or type: key and no module.exports is yaml; anything else js.
func sniffExtensionKind(src string) string {
	if !strings.Contains(src, "module.exports") && reYAMLTopKey.MatchString(src) {
		return "yaml"
	}
	return "js"
}

// extensionKind is the language a file is linted as, from its name.
func extensionKind(path string) string {
	switch {
	case yamlext.IsYAMLExtension(path):
		return "yaml"
	case strings.EqualFold(filepath.Ext(path), ".ts"):
		return "ts"
	default:
		return "js"
	}
}

// lintFile reads and lints a single file. A file that cannot be read is one
// error issue rather than a command failure, so a directory lint reports it
// alongside the others.
func lintFile(path string) lintedFile {
	kind := extensionKind(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return lintedFile{kind: kind, result: &jsext.LintResult{
			Path: path,
			Issues: []jsext.LintIssue{{
				Severity: jsext.LintError, Rule: "read",
				Message: fmt.Sprintf("failed to read: %v", err),
			}},
		}}
	}
	return lintSource(path, string(data), kind)
}

// lintSource lints source as kind. Every file lint sees is held to extension
// rules (LintOptions.Extension): it was named, found in a directory, or piped.
func lintSource(path, source, kind string) lintedFile {
	if kind == "yaml" {
		return lintedFile{kind: kind, result: lintYAMLFile(path, source)}
	}
	original := source
	if kind == "ts" {
		transpiled, err := jsext.TranspileTS(source, filepath.Base(path))
		if err != nil {
			return lintedFile{kind: kind, result: &jsext.LintResult{
				Path:        path,
				SourceLines: strings.Split(original, "\n"),
				Issues: []jsext.LintIssue{{
					Severity: jsext.LintError, Rule: jsext.RuleTranspile,
					Message: fmt.Sprintf("TypeScript transpile error: %v", err),
				}},
			}}
		}
		source = transpiled
	}
	result := jsext.LintSourceWithOptions(source, path, jsext.LintOptions{Extension: true})
	result.Path = path
	return lintedFile{kind: kind, result: result}
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
			Col:      yi.Col,
			Message:  yi.Message,
			Rule:     yi.Rule,
		})
	}
	return result
}

// lintDirectory lints all .js, .ts, and .vgm.yaml files in a directory (non-recursive).
func lintDirectory(dir string) ([]lintedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var files []lintedFile
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
		files = append(files, lintFile(filepath.Join(dir, name)))
	}

	return files, nil
}

// printLintResults formats and prints all lint results. Returns true if any errors were found.
func printLintResults(files []lintedFile) bool {
	totalErrors := 0
	totalWarnings := 0
	cleanFiles := 0

	for _, f := range files {
		r := f.result
		if len(r.Issues) == 0 {
			cleanFiles++
			fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green(r.Path))
			continue
		}

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
			rule := ""
			if issue.Rule != "" {
				rule = "  " + terminal.Gray("["+issue.Rule+"]")
			}

			if locStr != "" {
				fmt.Printf("  %s %s %s  %s%s\n", symbol, terminal.Gray(locStr), sevLabel, issue.Message, rule)
			} else {
				fmt.Printf("  %s %s  %s%s\n", symbol, sevLabel, issue.Message, rule)
			}

			// Show source context: 2 lines before and after the error line.
			// TypeScript positions refer to the transpiled output, so the
			// original lines are only shown for JS and YAML.
			if issue.Line > 0 && len(r.SourceLines) > 0 && f.kind != "ts" {
				printSourceContext(r.SourceLines, issue.Line, issue.Col)
			} else if issue.Source != "" {
				fmt.Printf("    %s\n", terminal.Gray(issue.Source))
			}
		}
	}

	// Summary
	fmt.Println()
	totalFiles := len(files)
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
	if errLine > total {
		return
	}
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
