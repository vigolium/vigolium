package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var sessionLintStdin bool

var sessionLintCmd = &cobra.Command{
	Use:   "lint [session-file...]",
	Short: "Validate session auth config files for errors and warnings",
	Long: `Lint session authentication configuration files for common issues:
  - Unknown fields (a misspelt key such as "extarct"), with line and column
  - Missing or invalid fields (name, role, url, method)
  - Invalid extract rules (missing source, path, apply_as)
  - Unknown login types or extract sources
  - Multiple primary sessions, duplicate names
  - Unreachable shorthand configurations

Every form --auth-file and 'auth load' accept is linted: a sessions: bundle, a
single session at the top level, and an agent session-config.json. The parser is
the one those loaders use; where they warn about an unknown field, lint fails.

Exits 1 (error code lint_failed) when any file has an error; warnings alone
exit 0. With -j the issues are items: {file, field, line, column, severity,
message}.`,
	RunE: runSessionLint,
}

func init() {
	authCmd.AddCommand(sessionLintCmd)
	sessionLintCmd.Flags().BoolVar(&sessionLintStdin, "stdin", false, "Read session config from stdin")
}

// sessionLintItem is one issue in the -j document.
type sessionLintItem struct {
	File string `json:"file"`
	authentication.LintIssue
}

func runSessionLint(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	type input struct {
		name string
		data []byte
	}
	var inputs []input
	switch {
	case sessionLintStdin:
		if len(args) > 0 {
			return usageErrorf("cannot use both --stdin and a file argument")
		}
		data, err := readStdin()
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		inputs = append(inputs, input{"<stdin>", data})
	case len(args) == 0:
		return usageErrorf("provide one or more session config files, or use --stdin")
	default:
		for _, path := range args {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			inputs = append(inputs, input{path, data})
		}
	}

	w := humanOut()

	items := []sessionLintItem{}
	errorsN, warningsN, filesWithErrors := 0, 0, 0
	for _, in := range inputs {
		issues := lintSessionFile(in.name, in.data)
		fileErrors := 0
		for _, is := range issues {
			items = append(items, sessionLintItem{File: in.name, LintIssue: is})
			switch is.Severity {
			case "error":
				errorsN++
				fileErrors++
			case "warning":
				warningsN++
			}
		}
		if fileErrors > 0 {
			filesWithErrors++
		}
		if !globalJSON {
			printSessionLintFile(w, in.name, issues)
		}
	}
	if !globalJSON {
		printSessionLintSummary(w, len(inputs), errorsN, warningsN)
	}

	var lintErr error
	if errorsN > 0 {
		lintErr = codedErrorf(apicontract.CodeLintFailed, "auth lint: %d error(s), %d warning(s) in %d of %d file(s)",
			errorsN, warningsN, filesWithErrors, len(inputs))
	}
	if globalJSON {
		var opts []envOpt
		opts = append(opts,
			withExtra("files", len(inputs)),
			withExtra("errors", errorsN),
			withExtra("warnings", warningsN))
		if err := emitRead(cmd, "", items, int64(len(items)), 0, len(items), opts...); err != nil {
			return err
		}
	}
	return lintErr
}

// lintSessionFile parses one file strictly and returns every issue: unknown
// fields, then semantic problems. A file that does not parse is one error
// issue, positioned where the decoder said.
func lintSessionFile(name string, data []byte) []authentication.LintIssue {
	doc, err := authentication.ParseSessionDocument(data, name, authentication.ParseOptions{Strict: true})
	if err != nil {
		is := authentication.LintIssue{Severity: "error", Message: err.Error()}
		var pe *authentication.ParseError
		if errors.As(err, &pe) {
			is.Message = "failed to parse: " + pe.Err.Error()
			is.Line, is.Column = pe.Line, pe.Column
		}
		return []authentication.LintIssue{is}
	}
	return append(doc.Issues, doc.Lint()...)
}

func printSessionLintFile(w io.Writer, filePath string, issues []authentication.LintIssue) {
	if len(issues) == 0 {
		_, _ = fmt.Fprintf(w, "%s %s\n", terminal.SuccessSymbol(), terminal.Green(filePath))
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s %s\n", terminal.ErrorSymbol(), terminal.BoldRed(filePath))
	for _, issue := range issues {
		var symbol, sevLabel string
		switch issue.Severity {
		case "error":
			symbol = terminal.ErrorSymbol()
			sevLabel = terminal.BoldRed("error")
		case "warning":
			symbol = terminal.WarningSymbol()
			sevLabel = terminal.BoldYellow("warning")
		default:
			symbol = terminal.InfoSymbol()
			sevLabel = "info"
		}

		loc := ""
		if pos := issuePos(issue); pos != "" {
			loc = terminal.Gray("line "+strings.TrimPrefix(pos, ":")) + "  "
		}
		fieldStr := ""
		if issue.Field != "" {
			fieldStr = terminal.Gray(issue.Field) + "  "
		}
		_, _ = fmt.Fprintf(w, "  %s %s%s%s  %s\n", symbol, loc, fieldStr, sevLabel, issue.Message)
	}
}

func printSessionLintSummary(w io.Writer, files, errorsN, warningsN int) {
	_, _ = fmt.Fprintln(w)
	if errorsN == 0 && warningsN == 0 {
		_, _ = fmt.Fprintf(w, "%s %d file(s) checked, all clean\n", terminal.SuccessSymbol(), files)
		return
	}
	parts := []string{fmt.Sprintf("%d file(s) checked", files)}
	if errorsN > 0 {
		parts = append(parts, terminal.BoldRed(fmt.Sprintf("%d error(s)", errorsN)))
	}
	if warningsN > 0 {
		parts = append(parts, terminal.BoldYellow(fmt.Sprintf("%d warning(s)", warningsN)))
	}
	_, _ = fmt.Fprintf(w, "%s %s\n", terminal.InfoSymbol(), strings.Join(parts, ", "))
}
