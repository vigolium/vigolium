package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/session"
	"github.com/vigolium/vigolium/pkg/terminal"
	"gopkg.in/yaml.v3"
)

var sessionLintStdin bool

// errSessionLintFailed is returned when lint finds errors, causing a non-zero exit without printing an error message.
var errSessionLintFailed = errors.New("")

var sessionLintCmd = &cobra.Command{
	Use:   "lint [session-file]",
	Short: "Validate session auth config files for errors and warnings",
	Long: `Lint session authentication configuration files for common issues:
  - Missing or invalid fields (name, role, url, method)
  - Invalid extract rules (missing source, path, apply_as)
  - Unknown login types or extract sources
  - Multiple primary sessions, duplicate names
  - Unreachable shorthand configurations

Examples:
  # Lint a session config file
  vigolium session lint auth-config.yaml

  # Lint a JSON session config
  vigolium session lint session-config.json

  # Lint from stdin
  cat auth-config.yaml | vigolium session lint --stdin`,
	Args:          cobra.MaximumNArgs(1),
	SilenceErrors: true,
	RunE:          runSessionLint,
}

func init() {
	sessionCmd.AddCommand(sessionLintCmd)
	sessionLintCmd.Flags().BoolVar(&sessionLintStdin, "stdin", false, "Read session config from stdin")
}

func runSessionLint(_ *cobra.Command, args []string) error {
	defer syncLogger()

	var data []byte
	var err error
	var filePath string

	if sessionLintStdin {
		if len(args) > 0 {
			return fmt.Errorf("cannot use both --stdin and a file argument")
		}
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		filePath = "<stdin>"
	} else if len(args) == 0 {
		return fmt.Errorf("provide a session config file or use --stdin")
	} else {
		filePath = args[0]
		data, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", filePath, err)
		}
	}

	content := os.ExpandEnv(string(data))
	lines := strings.Split(content, "\n")

	// Parse the config.
	var cfg session.SessionConfig
	var parseErr error

	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || strings.HasSuffix(filePath, ".json") {
		parseErr = json.Unmarshal([]byte(content), &cfg)
	} else {
		parseErr = yaml.Unmarshal([]byte(content), &cfg)
	}

	if parseErr != nil {
		fmt.Printf("\n%s %s\n", terminal.ErrorSymbol(), terminal.BoldRed(filePath))
		fmt.Printf("  %s %s  failed to parse: %v\n\n", terminal.ErrorSymbol(), terminal.BoldRed("error"), parseErr)
		return errSessionLintFailed
	}

	// Run lint.
	issues := session.LintSessionConfig(&cfg)

	// Print results.
	hasErrors := printSessionLintResults(filePath, lines, issues)
	if hasErrors {
		return errSessionLintFailed
	}

	return nil
}

// printSessionLintResults formats and prints lint issues. Returns true if any errors were found.
func printSessionLintResults(filePath string, _ []string, issues []session.LintIssue) bool {
	totalErrors := 0
	totalWarnings := 0

	if len(issues) == 0 {
		fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green(filePath))
		fmt.Printf("\n%s 1 file checked, all clean\n", terminal.SuccessSymbol())
		return false
	}

	fmt.Printf("\n%s %s\n", terminal.ErrorSymbol(), terminal.BoldRed(filePath))

	for _, issue := range issues {
		var symbol, sevLabel string
		switch issue.Severity {
		case "error":
			symbol = terminal.ErrorSymbol()
			sevLabel = terminal.BoldRed("error")
			totalErrors++
		case "warning":
			symbol = terminal.WarningSymbol()
			sevLabel = terminal.BoldYellow("warning")
			totalWarnings++
		default:
			symbol = terminal.InfoSymbol()
			sevLabel = "info"
		}

		fieldStr := ""
		if issue.Field != "" {
			fieldStr = terminal.Gray(issue.Field) + "  "
		}

		fmt.Printf("  %s %s%s  %s\n", symbol, fieldStr, sevLabel, issue.Message)
	}

	// Summary.
	fmt.Println()
	parts := []string{"1 file checked"}
	if totalErrors > 0 {
		parts = append(parts, terminal.BoldRed(fmt.Sprintf("%d error(s)", totalErrors)))
	}
	if totalWarnings > 0 {
		parts = append(parts, terminal.BoldYellow(fmt.Sprintf("%d warning(s)", totalWarnings)))
	}
	fmt.Printf("%s %s\n", terminal.InfoSymbol(), strings.Join(parts, ", "))

	return totalErrors > 0
}
