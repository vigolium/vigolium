package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/spf13/cobra"
)

var (
	evalStdin   bool
	evalExtFile string
)

var extensionsEvalCmd = &cobra.Command{
	Use:     "eval [code]",
	Aliases: []string{"run", "exec"},
	Short:   "Evaluate JavaScript code with vigolium.* APIs available",
	Long: `Run ad-hoc JavaScript with access to the full vigolium.* API surface.

Examples:
  # Inline code
  vigolium ext eval 'vigolium.log.info("hello")'

  # From a file
  vigolium ext eval --ext-file script.js

  # From stdin
  echo 'vigolium.utils.md5("hello")' | vigolium ext eval --stdin`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExtensionsEval,
}

func init() {
	extensionsEvalCmd.Flags().BoolVar(&evalStdin, "stdin", false, "Read JS code from stdin")
	extensionsEvalCmd.Flags().StringVar(&evalExtFile, "ext-file", "", "Path to JS file to evaluate")
}

func runExtensionsEval(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Determine JS source — exactly one input method required
	source, err := resolveEvalSource(args)
	if err != nil {
		return err
	}

	// Load settings
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	// Build API options
	opts := jsext.APIOptions{
		ScriptID:    "eval",
		ConfigVars:  settings.Audit.Extensions.Variables,
		AllowExec:   settings.Audit.Extensions.AllowExec,
		SandboxDir:  config.ExpandPath(settings.Audit.Extensions.SandboxDir),
		ExecTimeout: settings.Audit.Extensions.ExecTimeout(),
	}

	// Set up optional database repository
	db, err := getDB()
	if err == nil && db != nil {
		defer closeDatabaseOnExit()
		opts.Repository = database.NewRepository(db)
	}

	// Set up scope if configured
	if settings.Scope.Host.Include != nil || settings.Scope.Path.Include != nil {
		matcher := config.NewScopeMatcher(settings.Scope)
		opts.ScopeMatcher = matcher
		opts.ScopeConfig = &settings.Scope
	}

	// Evaluate
	result := jsext.Eval(source, opts)
	if result.Error != nil {
		return fmt.Errorf("eval error: %w", result.Error)
	}

	if result.Value != "" {
		fmt.Println(result.Value)
	}

	return nil
}

// resolveEvalSource determines the JS source code from one of three input methods.
func resolveEvalSource(args []string) (string, error) {
	inputs := 0
	if evalStdin {
		inputs++
	}
	if evalExtFile != "" {
		inputs++
	}
	if len(args) > 0 {
		inputs++
	}

	if inputs == 0 {
		return "", fmt.Errorf("no input provided; use a positional argument, --ext-file, or --stdin")
	}
	if inputs > 1 {
		return "", fmt.Errorf("multiple inputs provided; use only one of: positional argument, --ext-file, or --stdin")
	}

	switch {
	case evalStdin:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read stdin: %w", err)
		}
		return string(data), nil

	case evalExtFile != "":
		data, err := os.ReadFile(evalExtFile)
		if err != nil {
			return "", fmt.Errorf("failed to read file %s: %w", evalExtFile, err)
		}
		source := string(data)

		// Transpile TypeScript if needed
		if strings.EqualFold(filepath.Ext(evalExtFile), ".ts") {
			source, err = jsext.TranspileTS(source, evalExtFile)
			if err != nil {
				return "", err
			}
		}
		return source, nil

	default:
		return args[0], nil
	}
}
