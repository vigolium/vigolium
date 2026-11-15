package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/jsext"
)

var (
	evalStdin   bool
	evalExtFile string
	evalTimeout time.Duration
)

var extensionsEvalCmd = &cobra.Command{
	Use:     "eval [code]",
	Aliases: []string{"exec"},
	Short:   "Evaluate JavaScript code with vigolium.* APIs available",
	Long: `Run ad-hoc JavaScript with access to the full vigolium.* API surface.

Takes the code as a positional argument, from a file (--ext-file, .ts is
transpiled), or on stdin (--stdin). See also "vigolium js", which runs the
same API surface and additionally sets a TARGET variable (--target) and
selects an output format (--format).

With --record-uuid it runs an extension instead: the one named with --ext,
loaded as a scan loads it, against a stored record, offline unless
--allow-network. That mode is "vigolium ext run"; see its help.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExtensionsEval,
}

func init() {
	extensionsEvalCmd.Flags().BoolVar(&evalStdin, "stdin", false, "Read JS code from stdin")
	extensionsEvalCmd.Flags().StringVar(&evalExtFile, "ext-file", "", "Path to JS file to evaluate")
	extensionsEvalCmd.Flags().DurationVar(&evalTimeout, "timeout", 30*time.Second, "Execution timeout")
}

func runExtensionsEval(cmd *cobra.Command, args []string) error {
	// --record-uuid (and its companions) switch eval to `ext run`: one
	// extension (--ext) against one stored record.
	if extRunFlagsSet(cmd) {
		if len(args) > 0 || evalStdin || evalExtFile != "" {
			return usageErrorf("--record-uuid runs the extension named with --ext against a stored record; " +
				"it does not take code (an argument, --ext-file or --stdin)")
		}
		// The output is ext run's, so the document names ext run (and its
		// schema applies), whichever spelling ran it: runExtensionOnRecord
		// emits under extensionsRunCmd.
		return runExtensionOnRecord(cmd, "")
	}

	defer syncLogger()

	// Determine JS source — exactly one input method required
	source, err := resolveEvalSource(args)
	if err != nil {
		return err
	}

	// Load settings
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	// Build the API surface (DB, scope, HTTP stack) shared with
	// `vigolium js`.
	opts, cleanup, err := buildJSEvalOptions("eval", settings)
	if err != nil {
		return err
	}
	defer cleanup()

	// Evaluate under the same bounded-execution helper as `vigolium js`,
	// so an accidental infinite loop in a pasted snippet cannot hang the
	// process.
	result := evalWithTimeout(source, opts, "", evalTimeout)
	if result.Error != nil {
		return fmt.Errorf("eval error: %w", result.Error)
	}

	if globalJSON {
		// The same document as `js -j`: items:[{"value": …}].
		return emitJSEvalResult(cmd, result.Value)
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
		return "", usageErrorf("no input provided; use a positional argument, --ext-file, or --stdin")
	}
	if inputs > 1 {
		return "", fmt.Errorf("multiple inputs provided; use only one of: positional argument, --ext-file, or --stdin")
	}

	switch {
	case evalStdin:
		data, err := readStdin()
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
