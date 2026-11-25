package configcmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func newCleanCmd(deps Deps, example string) *cobra.Command {
	return &cobra.Command{
		Use:     "clean",
		Short:   "Reset Vigolium to a clean state",
		Long:    "Remove the ~/.vigolium/ directory (config, database, extensions) and regenerate fresh defaults.",
		Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigClean(cmd, deps)
		},
	}
}

func runConfigClean(cmd *cobra.Command, deps Deps) error {
	vigoliumDir := paths.VigoliumDir()
	if vigoliumDir == "" {
		return fmt.Errorf("failed to resolve the state directory: no home directory and %s is unset", paths.StateDirEnv)
	}

	displayDir := config.ContractPath(vigoliumDir)

	asJSON := deps.mutationJSONRequested()
	// Prose goes to stderr under -j, so stdout carries only the document.
	out := io.Writer(os.Stdout)
	if asJSON {
		out = os.Stderr
	}
	result := func(changed bool, action string, extra map[string]any) error {
		items := []configCleanResult{}
		if changed {
			items = append(items, configCleanResult{Path: displayDir, Reinitialized: true})
		}
		return deps.WriteMutation(cmd, items, changed, action, extra)
	}

	// Check if directory exists
	if _, err := os.Stat(vigoliumDir); os.IsNotExist(err) {
		_, _ = fmt.Fprintf(out, "%s Nothing to clean — %s does not exist.\n", terminal.InfoSymbol(), displayDir)
		if asJSON {
			return result(false, "noop", map[string]any{"path": displayDir})
		}
		return nil
	}

	_, _ = fmt.Fprintf(out, "%s This will remove %s (config, database, and all local data)\n", terminal.BoldRed(terminal.SymbolFailed+" Warn:"), terminal.Cyan(displayDir))

	if done, err := clicommon.HandleConfirmation(
		fmt.Sprintf("removing %s and every file under it", displayDir), deps.Force()); done {
		if err == nil && asJSON {
			return result(false, "noop", map[string]any{"path": displayDir, "aborted": true})
		}
		return err
	}

	if err := os.RemoveAll(vigoliumDir); err != nil {
		return fmt.Errorf("failed to remove %s: %w", vigoliumDir, err)
	}

	_, _ = fmt.Fprintf(out, "%s Removed %s\n", terminal.SuccessSymbol(), displayDir)

	// Regenerate fresh defaults
	if err := deps.Reinitialize(); err != nil {
		return fmt.Errorf("failed to reinitialize: %w", err)
	}

	if asJSON {
		return result(true, "delete", nil)
	}
	return nil
}

// configCleanResult is the `config clean -j` row: the directory removed and
// regenerated with defaults.
type configCleanResult struct {
	Path          string `json:"path"`
	Reinitialized bool   `json:"reinitialized"`
}
