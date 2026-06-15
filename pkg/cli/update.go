package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

const (
	// installScriptURL is the public, README-documented installer one-liner.
	// Re-running it is the supported upgrade path: it resolves the latest
	// release from CDN metadata, verifies the checksum, and installs to
	// ~/.local/bin/vigolium.
	installScriptURL = "https://vigolium.com/install.sh"

	nucleiTemplatesRepo = "https://github.com/projectdiscovery/nuclei-templates.git"

	// installedBinaryPath is where install.sh always places the binary.
	installedBinaryPath = "~/.local/bin/vigolium"

	// updateStepTimeout bounds each external step (installer / git). The
	// nuclei-templates repo is large, so this matches the 10m budget
	// knownissuescan uses for its first-time clone.
	updateStepTimeout = 10 * time.Minute
)

var (
	updateSkipBinary    bool
	updateSkipTemplates bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Vigolium and its nuclei templates to the latest version",
	Long: `Update re-runs the official install script to fetch the latest Vigolium
release binary, then refreshes the local nuclei-templates checkout used by the
known-issue scan.

By default both are updated. Use --skip-binary to only refresh templates, or
--skip-templates to only reinstall the binary. The binary update runs the same
installer as:

  curl -fsSL ` + installScriptURL + ` | bash

which installs to ` + installedBinaryPath + ` regardless of where the current
binary lives — a warning is printed if the running binary is somewhere else
(e.g. a ` + "`make install`" + ` build in $GOPATH/bin or a Homebrew install).`,
	RunE: runUpdateCmd,
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolVar(&updateSkipBinary, "skip-binary", false, "Only update nuclei templates; do not reinstall the binary")
	updateCmd.Flags().BoolVar(&updateSkipTemplates, "skip-templates", false, "Only reinstall the binary; do not refresh nuclei templates")
}

// updateStepResult is one line of the --json summary.
type updateStepResult struct {
	Step    string `json:"step"`   // "binary" | "templates"
	Status  string `json:"status"` // "ok" | "failed" | "skipped"
	Message string `json:"message,omitempty"`
}

type updateOutput struct {
	Steps []updateStepResult `json:"steps"`
}

// updateSay prints decorative/progress output to stdout, but stays silent under
// --json so stdout remains a single parseable JSON document.
func updateSay(format string, args ...any) {
	if globalJSON {
		return
	}
	fmt.Printf(format, args...)
}

func runUpdateCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	if updateSkipBinary && updateSkipTemplates {
		return fmt.Errorf("--skip-binary and --skip-templates are mutually exclusive (nothing to do)")
	}

	doBinary := !updateSkipBinary
	doTemplates := !updateSkipTemplates

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}
	templatesDir := diagnostics.NucleiTemplatesDir(settings)

	updateSay("%s %s\n", terminal.BoldCyan("Vigolium update"), terminal.White("will perform:"))
	if doBinary {
		updateSay("  %s reinstall the latest binary via %s\n", terminal.InfoSymbol(), terminal.Gray(installScriptURL))
		updateSay("    %s installs to %s\n", terminal.Gray(terminal.SymbolDot), terminal.Gray(installedBinaryPath))
	}
	if doTemplates {
		updateSay("  %s update nuclei templates at %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(templatesDir)))
	}

	var out updateOutput
	var firstErr error

	if doBinary {
		updateSay("\n%s %s\n", terminal.BoldCyan(terminal.SymbolStart), terminal.White("Updating binary..."))
		if berr := updateBinary(); berr != nil {
			out.Steps = append(out.Steps, updateStepResult{Step: "binary", Status: "failed", Message: berr.Error()})
			if firstErr == nil {
				firstErr = berr
			}
			updateSay("  %s binary update failed: %v\n", terminal.ErrorSymbol(), berr)
		} else {
			msg := "binary reinstalled"
			if w := binaryPathWarning(); w != "" {
				msg = msg + "; " + w
				updateSay("  %s %s\n", terminal.SuccessSymbol(), terminal.White("binary reinstalled"))
				updateSay("  %s %s\n", terminal.WarningSymbol(), terminal.Yellow(w))
			} else {
				updateSay("  %s %s\n", terminal.SuccessSymbol(), terminal.White("binary reinstalled"))
			}
			out.Steps = append(out.Steps, updateStepResult{Step: "binary", Status: "ok", Message: msg})
		}
	} else {
		out.Steps = append(out.Steps, updateStepResult{Step: "binary", Status: "skipped"})
	}

	if doTemplates {
		updateSay("\n%s %s\n", terminal.BoldCyan(terminal.SymbolStart), terminal.White("Updating nuclei templates..."))
		if msg, terr := updateNucleiTemplates(templatesDir); terr != nil {
			out.Steps = append(out.Steps, updateStepResult{Step: "templates", Status: "failed", Message: terr.Error()})
			if firstErr == nil {
				firstErr = terr
			}
			updateSay("  %s templates update failed: %v\n", terminal.ErrorSymbol(), terr)
		} else {
			out.Steps = append(out.Steps, updateStepResult{Step: "templates", Status: "ok", Message: msg})
			updateSay("  %s %s\n", terminal.SuccessSymbol(), terminal.White(msg))
		}
	} else {
		out.Steps = append(out.Steps, updateStepResult{Step: "templates", Status: "skipped"})
	}

	if globalJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	}

	return firstErr
}

// updateBinary re-runs the public installer. Its output is routed to stderr so
// stdout stays a clean JSON document under --json.
func updateBinary() error {
	ctx, cancel := context.WithTimeout(context.Background(), updateStepTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", "curl -fsSL "+installScriptURL+" | bash")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install script failed: %w", err)
	}
	return nil
}

// updateNucleiTemplates refreshes the templates checkout in place when it is an
// existing git clone, clones it fresh when absent, and refuses to touch a path
// that exists but is not a git repository (it may hold user data).
//
// The codebase clones with --depth 1, so a plain `git pull` is unsafe; a
// shallow fetch followed by `reset --hard FETCH_HEAD` is the robust shallow
// update and does not depend on knowing the default branch name.
func updateNucleiTemplates(dir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), updateStepTimeout)
	defer cancel()

	info, err := os.Stat(dir)
	switch {
	case err == nil && info.IsDir():
		if gi, gerr := os.Stat(filepath.Join(dir, ".git")); gerr != nil || !gi.IsDir() {
			return "", fmt.Errorf("%s exists but is not a git repository; remove it (or point known_issue_scan.templates_dir elsewhere) and re-run", config.ContractPath(dir))
		}
		if e := runGit(ctx, dir, "fetch", "--quiet", "--depth", "1", "origin"); e != nil {
			return "", fmt.Errorf("git fetch failed: %w", e)
		}
		if e := runGit(ctx, dir, "reset", "--quiet", "--hard", "FETCH_HEAD"); e != nil {
			return "", fmt.Errorf("git reset failed: %w", e)
		}
		return fmt.Sprintf("nuclei templates updated at %s", config.ContractPath(dir)), nil
	case err == nil && !info.IsDir():
		return "", fmt.Errorf("%s exists but is not a directory", config.ContractPath(dir))
	case os.IsNotExist(err):
		if e := runGit(ctx, "", "clone", "--quiet", "--depth", "1", nucleiTemplatesRepo, dir); e != nil {
			return "", fmt.Errorf("git clone failed: %w", e)
		}
		return fmt.Sprintf("nuclei templates cloned to %s", config.ContractPath(dir)), nil
	default:
		return "", fmt.Errorf("cannot stat %s: %w", config.ContractPath(dir), err)
	}
}

// runGit runs git with output wired to stderr. When dir is non-empty it is
// passed via -C so the command operates on that working tree.
func runGit(ctx context.Context, dir string, args ...string) error {
	full := args
	if dir != "" {
		full = append([]string{"-C", dir}, args...)
	}
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// binaryPathWarning returns a non-empty warning when the running binary is not
// the one the installer just wrote to ~/.local/bin/vigolium — in that case the
// freshly installed binary will only be picked up if ~/.local/bin precedes the
// current binary's directory on PATH.
func binaryPathWarning() string {
	expected := config.ExpandPath(installedBinaryPath)
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	if resolved, rerr := filepath.EvalSymlinks(expected); rerr == nil {
		expected = resolved
	}
	if filepath.Clean(exe) == filepath.Clean(expected) {
		return ""
	}
	return fmt.Sprintf("running binary is %s but the update installed to %s — ensure ~/.local/bin precedes it on PATH, or replace that copy manually",
		filepath.Clean(exe), config.ExpandPath(installedBinaryPath))
}
