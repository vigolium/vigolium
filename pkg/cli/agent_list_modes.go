package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/vigolium/vigolium/pkg/audit/bin"
)

// runListModes streams the embedded vigolium-audit binary's `list` output
// verbatim. audit owns the canonical mode graph, so shelling out keeps
// `--list-modes` in lock-step with whatever audit ships rather than
// re-rendering (which would drift). jsonOut requests NDJSON.
func runListModes(jsonOut bool) error {
	bin, err := bin.Path()
	if err != nil {
		return fmt.Errorf("vigolium-audit binary not embedded — run `make build-audit` and rebuild vigolium: %w", err)
	}

	args := []string{"list"}
	if jsonOut {
		args = append(args, "--json")
	}

	cmd := exec.CommandContext(context.Background(), bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("audit list failed: %w", err)
	}

	if !jsonOut {
		_, _ = fmt.Fprintln(os.Stdout)
		_, _ = fmt.Fprintln(os.Stdout, "Note: this is audit's mode graph. piolium (driver=piolium) supports")
		_, _ = fmt.Fprintln(os.Stdout, "lite, balanced, deep, revisit, confirm, merge, diff, longshot — it does")
		_, _ = fmt.Fprintln(os.Stdout, "not support reinvest/mock/refresh. With --modes on driver=auto/both,")
		_, _ = fmt.Fprintln(os.Stdout, "modes a driver can't run are skipped on that driver's leg.")
	}
	return nil
}
