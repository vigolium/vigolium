package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium schema pace` publishes which pace dial binds in which phase, the
// table behind pace_unsupported and scan.started's pace_ignored, so a caller
// reads it instead of keeping its own copy.

var schemaPaceCmd = &cobra.Command{
	Use:   "pace",
	Short: "List which pace dial (--concurrency, --rate-limit, --max-per-host) each phase enforces",
	Long: "List every (phase, dial) pair of the pace vocabulary and whether that phase enforces the dial. " +
		"A phase-qualified flag or --set naming a pair with enforced false is refused (exit 2 " +
		"pace_unsupported); the same pair from a config file warns and is reported on scan.started as " +
		"pace_ignored.",
	Example: "  vigolium schema pace\n  vigolium schema pace -j",
	Args:    cobra.NoArgs,
	RunE:    runSchemaPace,
}

func init() {
	schemaCmd.AddCommand(schemaPaceCmd)
}

// schemaPaceRow is one `schema pace -j` row.
type schemaPaceRow struct {
	Phase string `json:"phase"`
	// Dial is the pace field (concurrency, rate_limit, max_per_host); Flag is
	// the flag that sets it, qualified as `--<flag> <phase>=N`.
	Dial     string `json:"dial"`
	Flag     string `json:"flag"`
	Enforced bool   `json:"enforced"`
}

func schemaPaceRows() []schemaPaceRow {
	pairs := config.PhasePacePairs()
	out := make([]schemaPaceRow, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, schemaPaceRow{Phase: p.Phase, Dial: p.Dial, Flag: "--" + paceDialFlag(p.Dial).flagName, Enforced: p.Enforced})
	}
	return out
}

func runSchemaPace(cmd *cobra.Command, _ []string) error {
	rows := schemaPaceRows()
	if globalJSON {
		return emitRead(cmd, "", rows, int64(len(rows)), 0, len(rows))
	}
	for _, r := range rows {
		mark := terminal.Gray("not enforced")
		if r.Enforced {
			mark = terminal.Green("enforced    ")
		}
		fmt.Printf("  %s  %-20s %s\n", mark, r.Phase, r.Flag)
	}
	return nil
}
