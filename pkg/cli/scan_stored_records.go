package cli

import (
	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/types"
)

// Stored records in a targeted scan.
//
// `scan -t` names an origin, so it tests the records already stored for that
// origin too, and says how many; --input-only turns that off. scan-url,
// scan-request and `run <phase> -t` name an input, so they test only it (and
// what the run finds from it) unless --include-stored asks for the rest.

var (
	scanInputOnly     bool
	scanIncludeStored bool
)

// registerInputOnlyFlag adds scan's --input-only.
func registerInputOnlyFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&scanInputOnly, "input-only", false,
		"Test only the targets/input and what this run finds from them, not the records already stored for their hosts")
}

// registerIncludeStoredFlag adds --include-stored to the input-only commands.
func registerIncludeStoredFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&scanIncludeStored, "include-stored", false,
		"Also test the records already stored for the target's hosts (by default only the input and what this run finds from it are tested)")
}

// storedRecordsMode is the Options.StoredRecords value for cmd: "exclude"
// for --input-only and for the input-only commands without --include-stored,
// "include" for --include-stored, "" (include) otherwise.
func storedRecordsMode(cmd *cobra.Command, hasTargets bool) string {
	switch commandPathWithoutRoot(cmd) {
	case "scan-url", "scan-request":
		if scanIncludeStored {
			return types.StoredRecordsInclude
		}
		return types.StoredRecordsExclude
	case "run":
		if scanIncludeStored {
			return types.StoredRecordsInclude
		}
		if hasTargets {
			return types.StoredRecordsExclude
		}
		return ""
	}
	if scanInputOnly {
		return types.StoredRecordsExclude
	}
	return ""
}
