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

// storedRecordsMode is the Options.StoredRecords value for cmd. A command
// with --include-stored names an input: "include" with the flag, "exclude"
// when it has targets, "" (include) over stored records alone. Any other
// command names an origin: "exclude" only for --input-only.
func storedRecordsMode(cmd *cobra.Command, hasTargets bool) string {
	switch {
	case cmd.Flags().Lookup("include-stored") == nil:
		if scanInputOnly {
			return types.StoredRecordsExclude
		}
		return ""
	case scanIncludeStored:
		return types.StoredRecordsInclude
	case hasTargets:
		return types.StoredRecordsExclude
	}
	return ""
}

// validateNoAuth rejects --no-auth together with --auth/--auth-file: one says
// scan without a session, the other names one.
func validateNoAuth() error {
	if scanOpts.NoAuth && len(scanOpts.AuthFiles)+len(scanOpts.AuthInline) > 0 {
		return usageErrorf("--no-auth and --auth/--auth-file are mutually exclusive")
	}
	return nil
}
