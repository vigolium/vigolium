package cli

import "github.com/spf13/cobra"

var runCmd = &cobra.Command{
	Use:   "run <phase>",
	Short: "Run a single native scan phase (alias for scan --only <phase>)",
	Long: `Run a single scan phase directly. Equivalent to "vigolium scan --only <phase>".

Valid phases: ingestion, discovery (deparos), external-harvest, known-issue-scan, spidering (spitolas), sast, dynamic-assessment (dast, audit, assessment), extension (ext)`,
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"r"},
	RunE: func(cmd *cobra.Command, args []string) error {
		globalOnly = args[0]
		return runScanCmd(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	registerNativeScanFlags(runCmd.Flags(), true)
}
