package cli

import (
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  "Inspect and edit Vigolium settings stored in ~/.vigolium/vigolium-configs.yaml. Subcommands list current values, set keys via dot-notation, and reset to clean defaults.",
}

func init() {
	rootCmd.AddCommand(configCmd)
}
