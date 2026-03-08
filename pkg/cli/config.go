package cli

import (
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
}

func init() {
	rootCmd.AddCommand(configCmd)
}
