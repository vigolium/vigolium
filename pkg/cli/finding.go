package cli

import (
	"github.com/spf13/cobra"
)

var findingCmd = &cobra.Command{
	Use:     "finding",
	Aliases: []string{"findings"},
	Short:   "Browse findings (alias: db ls --table findings)",
	Long:    "Alias for 'vigolium db ls --table findings'. Browse vulnerability findings with filtering and sorting.",
	RunE: func(cmd *cobra.Command, args []string) error {
		globalTable = "findings"
		return runDBList(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(findingCmd)
	registerListFlags(findingCmd)
	findingCmd.Flags().StringVar(&dbSearch, "search", "", "Quick search across findings")
}
