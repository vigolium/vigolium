package cli

import (
	"fmt"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var strategyCmd = &cobra.Command{
	Use:     "strategy",
	Aliases: []string{"st", "phase"},
	Short:   "Manage scanning strategies",
	Run: func(cmd *cobra.Command, args []string) {
		_ = runStrategyLs(cmd, args)
	},
}

var strategyLsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List available scanning strategies",
	RunE:    runStrategyLs,
}

func init() {
	rootCmd.AddCommand(strategyCmd)
	strategyCmd.AddCommand(strategyLsCmd)
}

func runStrategyLs(_ *cobra.Command, _ []string) error {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	cfg := &settings.ScanningStrategy
	defaultName := cfg.DefaultStrategy

	// Show active scanning profile
	activeProfile := cfg.ScanningProfile
	if activeProfile == "" {
		activeProfile = terminal.Gray("none")
	} else {
		activeProfile = terminal.BoldCyan(activeProfile)
	}

	fmt.Printf("\n  %s Scanning Strategies (default: %s, profile: %s)\n\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(defaultName),
		activeProfile)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "EXT HARVESTER", "DISCOVERY", "SPIDERING", "KNOWN-ISSUE-SCAN", "DYNAMIC", "SOURCE-AWARE")
	for _, name := range cfg.StrategyNames() {
		phases, _ := cfg.GetStrategy(name)

		label := name
		if name == defaultName {
			label = name + " *"
		}

		tbl.AddRow(
			terminal.Cyan(label),
			boolCell(phases.ExternalHarvesting),
			boolCell(phases.Discovery),
			boolCell(phases.Spidering),
			boolCell(phases.KnownIssueScan),
			boolCell(phases.DynamicAssessment),
			boolCell(phases.SourceAware),
		)
	}
	tbl.Print()

	fmt.Println()
	fmt.Printf("%s Select a strategy: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium scan --strategy <name>"))
	fmt.Printf("%s Available phases:\n", terminal.InfoSymbol())
	fmt.Printf("  %s %s\n", terminal.Yellow(terminal.SymbolBowtie), terminal.Yellow("ingestion (in background)"))
	fmt.Printf("    %s\n", terminal.Gray("Continuously ingest inputs from multiple sources such as URLs,"))
	fmt.Printf("    %s\n", terminal.Gray("OpenAPI specs, Burp exports, and others into the database"))
	fmt.Printf("  %s %s\n", terminal.ListSymbol(), terminal.HiBlue("discovery"))
	fmt.Printf("    %s\n", terminal.Gray("Enumerate and uncover directories, files, and hidden endpoints"))
	fmt.Printf("    %s\n", terminal.Gray("using the Deparos adaptive content discovery engine"))
	fmt.Printf("  %s %s\n", terminal.ListSymbol(), terminal.HiBlue("external-harvest"))
	fmt.Printf("    %s\n", terminal.Gray("Aggregate known URLs from external intelligence sources such as"))
	fmt.Printf("    %s\n", terminal.Gray("Wayback Machine, Common Crawl, AlienVault OTX"))
	fmt.Printf("  %s %s\n", terminal.ListSymbol(), terminal.HiBlue("spidering"))
	fmt.Printf("    %s\n", terminal.Gray("Crawl the target using a headless browser to discover dynamic"))
	fmt.Printf("    %s\n", terminal.Gray("content, JavaScript-driven routes, and client-side state transitions"))
	fmt.Printf("  %s %s\n", terminal.ListSymbol(), terminal.HiBlue("known-issue-scan"))
	fmt.Printf("    %s\n", terminal.Gray("Perform a known issue scan leveraging Nuclei templates"))
	fmt.Printf("    %s\n", terminal.Gray("and trusted third-party validation checks"))
	fmt.Printf("  %s %s\n", terminal.ListSymbol(), terminal.HiBlue("dynamic-assessment"))
	fmt.Printf("    %s\n", terminal.Gray("The core Vigolium engine for executing dynamic security assessments"))
	fmt.Printf("    %s\n", terminal.Gray("through coordinated active and passive scanning modules"))
	fmt.Printf("%s Run a single phase: %s or %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium run <phase>"),
		terminal.Gray("vigolium scan --only <phase>"))
	fmt.Printf("%s Set default in config: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium config set scanning_strategy.default_strategy <name>"))

	// List scanning profiles
	profilesList, _ := cfg.ListProfiles()
	if len(profilesList) > 0 {
		fmt.Printf("%s Scanning profiles (%s):\n",
			terminal.InfoSymbol(),
			terminal.Gray(config.ContractPath(config.ExpandPath(cfg.ProfilesDir))))
		for _, name := range profilesList {
			path := cfg.ResolveProfilePath(name)
			desc := config.ProfileDescription(path)
			if desc != "" {
				fmt.Printf("  %s %s %s\n", terminal.ListSymbol(), terminal.Cyan(name), terminal.Gray("— "+desc))
			} else {
				fmt.Printf("  %s %s\n", terminal.ListSymbol(), terminal.Cyan(name))
			}
		}
		fmt.Printf("%s Use a profile: %s\n",
			terminal.InfoSymbol(),
			terminal.Gray("vigolium scan --scanning-profile <name>"))
	}

	return nil
}

func boolCell(v bool) string {
	if v {
		return terminal.Green("yes")
	}
	return terminal.Gray("-")
}
