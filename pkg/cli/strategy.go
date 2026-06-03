package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var strategyCmd = &cobra.Command{
	Use:     "strategy",
	Aliases: []string{"st", "phase"},
	Short:   "Show scanning strategies, phases, intensities, and agent modes",
	Long: "Inspect built-in scanning strategies (lite, balanced, deep) and the phases they bundle, " +
		"the scan intensity levels that tune how hard agent and native scans run, the available agent modes, " +
		"and the installed scanning profiles. Pass a strategy to a scan with --strategy.",
	RunE: runStrategy,
}

func init() {
	rootCmd.AddCommand(strategyCmd)
}

// strategy output palette: orange symbols, green labels, white data. The
// native-scan phases block instead uses blue symbols + blue labels (b* helpers)
// to set it apart.
func sInfo() string { return terminal.Orange(terminal.SymbolInfo) }
func sList() string { return terminal.Orange(terminal.SymbolMenu) }
func bInfo() string { return terminal.Blue(terminal.SymbolInfo) }
func bList() string { return terminal.Blue(terminal.SymbolMenu) }

func runStrategy(_ *cobra.Command, _ []string) error {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	cfg := &settings.ScanningStrategy
	defaultName := cfg.DefaultStrategy

	// Show active scanning profile (native scan data → cyan)
	activeProfile := terminal.Cyan("none")
	if cfg.ScanningProfile != "" {
		activeProfile = terminal.Cyan(cfg.ScanningProfile)
	}

	fmt.Printf("\n  %s %s (default: %s, profile: %s)\n\n",
		sInfo(),
		terminal.Green("Scanning Strategies"),
		terminal.Cyan(defaultName),
		activeProfile)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "EXT HARVESTER", "DISCOVERY", "SPIDERING", "KNOWN-ISSUE-SCAN", "DYNAMIC")
	for _, name := range cfg.StrategyNames() {
		phases, _ := cfg.GetStrategy(name)

		label := name
		if name == defaultName {
			label = name + " *"
		}

		tbl.AddRow(
			terminal.Green(label),
			boolCell(phases.ExternalHarvesting),
			boolCell(phases.Discovery),
			boolCell(phases.Spidering),
			boolCell(phases.KnownIssueScan),
			boolCell(phases.DynamicAssessment),
		)
	}
	tbl.Print()

	fmt.Println()
	fmt.Printf("%s %s %s\n",
		bInfo(),
		terminal.Blue("Select a strategy:"),
		terminal.White("vigolium scan --strategy <name>"))
	fmt.Printf("%s %s\n", bInfo(), terminal.Blue("Available phases:"))
	fmt.Printf("  %s %s\n", terminal.Blue(terminal.SymbolBowtie), terminal.Blue("ingestion (in background)"))
	fmt.Printf("    %s\n", terminal.White("Continuously ingest inputs from multiple sources such as URLs,"))
	fmt.Printf("    %s\n", terminal.White("OpenAPI specs, Burp exports, and others into the database"))
	fmt.Printf("  %s %s\n", bList(), terminal.Blue("discovery"))
	fmt.Printf("    %s\n", terminal.White("Enumerate and uncover directories, files, and hidden endpoints"))
	fmt.Printf("    %s\n", terminal.White("using the Deparos adaptive content discovery engine"))
	fmt.Printf("  %s %s\n", bList(), terminal.Blue("external-harvest"))
	fmt.Printf("    %s\n", terminal.White("Aggregate known URLs from external intelligence sources such as"))
	fmt.Printf("    %s\n", terminal.White("Wayback Machine, Common Crawl, AlienVault OTX"))
	fmt.Printf("  %s %s\n", bList(), terminal.Blue("spidering"))
	fmt.Printf("    %s\n", terminal.White("Crawl the target using a headless browser to discover dynamic"))
	fmt.Printf("    %s\n", terminal.White("content, JavaScript-driven routes, and client-side state transitions"))
	fmt.Printf("  %s %s\n", bList(), terminal.Blue("known-issue-scan"))
	fmt.Printf("    %s\n", terminal.White("Perform a known issue scan leveraging Nuclei templates"))
	fmt.Printf("    %s\n", terminal.White("and trusted third-party validation checks"))
	fmt.Printf("  %s %s\n", bList(), terminal.Blue("dynamic-assessment"))
	fmt.Printf("    %s\n", terminal.White("The core Vigolium engine for executing dynamic security assessments"))
	fmt.Printf("    %s\n", terminal.White("through coordinated active and passive scanning modules"))
	fmt.Printf("%s %s %s or %s\n",
		bInfo(),
		terminal.Blue("Run a single phase:"),
		terminal.White("vigolium run <phase>"),
		terminal.White("vigolium scan --only <phase>"))
	fmt.Printf("%s %s %s\n",
		bInfo(),
		terminal.Blue("Set default in config:"),
		terminal.White("vigolium config set scanning_strategy.default_strategy <name>"))

	printScanIntensities()
	printAgentModes()
	printScanningProfiles(cfg)

	return nil
}

// printScanningProfiles lists the installed scanning profiles (native-scan
// presets selectable via --scanning-profile), honoring the command's promise to
// show "the installed scanning profiles". No-op when none are installed.
func printScanningProfiles(cfg *config.ScanningStrategyConfig) {
	profilesList, _ := cfg.ListProfiles()
	if len(profilesList) == 0 {
		return
	}
	fmt.Println()
	fmt.Printf("  %s %s (%s)\n\n",
		sInfo(),
		terminal.Green("Scanning Profiles"),
		terminal.White(config.ContractPath(config.ExpandPath(cfg.ProfilesDir))))
	for _, name := range profilesList {
		desc := config.ProfileDescription(cfg.ResolveProfilePath(name))
		if desc != "" {
			fmt.Printf("  %s %s %s\n", sList(), terminal.Green(name), terminal.White("— "+desc))
		} else {
			fmt.Printf("  %s %s\n", sList(), terminal.Green(name))
		}
	}
	fmt.Printf("%s %s %s\n",
		sInfo(),
		terminal.Green("Use a profile:"),
		terminal.White("vigolium scan --scanning-profile <name>"))
}

// printScanIntensities renders the --intensity levels and what each one tunes,
// sourced from the agenttypes presets so the table stays in lockstep with the
// values the agent modes actually use.
func printScanIntensities() {
	fmt.Println()
	fmt.Printf("  %s %s\n\n",
		sInfo(),
		terminal.Green(fmt.Sprintf("Scan Intensity (--intensity, default: %s)", agenttypes.IntensityBalanced)))
	fmt.Printf("    %s\n", terminal.White("--strategy picks WHICH phases run; --intensity tunes HOW HARD the"))
	fmt.Printf("    %s\n\n", terminal.White("agent modes (autopilot/swarm/audit) and native scans push."))

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "INTENSITY", "NATIVE PROFILE", "AUTOPILOT", "SWARM", "AUDIT")
	for _, in := range []agenttypes.Intensity{agenttypes.IntensityQuick, agenttypes.IntensityBalanced, agenttypes.IntensityDeep} {
		ap := agenttypes.AutopilotPresets[in]
		sw := agenttypes.SwarmPresets[in]
		au := agenttypes.AuditDriverPresets[in]

		label := string(in)
		if in == agenttypes.IntensityBalanced {
			label += " *"
		}

		tbl.AddRow(
			terminal.Green(label),
			terminal.Cyan(agenttypes.NativeScanIntensityProfiles[in]),
			fmt.Sprintf("%d cmd / %s", ap.MaxCommands, humanHours(ap.Timeout)),
			swarmIntensityCell(sw),
			strings.Join(au.Modes, "→"),
		)
	}
	tbl.Print()

	fmt.Printf("%s %s %s\n",
		sInfo(),
		terminal.Green("Set the intensity:"),
		terminal.White("vigolium scan --intensity deep"))
}

// swarmIntensityCell summarizes a swarm preset: iteration count plus the flags
// that flip on as intensity climbs (triage, then auth on deep).
func swarmIntensityCell(p agenttypes.SwarmIntensityPreset) string {
	s := fmt.Sprintf("%d iter", p.MaxIterations)
	if p.Triage {
		s += ", triage"
	}
	if p.Auth {
		s += ", auth"
	}
	return s
}

// printAgentModes lists the agent subcommands and the audit mode vocabulary.
func printAgentModes() {
	fmt.Println()
	fmt.Printf("  %s %s (%s)\n\n",
		sInfo(), terminal.Green("Agent Modes"), terminal.White("vigolium agent <mode>"))

	modes := []struct{ name, desc string }{
		{"query", "Single-shot prompt — code review, endpoint & secret discovery (no scanning)"},
		{"autopilot", "Autonomous AI-driven vulnerability scanning"},
		{"swarm", "AI-guided vulnerability swarm; add --discover for full-scope scanning"},
		{"olium", "Interactive TUI agent (olium engine)"},
		{"audit", "Source-code security audit (audit / piolium drivers)"},
	}
	for _, m := range modes {
		fmt.Printf("  %s %s %s\n",
			sList(),
			terminal.Green(fmt.Sprintf("%-10s", m.name)),
			terminal.White("— "+m.desc))
	}
	fmt.Printf("%s %s %s\n",
		sInfo(),
		terminal.Green("Audit modes (--mode / --modes):"),
		terminal.White("lite, balanced, deep, revisit, confirm, merge"))
	fmt.Printf("%s %s %s\n",
		sInfo(),
		terminal.Green("Full audit mode graph:"),
		terminal.White("vigolium agent audit --list-modes"))
}

// humanHours renders a duration in hours, dropping trailing zeros via %g so
// whole hours stay compact (1h, 6h, 12h) while fractional presets still read
// correctly (1.5h).
func humanHours(d time.Duration) string {
	return fmt.Sprintf("%gh", d.Hours())
}

func boolCell(v bool) string {
	if v {
		return terminal.Green("yes")
	}
	return terminal.Gray("-")
}
