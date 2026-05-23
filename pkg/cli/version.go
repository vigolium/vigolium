package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/logger"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	Name               = "vigolium"
	Description        = "High-fidelity vulnerability scanner that combines speed, modularity, and precision"
	Author             = "@j3ssie"
	InitialContributor = "@theblackturtle"
	Version            = "v0.1.10-alpha"
	Commit             = ""
	BuildTime          = ""
)

// DiscoveryAuthors credits the discovery and spidering phases.
const DiscoveryAuthors = "@j3ssie"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Print Vigolium version, build time, git commit, and author/contributor info. Pair with -j/--json to emit a machine-readable JSON object instead.",
	Run: func(cmd *cobra.Command, args []string) {
		printVersion()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	// Expose the binary version to httpmsg so a configured User-Agent
	// containing {version} resolves correctly (httpmsg cannot import this
	// package without an import cycle). Uses the ldflag-injected Version
	// directly to keep init side-effect-free (no git exec on every run).
	httpmsg.SetBuildVersion(Version)
}

func getVersion() string {
	if Version != "dev" {
		return Version
	}
	if Commit != "" {
		return Commit[:min(7, len(Commit))]
	}
	// Try to get git commit at runtime
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "dev"
}

func GetBanner() string {
	return bannerFor(Author)
}

// GetDiscoveryBanner returns the banner crediting the discovery/spidering
// co-author alongside the default author.
func GetDiscoveryBanner() string {
	return bannerFor(DiscoveryAuthors)
}

// GetOliumBanner returns the startup banner for the olium agent CLI.
// Uses a cooler palette (cyan body + magenta eye) to distinguish it from
// the scanner banner at a glance.
func GetOliumBanner() string {
	mascot := terminal.ColoredMascot(terminal.RandomMascot(), terminal.BoldGreen, terminal.BoldRed)
	return fmt.Sprintf("%s %s - Crafted with %s by %s\n",
		mascot,
		terminal.BoldCyan("olium "+getVersion()),
		terminal.Red("<3"),
		terminal.BoldMagenta(Author),
	)
}

func bannerFor(authors string) string {
	mascot := terminal.ColoredMascot(terminal.RandomMascot(), terminal.BoldGreen, terminal.BoldRed)
	return fmt.Sprintf("%s %s - Crafted with %s by %s\n",
		mascot,
		terminal.BoldGreen(Name+" "+getVersion()),
		terminal.Red("<3"),
		terminal.BoldMagenta(authors),
	)
}

func printVersion() {
	if globalJSON {
		printVersionJSON()
		return
	}

	fmt.Printf("%s - %s\n", terminal.BoldCyan("Vigolium"), terminal.White(Description))
	fmt.Printf("%s %s\n", terminal.HiWhite("Version:"), terminal.BoldGreen(getVersion()))
	if BuildTime != "" {
		fmt.Printf("%s %s\n", terminal.HiWhite("Build:"), terminal.Yellow(BuildTime))
	}
	if Commit != "" {
		commit := Commit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		fmt.Printf("%s %s\n", terminal.HiWhite("Commit:"), terminal.Yellow(commit))
	}
	fmt.Printf("%s %s\n", terminal.HiWhite("Author:"), terminal.Magenta(Author))
	fmt.Printf("%s %s\n", terminal.HiWhite("Initial Contributor:"), terminal.Magenta(InitialContributor))
	fmt.Printf("%s %s\n", terminal.HiWhite("Website:"), terminal.Blue("https://www.vigolium.com"))
	fmt.Printf("%s %s\n", terminal.HiWhite("Docs:"), terminal.Blue("https://docs.vigolium.com"))
}

func printVersionJSON() {
	commit := Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}

	info := map[string]string{
		"name":                Name,
		"version":             getVersion(),
		"author":              Author,
		"initial_contributor": InitialContributor,
		"website":             "https://www.vigolium.com",
		"docs":                "https://docs.vigolium.com",
	}
	if BuildTime != "" {
		info["build_time"] = BuildTime
	}
	if commit != "" {
		info["commit"] = commit
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

func initLogger(verbose, silent, debug, dumpTraffic bool, logFile string) *zap.Logger {
	cfg := logger.Config{
		Level:   logger.ErrorLevel,
		Verbose: verbose || debug || dumpTraffic,
		LogFile: logFile,
	}
	if verbose {
		cfg.Level = logger.InfoLevel
	}
	if debug || dumpTraffic {
		cfg.Level = logger.DebugLevel
	}
	if silent {
		cfg.Level = logger.SilentLevel
	}
	return logger.Init(cfg)
}
