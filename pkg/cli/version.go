package cli

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/logger"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	Name               = "vigolium"
	Description        = "High-fidelity vulnerability scanner that combines speed, modularity, and precision"
	Author             = "@j3ssie"
	InitialContributor = "@theblackturtle"
	Version            = "v0.5.7"
	Commit             = ""
	BuildTime          = ""
)

// DiscoveryAuthors credits the discovery and spidering phases.
const DiscoveryAuthors = "@j3ssie"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Print Vigolium version, build time, git commit, and author/contributor info. Pair with -j/--json to emit a machine-readable JSON object instead.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return printVersion(cmd)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	// Expose the binary version to httpmsg so a configured User-Agent
	// containing {version} resolves correctly (httpmsg cannot import this
	// package without an import cycle). Uses the ldflag-injected Version
	// directly to keep init side-effect-free (no git exec on every run).
	httpmsg.SetBuildVersion(Version)
	// schema_meta.written_by names the build that last migrated a store, so a
	// schema_too_new refusal can say which vigolium to upgrade to.
	database.SetBinaryVersion(Version)
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
		Name+" "+getVersion(),
		terminal.Red("<3"),
		terminal.BoldMagenta(authors),
	)
}

func printVersion(cmd *cobra.Command) error {
	if globalJSON {
		return printVersionJSON(cmd)
	}

	fmt.Printf("%s - %s\n", terminal.BoldCyan("Vigolium"), Description)
	fmt.Printf("%s %s\n", "Version:", terminal.BoldGreen(getVersion()))
	if BuildTime != "" {
		fmt.Printf("%s %s\n", "Build:", terminal.Yellow(BuildTime))
	}
	if Commit != "" {
		commit := Commit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		fmt.Printf("%s %s\n", "Commit:", terminal.Yellow(commit))
	}
	fmt.Printf("%s %s\n", "Features:", strings.Join(versionFeatureNames(), ", "))
	fmt.Printf("%s %s\n", "Author:", terminal.Magenta(Author))
	fmt.Printf("%s %s\n", "Initial Contributor:", terminal.Magenta(InitialContributor))
	fmt.Printf("%s %s\n", "Website:", terminal.Blue("https://www.vigolium.com"))
	fmt.Printf("%s %s\n", "Docs:", terminal.Blue("https://docs.vigolium.com"))
	return nil
}

// printVersionJSON writes the version facts as items:[info]; --json-legacy-keys
// flattens them back to the top level, the bare object this printed before.
func printVersionJSON(cmd *cobra.Command) error {
	commit := Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}

	// The two version numbers a consumer actually needs are the ones that were
	// missing: schema_version says which -j envelope contract this binary speaks,
	// and db_schema_version says which database layout it expects. Without them a
	// drift is discovered as a parse failure in production; with them it is a
	// check at startup.
	info := map[string]any{
		"name":                Name,
		"version":             getVersion(),
		"schema_version":      AgentSchemaVersion,
		"db_schema_version":   database.CurrentSchemaVersion(),
		"author":              Author,
		"initial_contributor": InitialContributor,
		"website":             "https://www.vigolium.com",
		"docs":                "https://docs.vigolium.com",
	}
	// The reader floor this binary stamps on stores it migrates. A store is
	// readable here when its min_reader_version <= db_schema_version, and
	// writable only when its version <= db_schema_version (else schema_too_new).
	info["db_min_reader_version"] = database.MinReaderVersion()
	// features names the capabilities a caller may gate on (version_features.go).
	info["features"] = versionFeatureNames()
	if BuildTime != "" {
		info["build_time"] = BuildTime
	}
	if commit != "" {
		info["commit"] = commit
	}

	return emitObject(cmd, ".", info)
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
