package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/vigolium/vigolium/internal/logger"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	Name        = "vigolium"
	Description = "High-fidelity vulnerability scanner that combines speed, modularity, and precision"
	Author      = "@j3ssie"
	Version     = "v0.0.1-alpha"
	Commit      = ""
	BuildTime   = ""
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		printVersion()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
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
	return fmt.Sprintf("%s %s - Crafted with %s by %s\n",
		terminal.BoldYellow(terminal.SymbolLightning),
		terminal.BoldGreen(Name+" "+getVersion()),
		terminal.Red("<3"),
		terminal.BoldMagenta(Author),
	)
}

func printVersion() {
	if globalJSON {
		printVersionJSON()
		return
	}

	fmt.Printf("%s - %s\n", terminal.BoldCyan(Name), terminal.White(Description))
	fmt.Printf("%s %s\n", terminal.Cyan("Version:"), terminal.BoldGreen(getVersion()))
	if BuildTime != "" {
		fmt.Printf("%s %s\n", terminal.Cyan("Build:"), terminal.Yellow(BuildTime))
	}
	if Commit != "" {
		commit := Commit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		fmt.Printf("%s %s\n", terminal.Cyan("Commit:"), terminal.Yellow(commit))
	}
	fmt.Printf("%s %s\n", terminal.Cyan("Author:"), terminal.Magenta(Author))
	fmt.Printf("%s %s\n", terminal.Cyan("Docs:"), terminal.Blue("https://docs.vigolium.io"))
}

func printVersionJSON() {
	commit := Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}

	info := map[string]string{
		"name":    Name,
		"version": getVersion(),
		"author":  Author,
		"docs":    "https://docs.vigolium.io",
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
