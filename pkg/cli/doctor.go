package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system readiness and diagnose configuration issues",
	Long:  "Run diagnostic checks on database, agent backends, third-party tools, and other dependencies to verify the scanner is ready to operate.",
	RunE:  runDoctorCmd,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctorCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	deps := diagnostics.Deps{Settings: settings}

	// Try to open DB (optional — report error if it fails)
	db, dbErr := getDB()
	if dbErr == nil {
		deps.DB = db
		defer closeDatabaseOnExit()
	}

	report := diagnostics.Run(deps)

	if globalJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	printDoctorReport(report)
	return nil
}

func printDoctorReport(r *diagnostics.Report) {
	fmt.Println()
	fmt.Printf("  %s %s\n", terminal.BoldCyan("Vigolium Doctor"), terminal.White("— system readiness check"))
	fmt.Println()

	printCheck("Database", r.Database.Status, r.Database.Message)
	printCheck("Agent", r.Agent.Status, formatAgentMessage(r.Agent))

	if r.Queue != nil {
		printCheck("Queue", r.Queue.Status, r.Queue.Message)
	}

	printCheck("Browser", r.Browser.Status, r.Browser.Message)

	for name, tool := range r.Tools {
		msg := tool.Path
		if msg == "" {
			msg = tool.Message
		}
		printCheck("Tool: "+name, tool.Status, msg)
	}

	printCheck("Templates Dir", r.TemplatesDir.Status, r.TemplatesDir.Message)
	printCheck("Sessions Dir", r.SessionsDir.Status, r.SessionsDir.Message)

	fmt.Println()
	switch r.Status {
	case "ready":
		fmt.Printf("  %s %s\n", terminal.BoldGreen(terminal.SymbolSuccess), terminal.BoldGreen("All systems ready"))
	case "degraded":
		fmt.Printf("  %s %s\n", terminal.BoldYellow(terminal.SymbolWarning), terminal.BoldYellow("System degraded — some optional components unavailable"))
	default:
		fmt.Printf("  %s %s\n", terminal.BoldRed(terminal.SymbolError), terminal.BoldRed("System not ready — critical components missing"))
	}
	fmt.Println()
}

func printCheck(label string, status diagnostics.Status, message string) {
	var symbol, coloredLabel string
	switch status {
	case diagnostics.StatusOK:
		symbol = terminal.Green(terminal.SymbolSuccess)
		coloredLabel = terminal.Green(label)
	case diagnostics.StatusWarning:
		symbol = terminal.Yellow(terminal.SymbolWarning)
		coloredLabel = terminal.Yellow(label)
	default:
		symbol = terminal.Red(terminal.SymbolError)
		coloredLabel = terminal.Red(label)
	}

	if message != "" {
		fmt.Printf("  %s %-20s %s\n", symbol, coloredLabel, terminal.White(message))
	} else {
		fmt.Printf("  %s %s\n", symbol, coloredLabel)
	}
}

func formatAgentMessage(a *diagnostics.AgentCheck) string {
	if a.Status != diagnostics.StatusOK {
		return a.Message
	}
	return fmt.Sprintf("name=%s, protocol=%s, binary=%s", a.Name, a.Protocol, a.Binary)
}
