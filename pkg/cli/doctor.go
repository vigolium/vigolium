package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	doctorFix  bool
	doctorOnly []string
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system readiness and diagnose configuration issues",
	Long:  "Run diagnostic checks on database, agent backends, third-party tools, and other dependencies to verify the scanner is ready to operate.",
	RunE:  runDoctorCmd,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "Auto-install/fix failing checks")
	doctorCmd.Flags().StringSliceVar(&doctorOnly, "only", nil, "Fix only specific items (bun,chrome,ast-grep,agent-browser,claude,nuclei)")
}

// doctorOutput is the JSON structure when --fix is used with --json.
type doctorOutput struct {
	Report  *diagnostics.Report      `json:"report"`
	Fixes   []diagnostics.FixResult  `json:"fixes,omitempty"`
	Updated *diagnostics.Report      `json:"updated,omitempty"`
}

func runDoctorCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	if len(doctorOnly) > 0 && !doctorFix {
		fmt.Printf("  %s --only has no effect without --fix\n", terminal.Yellow(terminal.SymbolWarning))
		return nil
	}

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

	if !doctorFix {
		if globalJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}
		printDoctorReport(report, globalVerbose || globalDebug)
		return nil
	}

	// --fix mode: print initial report, fix, then recheck.
	verbose := globalVerbose || globalDebug
	if !globalJSON {
		printDoctorReport(report, verbose)
		fmt.Printf("  %s\n", terminal.BoldCyan("Fixing issues..."))
		fmt.Println()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fixes := diagnostics.RunFixes(ctx, report, settings, doctorOnly)

	if !globalJSON {
		fmt.Println()
		printFixResults(fixes)
	}

	// Re-run checks to show updated status (skip agent ping — it wasn't fixed).
	deps.SkipAgentPing = true
	updated := diagnostics.Run(deps)

	if globalJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(doctorOutput{
			Report:  report,
			Fixes:   fixes,
			Updated: updated,
		})
	}

	fmt.Println()
	fmt.Printf("  %s\n", terminal.BoldCyan("Updated status:"))
	printDoctorReport(updated, verbose)
	return nil
}

func printFixResults(results []diagnostics.FixResult) {
	for _, r := range results {
		if r.Success {
			fmt.Printf("  %s %-20s %s\n", terminal.Green(terminal.SymbolSuccess), terminal.Green(r.Label), terminal.White(r.Message))
		} else {
			fmt.Printf("  %s %-20s %s\n", terminal.Red(terminal.SymbolError), terminal.Red(r.Label), terminal.White(r.Message))
		}
	}
}

func printDoctorReport(r *diagnostics.Report, verbose bool) {
	fmt.Println()
	fmt.Printf("  %s %s\n", terminal.BoldCyan("Vigolium Doctor"), terminal.White("— system readiness check"))
	fmt.Println()

	printCheck("Database", r.Database.Status, r.Database.Message)
	printDetails(verbose, r.Database.Details)
	printTip(r.Database.Tip)
	printCheck("Agent", r.Agent.Status, formatAgentMessage(r.Agent))
	printDetails(verbose, r.Agent.Details)
	printTip(r.Agent.Tip)

	if r.Queue != nil {
		printCheck("Queue", r.Queue.Status, r.Queue.Message)
		printTip(r.Queue.Tip)
	}

	printCheck("Agent Browser", r.Browser.Status, r.Browser.Message)
	printDetails(verbose, r.Browser.Details)
	printTip(r.Browser.Tip)

	toolNames := make([]string, 0, len(r.Tools))
	for name := range r.Tools {
		toolNames = append(toolNames, name)
	}
	sort.Strings(toolNames)
	for _, name := range toolNames {
		tool := r.Tools[name]
		msg := tool.Path
		if msg == "" {
			msg = tool.Message
		}
		printCheck("Tool: "+name, tool.Status, msg)
		printDetails(verbose, tool.Details)
		printTip(tool.Tip)
	}

	printCheck("Templates Dir", r.TemplatesDir.Status, r.TemplatesDir.Message)
	printDetails(verbose, r.TemplatesDir.Details)
	printTip(r.TemplatesDir.Tip)

	printCheck("Nuclei Templates", r.NucleiTemplates.Status, r.NucleiTemplates.Message)
	printDetails(verbose, r.NucleiTemplates.Details)
	printTip(r.NucleiTemplates.Tip)

	fmt.Println()
	switch r.Status {
	case "ready":
		fmt.Printf("  %s %s\n", terminal.BoldGreen(terminal.SymbolSuccess), terminal.BoldGreen("All systems ready"))
	case "degraded":
		fmt.Printf("  %s %s\n", terminal.BoldYellow(terminal.SymbolWarning), terminal.BoldYellow("System degraded — some optional components unavailable"))
	default:
		fmt.Printf("  %s %s\n", terminal.BoldRed(terminal.SymbolError), terminal.BoldRed("System not ready — critical components missing"))
	}
	if !verbose && reportHasHiddenDetail(r) {
		fmt.Printf("  %s %s\n", terminal.Yellow(terminal.SymbolTip), terminal.White("re-run with --verbose to see per-check diagnostics (resolved paths, ping errors, config lookups)"))
	}
	fmt.Println()
}

// reportHasHiddenDetail reports whether any non-OK check carries verbose
// detail lines that the user won't see without --verbose.
func reportHasHiddenDetail(r *diagnostics.Report) bool {
	hidden := func(status diagnostics.Status, details []string) bool {
		return status != diagnostics.StatusOK && len(details) > 0
	}
	if r.Database != nil && hidden(r.Database.Status, r.Database.Details) {
		return true
	}
	if r.Agent != nil && hidden(r.Agent.Status, r.Agent.Details) {
		return true
	}
	if r.Browser != nil && hidden(r.Browser.Status, r.Browser.Details) {
		return true
	}
	if r.TemplatesDir != nil && hidden(r.TemplatesDir.Status, r.TemplatesDir.Details) {
		return true
	}
	if r.NucleiTemplates != nil && hidden(r.NucleiTemplates.Status, r.NucleiTemplates.Details) {
		return true
	}
	for _, t := range r.Tools {
		if t != nil && hidden(t.Status, t.Details) {
			return true
		}
	}
	return false
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
		fmt.Printf("  %s %-20s %s\n", symbol, coloredLabel, highlightKeyValues(message))
	} else {
		fmt.Printf("  %s %s\n", symbol, coloredLabel)
	}
}

func printDetails(verbose bool, details []string) {
	if !verbose || len(details) == 0 {
		return
	}
	for _, d := range details {
		fmt.Printf("      %s %s\n", terminal.Gray(terminal.SymbolTriangle), highlightDetail(d))
	}
}

// printTip renders a remediation hint under a check. Shown at all verbosity
// levels — this is the user-facing "what to do next" line.
func printTip(tip string) {
	if tip == "" {
		return
	}
	fmt.Printf("      %s %s\n", terminal.Yellow(terminal.SymbolTip), terminal.White(tip))
}

// highlightKeyValues highlights values in key=value pairs within a message string.
func highlightKeyValues(msg string) string {
	parts := strings.Split(msg, ", ")
	for i, part := range parts {
		if idx := strings.Index(part, "="); idx > 0 {
			key := part[:idx+1]
			val := part[idx+1:]
			parts[i] = terminal.White(key) + terminal.Cyan(val)
		} else {
			parts[i] = terminal.White(part)
		}
	}
	return strings.Join(parts, terminal.White(", "))
}

// highlightDetail highlights key: value patterns and quoted strings in detail lines.
func highlightDetail(detail string) string {
	if idx := strings.Index(detail, ": "); idx > 0 {
		key := detail[:idx+1]
		val := detail[idx+2:]
		return terminal.Gray(key) + " " + terminal.Cyan(val)
	}
	return terminal.Gray(detail)
}

func formatAgentMessage(a *diagnostics.AgentCheck) string {
	if a.Status != diagnostics.StatusOK {
		return a.Message
	}
	msg := fmt.Sprintf("name=%s, protocol=%s, binary=%s", a.Name, a.Protocol, a.Binary)
	if a.PingResponse != "" {
		msg += ", ping=ok"
	}
	return msg
}
