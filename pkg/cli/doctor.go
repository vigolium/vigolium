package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
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
	Args:  cobra.NoArgs,
	RunE:  runDoctorCmd,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "Auto-install/fix failing checks")
	doctorCmd.Flags().StringSliceVar(&doctorOnly, "only", nil, "Fix only specific items (nuclei,chrome,bun,claude,agent-browser,pi,piolium)")
}

// doctorOutput is the JSON structure when --fix is used with --json.
type doctorOutput struct {
	Report  *diagnostics.Report     `json:"report"`
	Fixes   []diagnostics.FixResult `json:"fixes,omitempty"`
	Updated *diagnostics.Report     `json:"updated,omitempty"`
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

	deps := diagnostics.Deps{Settings: settings, ProbeBrowserLaunch: true}

	// Try to open DB (optional — report error if it fails). The error is
	// passed through to diagnostics so a postgres connect failure surfaces as
	// the real driver error instead of "not configured".
	db, dbErr := getDB()
	if dbErr == nil {
		deps.DB = db
		defer closeDatabaseOnExit()
	} else {
		deps.DBErr = dbErr
	}

	report := diagnostics.Run(deps)

	// Backfill the first-run marker only when the mandatory native-scan deps are
	// actually present (chromium + nuclei-templates). A read-only doctor on a
	// machine missing them must NOT stamp it, or the next scan would skip the
	// first-run auto-install. The --fix path re-checks below after RunFixes.
	ensureInitMarkerIfDepsPresent(report)

	if !doctorFix {
		if globalJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}
		printDoctorReport(report)
		return nil
	}

	// --fix mode: print initial report, fix, then recheck. When --only narrows
	// the run to specific components, render a focused view of just those
	// components (no full report, shown once) instead of the whole doctor log.
	focused := len(doctorOnly) > 0
	if !globalJSON {
		if focused {
			fmt.Println()
			fmt.Printf("  %s %s\n", terminal.BoldCyan("Vigolium Doctor"),
				terminal.White("— fixing "+strings.Join(focusedLabels(report, doctorOnly), ", ")))
		} else {
			printDoctorReport(report)
			fmt.Printf("  %s\n", terminal.BoldCyan("Fixing issues..."))
			fmt.Println()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fixes := diagnostics.RunFixes(ctx, report, settings, doctorOnly)

	if !globalJSON && len(fixes) > 0 {
		fmt.Println()
		printFixResults(fixes)
	}

	// Re-run checks to show updated status.
	updated := diagnostics.Run(deps)

	// If --fix just installed chromium + nuclei-templates, backfill the marker
	// so subsequent scans skip the redundant first-run check.
	ensureInitMarkerIfDepsPresent(updated)

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
	if focused {
		printDoctorFocused(updated, doctorOnly)
		fmt.Println()
	} else {
		printDoctorReport(updated)
	}
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

// focusedCheck resolves a single --only token to its display label and the
// matching check in the report (status/message/tip/details). ok is false for
// tokens that don't map to a renderable check or whose check is absent.
func focusedCheck(r *diagnostics.Report, name string) (label string, c *diagnostics.CheckResult, ok bool) {
	// CheckResult and ToolCheck share the fields the focused view needs; flatten
	// ToolCheck rows into a CheckResult so a single renderer covers both.
	tool := func(key string) (*diagnostics.CheckResult, bool) {
		t := r.Tools[key]
		if t == nil {
			return nil, false
		}
		return &diagnostics.CheckResult{Status: t.Status, Message: toolMessage(t), Details: t.Details, Tip: t.Tip}, true
	}
	switch diagnostics.ResolveFixKey(name) {
	case "nuclei-templates":
		if r.NucleiTemplates != nil {
			return "Nuclei Templates", r.NucleiTemplates, true
		}
	case "chromium":
		if c, ok := tool("chromium"); ok {
			return "Chromium", c, true
		}
	case "bun":
		if c, ok := tool("bun"); ok {
			return "Bun", c, true
		}
	case "claude":
		if c, ok := tool("claude"); ok {
			return "Claude Code", c, true
		}
	case "agent-browser":
		if c, ok := tool("agent-browser"); ok {
			return "agent-browser", c, true
		}
	case "pi":
		if c, ok := tool("pi"); ok {
			return "Pi", c, true
		}
	case "piolium":
		if r.Piolium != nil {
			return "Piolium", r.Piolium, true
		}
	}
	return "", nil, false
}

// focusedLabels returns the display labels for the components named in `only`,
// for the "fixing X, Y" header. Unknown tokens fall back to the raw token.
func focusedLabels(r *diagnostics.Report, only []string) []string {
	labels := make([]string, 0, len(only))
	for _, name := range only {
		if label, _, ok := focusedCheck(r, name); ok {
			labels = append(labels, label)
		} else {
			labels = append(labels, name)
		}
	}
	return labels
}

// printDoctorFocused renders only the checks named in `only` (e.g.
// --only nuclei,chrome) rather than the full grouped report. Used by the --fix
// path so a targeted fix shows just the components it touched, once. Verbose
// per-check details are omitted here (the focused view is meant to be concise);
// the remediation tip is kept so a still-failing component says what to do.
func printDoctorFocused(r *diagnostics.Report, only []string) {
	for _, name := range only {
		label, c, ok := focusedCheck(r, name)
		if !ok {
			printCheck(name, diagnostics.StatusWarning, "unknown component")
			continue
		}
		printCheck(label, c.Status, c.Message)
		printTip(c.Tip)
	}
}

// printDoctorReport renders the grouped human-readable report. Details are
// always shown (verbose-by-default) — there's no `--brief` toggle today.
//
// The layout intentionally mirrors how users invoke the scanner:
//   - "Core" surfaces the only true blocker (database).
//   - "Native scan" lists what `vigolium scan` / `vigolium run` need.
//   - "Agentic scan" splits into the olium-based modes (autopilot, swarm,
//     and the single-shot query mode), the optional audit mode with its
//     two independent driver paths, and a tail bucket of informational
//     tools that don't gate any feature.
func printDoctorReport(r *diagnostics.Report) {
	fmt.Println()
	fmt.Printf("  %s %s\n", terminal.BoldCyan("Vigolium Doctor"), terminal.White("— system readiness check"))

	// ── Core ──
	printDoctorSection("Core", "")
	if r.Database != nil {
		printCheck("Database", r.Database.Status, r.Database.Message)
		printDetails(true, r.Database.Details)
		printTip(r.Database.Tip)
	}
	if r.Initialized != nil {
		printCheck("Initialized", r.Initialized.Status, r.Initialized.Message)
		printDetails(true, r.Initialized.Details)
		printTip(r.Initialized.Tip)
	}

	// ── Native scan ──
	printDoctorSection("Native scan", "vigolium scan / vigolium run")
	if t := r.Tools["chromium"]; t != nil {
		printCheck("Chromium", t.Status, toolMessage(t))
		printDoctorPurpose(doctorDetailIndent, "powers headless rendering for the spidering phase")
		printDetails(true, t.Details)
		printTip(t.Tip)
	}
	if r.NucleiTemplates != nil {
		printCheck("Nuclei Templates", r.NucleiTemplates.Status, r.NucleiTemplates.Message)
		printDoctorPurpose(doctorDetailIndent, "drives the KnownIssueScan phase")
		printDetails(true, r.NucleiTemplates.Details)
		printTip(r.NucleiTemplates.Tip)
	}
	if c := embeddedBinaryCheck(r, "jstangle"); c != nil {
		printCheck("Embedded jstangle", c.Status, c.Message)
		printDetails(true, c.Details)
		printTip(c.Tip)
	}

	// ── Agentic scan ──
	printDoctorSection("Agentic scan", "")

	printDoctorSubsection("Olium-based modes (autopilot + swarm)")
	if r.Agent != nil {
		printSubCheck("Olium agent", r.Agent.Status, formatAgentMessage(r.Agent))
		printSubDetails(true, r.Agent.Details)
		printSubTip(r.Agent.Tip)
	}
	if r.SessionsDir != nil {
		printSubCheck("Sessions Dir", r.SessionsDir.Status, r.SessionsDir.Message)
		printSubDetails(true, r.SessionsDir.Details)
		printSubTip(r.SessionsDir.Tip)
	}
	if r.TemplatesDir != nil {
		printSubCheck("Templates Dir", r.TemplatesDir.Status, r.TemplatesDir.Message)
		printSubDetails(true, r.TemplatesDir.Details)
		printSubTip(r.TemplatesDir.Tip)
	}
	if r.Browser != nil {
		printSubCheck("Agent Browser", r.Browser.Status, r.Browser.Message)
		printSubDetails(true, r.Browser.Details)
		printSubTip(r.Browser.Tip)
	}

	printDoctorSubsection("Audit mode (vigolium agent audit) — optional")
	printAuditSection(r)

	if r.Queue != nil {
		printDoctorSubsection("Server queue")
		printSubCheck("Queue", r.Queue.Status, r.Queue.Message)
		printSubTip(r.Queue.Tip)
	}

	printDoctorSubsection("Tools (informational)")
	printInfoTools(r)

	fmt.Println()
	switch r.Status {
	case "ready":
		fmt.Printf("  %s %s\n", terminal.BoldGreen(terminal.SymbolSuccess), terminal.BoldGreen("All systems ready"))
	case "degraded":
		fmt.Printf("  %s %s\n", terminal.BoldYellow(terminal.SymbolWarning), terminal.BoldYellow("System degraded — some scan modes unavailable"))
	default:
		// "not_ready" can only mean Database failed under the new status
		// rules; native and agentic checks degrade rather than block.
		fmt.Printf("  %s %s\n", terminal.BoldRed(terminal.SymbolError), terminal.BoldRed("System not ready — database unavailable"))
	}
	if !doctorFix && diagnostics.HasFixableIssues(r) {
		fmt.Printf("  %s %s%s%s\n",
			terminal.Yellow(terminal.SymbolTip),
			terminal.White("re-run with "),
			terminal.BoldCyan("vigolium doctor --fix"),
			terminal.White(" to attempt auto-installation of missing components"),
		)
	}
	fmt.Println()
}

// printDoctorSection renders a top-level group header (Core, Native scan, Agentic scan).
func printDoctorSection(title, hint string) {
	fmt.Println()
	if hint != "" {
		fmt.Printf("  %s  %s\n", terminal.BoldCyan(title), terminal.Gray("("+hint+")"))
	} else {
		fmt.Printf("  %s\n", terminal.BoldCyan(title))
	}
}

// printDoctorSubsection renders a nested header within "Agentic scan".
func printDoctorSubsection(title string) {
	fmt.Println()
	fmt.Printf("    %s\n", terminal.BoldBlue(title))
}

// toolMessage returns the resolved binary path when present, falling back to
// the failure message. Lets the renderer treat ToolCheck rows the same way
// it treats CheckResult rows.
func toolMessage(t *diagnostics.ToolCheck) string {
	if t.Path != "" {
		return t.Path
	}
	return t.Message
}

func embeddedBinaryCheck(r *diagnostics.Report, name string) *diagnostics.CheckResult {
	if r == nil || r.EmbeddedBinaries == nil {
		return nil
	}
	return r.EmbeddedBinaries[name]
}

// printAuditSection renders the two independent audit driver paths plus a
// header status that's green when *either* path is usable. The Path A/B
// labels match the language used in the user-facing tip text.
//
// Tool/check details for components inside each path are rendered inline
// when the path is failing (so the user sees exactly which piece is missing)
// and elided when the path is healthy (the green summary is enough).
func printAuditSection(r *diagnostics.Report) {
	pathA := diagnostics.AuditPathA(r)
	pathB := diagnostics.AuditPathB(r)

	headerStatus := diagnostics.StatusWarning
	headerMsg := "neither driver path is installed — audit mode unavailable"
	switch {
	case pathA.OK && pathB.OK:
		headerStatus = diagnostics.StatusOK
		headerMsg = "both driver paths available"
	case pathA.OK:
		headerStatus = diagnostics.StatusOK
		headerMsg = "Path A (claude) ready"
	case pathB.OK:
		headerStatus = diagnostics.StatusOK
		headerMsg = "Path B (piolium) ready"
	}
	printSubCheck("Audit", headerStatus, headerMsg)

	if c := embeddedBinaryCheck(r, "vigolium-audit"); c != nil {
		printSubCheck("Embedded audit", c.Status, c.Message)
		if c.Status != diagnostics.StatusOK {
			printSubDetails(true, c.Details)
			printSubTip(c.Tip)
		}
	}

	// Path A: claude CLI + embedded vigolium-audit binary.
	if pathA.OK {
		claudePath := ""
		if t := r.Tools["claude"]; t != nil {
			claudePath = t.Path
		}
		printSubCheck("Path A (claude+audit)", diagnostics.StatusOK, claudePath)
	} else {
		printSubCheck("Path A (claude+audit)", diagnostics.StatusError, strings.Join(pathA.Reasons, "; "))
		if t := r.Tools["claude"]; t != nil && t.Status != diagnostics.StatusOK {
			printSubDetails(true, t.Details)
		}
		if r.Audit != nil && r.Audit.Status != diagnostics.StatusOK {
			printSubDetails(true, r.Audit.Details)
		}
		printSubTip("install with `vigolium doctor --fix --only claude` (Claude Code), then rebuild vigolium with `make build-audit` to embed the vigolium-audit harness")
	}

	// Path B: pi + piolium extension. `--fix --only piolium` self-resolves
	// the whole path — it installs pi (via bun or npm, bootstrapping bun
	// only when neither exists) and then the piolium Pi extension.
	//
	// When Path A is already healthy we treat Path B as optional: render
	// a warning row instead of an error and skip the noisy per-component
	// details, since audit mode is already usable through claude+audit.
	if pathB.OK {
		pioliumMsg := ""
		if r.Piolium != nil {
			pioliumMsg = r.Piolium.Message
		}
		printSubCheck("Path B (pi+piolium)", diagnostics.StatusOK, pioliumMsg)
	} else if pathA.OK {
		printSubCheck("Path B (pi+piolium)", diagnostics.StatusWarning, "optional — Path A (claude+audit) already provides audit mode")
		printSubTip("install only if you also want the piolium driver: `vigolium doctor --fix --only piolium`")
	} else {
		printSubCheck("Path B (pi+piolium)", diagnostics.StatusError, strings.Join(pathB.Reasons, "; "))
		if t := r.Tools["pi"]; t != nil && t.Status != diagnostics.StatusOK {
			printSubDetails(true, t.Details)
		}
		if r.Piolium != nil && r.Piolium.Status != diagnostics.StatusOK {
			printSubDetails(true, r.Piolium.Details)
		}
		printSubTip("install with `vigolium doctor --fix --only piolium` (installs pi via bun/npm, then the piolium extension)")
	}
}

// printInfoTools renders tool rows that don't gate any specific feature
// (they're not part of any scan path's required set). codex is the canonical
// example today — kept for visibility but never status-affecting.
func printInfoTools(r *diagnostics.Report) {
	// Tools surfaced under their own group (chromium, claude, pi,
	// agent-browser) are excluded here to avoid double-rendering. bun and
	// npm fall through to this informational bucket — they're optional
	// accelerators for the JS installs, not part of any path's gate.
	groupedElsewhere := map[string]bool{
		"chromium":      true,
		"claude":        true,
		"pi":            true,
		"agent-browser": true,
	}
	names := make([]string, 0, len(r.Tools))
	for name := range r.Tools {
		if !groupedElsewhere[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		t := r.Tools[name]
		printSubCheck(name, t.Status, toolMessage(t))
		printSubDetails(true, t.Details)
		printSubTip(t.Tip)
	}
}

// Indent strings used by the grouped doctor renderer. Two levels:
//   - section rows live under top-level groups (Core, Native scan)
//   - subsection rows live under nested groups inside Agentic scan
//
// Detail/tip rows hang off whichever row they belong to, four spaces deeper.
const (
	doctorRowIndentSection    = "    "       // rows under "Core" / "Native scan"
	doctorRowIndentSubsection = "      "     // rows under nested Agentic-scan groups
	doctorDetailIndent        = "        "   // details under section rows
	doctorDetailIndentSub     = "          " // details under subsection rows
	doctorLabelWidth          = 24           // wide enough for "Path B (bun+pi+piolium)"
)

func printCheck(label string, status diagnostics.Status, message string) {
	printCheckAt(doctorRowIndentSection, label, status, message)
}

func printSubCheck(label string, status diagnostics.Status, message string) {
	printCheckAt(doctorRowIndentSubsection, label, status, message)
}

func printCheckAt(indent, label string, status diagnostics.Status, message string) {
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
		fmt.Printf("%s%s %-*s %s\n", indent, symbol, doctorLabelWidth, coloredLabel, highlightKeyValues(message))
	} else {
		fmt.Printf("%s%s %s\n", indent, symbol, coloredLabel)
	}
}

func printDetails(verbose bool, details []string) {
	printDetailsAt(doctorDetailIndent, verbose, details)
}

func printSubDetails(verbose bool, details []string) {
	printDetailsAt(doctorDetailIndentSub, verbose, details)
}

func printDetailsAt(indent string, verbose bool, details []string) {
	if !verbose || len(details) == 0 {
		return
	}
	for _, d := range details {
		fmt.Printf("%s%s %s\n", indent, terminal.Gray(terminal.SymbolTriangle), highlightDetail(d))
	}
}

// printTip renders a remediation hint under a check. Shown at all verbosity
// levels — this is the user-facing "what to do next" line.
func printTip(tip string) {
	printTipAt(doctorDetailIndent, tip)
}

func printSubTip(tip string) {
	printTipAt(doctorDetailIndentSub, tip)
}

func printTipAt(indent, tip string) {
	if tip == "" {
		return
	}
	fmt.Printf("%s%s %s\n", indent, terminal.Yellow(terminal.SymbolTip), highlightTipCommands(tip))
}

// tipCommandRe matches backtick-delimited command/path segments in a tip,
// e.g. the `sudo apt install chromium-browser` in a chromium install hint.
var tipCommandRe = regexp.MustCompile("`([^`]+)`")

// highlightTipCommands renders a remediation tip with backtick-wrapped
// commands picked out in bold cyan so the actionable bit stands out, while
// the surrounding prose stays white like the rest of the doctor report.
// When color is disabled the backticks are preserved so commands remain
// visually delimited in plain output.
func highlightTipCommands(tip string) string {
	if !terminal.IsColorEnabled() {
		return tip
	}
	var b strings.Builder
	last := 0
	for _, m := range tipCommandRe.FindAllStringSubmatchIndex(tip, -1) {
		b.WriteString(terminal.White(tip[last:m[0]]))
		b.WriteString(terminal.BoldCyan(tip[m[2]:m[3]]))
		last = m[1]
	}
	b.WriteString(terminal.White(tip[last:]))
	return b.String()
}

// printDoctorPurpose renders a small "what this is for" line under a check
// row. Always shown (regardless of status) so users see the role of each
// dependency at a glance — useful when triaging which scan modes degrade
// when a given component is missing.
func printDoctorPurpose(indent, purpose string) {
	if purpose == "" {
		return
	}
	fmt.Printf("%s%s %s\n", indent, terminal.Gray(terminal.SymbolDot), terminal.Gray(purpose))
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
	msg := fmt.Sprintf("name=%s, protocol=%s", a.Name, a.Protocol)
	if a.Binary != "" {
		msg += fmt.Sprintf(", binary=%s", a.Binary)
	}
	if a.PingResponse != "" {
		msg += ", ping=ok"
	}
	return msg
}
