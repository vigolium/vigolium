package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	doctorFix    bool
	doctorOnly   []string
	doctorStrict bool
	// doctorFor scopes the verdict to one purpose (scan, agent, server).
	doctorFor string
	// doctorTarget adds DNS/TCP/TLS reachability checks for a URL (--for scan).
	doctorTarget string
	// doctorYes consents to vendor installers (curl | bash, global agent tools).
	doctorYes bool
	// doctorDryRun lists what --fix would install without installing it.
	doctorDryRun bool
)

// doctorRunDiagnostics is diagnostics.Run, replaced in tests: a real run spawns
// a browser and extracts embedded binaries.
var doctorRunDiagnostics = diagnostics.Run

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system readiness and diagnose configuration issues",
	Long: "Run diagnostic checks on database, agent backends, third-party tools, scope rules, OAST reachability, the proxy, and other dependencies to verify the scanner is ready to operate.\n\n" +
		"The verdict comes first, then one line per check; -v adds each check's detail lines. " +
		"-j lists the checks flat in items (id, group, status, message, affects, fix_argv, and on a failing check the setting it tested and where that came from), with the verdict as status and what still works as capabilities " +
		"(scan, spidering, known_issue_scan, out_of_band, agent, audit). --json-legacy-keys keeps the old nested report. " +
		"--only narrows the checks shown (and, with --fix, the ones repaired). An agent provider behind an endpoint is reported unverified; --for agent probes it.\n\n" +
		"--fix --dry-run lists each install --fix would run: what, how, where to and roughly how large.\n\n" +
		"Exits 1 (error.code not_ready) when the verdict is not_ready; with --strict also when it is degraded. " +
		"The report is written first either way, so -j consumers always get it on stdout.",
	Args: cobra.NoArgs,
	RunE: runDoctorCmd,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "Auto-install/fix failing checks")
	doctorCmd.Flags().StringSliceVar(&doctorOnly, "only", nil, "Show (and with --fix, repair) only these checks: a check id or fix key (nuclei,chrome,bun,claude,agent-browser,pi,piolium,skill,oast,agent,proxy,…)")
	doctorCmd.Flags().BoolVar(&doctorDryRun, "dry-run", false, "With --fix: list each install (method, destination, approximate size) without running it")
	doctorCmd.Flags().BoolVar(&doctorStrict, "strict", false, "Exit 1 when the verdict is degraded, not only when it is not_ready")
	doctorCmd.Flags().BoolVarP(&doctorYes, "yes", "y", false, "With --fix: also run vendor installers piped into a shell and global agent tooling installs (bun, claude, agent-browser, pi, piolium) without asking")
	doctorCmd.Flags().StringVar(&doctorFor, "for", "", "Scope the verdict to one purpose: "+strings.Join(diagnostics.Purposes, "|")+" (checks that do not affect it are reported but not counted)")
	doctorCmd.Flags().StringVarP(&doctorTarget, "target", "t", "", "With --for scan: also check DNS, TCP and TLS reachability of this URL")
	doctorCmd.Flags().BoolVarP(&globalStateless, "stateless", "S", false, "With --for scan: the scan will use a temporary database, so the database check is skipped")
}

// doctorScoped builds the --for report from the full one (nil without --for).
func doctorScoped(report *diagnostics.Report, settings *config.Settings) *diagnostics.ScopedReport {
	if doctorFor == "" || report == nil {
		return nil
	}
	deps := diagnostics.ScopedDeps{
		Settings:  settings,
		Stateless: globalStateless,
		Proxy:     globalProxy,
		Target:    doctorTarget,
	}
	if settings != nil && settings.Database.Driver == "sqlite" && !globalStateless {
		deps.DBDir = filepath.Dir(config.ExpandPath(settings.Database.SQLite.Path))
	}
	scoped, err := diagnostics.Scoped(doctorFor, report, deps)
	if err != nil {
		return nil
	}
	return scoped
}

// printScopedReport renders a --for report.
func printScopedReport(s *diagnostics.ScopedReport) {
	fmt.Println()
	fmt.Printf("  %s %s\n", terminal.BoldCyan("Vigolium Doctor"), terminal.White("— ready for "+s.For+"?"))
	fmt.Println()
	for _, c := range s.Checks {
		status := diagnostics.StatusOK
		switch c.Status {
		case diagnostics.ScopedNotReady:
			status = diagnostics.StatusError
		case diagnostics.ScopedDegraded, diagnostics.ScopedWarning:
			status = diagnostics.StatusWarning
		}
		msg := c.Message
		if !c.Counts && c.Status != diagnostics.ScopedOK {
			msg += " (not counted)"
		}
		if c.Status == diagnostics.ScopedSkipped {
			msg = "skipped — " + c.Message
		}
		printCheck(c.ID, status, msg)
		if len(c.Affects) > 0 && c.Status != diagnostics.ScopedOK {
			printDetails(true, []string{"affects: " + strings.Join(c.Affects, "; ")})
		}
		if len(c.FixArgv) > 0 && c.Status != diagnostics.ScopedOK {
			printTip("`" + strings.Join(c.FixArgv, " ") + "`")
		}
	}
	fmt.Println()
	fmt.Printf("  %s %s\n", terminal.BoldCyan("Verdict:"), terminal.White(string(s.Status)))
	fmt.Println()
}

func runDoctorCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	if doctorFor != "" && !diagnostics.ValidPurpose(doctorFor) {
		return usageErrorf("invalid --for %q (want one of: %s)", doctorFor, strings.Join(diagnostics.Purposes, ", "))
	}
	if doctorTarget != "" && doctorFor != diagnostics.PurposeScan {
		return usageErrorf("--target checks scan reachability; use it with --for scan")
	}
	if doctorDryRun && !doctorFix {
		return usageErrorf("--dry-run previews --fix; add --fix to list the installs it would run")
	}

	// doctor is the one command that must not fail on a broken config: reporting
	// that the config is broken is its job. The error is carried into the report
	// as a failed check rather than warned into a logger and then contradicted by
	// a green readout.
	settings, cfgErr := clicommon.LoadSettings(globalConfig)
	overlayProject := ""
	if cfgErr != nil {
		settings = config.DefaultSettings()
	} else if project, perr := overlayProjectUUID(); perr == nil {
		// The scope checks judge the scope a scan would run under, which
		// includes the project's overlay. A broken overlay is reported as the
		// config failure it is; the global settings stay in use for the rest.
		overlayProject = project
		cfgErr = config.ApplyProjectOverlay(settings, project)
	}

	deps := diagnostics.Deps{
		Settings:           settings,
		ConfigErr:          cfgErr,
		ConfigPath:         effectiveConfigPath(),
		ProbeBrowserLaunch: true,
		ProbeNetwork:       true,
	}

	// Try to open DB (optional — report error if it fails). The error is
	// passed through to diagnostics so a postgres connect failure surfaces as
	// the real driver error instead of "not configured".
	// A stateless scan never opens the project database, so `--for scan -S`
	// does not either.
	if !globalStateless || doctorFor != diagnostics.PurposeScan {
		db, dbErr := getDB()
		if dbErr == nil {
			deps.DB = db
			defer closeDatabaseOnExit()
		} else {
			deps.DBErr = dbErr
		}
	}

	report := doctorRunDiagnostics(deps)
	attachDoctorSkillCheck(report)
	ctxInfo := newDoctorContext(settings, overlayProject)

	// --only names checks; an unknown name is a typo, not an empty report.
	if err := validateDoctorOnly(ctxInfo.checks(report)); err != nil {
		return err
	}

	// Backfill the first-run marker only when the mandatory native-scan deps are
	// actually present (chromium + nuclei-templates). A read-only doctor on a
	// machine missing them must NOT stamp it, or the next scan would skip the
	// first-run notice. The --fix path re-checks below after RunFixes.
	ensureInitMarkerIfDepsPresent(report)

	if !doctorFix {
		scoped := doctorScoped(report, settings)
		if globalJSON {
			// Through the shared writer so this counts as the invocation's one
			// result document and the error path does not append a second.
			if err := emitDoctorJSON(cmd, ctxInfo, report, nil, nil, scoped); err != nil {
				return err
			}
			return doctorVerdict(report, scoped)
		}
		switch {
		case scoped != nil:
			printScopedReport(scoped)
		case len(doctorOnly) > 0:
			printDoctorChecks(report, ctxInfo.filter(ctxInfo.checks(report)))
		default:
			printDoctorReport(report, ctxInfo)
		}
		return doctorVerdict(report, scoped)
	}

	// --fix: repair, then report the re-checked state once. The report before
	// the fix is not printed: it is the same report minus the repairs, and
	// printing both doubled the output for nothing.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fixOnly := doctorFixKeys(doctorOnly)
	if !globalJSON && !doctorDryRun {
		label := "Fixing issues..."
		if len(doctorOnly) > 0 {
			label = "Fixing " + strings.Join(focusedLabels(report, doctorOnly), ", ") + "..."
		}
		fmt.Println()
		fmt.Printf("  %s\n", terminal.BoldCyan(label))
		fmt.Println()
	}
	fixes := diagnostics.RunFixesWith(ctx, report, settings, fixOnly, diagnostics.FixOptions{
		AssumeYes: doctorYes,
		Confirm:   doctorVendorConfirm(),
		DryRun:    doctorDryRun,
	})
	// The skill reinstall is CLI-side: it needs this binary's embedded bundle
	// and version, which pkg/diagnostics cannot import.
	if doctorSkillFixSelected(doctorOnly) {
		if doctorDryRun {
			fixes = append(fixes, diagnostics.FixResult{Key: doctorSkillFixKey, Label: "Agent skill", Planned: true,
				Method: "copy the embedded skill bundle", Destination: "the skill directories of installed coding agents", Size: "<1 MB", Message: "would reinstall"})
		} else {
			fixes = append(fixes, fixStaleSkills(Version, Commit)...)
		}
	}

	if doctorDryRun {
		if globalJSON {
			return emitDoctorDryRun(cmd, ctxInfo, report, fixes)
		}
		printFixPlan(fixes)
		return nil
	}

	if !globalJSON && len(fixes) > 0 {
		printFixResults(fixes)
	}

	// Re-run checks to show updated status.
	updated := doctorRunDiagnostics(deps)
	attachDoctorSkillCheck(updated)

	// If --fix just installed chromium + nuclei-templates, backfill the marker
	// so subsequent scans skip the redundant first-run check.
	ensureInitMarkerIfDepsPresent(updated)

	scopedUpdated := doctorScoped(updated, settings)
	if globalJSON {
		if err := emitDoctorJSON(cmd, ctxInfo, report, fixes, updated, scopedUpdated); err != nil {
			return err
		}
		return doctorVerdict(updated, scopedUpdated)
	}

	fmt.Println()
	switch {
	case scopedUpdated != nil:
		printScopedReport(scopedUpdated)
		return doctorVerdict(updated, scopedUpdated)
	case len(doctorOnly) > 0:
		printDoctorChecks(updated, ctxInfo.filter(ctxInfo.checks(updated)))
	default:
		printDoctorReport(updated, ctxInfo)
	}
	return doctorVerdictError(updated)
}

// doctorVerdictError turns the report's verdict into the exit status, after
// the report has been written: not_ready exits 1 (error.code not_ready), and
// so does degraded under --strict. doctor always exited 0 before, so a script
// gating on it could not tell a working install from one with no database.
// Under --fix it is called with the re-checked report, so a fix that worked
// exits 0.
func doctorVerdictError(r *diagnostics.Report) error {
	switch {
	case r == nil:
		return nil
	case r.Status == "not_ready":
		return clicommon.CodedErrorf(apicontract.CodeNotReady, "doctor: system not ready (%s)", doctorBlockers(r))
	case doctorStrict && r.Status == "degraded":
		return clicommon.CodedErrorf(apicontract.CodeNotReady, "doctor: system degraded (--strict)")
	}
	return nil
}

// doctorVerdict is doctorVerdictError, scoped by --for when given: the
// scoped verdict (the worst counted check) decides the exit.
func doctorVerdict(r *diagnostics.Report, scoped *diagnostics.ScopedReport) error {
	if scoped == nil {
		return doctorVerdictError(r)
	}
	var blockers []string
	for _, c := range scoped.Checks {
		if c.Counts && c.Status == diagnostics.ScopedNotReady {
			blockers = append(blockers, c.ID+": "+c.Message)
		}
	}
	switch {
	case scoped.Status == "not_ready":
		return clicommon.CodedErrorf(apicontract.CodeNotReady, "doctor: not ready for %s (%s)", scoped.For, strings.Join(blockers, "; "))
	case doctorStrict && scoped.Status == "degraded":
		return clicommon.CodedErrorf(apicontract.CodeNotReady, "doctor: degraded for %s (--strict)", scoped.For)
	}
	return nil
}

// doctorBlockers names the failing check behind a not_ready verdict.
func doctorBlockers(r *diagnostics.Report) string {
	if r.Database != nil && r.Database.Status == diagnostics.StatusError {
		if r.Database.Message != "" {
			return "database: " + r.Database.Message
		}
		return "database unavailable"
	}
	return "see the report"
}

func printFixResults(results []diagnostics.FixResult) {
	for _, r := range results {
		if r.Success {
			fmt.Printf("  %s %-20s %s\n", terminal.Green(terminal.SymbolSuccess), terminal.Green(r.Label), terminal.White(r.Message))
		} else if r.Skipped {
			fmt.Printf("  %s %-20s %s\n", terminal.Yellow(terminal.SymbolWarning), terminal.Yellow(r.Label), terminal.White(r.Message))
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
	case "vigolium-audit":
		if c := r.EmbeddedBinaries["vigolium-audit"]; c != nil {
			return "vigolium-audit helper", c, true
		}
	case doctorSkillFixKey, "skills":
		if r.Skill != nil {
			return "Agent skill", r.Skill, true
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

// detailsVisible reports whether the verbose `▸` detail lines should render for
// a check with the given status. Plain `vigolium doctor` stays fully verbose;
// `vigolium doctor --fix` runs compact — OK checks collapse to their single
// status row (the status message already carries the key facts) — unless
// `--verbose` is passed to expand them again.
func detailsVisible(diagnostics.Status) bool {
	return globalVerbose
}

// printDoctorReport renders the grouped human-readable report. Plain
// `vigolium doctor` shows every check's `▸` detail lines (verbose-by-default).
// `vigolium doctor --fix` renders compact — OK checks collapse to their single
// status row so the twice-rendered fix output stays short — while `--verbose`
// restores the full detail lines. The gating lives in detailsVisible().
//
// The layout intentionally mirrors how users invoke the scanner:
//   - "Core" surfaces the only true blocker (database).
//   - "Native scan" lists what `vigolium scan` / `vigolium run` need.
//   - "Agentic scan" splits into the olium-based modes (autopilot, swarm,
//     and the single-shot query mode), the optional audit mode with its
//     two independent driver paths, and a tail bucket of informational
//     tools that don't gate any feature.
func printDoctorReport(r *diagnostics.Report, dc *doctorContext) {
	fmt.Println()
	fmt.Printf("  %s %s\n", terminal.BoldCyan("Vigolium Doctor"), terminal.White("— system readiness check"))
	fmt.Println()
	printDoctorVerdict(r)
	sources := map[string]string{}
	if dc != nil {
		for _, ch := range dc.checks(r) {
			if ch.Source != "" {
				sources[ch.ID] = ch.Source
			}
		}
	}

	// ── Core ──
	printDoctorSection("Core", "")
	if r.Config != nil {
		printCheck("Config", r.Config.Status, r.Config.Message)
		printDetails(detailsVisible(r.Config.Status), r.Config.Details)
		printTip(r.Config.Tip)
	}
	if r.Scope != nil {
		printCheck("Scope", r.Scope.Status, r.Scope.Message)
		printDetails(detailsVisible(r.Scope.Status), r.Scope.Details)
		printTip(r.Scope.Tip)
	}
	if r.Database != nil {
		printCheck("Database", r.Database.Status, r.Database.Message)
		if src := sources["database"]; src != "" {
			printDetails(true, []string{"setting: " + src})
		}
		printDetails(detailsVisible(r.Database.Status), r.Database.Details)
		printTip(r.Database.Tip)
	}
	if r.Initialized != nil {
		printCheck("Initialized", r.Initialized.Status, r.Initialized.Message)
		printDetails(detailsVisible(r.Initialized.Status), r.Initialized.Details)
		printTip(r.Initialized.Tip)
	}
	if dc != nil {
		pc := diagnostics.ProxyCheck(dc.proxyURL, dc.proxySource)
		printCheck("Proxy", pc.Status, pc.Message)
		printDetails(detailsVisible(pc.Status), pc.Details)
		printTip(pc.Tip)
	}

	// ── Native scan ──
	printDoctorSection("Native scan", "vigolium scan / vigolium run")
	if t := r.Tools["chromium"]; t != nil {
		printCheck("Chromium", t.Status, toolMessage(t))
		printDoctorPurpose(doctorDetailIndent, "powers headless rendering for the spidering phase")
		printDetails(detailsVisible(t.Status), t.Details)
		printTip(t.Tip)
	}
	if r.NucleiTemplates != nil {
		printCheck("Nuclei Templates", r.NucleiTemplates.Status, r.NucleiTemplates.Message)
		printDoctorPurpose(doctorDetailIndent, "drives the KnownIssueScan phase")
		printDetails(detailsVisible(r.NucleiTemplates.Status), r.NucleiTemplates.Details)
		printTip(r.NucleiTemplates.Tip)
	}
	if c := embeddedBinaryCheck(r, "jstangle"); c != nil {
		printCheck("Embedded jstangle", c.Status, c.Message)
		printDetails(detailsVisible(c.Status), c.Details)
		printTip(c.Tip)
	}
	if r.OAST != nil {
		printCheck("OAST", r.OAST.Status, r.OAST.Message)
		if src := sources["oast"]; src != "" {
			printDetails(true, []string{"setting: " + src})
		}
		printDoctorPurpose(doctorDetailIndent, "callback channel for blind (out-of-band) checks")
		printDetails(detailsVisible(r.OAST.Status), r.OAST.Details)
		printTip(r.OAST.Tip)
	}

	// ── Agentic scan ──
	printDoctorSection("Agentic scan", "")

	printDoctorSubsection("Olium-based modes (autopilot + swarm)")
	if r.Agent != nil {
		agentStatus := r.Agent.Status
		if r.Agent.Unverified {
			agentStatus = diagnostics.StatusWarning
		}
		printSubCheck("Olium agent", agentStatus, formatAgentMessage(r.Agent))
		printSubDetails(detailsVisible(r.Agent.Status), r.Agent.Details)
		printSubTip(r.Agent.Tip)
	}
	if r.SessionsDir != nil {
		printSubCheck("Sessions Dir", r.SessionsDir.Status, r.SessionsDir.Message)
		printSubDetails(detailsVisible(r.SessionsDir.Status), r.SessionsDir.Details)
		printSubTip(r.SessionsDir.Tip)
	}
	if r.TemplatesDir != nil {
		printSubCheck("Templates Dir", r.TemplatesDir.Status, r.TemplatesDir.Message)
		printSubDetails(detailsVisible(r.TemplatesDir.Status), r.TemplatesDir.Details)
		printSubTip(r.TemplatesDir.Tip)
	}
	if r.Browser != nil {
		printSubCheck("Agent Browser", r.Browser.Status, r.Browser.Message)
		printSubDetails(detailsVisible(r.Browser.Status), r.Browser.Details)
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

	// ── Coding agent ──
	if r.Skill != nil {
		printDoctorSection("Coding agent", "vigolium skills install")
		printCheck("Agent skill", r.Skill.Status, r.Skill.Message)
		printDetails(detailsVisible(r.Skill.Status), r.Skill.Details)
		printTip(r.Skill.Tip)
	}

	fmt.Println()
	if !globalVerbose {
		fmt.Printf("  %s %s\n", terminal.Yellow(terminal.SymbolTip), terminal.White("-v shows each check's detail lines"))
	}
	if !doctorFix && (diagnostics.HasFixableIssues(r) || doctorSkillStale()) {
		fmt.Printf("  %s %s%s%s\n",
			terminal.Yellow(terminal.SymbolTip),
			terminal.White("re-run with "),
			terminal.BoldCyan("vigolium doctor --fix --only chrome,nuclei"),
			terminal.White(" to install the scan dependencies (add --yes for agent tooling)"),
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
		printSubDetails(detailsVisible(t.Status), t.Details)
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
	if a.Unverified {
		msg += " — unverified: " + a.Message
	}
	return msg
}

// doctorVendorConfirm returns the interactive consent prompt for vendor
// installers, or nil when there is no terminal to ask on (-j, piped stdin):
// then only --only and --yes consent.
func doctorVendorConfirm() func(label, source string) bool {
	if globalJSON || !stdinIsTerminal() || !terminal.StderrIsTerminal() {
		return nil
	}
	reader := bufio.NewReader(os.Stdin)
	return func(label, source string) bool {
		fmt.Fprintf(os.Stderr, "  %s Install %s by running `%s`? [y/N] ", terminal.Yellow(terminal.SymbolTip), label, source)
		line, _ := reader.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true
		}
		return false
	}
}
