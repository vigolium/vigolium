package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/http/proxyenv"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// doctorContext is what the flat check view needs beyond the report: where
// each setting came from, and which proxy requests go through.
type doctorContext struct {
	sources     map[string]string
	proxy       *proxyenv.Route
	proxySource string
}

func newDoctorContext(settings *config.Settings, project string) *doctorContext {
	c := &doctorContext{}
	c.sources, _ = config.TraceSources(config.TraceOptions{ConfigPath: globalConfig, ProjectUUID: project, FlagKeys: configFlagKeys()})
	c.proxy, c.proxySource = effectiveProxy(globalProxy)
	return c
}

// doctorCheckKeys is the setting each check tests, for the source it names
// when it fails.
var doctorCheckKeys = map[string]string{
	"oast":             "oast.server_url",
	"database":         "database.sqlite.path",
	"agent":            "agent.olium.provider",
	"sessions_dir":     "agent.sessions_dir",
	"templates_dir":    "agent.templates_dir",
	"nuclei_templates": "known_issue_scan.templates_dir",
}

// checks is the report's flat view plus the proxy row, with the source of the
// tested setting on every check that is not ok.
func (c *doctorContext) checks(r *diagnostics.Report) []diagnostics.Check {
	base := r.Checks()
	pc := diagnostics.ProxyCheck(c.proxy, c.proxySource)
	proxy := diagnostics.Check{ID: "proxy", Group: "core", Status: string(pc.Status), Message: pc.Message, Tip: pc.Tip, Details: pc.Details}
	if pc.Status != diagnostics.StatusOK {
		proxy.Affects = []string{"every request"}
		proxy.Source = c.proxySource
	}
	anchor := "database"
	if slices.ContainsFunc(base, func(x diagnostics.Check) bool { return x.ID == "initialized" }) {
		anchor = "initialized"
	}
	out := make([]diagnostics.Check, 0, len(base)+1)
	inserted := false
	for _, ch := range base {
		if ch.Status != string(diagnostics.StatusOK) {
			if key, ok := doctorCheckKeys[ch.ID]; ok {
				ch.Source = key + " from " + config.SourceOf(c.sources, key)
			}
		}
		out = append(out, ch)
		if ch.ID == anchor {
			out = append(out, proxy)
			inserted = true
		}
	}
	if !inserted {
		out = append(out, proxy)
	}
	return out
}

// filter keeps the checks --only names (all of them without --only).
func (c *doctorContext) filter(checks []diagnostics.Check) []diagnostics.Check {
	if len(doctorOnly) == 0 {
		return checks
	}
	var keep []string
	for _, tok := range doctorOnly {
		keep = append(keep, doctorOnlyCheckID(tok, checks))
	}
	var out []diagnostics.Check
	for _, ch := range checks {
		if slices.Contains(keep, ch.ID) {
			out = append(out, ch)
		}
	}
	return out
}

// doctorOnlyCheckID maps an --only token to a check id ("" when it names
// none).
func doctorOnlyCheckID(tok string, checks []diagnostics.Check) string {
	t := strings.ToLower(strings.TrimSpace(tok))
	if t == doctorSkillFixKey || t == "skills" {
		return "skill"
	}
	return diagnostics.CheckIDForToken(t, checks)
}

// validateDoctorOnly refuses an --only token that names no check.
func validateDoctorOnly(checks []diagnostics.Check) error {
	for _, tok := range doctorOnly {
		if doctorOnlyCheckID(tok, checks) != "" || diagnostics.ResolveFixKey(tok) == "vigolium-audit" {
			continue
		}
		ids := make([]string, 0, len(checks))
		for _, ch := range checks {
			ids = append(ids, ch.ID)
		}
		return usageErrorf("--only %q names no check; valid: %s (aliases: chrome, nuclei)", tok, strings.Join(ids, ", "))
	}
	return nil
}

// doctorFixKeys turns --only tokens into the fix keys RunFixes takes.
func doctorFixKeys(only []string) []string {
	out := make([]string, 0, len(only))
	for _, tok := range only {
		t := strings.ToLower(strings.TrimSpace(tok))
		if t == "nuclei_templates" {
			t = "nuclei-templates"
		}
		out = append(out, t)
	}
	return out
}

// emitDoctorJSON writes the doctor -j document: items are the flat checks
// (the --for checks under --for), status is the verdict, capabilities says
// what still works. Under --fix, fixes rides along and items are the
// re-checked state the exit code follows. --json-legacy-keys keeps the
// nested report it replaced.
func emitDoctorJSON(cmd *cobra.Command, dc *doctorContext, report *diagnostics.Report, fixes []diagnostics.FixResult, updated *diagnostics.Report, scoped *diagnostics.ScopedReport) error {
	if jsonLegacyKeysEnabled() {
		return emitDoctorLegacyJSON(cmd, report, fixes, updated, scoped)
	}
	verdict := report
	if updated != nil {
		verdict = updated
	}
	var opts []envOpt
	if updated != nil {
		if fixes == nil {
			fixes = []diagnostics.FixResult{}
		}
		opts = append(opts, withExtra("fixes", fixes))
	}
	opts = append(opts, withExtra("capabilities", verdict.Capabilities()))
	if scoped != nil {
		opts = append(opts, withExtra("status", scoped.Status), withExtra("for", scoped.For), withExtra("checks", scoped.Checks))
		return emitRead(cmd, "", scoped.Checks, int64(len(scoped.Checks)), 0, len(scoped.Checks), opts...)
	}
	checks := dc.filter(dc.checks(verdict))
	opts = append(opts, withExtra("status", verdict.Status))
	return emitRead(cmd, "", checks, int64(len(checks)), 0, len(checks), opts...)
}

// emitDoctorDryRun writes `doctor --fix --dry-run -j`: the current checks and
// the installs --fix would run, as fixes rows with planned set.
func emitDoctorDryRun(cmd *cobra.Command, dc *doctorContext, report *diagnostics.Report, plan []diagnostics.FixResult) error {
	if plan == nil {
		plan = []diagnostics.FixResult{}
	}
	checks := dc.filter(dc.checks(report))
	return emitRead(cmd, "", checks, int64(len(checks)), 0, len(checks),
		withExtra("status", report.Status), withExtra("capabilities", report.Capabilities()),
		withExtra("fixes", plan), func(e *agentEnvelope) { e.DryRun = true })
}

// emitDoctorLegacyJSON is the pre-flattening document: items:[report], and
// under --fix the {report, fixes, updated} keys.
func emitDoctorLegacyJSON(cmd *cobra.Command, report *diagnostics.Report, fixes []diagnostics.FixResult, updated *diagnostics.Report, scoped *diagnostics.ScopedReport) error {
	verdict := report
	legacyKey := "."
	var opts []envOpt
	if updated != nil {
		verdict = updated
		legacyKey = "report"
		if fixes == nil {
			fixes = []diagnostics.FixResult{}
		}
		opts = append(opts, withExtra("fixes", fixes), withExtra("updated", updated))
	}
	switch {
	case scoped != nil:
		opts = append(opts, withExtra("status", scoped.Status), withExtra("for", scoped.For), withExtra("checks", scoped.Checks))
	case verdict != nil:
		opts = append(opts, withExtra("status", verdict.Status))
	}
	return emitObject(cmd, legacyKey, report, opts...)
}

// printDoctorVerdict prints the verdict line and what still works.
func printDoctorVerdict(r *diagnostics.Report) {
	switch r.Status {
	case "ready":
		fmt.Printf("  %s %s\n", terminal.BoldGreen(terminal.SymbolSuccess), terminal.BoldGreen("Ready"))
	case "degraded":
		fmt.Printf("  %s %s\n", terminal.BoldYellow(terminal.SymbolWarning), terminal.BoldYellow("Degraded — some scan modes are unavailable or scope rules are broken"))
	default:
		fmt.Printf("  %s %s\n", terminal.BoldRed(terminal.SymbolError), terminal.BoldRed("Not ready — "+doctorBlockers(r)))
	}
	caps := r.Capabilities()
	parts := []string{}
	for _, kv := range []struct{ name, state string }{
		{"scan", caps.Scan}, {"spidering", caps.Spidering}, {"known-issue scan", caps.KnownIssueScan},
		{"out-of-band", caps.OutOfBand}, {"agent", caps.Agent}, {"audit", caps.Audit},
	} {
		mark := terminal.Green(kv.name)
		switch kv.state {
		case diagnostics.CapabilityUnavailable:
			mark = terminal.Red(kv.name + " ✗")
		case diagnostics.CapabilityUnverified:
			mark = terminal.Yellow(kv.name + " ?")
		}
		parts = append(parts, mark)
	}
	fmt.Printf("    %s %s\n", terminal.Gray("works:"), strings.Join(parts, terminal.Gray(", ")))
}

// printDoctorChecks prints the verdict and one line per check (--only).
func printDoctorChecks(r *diagnostics.Report, checks []diagnostics.Check) {
	fmt.Println()
	printDoctorVerdict(r)
	fmt.Println()
	for _, ch := range checks {
		status := diagnostics.Status(ch.Status)
		if ch.Status == diagnostics.CheckStatusUnverified {
			status = diagnostics.StatusWarning
		}
		msg := ch.Message
		if ch.Status == diagnostics.CheckStatusUnverified {
			msg = "unverified: " + msg
		}
		printCheck(ch.ID, status, msg)
		printDetails(globalVerbose, ch.Details)
		if ch.Source != "" {
			printDetails(true, []string{"setting: " + ch.Source})
		}
		printTip(ch.Tip)
	}
	fmt.Println()
}

// printFixPlan renders `doctor --fix --dry-run`.
func printFixPlan(plan []diagnostics.FixResult) {
	fmt.Println()
	if len(plan) == 0 {
		fmt.Printf("  %s %s\n", terminal.SuccessSymbol(), terminal.White("Nothing to install: --fix would change nothing."))
		fmt.Println()
		return
	}
	fmt.Printf("  %s %s\n", terminal.BoldCyan("doctor --fix would run:"), terminal.Gray("(dry run; nothing installed)"))
	for _, p := range plan {
		dest := p.Destination
		if dest == "" {
			dest = "-"
		}
		fmt.Printf("  %s %-24s %s\n", terminal.Cyan(terminal.SymbolStart), p.Label, terminal.Gray(fmt.Sprintf("%s · %s · %s", p.Method, dest, p.Size)))
		if p.Source != "" {
			fmt.Printf("      %s %s\n", terminal.Gray("$"), terminal.Gray(p.Source))
		}
		if p.Message != "" && p.Message != "would install" {
			fmt.Printf("      %s\n", terminal.Yellow(p.Message))
		}
	}
	fmt.Println()
}
