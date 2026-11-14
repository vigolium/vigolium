package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// scanDryRun is --dry-run on scan and `run <phase>`: resolve the scan plan,
// print it, exit. See runScanDryRun.
var scanDryRun bool

const dryRunUsage = "Resolve and print the scan plan — phases (with why each disabled one is off), budgets, pace, modules, scope, auth session names, scope admission and a rough request estimate — then exit without scanning. Mints no scan UUID, writes no output file or scan row, materializes no wordlist, runs no login and registers no OAST; an existing database is only read. -j prints it as a document (items = phases, plan = the full plan, dry_run: true)"

func init() {
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, dryRunUsage)
	runCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, dryRunUsage)
}

// scanSeededTargets is every target `vigolium scan` will seed — -t /
// positional targets, -T target-list lines and a piped URL list — read
// without seeding them, plus the -T share. ok is false when the scan's input
// is not a target list (-i, raw requests on stdin, a DB rescan).
func scanSeededTargets(opts *types.Options, inputModeExplicit bool) (targets []string, fromFiles int, ok bool) {
	if opts == nil || (globalInput != "" && globalInput != "-") {
		return nil, 0, false
	}
	targets = opts.Targets
	if len(opts.TargetsFilePaths) > 0 {
		if !source.IsTargetListFormat(opts.InputFileMode) {
			return nil, 0, false
		}
		lines, err := readTargetFilesLines(opts.TargetsFilePaths)
		if err != nil {
			return nil, 0, false
		}
		before := len(targets)
		targets, _ = mergePositionalTargets(targets, lines)
		fromFiles = len(targets) - before
	}
	if opts.Stdin {
		if !source.IsTargetListFormat(opts.InputFileMode) || !scanStdinPrefetchedReady {
			return nil, 0, false
		}
		content := strings.TrimSpace(string(scanStdinPrefetched))
		if stdinHoldsRawRequests(content, inputModeExplicit) {
			return nil, 0, false
		}
		targets, _ = mergePositionalTargets(targets, targetLinesFrom(content))
	}
	return targets, fromFiles, len(targets) > 0
}

// resolveCLIScanPlan resolves the plan of the scan this invocation describes:
// runner.ResolvePlan over the resolved options and settings and the targets
// the scan will seed. repo is optional and only read.
func resolveCLIScanPlan(cmd *cobra.Command, opts *types.Options, settings *config.Settings, strategyName string, repo *database.Repository, dryRun bool) (*scanplan.Plan, error) {
	inputModeExplicit := cmd != nil && cmd.Flags().Changed("input-mode")
	targets, fromFiles, isInput := scanSeededTargets(opts, inputModeExplicit)
	in := runner.PlanInput{
		Opts:            opts,
		Settings:        settings,
		StrategyName:    strategyName,
		Repo:            repo,
		Targets:         targets,
		FromFiles:       fromFiles,
		TargetsAreInput: isInput,
		AllRecords:      globalAllRecords,
		Verbose:         globalVerbose,
		DryRun:          dryRun,
	}
	if in.Targets == nil {
		in.Targets = []string{}
	}
	if settings != nil && settings.DynamicAssessment.Extensions.Enabled {
		in.ExtensionCount = countExtensionFiles(&settings.DynamicAssessment.Extensions)
	}
	plan, err := runner.ResolvePlan(context.Background(), in)
	if err != nil {
		return nil, err
	}
	if globalInput != "" && globalInput != "-" {
		plan.AddWarning("input_file", "-i %s is parsed when the scan runs; its requests are not in the estimate", globalInput)
	}
	return plan, nil
}

// runScanDryRun is `scan --dry-run`: resolve the plan and print it, with no
// side effect beyond reading an existing database. Exit 1 (no_targets_in_scope)
// when scope refuses every seeded target, as the real scan would.
func runScanDryRun(cmd *cobra.Command, settings *config.Settings, strategyName string) error {
	repo, dbPath, closeDB := openPlanDB(settings)
	defer closeDB()

	plan, err := resolveCLIScanPlan(cmd, scanOpts, settings, strategyName, repo, true)
	if err != nil {
		return err
	}
	if plan.Targets.Seeded > 0 && plan.Targets.Admitted == 0 {
		if !globalJSON {
			renderPlan(os.Stdout, plan)
		}
		inputModeExplicit := cmd != nil && cmd.Flags().Changed("input-mode")
		targets, _, _ := scanSeededTargets(scanOpts, inputModeExplicit)
		return noTargetsInScopeError(runner.AdmitTargets(settings.Scope, targets))
	}
	if globalJSON {
		env := newMachineEnvelope(cmd, kindScan, "", plan.Phases, int64(len(plan.Phases)), 0, len(plan.Phases))
		env.DryRun = true
		env.With("plan", plan)
		if dbPath != "" {
			env.DBPath = dbPath
		}
		return writeAgentJSON(env)
	}
	renderPlan(os.Stdout, plan)
	return nil
}

// openPlanDB opens the configured database for a dry run, read-only, when it
// already exists: a SQLite file in mode=ro (falling back to the read pool for a
// live WAL file), Postgres through the read pool. A missing file is not
// created, and no schema is touched; any failure means "plan without a
// database".
func openPlanDB(settings *config.Settings) (*database.Repository, string, func()) {
	noop := func() {}
	if settings == nil || scanOpts.Stateless {
		return nil, "", noop
	}
	cfg := settings.Database
	path := ""
	if cfg.Driver == "" || cfg.Driver == "sqlite" {
		path = config.ExpandPath(cfg.SQLite.Path)
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return nil, "", noop
		}
		cfg.SQLite.ReadOnly = true
	}
	cfg.ReadIntent = true
	db, err := database.NewDB(&cfg)
	if err != nil && cfg.SQLite.ReadOnly {
		cfg.SQLite.ReadOnly = false
		db, err = database.NewDB(&cfg)
	}
	if err != nil {
		zap.L().Debug("dry run: database unavailable, planning without it", zap.Error(err))
		return nil, "", noop
	}
	return database.NewRepository(db), path, func() { _ = db.Close() }
}

// renderPlan writes the human form of a plan: one row per phase, then the
// targets, scope, auth, modules, shaping, estimate and warnings.
func renderPlan(w io.Writer, p *scanplan.Plan) {
	title := "Scan plan"
	if p.DryRun {
		title += " (dry run — nothing was sent)"
	}
	_, _ = fmt.Fprintf(w, "%s %s\n", terminal.Green(terminal.SymbolStart), terminal.BoldHiBlue(title))
	head := fmt.Sprintf("strategy=%s heuristics=%s", p.Strategy, p.Heuristics)
	if p.Intensity != "" {
		head += " intensity=" + p.Intensity
	}
	if p.Profile != "" {
		head += " profile=" + p.Profile
	}
	if p.ScanUUID != "" {
		head += " scan=" + p.ScanUUID
	}
	_, _ = fmt.Fprintf(w, "  %s\n\n", head)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  PHASE\tRUNS\tBUDGET\tPACE\tESTIMATE\tNOTE")
	for _, ph := range p.Phases {
		runs := "yes"
		note := ""
		if !ph.Enabled {
			runs = "no"
			note = "off: " + ph.DisabledBy
		} else if !ph.SendsTarget {
			note = "no target traffic"
		}
		if ph.RequestCap != "" {
			note = strings.TrimSpace(note + " cap=" + ph.RequestCap)
		}
		est := "-"
		if pe, ok := p.Estimate.ByPhase[ph.ID]; ok && ph.Enabled {
			est = formatRange(pe.Low, pe.High)
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", ph.ID, runs, formatPhaseBudget(ph.Budget), formatPace(ph.Pace), est, note)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(w)

	t := p.Targets
	line := fmt.Sprintf("Targets: %d seeded", t.Seeded)
	if t.FromFiles > 0 {
		line += fmt.Sprintf(" (%d from -T)", t.FromFiles)
	}
	line += fmt.Sprintf(", %d admitted, %d rejected", t.Admitted, t.Rejected)
	if t.AllRecords {
		line += ", all stored records are the input"
	}
	if t.DBRecordsInScope != nil {
		line += fmt.Sprintf(", %d stored records in scope", *t.DBRecordsInScope)
	}
	_, _ = fmt.Fprintf(w, "  %s\n", line)
	for _, r := range t.RejectedSample {
		_, _ = fmt.Fprintf(w, "    rejected %s (%s)\n", r.Target, r.Reason)
	}
	_, _ = fmt.Fprintf(w, "  Scope: origin=%s ignore-static=%v host+=%s host-=%s\n",
		p.Scope.OriginMode, p.Scope.IgnoreStatic, joinOrDash(p.Scope.HostInclude), joinOrDash(p.Scope.HostExclude))
	renderDerivedScope(w, p.Scope)
	b := p.Budgets
	_, _ = fmt.Fprintf(w, "  Budgets: max-duration=%s max-requests=%s max-requests-per-host=%s rate-limit=%s concurrency=%d max-per-host=%d\n",
		formatMS(b.ScanMaxDurationMS), zeroUnlimited(b.MaxRequests), zeroUnlimited(b.MaxRequestsPerHost), zeroUnlimited(int64(b.RateLimit)), b.Concurrency, b.MaxPerHost)
	if len(p.Auth) == 0 {
		_, _ = fmt.Fprintln(w, "  Auth: none")
	}
	for _, a := range p.Auth {
		desc := fmt.Sprintf("%s (%s, %s, from %s)", a.Name, a.Role, a.Kind, a.Source)
		if a.LoginHost != "" {
			desc += " login@" + a.LoginHost
		}
		_, _ = fmt.Fprintf(w, "  Auth: %s\n", desc)
	}
	m := p.Modules
	mods := fmt.Sprintf("Modules: %d active, %d passive, %d extensions (tier ceiling %s", m.Active, m.Passive, m.Extensions, m.TierCeiling)
	if m.TierFiltered > 0 {
		mods += fmt.Sprintf("; %d above tier", m.TierFiltered)
	}
	if m.HygieneSuppressed > 0 {
		mods += fmt.Sprintf("; %d hardening advisories off", m.HygieneSuppressed)
	}
	if m.RiskGated > 0 {
		mods += fmt.Sprintf("; %d risk:high withheld", m.RiskGated)
	}
	_, _ = fmt.Fprintf(w, "  %s)\n", mods)
	for _, g := range m.PayloadsGated {
		_, _ = fmt.Fprintf(w, "    %s: %d/%d payloads gated (%s; --allow-risky-payloads or --intensity deep)\n", g.Module, g.Gated, g.Total, g.Reason)
	}
	if m.ExtensionSelection != nil {
		_, _ = fmt.Fprintf(w, "    %s\n", m.ExtensionSelection.Summary)
	}
	if d := p.Discovery; d != nil {
		var lists []string
		for _, wl := range d.Wordlists {
			n := "?"
			if wl.Lines != nil {
				n = fmt.Sprintf("%d", *wl.Lines)
			}
			lists = append(lists, fmt.Sprintf("%s=%s(%s)", wl.Slot, shortName(wl.Name), n))
		}
		_, _ = fmt.Fprintf(w, "  Discovery: tier=%s fuzzing=%v recursion=%v/%d targets-at-once=%d wordlists: %s\n",
			d.WordlistTier, d.Fuzzing, d.RecursionEnabled, d.RecursionMaxDepth, d.TargetConcurrency, strings.Join(lists, " "))
		if d.JSTangle != nil {
			_, _ = fmt.Fprintf(w, "    jstangle: enabled=%v workers=%d memory=%dMB", d.JSTangle.Enabled, d.JSTangle.Workers, d.JSTangle.MemoryBudgetMB)
			if d.Sitemap != nil {
				_, _ = fmt.Fprintf(w, " | sitemap: enabled=%v max-urls=%d per-shape=%d", d.Sitemap.Enabled, d.Sitemap.MaxURLs, d.Sitemap.PerShape)
			}
			_, _ = fmt.Fprintln(w)
		}
	}
	if h := p.Harvest; h != nil {
		_, _ = fmt.Fprintf(w, "  Harvest: sources=%s max-urls=%d per-shape=%d cdx-max-rows=%d probe=%v\n",
			strings.Join(h.Sources, ","), h.MaxURLs, h.PerShape, h.CDXMaxRows, h.Probe)
	}
	if pm := p.ParamMining; pm != nil {
		_, _ = fmt.Fprintf(w, "  Param mining: %d endpoints/host × %d requests, %d workers\n", pm.EndpointsPerHost, pm.RequestsPerEndpoint, pm.Workers)
	}
	if e := p.Egress; e != nil && len(e.Exempt) > 0 {
		var ex []string
		for _, x := range e.Exempt {
			ex = append(ex, x.Path)
		}
		_, _ = fmt.Fprintf(w, "  Egress: %d gated paths; not gated: %s\n", len(e.Gated), strings.Join(ex, ", "))
	}
	est := p.Estimate
	headline := "Estimate (" + est.Confidence + "): " + formatRange(est.Low, est.High) + " requests"
	if est.CeilingByPace != nil {
		headline = fmt.Sprintf("Estimate (%s): at most %d requests by pace; %s expected", est.Confidence, *est.CeilingByPace, formatRange(est.Low, est.High))
	}
	if est.ClampedTo != nil {
		headline += fmt.Sprintf(" (clamped to --max-requests %d; hits it in %s)", *est.ClampedTo, strings.Join(est.HitsMaxRequests, ", "))
	}
	_, _ = fmt.Fprintf(w, "  %s\n", headline)
	for _, wa := range p.Warnings {
		_, _ = fmt.Fprintf(w, "  %s %s: %s\n", terminal.Yellow(terminal.SymbolWarning), wa.Code, wa.Message)
	}
}

func formatPhaseBudget(b *scanplan.PhaseBudget) string {
	if b == nil {
		return "-"
	}
	var parts []string
	if b.PerTargetMS > 0 {
		parts = append(parts, formatMS(b.PerTargetMS)+"/target")
	}
	if b.PhaseCeilingMS > 0 {
		label := "phase"
		switch b.Semantics {
		case scanplan.SemanticsPerLeg:
			label = "leg"
		case scanplan.SemanticsPerCall:
			label = "call"
		}
		parts = append(parts, formatMS(b.PhaseCeilingMS)+"/"+label)
	}
	if len(parts) == 0 {
		return "-"
	}
	out := strings.Join(parts, ", ") + " [" + b.Source
	if b.DurationFactor > 0 {
		out += fmt.Sprintf(" x%.1f", b.DurationFactor)
	}
	return out + "]"
}

func formatPace(p *scanplan.Pace) string {
	if p == nil {
		return "-"
	}
	var parts []string
	if p.RateLimit > 0 {
		parts = append(parts, fmt.Sprintf("%drps", p.RateLimit))
	}
	if p.Concurrency > 0 {
		parts = append(parts, fmt.Sprintf("c%d", p.Concurrency))
	}
	if p.MaxPerHost > 0 {
		parts = append(parts, fmt.Sprintf("h%d", p.MaxPerHost))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func formatRange(low, high int64) string {
	if low == high {
		return fmt.Sprintf("%d", low)
	}
	return fmt.Sprintf("%d-%d", low, high)
}

func formatMS(ms int64) string {
	if ms <= 0 {
		return "unlimited"
	}
	return (time.Duration(ms) * time.Millisecond).String()
}

func zeroUnlimited(n int64) string {
	if n <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", n)
}

func joinOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	s := append([]string(nil), v...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

func shortName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// storedScanPlan decodes the plan the runner stored on a scan row
// (scans.plan, written when the run starts) — the same object scan.plan
// carried and `scan --dry-run` prints. The scan -j document embeds it verbatim
// as `plan`. Nil for a row with no plan (an older binary, a direct-path scan).
func storedScanPlan(scan *database.Scan) *scanplan.Plan {
	if scan == nil {
		return nil
	}
	plan, err := scanplan.Decode(scan.Plan)
	if err != nil {
		zap.L().Debug("scan row carries an unreadable plan", zap.String("scan_uuid", scan.UUID), zap.Error(err))
		return nil
	}
	return plan
}

// scanDryRunDocSchema mirrors the `scan --dry-run -j` document for `vigolium
// schema`: the scan envelope spine with dry_run true, the plan's phases as
// items and the full plan beside them. It is a separate document because the
// scan document's items are finding views.
type scanDryRunDocSchema struct {
	SchemaVersion int              `json:"schema_version"`
	Command       string           `json:"command" jsonschema:"enum=scan,enum=run"`
	Kind          string           `json:"kind" jsonschema:"enum=scan"`
	OK            bool             `json:"ok"`
	DryRun        bool             `json:"dry_run"`
	ProjectSource string           `json:"project_source,omitempty"`
	DBPath        string           `json:"db_path,omitempty"`
	Total         int64            `json:"total"`
	Offset        int              `json:"offset"`
	Limit         int              `json:"limit"`
	Items         []scanplan.Phase `json:"items"`
	Plan          scanplan.Plan    `json:"plan"`
	GeneratedAt   string           `json:"generated_at,omitempty"`
	GeneratedAtMS int64            `json:"generated_at_ms,omitempty"`
}

// schemaDocScanDryRun names the dry-run document in `vigolium schema`.
const schemaDocScanDryRun = "scan-dry-run"

func init() {
	contract.RegisterDocument(contract.Document{Name: schemaDocPlan, Value: scanplan.Plan{},
		Description: "The resolved scan plan: phases with disabled_by, budgets, modules, scope, auth names, target admission and a rough request estimate. Printed by scan --dry-run, carried by the scan.plan event, stored on scans.plan."})
	contract.RegisterDocument(contract.Document{Name: schemaDocScanDryRun, Value: scanDryRunDocSchema{},
		Description: "The scan --dry-run / run <phase> --dry-run -j document: items are the plan's phases, plan the full plan, dry_run true."})
}

// renderDerivedScope prints the scope a file-input scan derived from its
// input: the scope targets, then every input host with its record
// count, excluded hosts marked.
func renderDerivedScope(w io.Writer, sc scanplan.Scope) {
	if len(sc.ScopeTargets) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "  Scope derived from input: %s (use -t or --scope-origin all to widen)\n", strings.Join(sc.ScopeTargets, ", "))
	for _, h := range sc.InputHosts {
		verdict := "in scope"
		if !h.InScope {
			verdict = "excluded"
		}
		_, _ = fmt.Fprintf(w, "    %-40s %6d records  %s\n", h.Host, h.Records, verdict)
	}
}
