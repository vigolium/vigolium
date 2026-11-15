package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/database"
	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/http/proxyenv"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// PlanInput is what ResolvePlan resolves a scan plan from: the options and
// settings AFTER scan-options resolution (resolveNativeScanOptions on the CLI,
// the same runner functions on REST and launch.go).
type PlanInput struct {
	Opts     *types.Options
	Settings *config.Settings
	// StrategyName is the strategy that applied ("" = none).
	StrategyName string
	// Repo is optional and only read: records in scope, the insertion-point
	// sample, DB-stored auth sessions. Nil under a dry run with no database.
	Repo *database.Repository
	// Targets are the targets the scan seeds (CLI, -T lines, a piped URL
	// list); nil means Opts.Targets. FromFiles is the -T share.
	Targets   []string
	FromFiles int
	// TargetsAreInput says the targets are the scan's input, so scope
	// admission and the preflight apply (false for -i, --all-records,
	// scan-on-receive).
	TargetsAreInput bool
	// AllRecords: the stored records are the input (--all-records).
	AllRecords bool
	// ExtensionCount is the number of extension files that will load, for a
	// plan resolved before the extensions are (the CLI's).
	ExtensionCount int
	// Verbose lists the running module ids.
	Verbose bool
	// DryRun marks the plan as resolved without running the scan.
	DryRun bool

	// Set by the runner once the extensions are loaded: the selection over
	// them and their active modules (which count in by_scope).
	extensions      *scanplan.ExtensionSelection
	extensionActive []modules.ActiveModule
	// admission is the runner's own verdict over Targets (targetAdmission),
	// reused instead of re-admitting when TargetsAreInput.
	admission *TargetAdmission
}

// ResolvePlan resolves the scan plan for already-resolved options and
// settings. It has no side effects: no file is written (wordlists are sized
// from the embedded copies, never materialized), no session logs in, no OAST
// is registered, nothing touches the network, and the database is only read.
// `scan --dry-run` prints its result; the runner emits it as scan.plan and
// stores it on the scan row.
func ResolvePlan(ctx context.Context, in PlanInput) (*scanplan.Plan, error) {
	if in.Opts == nil {
		return nil, errors.New("resolve plan: nil options")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opts := in.Opts
	settings := in.Settings
	if settings == nil {
		settings = config.DefaultSettings()
	}
	// A planning view over the same read-only helpers the phases use, so the
	// plan answers "which wordlists", "is fuzzing on", "which DB sessions"
	// exactly as the run will. Nothing here starts, dials or writes.
	pr := &Runner{options: opts, settings: settings, repository: in.Repo}

	targets := in.Targets
	if targets == nil {
		targets = opts.Targets
	}

	strategy := in.StrategyName
	if strategy == "" {
		strategy = opts.ScanningStrategy
	}
	if strategy == "" {
		strategy = "default"
	}
	p := &scanplan.Plan{
		SchemaVersion: scanplan.SchemaVersion,
		ScanUUID:      opts.ScanUUID,
		DryRun:        in.DryRun,
		Strategy:      strategy,
		Intensity:     opts.Intensity,
		Profile:       opts.ScanningProfile,
		Heuristics:    opts.HeuristicsCheck,
		Auth:          []scanplan.AuthSession{},
		Warnings:      []scanplan.Warning{},
		Budgets: scanplan.Budgets{
			ScanMaxDurationMS:  opts.ScanMaxDuration.Milliseconds(),
			MaxRequests:        opts.MaxRequests,
			MaxRequestsPerHost: opts.MaxRequestsPerHost,
			RateLimit:          opts.RateLimit,
			Concurrency:        opts.Concurrency,
			MaxPerHost:         opts.MaxPerHost,
		},
		Scope: planScope(settings.Scope),
	}
	planScopeTargets(&p.Scope, settings.Scope, opts)

	// Targets and scope admission (the same AdmitTargets the runner enforces).
	adm := TargetAdmission{Admitted: targets}
	switch {
	case in.TargetsAreInput && in.admission != nil:
		adm = *in.admission
	case in.TargetsAreInput:
		adm = AdmitTargets(settings.Scope, targets)
	}
	p.Targets = scanplan.Targets{
		Seeded:     len(targets),
		FromFiles:  in.FromFiles,
		AllRecords: in.AllRecords,
		Admitted:   len(adm.Admitted),
		Rejected:   len(adm.Rejected),
	}
	for i, v := range adm.Rejected {
		if i == 10 {
			break
		}
		p.Targets.RejectedSample = append(p.Targets.RejectedSample, scanplan.Rejection{Target: v.Target, Host: v.Host, Reason: v.Rule})
	}
	noneAdmitted := in.TargetsAreInput && adm.NoneAdmitted()
	switch {
	case noneAdmitted:
		p.AddWarning(database.ReasonNoTargetsInScope, "scope rejected all %d target(s): %s; nothing will be sent",
			len(adm.Rejected), DescribeRejected(adm.Rejected, 5))
	case len(adm.Rejected) > 0:
		p.AddWarning(database.ReasonTargetsOutOfScope, "scope rejected %d of %d target(s): %s",
			len(adm.Rejected), len(targets), DescribeRejected(adm.Rejected, 5))
	}

	// Stored records the assessment will read, and their insertion points.
	var sample database.InsertionPointSample
	if in.Repo != nil {
		var hosts []database.HostTarget
		haveHosts := true
		if len(adm.Admitted) > 0 {
			hosts = in.Repo.InScopeHosts(ctx, settings.Scope, adm.Admitted, opts.ProjectUUID, "")
			haveHosts = len(hosts) > 0
		}
		var n int64
		known := true
		if haveHosts && !noneAdmitted {
			var err error
			if n, err = in.Repo.CountRecordsAfterCursor(ctx, opts.ProjectUUID, time.Time{}, "", hosts...); err != nil {
				zap.L().Debug("plan: record count unavailable", zap.Error(err))
				known = false
			}
			if n > 0 {
				if s, err := in.Repo.SampleInsertionPoints(ctx, opts.ProjectUUID, hosts, planSampleLimit); err == nil {
					sample = s
				}
			}
		}
		if known {
			p.Targets.StoredRecords = types.StoredRecordsInclude
			if opts.ExcludesStoredRecords() {
				// Stored records are left alone: the assessment reads only
				// what this run seeds or finds.
				excluded, zero := n, int64(0)
				p.Targets.StoredRecords = types.StoredRecordsExclude
				p.Targets.DBRecordsExcluded = &excluded
				p.Targets.DBRecordsInScope = &zero
			} else {
				p.Targets.DBRecordsInScope = &n
			}
		}
	}

	// Phases, in execution order, enabled and disabled.
	nsp := BuildNativeScanPlan(opts)
	preflightOn := in.TargetsAreInput && len(adm.Admitted) > 0 && pr.preflightApplies(nsp)
	p.Phases = append(p.Phases, scanplan.Phase{ID: string(PhasePreflight), Enabled: preflightOn, SendsTarget: true})
	if !preflightOn {
		p.Phases[0].DisabledBy = preflightDisabledBy(opts)
	}
	for _, step := range nsp.Steps {
		ph := scanplan.Phase{ID: string(step.Phase), Enabled: step.Enabled, SendsTarget: !step.SkipsTarget}
		if !ph.Enabled {
			ph.DisabledBy = phaseDisabledBy(opts, step.Phase)
		}
		p.Phases = append(p.Phases, ph)
	}
	if noneAdmitted {
		for i := range p.Phases {
			if p.Phases[i].Enabled {
				p.Phases[i].Enabled = false
				p.Phases[i].DisabledBy = "scope"
			}
		}
	}
	enabledIDs := p.EnabledPhaseIDs()
	var capEnforcement map[string]string
	if opts.MaxRequests > 0 || opts.MaxRequestsPerHost > 0 {
		capEnforcement = egress.RequestCapEnforcement(enabledIDs)
	}
	for i := range p.Phases {
		ph := &p.Phases[i]
		ph.Budget = planPhaseBudget(settings, opts, NativePhase(ph.ID), len(adm.Admitted))
		ph.Pace = planPhasePace(settings, opts, ph.ID)
		if ph.Enabled {
			ph.RequestCap = capEnforcement[ph.ID]
		}
	}
	if len(enabledIDs) > 0 {
		p.Egress = planEgress(egress.Inventory(enabledIDs))
	}

	// Modules.
	planModules(p, opts, settings, in)

	// Auth sessions: names and kinds only, parsed, never hydrated.
	planAuth(ctx, p, pr, opts, settings)

	// Phase shaping.
	if ph := p.Phase(string(PhaseDiscovery)); ph != nil && ph.Enabled {
		p.Discovery = planDiscovery(pr, settings, len(adm.Admitted))
	}
	if ph := p.Phase(string(PhaseExternalHarvest)); ph != nil && ph.Enabled {
		p.Harvest = planHarvest(settings, p.Phase(string(PhaseHarvestProbe)))
	}
	if ph := p.Phase(string(PhaseParamMining)); ph != nil && ph.Enabled {
		pm := settings.DynamicAssessment.ParamMining
		p.ParamMining = &scanplan.ParamMining{
			EndpointsPerHost:    pm.EndpointsPerHost(),
			RequestsPerEndpoint: pm.RequestsPerEndpoint(),
			Workers:             pm.Workers(opts.Concurrency),
		}
	}

	if opts.ScanMaxDuration <= 0 && opts.MaxRequests <= 0 && !noneAdmitted {
		if ph := p.Phase(string(PhaseDiscovery)); ph != nil && ph.Enabled && len(adm.Admitted) > 0 {
			p.AddWarning("unbounded_discovery", "discovery has a per-target budget and no phase ceiling; pass --scanning-max-duration or --max-requests to bound the whole scan")
		}
	}

	p.Proxy = planProxy(opts.ProxyURL, adm.Admitted)

	p.Estimate = estimatePlan(p, planEstimateInput{
		settings: settings,
		opts:     opts,
		targets:  int64(len(adm.Admitted)),
		records:  derefInt64(p.Targets.DBRecordsInScope),
		sample:   sample,
	})
	return p, nil
}

// planSampleLimit bounds the insertion-point sample: enough for a stable
// average, small enough to read in milliseconds.
const planSampleLimit = 1000

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func planScope(s config.ScopeConfig) scanplan.Scope {
	nonNil := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return append([]string(nil), v...)
	}
	out := scanplan.Scope{
		OriginMode:   config.ResolveCLIOriginMode(s.CLIOriginMode),
		IgnoreStatic: s.IgnoreStaticFile,
		HostInclude:  nonNil(s.Host.Include),
		HostExclude:  nonNil(s.Host.Exclude),
		PathInclude:  nonNil(s.Path.Include),
		PathExclude:  nonNil(s.Path.Exclude),
	}
	for _, r := range config.NonDefaultScopeRules(s) {
		out.Rules = append(out.Rules, scanplan.ScopeRuleView{
			Class: r.Class, Include: nonNil(r.Rule.Include), Exclude: nonNil(r.Rule.Exclude),
		})
	}
	return out
}

// planScopeTargets adds the derived file-input scope to the plan:
// the scope-only targets and the input's host census with each verdict.
func planScopeTargets(out *scanplan.Scope, s config.ScopeConfig, opts *types.Options) {
	if opts == nil || len(opts.ScopeTargets) == 0 {
		return
	}
	out.ScopeTargets = append([]string(nil), opts.ScopeTargets...)
	if len(opts.ScopeCensus) == 0 {
		return
	}
	matcher := config.NewScopeMatcher(s, append(append([]string(nil), opts.Targets...), opts.ScopeTargets...)...)
	for host, n := range opts.ScopeCensus {
		out.InputHosts = append(out.InputHosts, scanplan.InputHost{Host: host, Records: n, InScope: matcher.HostInScope(host)})
	}
	sort.Slice(out.InputHosts, func(i, j int) bool {
		a, b := out.InputHosts[i], out.InputHosts[j]
		if a.Records != b.Records {
			return a.Records > b.Records
		}
		return a.Host < b.Host
	})
}

func planEgress(e *scanevents.Egress) *scanplan.Egress {
	if e == nil {
		return nil
	}
	out := &scanplan.Egress{Gated: append([]string{}, e.Gated...), Exempt: []scanplan.EgressExemption{}}
	for _, x := range e.Exempt {
		out.Exempt = append(out.Exempt, scanplan.EgressExemption{Path: x.Path, Reason: x.Reason})
	}
	return out
}

// preflightDisabledBy explains a preflight that will not run: --skip
// preflight, or a gate (the targets are not the input, a probe-only run, or a
// plan that sends nothing to the target).
func preflightDisabledBy(opts *types.Options) string {
	if opts.SkipPreflight {
		return "skip"
	}
	return "gate"
}

// phaseDisabledBy explains a disabled phase: what the scan-options resolution
// recorded (Options.PhaseSelection), else the gate or default that applies.
func phaseDisabledBy(opts *types.Options, phase NativePhase) string {
	if by := opts.PhaseSelection[string(phase)]; by != "" {
		return by
	}
	switch phase {
	case PhaseHeuristicsCheck:
		return "heuristics"
	case PhasePortSweep:
		if opts.SkipPortSweep {
			return "skip"
		}
		return "intensity"
	case PhaseParamMining:
		if opts.SkipDynamicAssessment {
			return "gate"
		}
		if opts.ParamMining != nil {
			return "flag"
		}
		return "intensity"
	case PhaseHarvestProbe, PhaseTargetedReSpider, PhaseSeed:
		if skipListNames(opts.SkipPhases, phase) {
			return "skip"
		}
		return "gate"
	default:
		return "default"
	}
}

// paceSource maps a scanning_pace provenance to the plan's budget source.
func paceSource(s config.PaceSource) string {
	switch s {
	case config.PaceSourceFactor:
		return scanplan.SourceFactor
	case config.PaceSourcePhase, config.PaceSourceCommon:
		return scanplan.SourceConfig
	default:
		return scanplan.SourceDefault
	}
}

// planPhaseBudget is the time budget a phase runs under, with what it bounds
// and where it came from, read from the same resolvers the phases use.
func planPhaseBudget(settings *config.Settings, opts *types.Options, phase NativePhase, targets int) *scanplan.PhaseBudget {
	pace := &settings.ScanningPace
	switch phase {
	case PhaseSpidering:
		per := SpideringBudget(settings, opts)
		if per <= 0 {
			per = config.DefaultSpideringConfig().MaxDurationParsed()
		}
		resolved := pace.ResolvePhase(string(PhaseSpidering))
		b := &scanplan.PhaseBudget{
			PerTargetMS:    per.Milliseconds(),
			PhaseCeilingMS: spideringPhaseCeiling(per, max(targets, 1)).Milliseconds(),
			GraceMS:        SpideringGrace(per).Milliseconds(),
			Semantics:      scanplan.SemanticsPerTargetCapped,
		}
		switch opts.SpideringMaxDurationSource {
		case SpideringSourceFlag:
			b.Source = scanplan.SourceFlag
		case string(config.PaceSourceFactor):
			b.Source = scanplan.SourceFactor
			b.DurationFactor = resolved.DurationFactor
			if per > opts.SpideringMaxDuration {
				b.Source = scanplan.SourceFloor
			}
		case string(config.PaceSourcePhase), string(config.PaceSourceCommon):
			b.Source = scanplan.SourceConfig
		default:
			b.Source = scanplan.SourceDefault
		}
		return b
	case PhaseDiscovery:
		per := DiscoveryBudget(settings, opts)
		resolved := pace.ResolvePhase(string(PhaseDiscovery))
		b := &scanplan.PhaseBudget{PerTargetMS: per.Milliseconds(), Semantics: scanplan.SemanticsPerTarget}
		switch {
		case resolved.MaxDuration > 0 && per == resolved.MaxDuration:
			b.Source = paceSource(resolved.Source)
			b.DurationFactor = resolved.DurationFactor
		case per == source.DefaultDiscoveryMaxDuration:
			b.Source = scanplan.SourceDefault
		default:
			b.Source = scanplan.SourceFlag
		}
		return b
	case PhaseDynamicAssessment, PhaseProbe, PhaseFingerprint:
		return phaseWideBudget(pace.ResolvePhase(string(phase)), scanplan.SemanticsPhase)
	case PhaseKnownIssueScan:
		return phaseWideBudget(pace.ResolvePhase(string(phase)), scanplan.SemanticsPerLeg)
	case PhaseExternalHarvest:
		return phaseWideBudget(pace.ResolvePhase("external_harvester"), scanplan.SemanticsPerCall)
	case PhaseTargetedReSpider:
		rs := &settings.Discovery.ReSpider
		return &scanplan.PhaseBudget{
			PerTargetMS:    rs.PerSeedDuration().Milliseconds(),
			PhaseCeilingMS: rs.StepDuration().Milliseconds(),
			Semantics:      scanplan.SemanticsPerTargetCapped,
			Source:         scanplan.SourceConfig,
		}
	}
	return nil
}

func phaseWideBudget(resolved config.ResolvedPhasePace, semantics string) *scanplan.PhaseBudget {
	if resolved.MaxDuration <= 0 {
		return nil
	}
	return &scanplan.PhaseBudget{
		PhaseCeilingMS: resolved.MaxDuration.Milliseconds(),
		DurationFactor: resolved.DurationFactor,
		Semantics:      semantics,
		Source:         paceSource(resolved.Source),
	}
}

// planPhasePace reports the pace fields a phase enforces (config.
// PhasePaceSupports), resolved as the phase resolves them; nil for a phase
// that enforces none.
func planPhasePace(settings *config.Settings, opts *types.Options, phase string) *scanplan.Pace {
	resolved := settings.ScanningPace.ResolvePhase(phase)
	var pace scanplan.Pace
	if config.PhasePaceSupports(phase, config.PaceFieldRateLimit) {
		pace.RateLimit = resolved.RateLimit
		if phase == string(PhaseDiscovery) {
			pace.RateLimit = settings.ScanningPace.DiscoveryRateLimit(opts)
		}
		if phase == string(PhaseKnownIssueScan) {
			pace.RateLimit = settings.ScanningPace.KnownIssueScanRateLimit(opts)
		}
	} else if phase == string(PhaseDynamicAssessment) {
		// No phase-local rate, but every request goes through the scan-wide
		// limiter, so that is the rate in force; 0 here would read "unlimited".
		pace.RateLimit = effectiveRateLimit(opts)
	}
	if config.PhasePaceSupports(phase, config.PaceFieldConcurrency) {
		pace.Concurrency = resolved.Concurrency
	}
	if config.PhasePaceSupports(phase, config.PaceFieldMaxPerHost) {
		pace.MaxPerHost = resolved.MaxPerHost
	}
	if pace == (scanplan.Pace{}) {
		return nil
	}
	return &pace
}

// planModules fills the module section from FilterModulesForRun — the runner's
// own selection — plus the extension count or selection.
func planModules(p *scanplan.Plan, opts *types.Options, settings *config.Settings, in PlanInput) {
	var sel ModuleSelection
	if !opts.ExtensionsOnly {
		sel = FilterModulesForRun(opts, settings)
	} else {
		sel.TierCeiling = scanTierCeiling(opts)
	}
	riskyAllowed := RiskyPayloadsAllowed(opts, settings)
	m := scanplan.Modules{
		Active:               len(sel.Active),
		Passive:              len(sel.Passive),
		TierCeiling:          tierNames[sel.TierCeiling],
		TierFiltered:         len(sel.TierDeferred),
		HygieneSuppressed:    len(sel.HygieneSuppressed),
		RiskGated:            len(sel.RiskWithheld),
		RiskyPayloadsAllowed: riskyAllowed,
		ByScope:              map[string]int{},
	}
	extEnabled := settings.DynamicAssessment.Extensions.Enabled
	switch {
	case in.extensions != nil:
		m.ExtensionSelection = in.extensions
		m.Extensions = in.extensions.Active + in.extensions.Passive
	case extEnabled:
		m.Extensions = in.ExtensionCount
	}
	active := append(append([]modules.ActiveModule(nil), sel.Active...), in.extensionActive...)
	for _, mod := range active {
		scopes := mod.ScanScopes()
		if scopes&modules.ScanScopeInsertionPoint != 0 {
			m.ByScope[scanplan.ScopeInsertionPoint]++
		}
		if scopes&modules.ScanScopeRequest != 0 {
			m.ByScope[scanplan.ScopeRequest]++
		}
		if scopes&modules.ScanScopeHost != 0 {
			m.ByScope[scanplan.ScopeHost]++
		}
		if rep, ok := mod.(modules.RiskyPayloadReporter); ok && !riskyAllowed {
			if risky, total := rep.RiskyPayloads(); risky > 0 {
				m.PayloadsGated = append(m.PayloadsGated, scanplan.PayloadGate{
					Module: mod.ID(), Gated: risky, Total: total, Reason: modules.TagRiskHigh,
				})
			}
		}
	}
	if in.Verbose {
		for _, mod := range active {
			m.IDs = append(m.IDs, mod.ID())
		}
		for _, mod := range sel.Passive {
			m.IDs = append(m.IDs, mod.ID())
		}
	}
	p.Modules = m
}

// planAuth lists the sessions the scan will use: --auth-file / --auth parsed
// (never hydrated, so no login runs), else the project's DB-stored sessions
// for the targets. A file that does not parse is a warning here; the real
// scan fails on it.
func planAuth(ctx context.Context, p *scanplan.Plan, pr *Runner, opts *types.Options, settings *config.Settings) {
	var sessions []*authentication.Session
	sources := map[*authentication.Session]string{}
	add := func(list []*authentication.Session, src string) {
		for _, s := range list {
			sessions = append(sessions, s)
			sources[s] = src
		}
	}
	if len(opts.AuthFiles) > 0 {
		loaded, err := authentication.LoadFromAuthFiles(opts.AuthFiles, settings.ScanningStrategy.Session.SessionDir)
		if err != nil {
			p.AddWarning("auth_invalid", "auth file: %v", err)
		}
		add(loaded, "file")
	}
	if len(opts.AuthInline) > 0 {
		loaded, err := authentication.LoadFromAuthInline(opts.AuthInline)
		if err != nil {
			p.AddWarning("auth_invalid", "--auth: %v", err)
		}
		add(loaded, "inline")
	}
	if len(opts.AuthFiles) == 0 && len(opts.AuthInline) == 0 && !opts.NoAuth && pr.repository != nil {
		loaded, _, _ := pr.loadSessionsFromDB(ctx)
		add(loaded, "db")
	}
	primaryIdx := -1
	for i, s := range sessions {
		if s.Role == authentication.RolePrimary {
			primaryIdx = i
			break
		}
	}
	if primaryIdx < 0 && len(sessions) > 0 {
		primaryIdx = 0
	}
	for i, s := range sessions {
		a := scanplan.AuthSession{Name: s.Name, Role: string(s.Role), Kind: "headers", Primary: i == primaryIdx, Source: sources[s]}
		switch {
		case s.Login != nil:
			a.Kind = "login_flow"
			if u, err := url.Parse(s.Login.LoginURL()); err == nil {
				a.LoginHost = u.Hostname()
			}
		case s.LoginRequest != "":
			a.Kind = "login_request"
		}
		// The manager promotes the first session to primary when none says so.
		if a.Primary {
			a.Role = string(authentication.RolePrimary)
		} else if a.Role == "" {
			a.Role = string(authentication.RoleCompare)
		}
		p.Auth = append(p.Auth, a)
	}
}

// planDiscovery is the discovery shaping: the wordlists and their sizes (from
// the embedded copies — nothing is materialized), fuzzing, recursion, target
// concurrency, the jstangle workers and the sitemap caps.
func planDiscovery(pr *Runner, settings *config.Settings, targets int) *scanplan.Discovery {
	dc := settings.Discovery
	refs, tier := pr.discoveryWordlistRefs()
	fuzzOn, fuzzReason := pr.discoveryFuzzingState()
	d := &scanplan.Discovery{
		WordlistTier:      tier,
		Wordlists:         []scanplan.Wordlist{},
		Fuzzing:           fuzzOn,
		FuzzingReason:     fuzzReason,
		RecursionEnabled:  dc.Recursion.Enabled,
		RecursionMaxDepth: dc.Recursion.MaxDepth,
		TargetConcurrency: source.DiscoveryTargetConcurrency(dc.TargetConcurrency, max(targets, 1)),
	}
	for _, ref := range refs {
		w := scanplan.Wordlist{Slot: ref.slot}
		if ref.embedded != "" {
			w.Source, w.Name = "embedded", ref.embedded
			if n, ok := wordlists.EmbeddedLineCount(ref.embedded); ok {
				w.Lines = &n
			}
		} else {
			w.Source, w.Name = "path", ref.path
			if n, ok := countFileWords(ref.path); ok {
				w.Lines = &n
			}
		}
		d.Wordlists = append(d.Wordlists, w)
	}
	jsOn := dc.JSTangle.IsEnabled()
	workers, budget := jstangle.ResolvedWorkers(dc.JSTangle.WorkerCount, int64(dc.JSTangle.MemoryBudgetMB)<<20)
	d.JSTangle = &scanplan.JSTangle{Enabled: jsOn, Workers: workers, MemoryBudgetMB: budget >> 20}
	sm := deparosconfig.SitemapConfig{MaxURLs: dc.Sitemap.MaxURLs, PerShape: dc.Sitemap.PerShape}
	d.Sitemap = &scanplan.Sitemap{Enabled: dc.Sitemap.IsEnabled(), MaxURLs: sm.EffectiveMaxURLs(), PerShape: sm.EffectivePerShape()}
	return d
}

// countFileWords counts the non-blank lines of a configured wordlist. Read
// only; ok is false when the file cannot be read.
func countFileWords(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()
	var n int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) > 0 {
			n++
		}
	}
	return n, sc.Err() == nil
}

func planHarvest(settings *config.Settings, probe *scanplan.Phase) *scanplan.Harvest {
	eh := settings.ExternalHarvester
	srcs := eh.Sources
	if len(srcs) == 0 {
		srcs = config.DefaultExternalHarvesterConfig().Sources
	}
	srcs = append([]string(nil), srcs...)
	sort.Strings(srcs)
	bounds := eh.HarvesterOptions().Resolved()
	return &scanplan.Harvest{
		Sources:    srcs,
		MaxURLs:    bounds.MaxURLs,
		PerShape:   bounds.PerShape,
		CDXMaxRows: bounds.CDXMaxRows,
		Probe:      probe != nil && probe.Enabled,
	}
}

// resolveRunPlan is the runner's plan: ResolvePlan over its own options,
// settings and repository, with the loaded extensions' selection. admission
// is the run's targetAdmission (nil when the targets are not its input).
func (r *Runner) resolveRunPlan(ctx context.Context, infra *phaseInfra, admission *TargetAdmission) (*scanplan.Plan, error) {
	in := PlanInput{
		Opts:            r.options,
		Settings:        r.settings,
		StrategyName:    r.options.ScanningStrategy,
		Repo:            r.repository,
		Targets:         r.options.Targets,
		TargetsAreInput: admission != nil,
		Verbose:         r.options.Verbose,
		admission:       admission,
	}
	if infra != nil && infra.jsEngine != nil {
		sel := r.selectExtensionModules(infra.jsEngine)
		in.extensions = &scanplan.ExtensionSelection{
			Active: len(sel.Active), Passive: len(sel.Passive), Skipped: sel.skipped(),
			Summary: sel.summary(),
		}
		if len(sel.Skipped) > 0 {
			in.extensions.SkippedBy = map[string]int{}
			for k, v := range sel.Skipped {
				if v > 0 {
					in.extensions.SkippedBy[k] = v
				}
			}
		}
		in.extensionActive = sel.Active
	}
	plan, err := ResolvePlan(ctx, in)
	if err != nil {
		return nil, err
	}
	if infra != nil {
		plan.ScanUUID = infra.scanUUID
	}
	return plan, nil
}

// announcePlan resolves the run's plan, emits it as scan.plan (the second
// event of the stream: the CLI's scan.started is the first, and nothing in the
// runner emits before this) and stores it on the scan row. A plan that cannot
// be resolved is logged and skipped: it describes the scan, it is not the scan.
func (r *Runner) announcePlan(ctx context.Context, infra *phaseInfra, admission *TargetAdmission) {
	plan, err := r.resolveRunPlan(ctx, infra, admission)
	if err != nil {
		zap.L().Warn("Failed to resolve the scan plan", zap.Error(err))
		return
	}
	zap.L().Debug("Scan plan resolved", zap.String("plan", planSummaryLine(plan)))
	scanevents.Emit(scanevents.Event{Type: scanevents.TypeScanPlan, Plan: plan})
	if r.repository == nil || infra == nil || infra.scanUUID == "" {
		return
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		zap.L().Warn("Failed to encode the scan plan", zap.Error(err))
		return
	}
	if err := r.repository.UpdateScanPartial(ctx, &database.Scan{UUID: infra.scanUUID, Plan: raw}); err != nil {
		zap.L().Warn("Failed to store the scan plan on the scan row", zap.Error(err))
	}
}

// planSummaryLine renders a one-line digest of a plan, for logs.
func planSummaryLine(p *scanplan.Plan) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("phases=%s modules=%d/%d estimate=%d-%d",
		strings.Join(p.EnabledPhaseIDs(), ","), p.Modules.Active, p.Modules.Passive, p.Estimate.Low, p.Estimate.High)
}

// planProxy is the plan's proxy section: nil when nothing is proxied.
func planProxy(cliProxy string, admitted []string) *scanplan.Proxy {
	choice := proxyenv.FromEnvironment(cliProxy)
	if !choice.Any() {
		return nil
	}
	out := &scanplan.Proxy{}
	for _, r := range choice.Routes() {
		out.Routes = append(out.Routes, scanplan.ProxyRoute{Scheme: r.Scheme, URL: r.URL, Source: r.Source})
	}
	out.NoProxy, out.NoProxySource = choice.NoProxy()
	for _, t := range admitted {
		if out.Targets == nil {
			out.Targets = map[string]string{}
		}
		out.Targets[t] = choice.Describe(t)
	}
	return out
}
