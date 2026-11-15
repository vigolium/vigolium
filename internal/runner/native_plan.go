package runner

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/types"
)

type NativePhase string

const (
	PhaseHeuristicsCheck   NativePhase = "heuristics-check"
	PhasePortSweep         NativePhase = "port-sweep"
	PhaseExternalHarvest   NativePhase = "external-harvest"
	PhaseHarvestProbe      NativePhase = "harvest-probe"
	PhaseSpidering         NativePhase = "spidering"
	PhaseProbe             NativePhase = "probe"
	PhaseFingerprint       NativePhase = "fingerprint"
	PhaseDiscovery         NativePhase = "discovery"
	PhaseTargetedReSpider  NativePhase = "targeted-respider"
	PhaseSeed              NativePhase = "seed"
	PhaseParamMining       NativePhase = "param-mining"
	PhaseKnownIssueScan    NativePhase = "known-issue-scan"
	PhaseDynamicAssessment NativePhase = "dynamic-assessment"
	// PhasePreflight carries the CLI-target tally (scope admission,
	// reachability) on a scan row. Not a plan step: RunNativeScan runs it
	// before the first phase whenever the targets are the input (see
	// preflight.go); --skip preflight turns the reachability GET off.
	PhasePreflight NativePhase = "preflight"
)

// nativePhaseSpelling is one canonical phase id plus every alternative spelling
// accepted for it.
type nativePhaseSpelling struct {
	Canonical string
	Aliases   []string
	// Skippable reports whether --skip accepts this phase.
	Skippable bool
	// Internal marks a step the plan schedules on its own gates (seed fills in
	// for a skipped ingestion, harvest-probe rides on external-harvest). It is listed so
	// every phase.* id a scan can emit is discoverable, is accepted by --skip
	// when Skippable, and is never accepted by --only: it cannot run alone.
	Internal bool
}

// onlyAccepted reports whether --only (and `run <phase>`) accepts this phase.
func (p nativePhaseSpelling) onlyAccepted() bool { return !p.Internal }

// nativePhaseVocabulary is the SINGLE owner of the phase-name vocabulary. Every
// consumer derives from it: NormalizeNativePhase maps a spelling to its canonical
// id, the --only/--skip valid-phase lists in error messages are rendered from it,
// and `run <phase>` inherits both. Keeping one table is what stops the two halves
// from drifting — the asymmetry it replaced had `discover` normalizing to
// discovery while `spider` did not normalize at all, so `run discover` worked and
// `run spider` failed with "invalid --only value" for no reason a user could see.
//
// Aliases are the spellings an operator (or a coding agent driving the CLI)
// actually reaches for: the gerund of each phase, the internal engine names
// (deparos/spitolas), and the vocabulary borrowed from the tools each phase
// replaces (crawl, cve). The list is deliberately generous — a rejected synonym
// costs a round trip, while an extra accepted one costs nothing.
var nativePhaseVocabulary = []nativePhaseSpelling{
	{Canonical: "ingestion", Aliases: []string{"ingest", "ingesting"}, Skippable: true},
	{Canonical: "probe", Aliases: []string{"probing", "httpx", "alive", "sweep"}, Skippable: true},
	{Canonical: "fingerprint", Aliases: []string{"fp", "tech", "recon"}, Skippable: true},
	{Canonical: "discovery", Aliases: []string{"discover", "discovering", "deparos"}, Skippable: true},
	{Canonical: "external-harvest", Aliases: []string{"harvest", "harvesting", "external-harvester", "external_harvester"}, Skippable: true},
	{Canonical: "spidering", Aliases: []string{"spider", "spitolas", "crawl", "crawling", "crawler"}, Skippable: true},
	{Canonical: "known-issue-scan", Aliases: []string{"cve", "kis", "known-issue", "known-issues"}, Skippable: true},
	{Canonical: "dynamic-assessment", Aliases: []string{"dast", "audit", "assessment", "assess"}, Skippable: true},
	// --skip extension turns extensions off for the run even when the config or
	// --ext enabled them; --only extension narrows the assessment to them.
	{Canonical: "extension", Aliases: []string{"ext", "extensions"}, Skippable: true},
	// The rows below are steps BuildNativeScanPlan schedules; they appear on
	// phase.started/phase.finished, so they must be nameable here.
	{Canonical: "heuristics-check", Aliases: []string{"heuristics", "heuristic"}, Skippable: true},
	{Canonical: "port-sweep", Aliases: []string{"ports", "portsweep", "port-scan"}, Skippable: true},
	// harvest-probe checks harvested URLs against the live target before a later
	// phase scans them. It rides on external-harvest (and on a later phase that
	// reaches the target), so it cannot run alone; --skip leaves the stubs for
	// those later phases to fetch unchecked.
	{Canonical: "harvest-probe", Aliases: []string{"harvest-check"}, Skippable: true, Internal: true},
	// targeted-respider re-crawls the rich/SPA routes discovery found after the
	// browser crawl. A full scan schedules it on its own gate (spidering,
	// discovery and an assessment to consume the records); --only may also name
	// it, alongside spidering and discovery, to get the re-crawl into the store
	// without an assessment (a caller that runs DAST as a separate invocation).
	// It cannot run alone: see validateOnlyRespider.
	{Canonical: "targeted-respider", Aliases: []string{"respider", "re-spider"}, Skippable: true},
	// param-mining discovers hidden parameters on the endpoints the scan
	// recorded, for the assessment to test. It rides on dynamic-assessment
	// (deep or --param-mining), so it cannot run alone; `vigolium kit
	// param-mine` is the standalone form.
	{Canonical: "param-mining", Aliases: []string{"params", "arjun", "param-miner"}, Skippable: true, Internal: true},
	{Canonical: "seed", Skippable: false, Internal: true},
	// preflight is the target reachability check (one GET per admitted CLI
	// target) RunNativeScan runs before any phase. --skip preflight
	// (opts.SkipPreflight) turns it off; it is not a plan step, so --only
	// never names it.
	{Canonical: "preflight", Skippable: true, Internal: true},
}

// nativePhaseAliasIndex resolves any accepted spelling (canonical included) to
// its canonical id. Built once from nativePhaseVocabulary.
var nativePhaseAliasIndex = func() map[string]string {
	idx := make(map[string]string)
	for _, p := range nativePhaseVocabulary {
		idx[p.Canonical] = p.Canonical
		for _, a := range p.Aliases {
			idx[a] = p.Canonical
		}
	}
	return idx
}()

// PhaseSpelling is the public projection of one vocabulary entry, for callers
// that need the structure rather than a rendered line — notably the machine
// output of `vigolium strategy`, which is how a caller discovers what --only
// and --skip accept without parsing help text.
type PhaseSpelling struct {
	Canonical string   `json:"canonical"`
	Aliases   []string `json:"aliases,omitempty"`
	Skippable bool     `json:"skippable"`
	// Internal: scheduled by the plan on its own gates; never accepted by --only.
	Internal bool `json:"internal"`
	// OnlyAccepted reports whether --only / `run <phase>` accepts this phase.
	OnlyAccepted bool `json:"only_accepted"`
}

// PhaseVocabulary returns the accepted phase spellings, derived from the same
// single table every other consumer reads. Building the machine list here rather
// than restating it in pkg/cli is what keeps a new phase from being runnable but
// undiscoverable.
func PhaseVocabulary() []PhaseSpelling {
	out := make([]PhaseSpelling, 0, len(nativePhaseVocabulary))
	for _, p := range nativePhaseVocabulary {
		aliases := append([]string(nil), p.Aliases...)
		out = append(out, PhaseSpelling{
			Canonical:    p.Canonical,
			Aliases:      aliases,
			Skippable:    p.Skippable,
			Internal:     p.Internal,
			OnlyAccepted: p.onlyAccepted(),
		})
	}
	return out
}

// acceptedBy reports whether the --skip (forSkip) or --only (!forSkip) list
// includes this phase.
func (p nativePhaseSpelling) acceptedBy(forSkip bool) bool {
	if forSkip {
		return p.Skippable
	}
	return p.onlyAccepted()
}

// PhaseVocabularyLines renders one "canonical (alias, alias)" entry per phase,
// for help text that lists them vertically. forSkip selects the phases --skip
// accepts; false selects the phases --only accepts. Returned as lines rather
// than a joined string because the alias lists are themselves comma-separated —
// splitting the flat form on ", " to lay it out would break entries apart
// mid-list.
func PhaseVocabularyLines(forSkip bool) []string {
	lines := make([]string, 0, len(nativePhaseVocabulary))
	for _, p := range nativePhaseVocabulary {
		if !p.acceptedBy(forSkip) {
			continue
		}
		entry := p.Canonical
		if len(p.Aliases) > 0 {
			entry += " (" + strings.Join(p.Aliases, ", ") + ")"
		}
		lines = append(lines, entry)
	}
	return lines
}

// phaseVocabularyDesc renders the vocabulary as "canonical (alias, alias), …".
func phaseVocabularyDesc(forSkip bool) string {
	return strings.Join(PhaseVocabularyLines(forSkip), ", ")
}

// PhaseNamesDesc renders the canonical phase ids alone, comma-separated. Flag
// help uses this (the full alias vocabulary is too long for one --help line);
// the error a wrong value produces quotes ValidOnlyPhasesDesc/ValidSkipPhasesDesc
// instead, which spells every accepted alias out.
func PhaseNamesDesc(forSkip bool) string {
	names := make([]string, 0, len(nativePhaseVocabulary))
	for _, p := range nativePhaseVocabulary {
		if !p.acceptedBy(forSkip) {
			continue
		}
		names = append(names, p.Canonical)
	}
	return strings.Join(names, ", ")
}

// ValidOnlyPhasesDesc and ValidSkipPhasesDesc are the human-readable phase lists
// rendered in --only/--skip validation error messages. Derived from
// nativePhaseVocabulary rather than hand-written, so a spelling that works can
// never go unlisted and a listed one can never fail to resolve.
var (
	ValidOnlyPhasesDesc = phaseVocabularyDesc(false)
	ValidSkipPhasesDesc = phaseVocabularyDesc(true)
)

type NativePhaseStep struct {
	Phase   NativePhase
	Enabled bool

	// SkipsTarget marks a phase that never sends a request to the scan target.
	// Declared here, in the same literal as the phase's own gate, rather than in
	// a side table keyed by phase: this file is the single owner of the phase
	// vocabulary, and a second per-phase map is exactly how the vocabulary and
	// the plan drifted apart before. A new phase has to answer the question
	// where it is declared.
	SkipsTarget bool
}

type NativeScanPlan struct {
	Steps []NativePhaseStep
}

func BuildNativeScanPlan(opts *types.Options) NativeScanPlan {
	steps := []NativePhaseStep{
		{Phase: PhaseHeuristicsCheck, Enabled: opts.HeuristicsCheck != "" && opts.HeuristicsCheck != "none"},
		// Alternate-port sweep of the original CLI target hosts. Independent of
		// the heuristics level — gated on deep / --follow-subdomains, or asked
		// for by name with --only port-sweep — so any confirmed extra web
		// services are appended to the target set before the ingestion/scan
		// phases consume it. --skip port-sweep, and any --only that does not
		// list it, set SkipPortSweep.
		{Phase: PhasePortSweep, Enabled: !opts.SkipPortSweep &&
			(opts.FollowSubdomains || strings.EqualFold(opts.Intensity, "deep") || OnlyPhaseSet(opts.OnlyPhase)[string(PhasePortSweep)])},
		// ExternalHarvest only queries third-party archives and OSINT sources
		// ABOUT the target; it never contacts it. See SendsTargetTraffic.
		{Phase: PhaseExternalHarvest, Enabled: opts.ExternalHarvestEnabled, SkipsTarget: true},
		// Liveness + one GET per harvested URL, so the phases below scan only the
		// archive URLs that still answer. Gated after the list is built, because
		// it runs only when a LATER step reaches the target: a harvest-only run
		// must stay target-silent. See gateHarvestProbe.
		{Phase: PhaseHarvestProbe},
		{Phase: PhaseSpidering, Enabled: opts.SpideringEnabled},
		// Host sweep: one request per target, passive-only, no content discovery.
		// Placed before discovery so a full scan's later phases see the probe's
		// records (and its followed-redirect targets) already in the corpus.
		// Opt-in — a normal scan's discovery phase already fetches every target.
		{Phase: PhaseProbe, Enabled: opts.ProbeEnabled},
		// Per-origin fingerprint: well-known paths, favicon, CORS, OPTIONS,
		// vhost variants and a not-found baseline, stored as host facts. Opt-in,
		// like probe, and after it so it sees the probe's resolved schemes.
		{Phase: PhaseFingerprint, Enabled: opts.FingerprintEnabled},
		{Phase: PhaseDiscovery, Enabled: !opts.SkipIngestion},
		// Re-spider rich/SPA routes that discovery surfaced after the one-shot
		// browser crawl. Needs browsers allowed (spidering enabled) and discovery
		// run; beyond that it rides along when an assessment phase will consume
		// the new records, or runs because --only named it (the records are the
		// point: a later invocation assesses them). The config toggle + runtime
		// gates are checked in the phase.
		{Phase: PhaseTargetedReSpider, Enabled: opts.SpideringEnabled && !opts.SkipIngestion && !opts.SkipTargetedRespider &&
			(!opts.SkipDynamicAssessment || OnlyPhaseSet(opts.OnlyPhase)[string(PhaseTargetedReSpider)])},
		{Phase: PhaseSeed, Enabled: opts.SkipIngestion && !opts.ScanOnReceive && (opts.KnownIssueScanEnabled || !opts.SkipDynamicAssessment)},
		// Hidden-parameter mining over the records every phase above stored, so
		// the assessment below tests the parameters it confirms. See
		// paramMiningEnabled.
		{Phase: PhaseParamMining, Enabled: paramMiningEnabled(opts)},
		{Phase: PhaseDynamicAssessment, Enabled: !opts.SkipDynamicAssessment},
		{Phase: PhaseKnownIssueScan, Enabled: opts.KnownIssueScanEnabled},
	}
	gateHarvestProbe(steps, opts)
	return NativeScanPlan{Steps: steps}
}

// gateHarvestProbe enables the harvest-probe step when external-harvest runs,
// --skip did not name it, and some enabled step after it reaches the target.
//
// The last condition is the contract: the probe sends requests, and it exists
// only to spare a later phase from scanning dead archive URLs. With nothing
// after it that reaches the target (`run external-harvest`), probing would turn
// the one target-silent phase into a GET sweep of the live host.
//
// --skip harvest-probe is read off SkipPhases rather than a dedicated option:
// the selection is still visible there after ApplyNativePhaseSelection, and
// --only (which clears SkipPhases) leaves the probe on whenever it lists
// external-harvest alongside a phase that reaches the target.
func gateHarvestProbe(steps []NativePhaseStep, opts *types.Options) {
	for i := range steps {
		if steps[i].Phase != PhaseHarvestProbe {
			continue
		}
		steps[i].Enabled = opts.ExternalHarvestEnabled &&
			!skipListNames(opts.SkipPhases, PhaseHarvestProbe) &&
			NativeScanPlan{Steps: steps[i+1:]}.SendsTargetTraffic()
	}
}

// paramMiningEnabled gates the param-mining step. It only feeds the assessment,
// so it never runs without one, and --skip param-mining (any alias) turns it
// off. Otherwise an explicit --param-mining[=false] decides, and without the
// flag it follows the intensity: on at deep, except under --only, which
// narrows a run to the phases it names and param-mining is not nameable there.
func paramMiningEnabled(opts *types.Options) bool {
	if opts.SkipDynamicAssessment || skipListNames(opts.SkipPhases, PhaseParamMining) {
		return false
	}
	if opts.ParamMining != nil {
		return *opts.ParamMining
	}
	return strings.EqualFold(opts.Intensity, "deep") && opts.OnlyPhase == ""
}

// skipListNames reports whether a --skip list names phase under any spelling.
func skipListNames(skip []string, phase NativePhase) bool {
	for _, s := range skip {
		if NormalizeNativePhase(s) == string(phase) {
			return true
		}
	}
	return false
}

// SendsTargetTraffic reports whether any enabled step in the plan will send a
// request to the scan target. Everything but ExternalHarvest reaches it,
// directly or through the shared requester, and so is affected by session
// headers and request hooks.
//
// Infrastructure whose only purpose is to shape target traffic is built on the
// strength of this. Session hydration in particular EXECUTES LOGIN FLOWS, so
// `vigolium run external-harvest --auth-file admin.yaml` used to authenticate
// against a host it was never going to touch.
func (p NativeScanPlan) SendsTargetTraffic() bool {
	for _, step := range p.Steps {
		if step.Enabled && !step.SkipsTarget {
			return true
		}
	}
	return false
}

// enables reports whether the plan has phase as an enabled step.
func (p NativeScanPlan) enables(phase NativePhase) bool {
	for _, step := range p.Steps {
		if step.Enabled && step.Phase == phase {
			return true
		}
	}
	return false
}

// parseOnlyPhases parses a comma-separated --only value into a normalized
// set + ordered slice. Empty entries are skipped, duplicates collapse, and an
// unknown phase produces an error using the canonical phase list.
func parseOnlyPhases(raw string) (map[string]bool, []string, error) {
	parts := strings.Split(raw, ",")
	allowed := make(map[string]bool, len(parts))
	normalized := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n := NormalizeNativePhase(p)
		if !IsOnlyPhaseSpelling(n) {
			return nil, nil, phaseSelectionErrorf("invalid --only value %q; valid phases: %s", p, ValidOnlyPhasesDesc)
		}
		if !allowed[n] {
			allowed[n] = true
			normalized = append(normalized, n)
		}
	}
	if len(allowed) == 0 {
		return nil, nil, phaseSelectionErrorf("--only requires at least one phase; valid phases: %s", ValidOnlyPhasesDesc)
	}
	return allowed, normalized, nil
}

// OnlyPhaseSet returns the set of normalized phases listed in a comma-separated
// --only value. Callers use it to gate behavior that depends on which phases
// are active (e.g. validating that --format=html was scoped to phases that
// produce a report). Returns nil for empty input.
func OnlyPhaseSet(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		set[NormalizeNativePhase(p)] = true
	}
	return set
}

// NormalizeNativePhase maps every accepted spelling of a phase to its canonical
// id. Input is trimmed and lowercased first: --only already trimmed, --skip did
// not, so `--skip Discovery` (or ` discovery`) reached the switch verbatim, fell
// through to default, and was reported as an invalid phase. Aliases are extra
// surface for a driver to get subtly wrong; normalizing here means every caller
// — --only, --skip, `run <phase>`, the pace-flag qualifiers, and the
// scan.started event's canonical phase list — agrees on what a spelling means.
func NormalizeNativePhase(phase string) string {
	phase = strings.ToLower(strings.TrimSpace(phase))
	if canonical, ok := nativePhaseAliasIndex[phase]; ok {
		return canonical
	}
	return phase
}

// IsNativePhaseSpelling reports whether s names a native scan phase under any
// accepted spelling. Callers that need to branch on "is this a phase?" ask here
// rather than re-listing spellings, so a new alias reaches them for free.
func IsNativePhaseSpelling(s string) bool {
	_, ok := nativePhaseAliasIndex[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// lookupPhaseSpelling returns the vocabulary row a spelling resolves to.
func lookupPhaseSpelling(s string) (nativePhaseSpelling, bool) {
	canonical, ok := nativePhaseAliasIndex[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return nativePhaseSpelling{}, false
	}
	for _, p := range nativePhaseVocabulary {
		if p.Canonical == canonical {
			return p, true
		}
	}
	return nativePhaseSpelling{}, false
}

// IsOnlyPhaseSpelling reports whether --only (and `run <phase>`) accepts s.
// Internal steps (seed, harvest-probe, param-mining, preflight) are phase names
// but not runnable on their own.
func IsOnlyPhaseSpelling(s string) bool {
	p, ok := lookupPhaseSpelling(s)
	return ok && p.onlyAccepted()
}

// IsSkippablePhaseSpelling reports whether --skip accepts s.
func IsSkippablePhaseSpelling(s string) bool {
	p, ok := lookupPhaseSpelling(s)
	return ok && p.Skippable
}

// ErrPhaseSelection marks a rejected --only/--skip selection: a misuse of the
// command line, which the CLI reports as a usage error (exit 2).
var ErrPhaseSelection = errors.New("invalid phase selection")

// phaseSelectionError is a rejected selection; errors.Is matches
// ErrPhaseSelection without the sentinel's text in the message.
type phaseSelectionError struct{ msg string }

func (e phaseSelectionError) Error() string        { return e.msg }
func (e phaseSelectionError) Is(target error) bool { return target == ErrPhaseSelection }

func phaseSelectionErrorf(format string, args ...any) error {
	return phaseSelectionError{msg: fmt.Sprintf(format, args...)}
}

// ApplyNativePhaseSelection resolves --only / --skip onto opts. setExtensions
// is how the caller's settings learn the extension decision: called with true
// when --only lists extension, false on --skip extension. It may be nil.
func ApplyNativePhaseSelection(opts *types.Options, setExtensions func(enabled bool)) error {
	if opts.OnlyPhase != "" && len(opts.SkipPhases) > 0 {
		return phaseSelectionErrorf("--only and --skip are mutually exclusive; use one or the other")
	}

	for i := range opts.SkipPhases {
		opts.SkipPhases[i] = NormalizeNativePhase(opts.SkipPhases[i])
	}

	if opts.OnlyPhase != "" {
		allowed, normalized, err := parseOnlyPhases(opts.OnlyPhase)
		if err != nil {
			return err
		}
		opts.OnlyPhase = strings.Join(normalized, ",")
		if err := validateOnlyRespider(allowed); err != nil {
			return err
		}

		opts.DiscoverEnabled = allowed["discovery"]
		opts.ExternalHarvestEnabled = allowed["external-harvest"]
		opts.SpideringEnabled = allowed["spidering"]
		opts.KnownIssueScanEnabled = allowed["known-issue-scan"]
		opts.ProbeEnabled = allowed["probe"]
		opts.FingerprintEnabled = allowed["fingerprint"]
		// "probe" is its own ingestion: it reads the CLI target list directly and
		// writes a record per target. Without this arm, --only probe would also
		// enable the discovery/ingestion phase (SkipIngestion is false unless BOTH
		// are absent) and every target would be fetched a second time.
		opts.SkipIngestion = !allowed["discovery"] && !allowed["ingestion"]
		opts.SkipDynamicAssessment = !allowed["dynamic-assessment"] && !allowed["extension"]
		if allowed["extension"] {
			// "extension" alone narrows dynamic-assessment to extension modules;
			// alongside "dynamic-assessment" it ADDS extensions to the built-ins.
			opts.ExtensionsOnly = !allowed["dynamic-assessment"]
			if setExtensions != nil {
				setExtensions(true)
			}
		}
		// The alternate-port sweep runs only when --only asked for it by name;
		// otherwise `--only dast --intensity deep` would still sweep ports.
		opts.SkipPortSweep = !allowed["port-sweep"]
		if allowed["heuristics-check"] {
			if opts.HeuristicsCheck == "" || opts.HeuristicsCheck == "none" {
				opts.HeuristicsCheck = "basic"
			}
		} else {
			opts.HeuristicsCheck = "none"
		}
		noteOnlySelection(opts, allowed)
	}

	applyProbeOnlyDefaults(opts)

	if len(opts.SkipPhases) > 0 {
		for _, phase := range opts.SkipPhases {
			if IsSkippablePhaseSpelling(phase) {
				opts.NotePhaseDisabled(phase, "skip")
			}
			switch phase {
			case "discovery", "ingestion":
				opts.SkipIngestion = true
				// Keep DiscoverEnabled in sync with the skip (mirrors the
				// --only path) so the config panel and downstream gates don't
				// still report discovery as active.
				opts.DiscoverEnabled = false
			case "external-harvest":
				opts.ExternalHarvestEnabled = false
			case "spidering":
				opts.SpideringEnabled = false
			case "probe":
				opts.ProbeEnabled = false
			case "fingerprint":
				opts.FingerprintEnabled = false
			case "known-issue-scan":
				opts.KnownIssueScanEnabled = false
			case "dynamic-assessment":
				opts.SkipDynamicAssessment = true
			case "extension":
				opts.ExtensionsOnly = false
				if setExtensions != nil {
					setExtensions(false)
				}
			case "heuristics-check":
				opts.HeuristicsCheck = "none"
			case "port-sweep":
				opts.SkipPortSweep = true
			case "harvest-probe":
				// Read off SkipPhases by gateHarvestProbe; nothing to set here.
			case "targeted-respider":
				opts.SkipTargetedRespider = true
			case "param-mining":
				// Read off SkipPhases by paramMiningEnabled; nothing to set here.
			case "preflight":
				opts.SkipPreflight = true
			default:
				return phaseSelectionErrorf("invalid --skip value %q; valid phases: %s", phase, ValidSkipPhasesDesc)
			}
		}
	}

	return nil
}

// validateOnlyRespider refuses an --only list that names targeted-respider
// without the phases it re-crawls after: spidering (whose crawl it extends, and
// whose having run is what allows a browser) and discovery or ingestion (whose
// records are its candidates). Refused up front rather than accepted and then
// silently skipped by the phase's runtime gate.
func validateOnlyRespider(allowed map[string]bool) error {
	if !allowed[string(PhaseTargetedReSpider)] {
		return nil
	}
	if allowed["spidering"] && (allowed["discovery"] || allowed["ingestion"]) {
		return nil
	}
	return phaseSelectionErrorf("--only targeted-respider re-crawls what discovery found after spidering; " +
		"list them with it: --only discovery,spidering,targeted-respider")
}

// noteOnlySelection records, for the scan plan, every --only-nameable phase
// the --only list left out (and clears any earlier record for the ones it
// names). The phases riding on others (harvest-probe, param-mining, …) are
// gated, not selected, so they are left to the plan to explain.
func noteOnlySelection(opts *types.Options, allowed map[string]bool) {
	for _, p := range nativePhaseVocabulary {
		if !p.onlyAccepted() {
			continue
		}
		id := p.Canonical
		on := allowed[id]
		switch id {
		case string(PhaseTargetedReSpider):
			// Named, it is selected; unnamed, it still rides on spidering,
			// discovery and an assessment (the plan's gate), so --only leaving
			// it out says nothing.
			if !on {
				continue
			}
		case "discovery":
			on = allowed["discovery"] || allowed["ingestion"]
		case "dynamic-assessment":
			on = allowed["dynamic-assessment"] || allowed["extension"]
		}
		if on {
			opts.NotePhaseEnabled(id)
		} else {
			opts.NotePhaseDisabled(id, "only")
		}
	}
}

// IsProbeOnlyRun reports whether this invocation is a standalone host sweep:
// `vigolium run probe`, `scan --only probe`, or REST {"only":"probe"}.
//
// The probe's own defaults apply only here. When the phase rides along inside a
// full scan, the scan's redirect and recording policy governs — silently
// swapping it out from under the other phases would be a surprise.
func IsProbeOnlyRun(opts *types.Options) bool {
	if opts == nil || !opts.ProbeEnabled {
		return false
	}
	only := OnlyPhaseSet(opts.OnlyPhase)
	return len(only) == 1 && only[string(PhaseProbe)]
}

// applyProbeOnlyDefaults gives a standalone host sweep the policy it wants.
//
// It lives HERE, inside ApplyNativePhaseSelection, because that is the one seam
// the CLI (pkg/cli/scan.go), the REST API (pkg/server/handlers_scan.go) and the
// programmatic launcher (internal/runner/launch.go) all pass through. Resolving
// it in the CLI instead — which is where it started — meant
// `POST /api/scan {"only":"probe"}` ran the same phase with a different redirect
// policy, no hop recording and the general-purpose transport: the same phase
// name doing materially different things depending on how it was started.
//
// Every default is applied only when the field is still unset, so an operator
// who asked for something else keeps it.
func applyProbeOnlyDefaults(opts *types.Options) {
	if !IsProbeOnlyRun(opts) {
		return
	}
	// A sweep is mostly redirects, and a chain collapsed into a single row is
	// the one thing that makes the output wrong rather than merely thin: the row
	// would carry the original URL against the final hop's body.
	if !opts.RecordRedirectChainSet {
		opts.RecordRedirectChain = true
	}
	// A host list is full of apex -> www and http -> https hops that are the
	// same application, while a hop to a different registrable domain is a
	// different party whose pages would otherwise be attributed to the target
	// that pointed at them.
	if opts.RedirectMode == "" {
		opts.RedirectMode = http.RedirectModeSameApex
	}
	// Retune the connection pool for many-hosts-one-request-each. Safe to set on
	// the shared options precisely BECAUSE this is a probe-only run: no other
	// phase will use this requester, so there is no active transport being
	// mutated out from under anyone and no second pool to pay for.
	if opts.TransportProfile == "" {
		opts.TransportProfile = http.TransportProfileSweep
	}
	// Proactive CDN/WAF-edge pacing is for a phase that is about to burst one
	// host with hundreds of requests. A sweep sends ONE request per host, so
	// there is no burst to pre-empt and nothing the throttle can protect — while
	// the costs are all still paid: PreArm flips the limiter's anyArmed flag, so
	// the first edge-fronted host switches adaptive feedback on for every host in
	// the run, and each one prints a "pacing per-host concurrency 40->10" notice
	// that is pure noise across thousands of targets. PreArmable() also gates the
	// per-response edge fingerprint, so turning this off removes that work too.
	//
	// Reactive back-off after an actual WAF block is untouched and still applies.
	if !opts.NoWafPacingSet {
		opts.NoWafPacing = true
	}
}
