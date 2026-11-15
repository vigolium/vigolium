package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/types"
)

// The three pace knobs (--rate-limit, --concurrency, --max-per-host) used to be
// plain ints applied to the whole invocation. That is the wrong granularity for
// a run that mixes phases with different needs: `--only
// known-issue-scan,dynamic-assessment` cannot cap the nuclei phase — which has
// no self-pacing of its own — without also capping the ~200 native modules,
// which pace themselves and do not need it. There was no way to express "slow
// that one down", so every caller either slowed both or slowed neither.
//
// Each flag therefore accepts two forms, repeatable and freely mixed:
//
//	--rate-limit 50                     the invocation-wide value (unchanged)
//	--rate-limit known-issue-scan=20    that phase only
//
// Resolution per phase is phase-scoped value → global value → config/strategy
// default, which is the order a reader expects and the order ResolvePace applies.
//
// Phase names go through runner.NormalizeNativePhase, so the aliases already
// accepted by --only/--skip (kis, cve, deparos, dast, …) work here too — a
// qualifier that is valid on one flag and unknown on another is exactly the kind
// of surface a driver gets subtly wrong.

// pacePhases is the set of phases a qualifier may name — derived from the config
// struct's own section vocabulary, so it cannot drift from the sections the
// overrides are written into. A phase absent here is rejected by name rather
// than silently ignored, because a typo'd qualifier that parses is a cap the
// operator believes is in force and is not.
var pacePhases = func() map[string]bool {
	out := map[string]bool{}
	for _, name := range config.PhaseSectionNames() {
		out[name] = true
	}
	return out
}()

// paceKnob is one of the three speed dials, in both its global and per-phase
// forms. The zero value is not usable — build one with newPaceKnob.
type paceKnob struct {
	flagName string
	// global is the invocation-wide destination, shared with every existing
	// reader of the old int global. It always holds the value those readers
	// should use, so nothing downstream needs to learn about per-phase values it
	// does not care about.
	global *int
	// globalSet records that the bare form was typed. Distinct from pflag's
	// Changed, which is also true when only a qualified form was given.
	globalSet bool
	perPhase  map[string]int
}

// newPaceKnob seeds *global with def before returning. Seeding here (rather than
// in an init func) is load-bearing: pflag reads String() at registration to
// populate DefValue, and registration happens inside other files' init
// functions, which Go may run before this file's. A knob that seeded later would
// print "0" in --help for whichever command registered first.
func newPaceKnob(flagName string, global *int, def int) *paceKnob {
	*global = def
	return &paceKnob{flagName: flagName, global: global, perPhase: map[string]int{}}
}

// String renders the current global value. pflag reads this once at registration
// to populate DefValue (what `--help` prints), so it must reflect the default
// the caller seeded into *global.
func (p *paceKnob) String() string {
	if p == nil || p.global == nil {
		return "0"
	}
	return strconv.Itoa(*p.global)
}

func (p *paceKnob) Type() string { return "int|phase=int" }

// GetSlice / Replace / Append implement pflag.SliceValue.
//
// This is what makes the flag survive the -P/--parallel fan-out. childScanArgs
// re-emits each parent flag to its child processes and treats String() as a
// re-passable value; String() renders only the GLOBAL int, so without this a
// `--rate-limit known-issue-scan=20 -T targets.txt` would hand every child a
// bare `--rate-limit 100` and drop the phase cap for every target — the same
// fail-open direction the flag exists to close, on the path most likely to be
// pointed at many hosts. Implementing SliceValue lets childScanArgs's existing
// slice branch emit each occurrence, with no new special case.
func (p *paceKnob) GetSlice() []string {
	if p == nil {
		return nil
	}
	var out []string
	if p.globalSet {
		out = append(out, strconv.Itoa(*p.global))
	}
	for _, phase := range p.sortedPhases() {
		out = append(out, phase+"="+strconv.Itoa(p.perPhase[phase]))
	}
	return out
}

func (p *paceKnob) Replace(values []string) error {
	p.perPhase = map[string]int{}
	p.globalSet = false
	for _, v := range values {
		if err := p.Set(v); err != nil {
			return err
		}
	}
	return nil
}

func (p *paceKnob) Append(value string) error { return p.Set(value) }

// sortedPhases keeps GetSlice deterministic — a child's argv must not reorder
// between runs.
func (p *paceKnob) sortedPhases() []string {
	out := make([]string, 0, len(p.perPhase))
	for phase := range p.perPhase {
		out = append(out, phase)
	}
	sort.Strings(out)
	return out
}

// Set parses one occurrence. A bare integer sets the global; `phase=int` sets
// one phase.
func (p *paceKnob) Set(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fmt.Errorf("--%s: empty value", p.flagName)
	}

	phase := ""
	if i := strings.LastIndexByte(value, '='); i >= 0 {
		phase = strings.TrimSpace(value[:i])
		value = strings.TrimSpace(value[i+1:])
		if phase == "" {
			return fmt.Errorf("--%s %q: missing phase before '='", p.flagName, raw)
		}
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("--%s %q: %q is not an integer", p.flagName, raw, value)
	}
	// A negative pace is not "unlimited", it is a typo. Reading it as unlimited
	// turns a caller asking for restraint into one explicitly asking for none —
	// the fail-open direction on a safety knob.
	if n < 0 {
		return fmt.Errorf("--%s %q: must be >= 0 (0 means unlimited; negative values are not accepted)", p.flagName, raw)
	}

	if phase == "" {
		*p.global = n
		p.globalSet = true
		return nil
	}

	canonical := runner.NormalizeNativePhase(phase)
	if !pacePhases[canonical] {
		return fmt.Errorf("--%s %q: unknown phase %q; valid phases: %s",
			p.flagName, raw, phase, strings.Join(pacePhaseNames(), ", "))
	}
	p.perPhase[canonical] = n
	return nil
}

// pacePhaseNames lists the accepted qualifiers, sorted, for error messages.
func pacePhaseNames() []string {
	names := make([]string, 0, len(pacePhases))
	for name := range pacePhases {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// forPhase returns the per-phase override for a canonical phase name.
func (p *paceKnob) forPhase(phase string) (int, bool) {
	if p == nil {
		return 0, false
	}
	v, ok := p.perPhase[phase]
	return v, ok
}

// globalChanged reports whether the BARE form was typed.
//
// Distinct from pflag's Changed, which is also true when only a qualified form
// was given — and every "did the operator set this?" gate in the scan path
// reads that. Consulting Changed made `--concurrency known-issue-scan=5` look
// like an explicit global concurrency, which (a) skipped the --strategy lite
// ceiling and (b) made the runner refuse to read the very per-phase value that
// flag had just written. Callers must ask this, never Changed.
func (p *paceKnob) globalChanged() bool { return p != nil && p.globalSet }

// The three live knobs, created ONCE and registered on every command's flagset
// that wants them.
//
// One instance per flag, not one per registration: five commands
// (scan/run/ingest/scan-url/scan-request) register these, all at init, and only
// one of them ever executes. A per-registration instance would leave the package
// variable pointing at whichever command registered last, so the executing
// command's parsed per-phase map would be written into an object nothing reads —
// the same shape of bug as two closures racing for one normalization slot. A
// shared instance makes registration order irrelevant: only the command that
// actually runs calls Set.
var (
	concurrencyKnob = newPaceKnob("concurrency", &globalConcurrency, defaultConcurrency)
	rateLimitKnob   = newPaceKnob("rate-limit", &globalRateLimit, defaultRateLimit)
	maxPerHostKnob  = newPaceKnob("max-per-host", &globalMaxPerHost, defaultMaxPerHost)
)

// registerPaceFlags declares the three speed dials on flags. Replaces the plain
// IntVar registrations so both the bare and the phase-qualified forms parse.
func registerPaceFlags(flags *pflag.FlagSet) {
	flags.VarP(concurrencyKnob, "concurrency", "c",
		"Number of concurrent scan workers. Accepts a phase qualifier, repeatable: --concurrency discovery=10")
	flags.VarP(rateLimitKnob, "rate-limit", "r",
		"Global requests/second cap, applied to native scanning AND known-issue-scan. "+
			"Applies at its documented default even when unset; pass 0 for no cap. "+
			"Accepts a phase qualifier, repeatable: --rate-limit known-issue-scan=20")
	flags.Var(maxPerHostKnob, "max-per-host",
		"Maximum concurrent requests allowed per host. Accepts a phase qualifier, repeatable: --max-per-host spidering=4")
}

// Built-in defaults for the three dials, named so the help text, the applied
// value and the scan.started event cannot drift apart.
const (
	defaultConcurrency = types.DefaultConcurrency
	defaultRateLimit   = 100
	defaultMaxPerHost  = types.DefaultMaxPerHost
)

// Defaults of the speed dials on the commands outside the scan family, named
// here so one place says what each command sends at by default (the flag
// vocabulary test refuses a literal default on these flags).
const (
	// defaultSendConcurrency: fuzz, replay, traffic --replay and dns workers.
	defaultSendConcurrency = 10
	// defaultParamMineRateLimit: kit param-mine requests/second.
	defaultParamMineRateLimit = 20
	// unlimitedRate: a --rate-limit default of no cap (finding verify).
	unlimitedRate = 0
)
