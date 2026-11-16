package config

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/types"
)

// ScanningPaceConfig provides centralized speed control parameters.
// Common values serve as a baseline for all phases; per-phase subsections
// override specific values. CLI flags still take higher precedence.
type ScanningPaceConfig struct {
	Concurrency int    `yaml:"concurrency"`
	RateLimit   int    `yaml:"rate_limit"`
	MaxPerHost  int    `yaml:"max_per_host"`
	MaxDuration string `yaml:"max_duration"`

	// AdaptivePerHost enables AIMD per-host concurrency control: each host starts
	// at MaxPerHost and backs off (halving, bounded by MinPerHost) on distress
	// signals (429/503/502/504, connection error, timeout), recovering toward the
	// ceiling as healthy responses accrue. Off by default — a healthy scan then
	// behaves exactly like the static MaxPerHost semaphore.
	AdaptivePerHost bool `yaml:"adaptive_per_host"`
	// MinPerHost is the adaptive back-off floor (0 = auto: max(1, MaxPerHost/10)).
	MinPerHost int `yaml:"min_per_host"`
	// MaxPerHostCeiling is the adaptive ramp ceiling. 0 means "pick by mode": with
	// adaptive_per_host on it defaults to 2x MaxPerHost so a healthy host can
	// actually ramp, and with only the WAF auto-arm throttle active it stays at
	// MaxPerHost (a host recovering from a block returns to the configured
	// concurrency, never past it). Set explicitly to pin either mode.
	MaxPerHostCeiling int `yaml:"max_per_host_ceiling"`

	// MaxRequests caps the wire attempts the whole scan may send (0 =
	// unlimited); MaxRequestsPerHost caps them per target host. Enforced by the
	// egress gate: exactly for gated traffic, within one watcher interval for
	// the browser crawl. --max-requests / --max-requests-per-host win.
	MaxRequests        int64 `yaml:"max_requests"`
	MaxRequestsPerHost int64 `yaml:"max_requests_per_host"`

	// ScanMaxDuration bounds the WHOLE scan's wall clock when --max-time is
	// not typed (default 1h; "0" = unlimited). Unlike max_duration it does not
	// rescale the per-phase budgets: it is the cap they share.
	ScanMaxDuration string `yaml:"scan_max_duration,omitempty"`
	// Reserve keeps a share of the scan's total time budget
	// (--scanning-max-duration) for later phases: a phase's deadline is capped
	// so the sum of the reserves of the phases the run plans after it stays
	// unspent. A phase the run does not plan (`--only discovery,spidering`
	// plans no assessment) reserves nothing. Keys are phase ids
	// with "_" or "-" (dynamic_assessment, known_issue_scan); values 0..1.
	// Only applies when the scan has a total budget.
	Reserve map[string]float64 `yaml:"reserve,omitempty"`

	Discovery         PhasePace `yaml:"discovery"`
	Probe             PhasePace `yaml:"probe"`
	Spidering         PhasePace `yaml:"spidering"`
	KnownIssueScan    PhasePace `yaml:"known_issue_scan"`
	ExternalHarvester PhasePace `yaml:"external_harvester"`
	DynamicAssessment PhasePace `yaml:"dynamic-assessment"`
}

// PhasePace holds per-phase speed overrides.
// Zero values mean "not set" and fall through to common or built-in defaults.
type PhasePace struct {
	Concurrency          int     `yaml:"concurrency"`
	RateLimit            int     `yaml:"rate_limit"`
	MaxPerHost           int     `yaml:"max_per_host"`
	MaxDuration          string  `yaml:"max_duration"`
	ConcurrencyFactor    float64 `yaml:"concurrency_factor"`
	DurationFactor       float64 `yaml:"duration_factor"`
	ParallelPassive      *bool   `yaml:"parallel_passive,omitempty"`
	FeedbackDrainTimeout string  `yaml:"feedback_drain_timeout,omitempty"`
	ActiveModuleTimeout  string  `yaml:"active_module_timeout,omitempty"`
	// RequestShare caps the phase at this share (0..1] of the --max-requests
	// budget still unspent when it starts. 0 = the phase default
	// (discovery: 0.4, others: uncapped); 1 = uncapped.
	RequestShare float64 `yaml:"request_share,omitempty"`
}

// PaceSource says where a resolved value came from.
type PaceSource string

// Provenance of ResolvedPhasePace.MaxDuration.
const (
	// PaceSourceUnset: neither the phase nor the common section set a duration.
	PaceSourceUnset PaceSource = ""
	// PaceSourcePhase: the phase's own max_duration.
	PaceSourcePhase PaceSource = "phase"
	// PaceSourceFactor: the common max_duration × the phase's duration_factor
	// (also the source when --scanning-max-duration seeded the common value).
	PaceSourceFactor PaceSource = "factor"
	// PaceSourceCommon: the common max_duration, unscaled.
	PaceSourceCommon PaceSource = "common"
)

// ResolvedPhasePace is the result of merging common + per-phase values.
type ResolvedPhasePace struct {
	Concurrency          int
	RateLimit            int
	MaxPerHost           int
	MaxDuration          time.Duration
	ConcurrencyFactor    float64
	DurationFactor       float64
	ParallelPassive      bool
	FeedbackDrainTimeout time.Duration
	ActiveModuleTimeout  time.Duration

	// Source is where MaxDuration came from. A derived (factor) budget may be
	// adjusted by its consumer (the spidering floor, SpideringBudget); an
	// explicit one never is.
	Source PaceSource
}

// DefaultScanningPaceConfig returns default scanning pace configuration
// matching the values shown in the example YAML config.
func DefaultScanningPaceConfig() *ScanningPaceConfig {
	return &ScanningPaceConfig{
		Concurrency: types.DefaultConcurrency,
		RateLimit:   100,
		MaxPerHost:  types.DefaultMaxPerHost,
		MaxDuration: "45m",

		ScanMaxDuration: DefaultScanMaxDuration,

		Reserve:           map[string]float64{"dynamic_assessment": 0.5, "known_issue_scan": 0.1},
		Discovery:         PhasePace{DurationFactor: 0.5},
		KnownIssueScan:    PhasePace{DurationFactor: 0.5},
		Spidering:         PhasePace{DurationFactor: 0.1},
		ExternalHarvester: PhasePace{DurationFactor: 0.1},
		DynamicAssessment: PhasePace{DurationFactor: 1.0, ParallelPassive: boolPtr(true), FeedbackDrainTimeout: "500ms"},
	}
}

// DefaultScanMaxDuration is the total scan budget when neither --max-time nor
// scanning_pace.scan_max_duration says otherwise.
const DefaultScanMaxDuration = "1h"

// ScanMaxDurationParsed parses scan_max_duration (0 when unset, "0" or bad).
func (c *ScanningPaceConfig) ScanMaxDurationParsed() time.Duration {
	if c == nil || c.ScanMaxDuration == "" {
		return 0
	}
	d, err := time.ParseDuration(c.ScanMaxDuration)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// maxDurationParsed parses the common max_duration string into a time.Duration.
// Returns 0 if unset or unparseable.
func (c *ScanningPaceConfig) maxDurationParsed() time.Duration {
	if c.MaxDuration == "" {
		return 0
	}
	d, err := time.ParseDuration(c.MaxDuration)
	if err != nil {
		return 0
	}
	return d
}

// MaxDurationParsed parses the max_duration string into a time.Duration.
// Returns 0 if unset or unparseable.
func (p *PhasePace) MaxDurationParsed() time.Duration {
	if p.MaxDuration == "" {
		return 0
	}
	d, err := time.ParseDuration(p.MaxDuration)
	if err != nil {
		return 0
	}
	return d
}

// Section returns the per-phase pace slot for a canonical phase id, or nil when
// the phase has none.
//
// It is the ONE place the phase→section vocabulary lives. It used to be spelled
// out in ResolvePhase and again in Validate, and a third copy in the CLI
// promptly disagreed with both — it said "external-harvest" where these said
// "external_harvester", so a per-phase override for that phase was written to
// the struct and then never read back. Both spellings are accepted here for
// exactly that reason: `external_harvester` is the YAML key operators already
// have in their config files, and `external-harvest` is the canonical phase id
// every other surface (--only/--skip, `run <phase>`, the event stream) uses.
func (c *ScanningPaceConfig) Section(phase string) *PhasePace {
	switch phase {
	case "discovery":
		return &c.Discovery
	case "probe":
		return &c.Probe
	case "spidering":
		return &c.Spidering
	case "known-issue-scan":
		return &c.KnownIssueScan
	case "external-harvest", "external_harvester":
		return &c.ExternalHarvester
	case "dynamic-assessment":
		return &c.DynamicAssessment
	default:
		return nil
	}
}

// paceSectionNames are the canonical phase ids Section resolves. Only canonical
// spellings belong here: `external_harvester` is accepted by Section as a
// legacy YAML key, but advertising it would offer operators a second spelling
// for a phase that already has one.
//
// This list and Section's switch are the one coupling in this file, and
// TestPhaseSectionNamesMatchSection holds them together — the comment here used
// to claim the list "derives from Section itself", which it never did, and a
// claim like that is exactly how a phase gets added to one and not the other.
var paceSectionNames = []string{
	"discovery", "probe", "spidering", "known-issue-scan",
	"external-harvest", "dynamic-assessment",
}

// PhaseSectionNames lists the canonical phase ids Section accepts, sorted.
func PhaseSectionNames() []string {
	names := append([]string(nil), paceSectionNames...)
	sort.Strings(names)
	return names
}

// phasePaceSupport states which pace fields each phase actually ENFORCES.
//
// It exists because a pace section accepts all three dials for every phase while
// most phases read only one of them. `--rate-limit spidering=5` parsed, was
// written into the config, appeared in the phase header and in the scan.started
// pace table, and changed nothing: the spidering phase has no limiter to put it
// in. A number presented as effective and silently ignored is worse than no knob
// at all, so display, flag validation and the pace table all read this one table.
//
// Honest as of improvement-2 WP11. Flipping an entry to true is part of the
// change that makes it true, never a separate bookkeeping step.
var phasePaceSupport = map[string]struct{ Concurrency, RateLimit, MaxPerHost bool }{
	// Deparos engine threads, and one token bucket shared by every concurrent
	// discovery target (through the scan's egress gate), so the rate is
	// phase-wide. Host slots are the scan's shared ones, not a section value.
	"discovery": {Concurrency: true, RateLimit: true},
	// The crawler is a single browser with no limiter fields at all.
	"spidering": {},
	// probePaceInfra builds a phase-local requester for all three.
	"probe": {Concurrency: true, RateLimit: true, MaxPerHost: true},
	// Workers only: the limiter and host semaphore are scan-wide.
	"dynamic-assessment": {Concurrency: true},
	// Nuclei owns its own HTTP stack and takes both.
	"known-issue-scan": {Concurrency: true, RateLimit: true},
	// Request-only: harvested URLs are stored, never fetched from the target,
	// so no target-facing dial applies (the archive queries are bounded by the
	// phase's max_duration alone).
	"external-harvest": {},
}

// Pace field names, as they appear in warnings and in the support table.
const (
	PaceFieldConcurrency = "concurrency"
	PaceFieldRateLimit   = "rate_limit"
	PaceFieldMaxPerHost  = "max_per_host"
)

// DiscoveryRateLimit resolves the requests-per-second ceiling the discovery
// engine will enforce. 0 means unpaced.
//
// Only an EXPLICIT setting counts: `scanning_pace.discovery.rate_limit`, or a
// typed `--rate-limit` on the command line. It deliberately does NOT fall through
// to the resolved global rate the way every other pace field does, because that
// rate carries a 100 rps default — discovery has never been paced, and adopting
// that default would quietly change the speed of every scan that merely loaded a
// config file (triage C13).
//
// The section value wins over the global flag: it is the more specific statement,
// and it is the form `--rate-limit discovery=N` writes. It lives here rather than
// in the runner so the number the banner and the scan.started pace table print is
// the number buildDeparosConfig hands the engine.
//
// Nil-safe on both arguments.
//
// VIGOLIUM_RATE_CEILING caps the answer, and turns "unpaced" into the ceiling.
func (c *ScanningPaceConfig) DiscoveryRateLimit(opts *types.Options) int {
	return CeilIntRate("discovery rate_limit", c.discoveryRateLimit(opts))
}

func (c *ScanningPaceConfig) discoveryRateLimit(opts *types.Options) int {
	if c != nil && c.Discovery.RateLimit > 0 {
		return c.Discovery.RateLimit
	}
	if opts != nil && opts.RateLimitExplicitlySet && opts.RateLimit > 0 {
		return opts.RateLimit
	}
	return 0
}

// KnownIssueScanDefaultRateLimit is the known-issue scan's unattended rate
// (requests/second): nuclei runs its own HTTP stack outside the egress gate
// and does not back off, so it opens conservatively. Mirrors
// knownissuescan.defaultRateLimit (a test holds them together).
const KnownIssueScanDefaultRateLimit = 20

// KnownIssueScanRateLimit resolves the rate the known-issue scan runs at, with
// the same explicit-only rule as DiscoveryRateLimit: the phase section's
// rate_limit, else a typed --rate-limit, else KnownIssueScanDefaultRateLimit.
// It does not inherit the global 100 rps default — that default always beat
// the phase's own 20 rps, which made the conservative default dead code.
//
// Nil-safe on both arguments.
//
// VIGOLIUM_RATE_CEILING caps the answer.
func (c *ScanningPaceConfig) KnownIssueScanRateLimit(opts *types.Options) int {
	return CeilIntRate("known-issue-scan rate_limit", c.knownIssueScanRateLimit(opts))
}

func (c *ScanningPaceConfig) knownIssueScanRateLimit(opts *types.Options) int {
	if c != nil && c.KnownIssueScan.RateLimit > 0 {
		return c.KnownIssueScan.RateLimit
	}
	if opts != nil && opts.RateLimitExplicitlySet && opts.RateLimit > 0 {
		return opts.RateLimit
	}
	return KnownIssueScanDefaultRateLimit
}

// PhasePaceSupports reports whether phase actually enforces the named pace field.
// An unknown phase or field reports false — the fail-closed direction, since the
// consequence is a warning or an omitted table entry rather than a changed scan.
func PhasePaceSupports(phase, field string) bool {
	support, ok := phasePaceSupport[phase]
	if !ok {
		return false
	}
	switch field {
	case PaceFieldConcurrency:
		return support.Concurrency
	case PaceFieldRateLimit:
		return support.RateLimit
	case PaceFieldMaxPerHost:
		return support.MaxPerHost
	default:
		return false
	}
}

// ResolvePhase merges common values with per-phase overrides for the named phase.
// Non-zero per-phase values win over common values. VIGOLIUM_RATE_CEILING caps
// the three dials of the result (a concurrency_factor above 1 included).
func (c *ScanningPaceConfig) ResolvePhase(phase string) ResolvedPhasePace {
	resolved := c.resolvePhase(phase)
	if ceil := ActiveRateCeiling(); ceil.Set() {
		resolved.RateLimit = ceilPhaseDial(ceil, phase, PaceFieldRateLimit, resolved.RateLimit)
		resolved.Concurrency = ceilPhaseDial(ceil, phase, PaceFieldConcurrency, resolved.Concurrency)
		resolved.MaxPerHost = ceilPhaseDial(ceil, phase, PaceFieldMaxPerHost, resolved.MaxPerHost)
	}
	return resolved
}

// ceilPhaseDial clamps one resolved phase dial. The clamp is reported only for
// a dial the phase enforces: lowering a number the phase never applies (the
// crawler's rate) changes nothing a reader needs told.
func ceilPhaseDial(c RateCeiling, phase, field string, v int) int {
	out := c.IntRate(v)
	if out != v && PhasePaceSupports(phase, field) {
		noteRateClamp(c, phase+" "+field, float64(v), float64(out))
	}
	return out
}

func (c *ScanningPaceConfig) resolvePhase(phase string) ResolvedPhasePace {
	var pp PhasePace
	if section := c.Section(phase); section != nil {
		pp = *section
	}

	resolved := ResolvedPhasePace{
		Concurrency: c.Concurrency,
		RateLimit:   c.RateLimit,
		MaxPerHost:  c.MaxPerHost,
	}

	// Concurrency: explicit per-phase > factor × common > common
	if pp.Concurrency > 0 {
		resolved.Concurrency = pp.Concurrency
	} else if pp.ConcurrencyFactor > 0 && c.Concurrency > 0 {
		resolved.Concurrency = int(math.Round(float64(c.Concurrency) * pp.ConcurrencyFactor))
		resolved.ConcurrencyFactor = pp.ConcurrencyFactor
	}

	if pp.RateLimit > 0 {
		resolved.RateLimit = pp.RateLimit
	}
	if pp.MaxPerHost > 0 {
		resolved.MaxPerHost = pp.MaxPerHost
	}

	// MaxDuration: explicit per-phase > factor × common > common
	commonDuration := c.maxDurationParsed()
	if pp.MaxDuration != "" {
		resolved.MaxDuration = pp.MaxDurationParsed()
		resolved.Source = PaceSourcePhase
	} else if pp.DurationFactor > 0 && commonDuration > 0 {
		resolved.MaxDuration = time.Duration(float64(commonDuration) * pp.DurationFactor)
		resolved.DurationFactor = pp.DurationFactor
		resolved.Source = PaceSourceFactor
	} else {
		resolved.MaxDuration = commonDuration
		if commonDuration > 0 {
			resolved.Source = PaceSourceCommon
		}
	}

	// ParallelPassive: an explicit per-phase value wins; otherwise the built-in
	// per-phase default, which is on for dynamic-assessment (the only phase that
	// runs passive modules at volume) and off elsewhere. The default lives here,
	// not only in DefaultScanningPaceConfig, so a pace config that never went
	// through the defaults (a zero Settings, a config file without the section)
	// still gets it.
	resolved.ParallelPassive = defaultParallelPassive(phase)
	if pp.ParallelPassive != nil {
		resolved.ParallelPassive = *pp.ParallelPassive
	}

	// FeedbackDrainTimeout: per-phase overrides common default (0 = executor default)
	if pp.FeedbackDrainTimeout != "" {
		if d, err := time.ParseDuration(pp.FeedbackDrainTimeout); err == nil {
			resolved.FeedbackDrainTimeout = d
		}
	}

	// ActiveModuleTimeout: per-phase overrides common default (0 = executor default)
	if pp.ActiveModuleTimeout != "" {
		if d, err := time.ParseDuration(pp.ActiveModuleTimeout); err == nil {
			resolved.ActiveModuleTimeout = d
		}
	}

	return resolved
}

// defaultParallelPassive is the built-in parallel_passive for phase when its
// pace section does not set one.
func defaultParallelPassive(phase string) bool {
	return phase == "dynamic-assessment"
}

// boolPtr returns a pointer to a bool value. Used for optional YAML fields.
func boolPtr(b bool) *bool { return &b }

// validateNonNegDuration parses a duration setting and rejects negative values.
//
// Parsing alone was not enough: "-5m" is a perfectly valid time.Duration, so a
// negative budget passed validation and then flowed into context.WithTimeout as
// an already-expired deadline. The phase it governed did nothing and reported no
// error. An empty string means "unset" and is always accepted; what a zero means
// is per-setting and is decided by the consumer, not here.
func validateNonNegDuration(field, s string) error {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%s: invalid duration %q: %w", field, s, err)
	}
	if d < 0 {
		return fmt.Errorf("%s: duration must not be negative, got %q", field, s)
	}
	return nil
}

// Validate rejects negative values and invalid duration strings.
func (c *ScanningPaceConfig) Validate() error {
	if c.Concurrency < 0 {
		return fmt.Errorf("scanning_pace.concurrency must be >= 0")
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("scanning_pace.rate_limit must be >= 0")
	}
	if c.MaxPerHost < 0 {
		return fmt.Errorf("scanning_pace.max_per_host must be >= 0")
	}
	if c.MaxRequests < 0 {
		return fmt.Errorf("scanning_pace.max_requests must be >= 0")
	}
	if c.MaxRequestsPerHost < 0 {
		return fmt.Errorf("scanning_pace.max_requests_per_host must be >= 0")
	}
	if err := validateNonNegDuration("scanning_pace.max_duration", c.MaxDuration); err != nil {
		return err
	}

	for _, name := range PhaseSectionNames() {
		pp := c.Section(name)
		if pp.Concurrency < 0 {
			return fmt.Errorf("scanning_pace.%s.concurrency must be >= 0", name)
		}
		if pp.RateLimit < 0 {
			return fmt.Errorf("scanning_pace.%s.rate_limit must be >= 0", name)
		}
		if pp.MaxPerHost < 0 {
			return fmt.Errorf("scanning_pace.%s.max_per_host must be >= 0", name)
		}
		if err := validateNonNegDuration(fmt.Sprintf("scanning_pace.%s.max_duration", name), pp.MaxDuration); err != nil {
			return err
		}
		if pp.ConcurrencyFactor < 0 {
			return fmt.Errorf("scanning_pace.%s.concurrency_factor must be >= 0", name)
		}
		if pp.DurationFactor < 0 {
			return fmt.Errorf("scanning_pace.%s.duration_factor must be >= 0", name)
		}
		if err := validateNonNegDuration(fmt.Sprintf("scanning_pace.%s.feedback_drain_timeout", name), pp.FeedbackDrainTimeout); err != nil {
			return err
		}
		if err := validateNonNegDuration(fmt.Sprintf("scanning_pace.%s.active_module_timeout", name), pp.ActiveModuleTimeout); err != nil {
			return err
		}
	}

	return nil
}

// DefaultDiscoveryRequestShare is discovery's default share of --max-requests.
const DefaultDiscoveryRequestShare = 0.4

// ReserveFraction returns the configured reserve for phase (dash or underscore
// spelling), 0 when unset or out of range.
func (c *ScanningPaceConfig) ReserveFraction(phase string) float64 {
	if c == nil || len(c.Reserve) == 0 {
		return 0
	}
	key := strings.ReplaceAll(strings.ToLower(phase), "-", "_")
	for k, v := range c.Reserve {
		if strings.ReplaceAll(strings.ToLower(k), "-", "_") == key && v > 0 && v < 1 {
			return v
		}
	}
	return 0
}
