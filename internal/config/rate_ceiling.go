package config

import (
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// VIGOLIUM_RATE_CEILING is a process-wide upper bound, in requests per second,
// on every rate this binary sends at. A driver that owns the operator's rules
// of engagement (gimorra sets it from the RoE's maxRps) exports it once, and no
// flag, config file, strategy, profile or built-in default can take a command
// above it:
//
//   - a rate dial (--rate-limit/-r on the scan family, `fuzz -r`, `kit
//     param-mine --rate-limit`, `finding verify --rate-limit`, every
//     scanning_pace rate) is lowered to the ceiling, and an unlimited one (0)
//     becomes the ceiling;
//   - a count dial (--concurrency, --max-per-host, and the adaptive per-host
//     ramp) is lowered to the ceiling as a whole number: more requests in
//     flight than requests allowed per second is not a pace the ceiling admits.
//
// A value at or below the ceiling is left alone. Every lowered dial is
// reported once per process on stderr and kept in RateClamps, which the scan
// runner turns into a `rate_ceiling` phase note (a scan.finished caveat).
//
// Whole-number dials hold floor(ceiling), at least 1: a ceiling below one
// request per second is exact on the fractional dials (`fuzz -r`, `finding
// verify --rate-limit`) and 1 on the others, which the stderr notice states.

// RateCeilingEnv names the variable.
const RateCeilingEnv = "VIGOLIUM_RATE_CEILING"

// RateCeiling is a parsed VIGOLIUM_RATE_CEILING; the zero value is "no ceiling".
type RateCeiling float64

// ParseRateCeiling reads a variable value. Blank is no ceiling; anything else
// must be a finite number above zero. A misspelled safety ceiling is an error,
// never "no ceiling" — reading it as unset would send at full speed while the
// operator believes a cap is in force.
func ParseRateCeiling(raw string) (RateCeiling, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return 0, fmt.Errorf("%s=%q: want a number of requests per second above 0", RateCeilingEnv, raw)
	}
	return RateCeiling(v), nil
}

// ValidateRateCeilingEnv parses the variable from the environment, for the CLI
// to reject a bad value (exit 2) before any command runs.
func ValidateRateCeilingEnv() error {
	_, err := ParseRateCeiling(os.Getenv(RateCeilingEnv))
	return err
}

// ActiveRateCeiling is the ceiling the environment sets now. An unparseable
// value reads as no ceiling here; the CLI refuses to start with one
// (ValidateRateCeilingEnv), so only a library caller can reach that case.
func ActiveRateCeiling() RateCeiling {
	c, err := ParseRateCeiling(os.Getenv(RateCeilingEnv))
	if err != nil {
		return 0
	}
	return c
}

// Set reports whether a ceiling is in force.
func (c RateCeiling) Set() bool { return c > 0 }

// wholeCap is the ceiling as a whole-number dial value: floor, at least 1.
func (c RateCeiling) wholeCap() int {
	return max(1, int(math.Floor(float64(c))))
}

// Rate clamps a fractional requests-per-second dial (0 or less = unlimited).
func (c RateCeiling) Rate(v float64) float64 {
	if !c.Set() {
		return v
	}
	if v <= 0 || v > float64(c) {
		return float64(c)
	}
	return v
}

// IntRate clamps a whole-number dial: a requests-per-second rate (0 or less =
// unlimited) or a concurrency/per-host count (0 or less = "the default",
// clamped too: every default it falls back to is above 1).
func (c RateCeiling) IntRate(v int) int {
	if !c.Set() {
		return v
	}
	if limit := c.wholeCap(); v <= 0 || v > limit {
		return limit
	}
	return v
}

// RateClamp is one dial the ceiling lowered.
type RateClamp struct {
	// Dial names the knob ("--rate-limit", "fuzz --rate-limit",
	// "known-issue-scan rate_limit").
	Dial string `json:"dial"`
	// From is the value the dial would have used (0 = unlimited or default).
	From float64 `json:"from"`
	// To is the value it runs at.
	To float64 `json:"to"`
}

var rateClamps struct {
	sync.Mutex
	seen map[string]bool
	list []RateClamp
	// out receives the one-line notices; nil means os.Stderr.
	out io.Writer
}

// noteRateClamp records a lowered dial and prints its notice the first time
// that dial is lowered in this process.
func noteRateClamp(c RateCeiling, dial string, from, to float64) {
	rateClamps.Lock()
	defer rateClamps.Unlock()
	if rateClamps.seen[dial] {
		return
	}
	if rateClamps.seen == nil {
		rateClamps.seen = map[string]bool{}
	}
	rateClamps.seen[dial] = true
	rateClamps.list = append(rateClamps.list, RateClamp{Dial: dial, From: from, To: to})
	out := rateClamps.out
	if out == nil {
		out = os.Stderr
	}
	fromText := formatRate(from)
	if from <= 0 {
		fromText = "unlimited/default"
	}
	line := fmt.Sprintf("%s %s=%s: %s lowered from %s to %s", terminal.WarnPrefix(), RateCeilingEnv,
		formatRate(float64(c)), dial, fromText, formatRate(to))
	if float64(c) < 1 && to == 1 && float64(c) != to {
		line += " (a whole-number dial cannot go below 1)"
	}
	_, _ = fmt.Fprintln(out, line)
}

func formatRate(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// RateClamps lists the dials the ceiling lowered in this process, in the order
// they were first lowered.
func RateClamps() []RateClamp {
	rateClamps.Lock()
	defer rateClamps.Unlock()
	return append([]RateClamp(nil), rateClamps.list...)
}

// CeilRate applies the active ceiling to a fractional rate dial and reports
// the clamp.
func CeilRate(dial string, v float64) float64 {
	c := ActiveRateCeiling()
	out := c.Rate(v)
	if out != v {
		noteRateClamp(c, dial, v, out)
	}
	return out
}

// CeilIntRate applies the active ceiling to a whole-number dial (a rate or a
// concurrency/per-host count, see IntRate) and reports the clamp.
func CeilIntRate(dial string, v int) int {
	c := ActiveRateCeiling()
	out := c.IntRate(v)
	if out != v {
		noteRateClamp(c, dial, float64(v), float64(out))
	}
	return out
}

// CeilOptionsPace clamps the three scan-wide dials on opts in place. Every
// entry point that builds a scan's Options runs it after the dials are final
// (the CLI's flag copy, ApplyScanPace, runner.New), so whichever source set a
// dial, the scan runs at most at the ceiling. Idempotent.
func CeilOptionsPace(opts *types.Options) {
	if opts == nil || !ActiveRateCeiling().Set() {
		return
	}
	opts.RateLimit = CeilIntRate("--rate-limit", opts.RateLimit)
	opts.Concurrency = CeilIntRate("--concurrency", opts.Concurrency)
	opts.MaxPerHost = CeilIntRate("--max-per-host", opts.MaxPerHost)
}

// CeilPace clamps the scanning_pace values in place: the common dials, the
// adaptive per-host ramp, and every phase section's non-zero dials (a zero
// section value inherits the clamped common one). The resolvers
// (ResolvePhase, DiscoveryRateLimit, KnownIssueScanRateLimit) clamp what they
// derive on top of this, so a factor or a built-in phase default cannot
// exceed the ceiling either.
func (c *ScanningPaceConfig) CeilPace() {
	if c == nil || !ActiveRateCeiling().Set() {
		return
	}
	c.RateLimit = CeilIntRate("scanning_pace.rate_limit", c.RateLimit)
	c.Concurrency = CeilIntRate("scanning_pace.concurrency", c.Concurrency)
	c.MaxPerHost = CeilIntRate("scanning_pace.max_per_host", c.MaxPerHost)
	// The adaptive ramp (default: twice MaxPerHost) may not climb past the
	// ceiling either. A zero ramp outside adaptive mode means "stay at
	// MaxPerHost", which is already clamped, so it is left as it is.
	if c.MaxPerHostCeiling > 0 || c.AdaptivePerHost {
		c.MaxPerHostCeiling = CeilIntRate("scanning_pace.max_per_host_ceiling", c.MaxPerHostCeiling)
	}
	for _, name := range PhaseSectionNames() {
		s := c.Section(name)
		if s.RateLimit > 0 {
			s.RateLimit = CeilIntRate(name+" rate_limit", s.RateLimit)
		}
		if s.Concurrency > 0 {
			s.Concurrency = CeilIntRate(name+" concurrency", s.Concurrency)
		}
		if s.MaxPerHost > 0 {
			s.MaxPerHost = CeilIntRate(name+" max_per_host", s.MaxPerHost)
		}
	}
}
