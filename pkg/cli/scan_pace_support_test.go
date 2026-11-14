package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// swapGlobal sets a package global for the duration of a test and restores
// whatever was there before.
//
// Restores the PREVIOUS value, not the zero value. Several ad-hoc reset helpers
// in this package did the latter, which is correct only as long as every test
// that uses them runs under defaults — the moment one is called from a subtest
// inside an outer swap, resetting to zero silently rewrites the outer value
// instead of returning it.
func swapGlobal[T any](t *testing.T, p *T, v T) {
	t.Helper()
	prev := *p
	*p = v
	t.Cleanup(func() { *p = prev })
}

// captureStream runs fn with *stream redirected to a pipe and returns what was
// written to it. stream is the address of os.Stdout or os.Stderr.
//
// The reader drains concurrently rather than after fn returns, so output larger
// than the OS pipe buffer (64KiB on Linux) cannot deadlock the test — which a
// JSONL export of any size would.
func captureStream(t *testing.T, stream **os.File, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := *stream
	*stream = w
	defer func() { *stream = orig }()

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		done <- sb.String()
	}()

	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
// The warnings under test go to stderr by design — they must not pollute stdout,
// which carries the machine output contract.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	return captureStream(t, &os.Stderr, fn)
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote, so
// the stdout-streaming export branch can be asserted.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	return captureStream(t, &os.Stdout, fn)
}

// paceTestOptions builds options whose plan runs every paceable phase, so a
// qualifier is never dropped for the "phase does not run" reason instead of the
// "phase does not enforce it" reason under test.
func paceTestOptions() *types.Options {
	return &types.Options{
		Targets:                []string{"https://example.com"},
		DiscoverEnabled:        true,
		SpideringEnabled:       true,
		ProbeEnabled:           true,
		ExternalHarvestEnabled: true,
		KnownIssueScanEnabled:  true,
		Concurrency:            25,
		RateLimit:              100,
		MaxPerHost:             40,
	}
}

// withPaceKnob installs a per-phase override on one of the package-global knobs
// and removes it afterwards. The knobs are process state (pflag owns them), so a
// test that left one set would change every later test's warnings.
func withPaceKnob(t *testing.T, knob *paceKnob, phase string, value int) {
	t.Helper()
	prior, had := knob.perPhase[phase]
	knob.perPhase[phase] = value
	t.Cleanup(func() {
		if had {
			knob.perPhase[phase] = prior
			return
		}
		delete(knob.perPhase, phase)
	})
}

func TestApplyPhasePaceOverridesWarnsOnUnenforcedField(t *testing.T) {
	opts := paceTestOptions()
	settings := &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}

	// Spidering has no limiter at all: this value parsed, was stored, and was
	// printed as effective while changing nothing.
	withPaceKnob(t, rateLimitKnob, "spidering", 5)

	out := captureStderr(t, func() { applyPhasePaceOverrides(settings, opts) })

	if !strings.Contains(out, "spidering") || !strings.Contains(out, "not enforced") {
		t.Fatalf("expected a not-enforced warning naming the phase, got %q", out)
	}
	if !strings.Contains(out, config.PaceFieldRateLimit) {
		t.Fatalf("the warning must name the field, got %q", out)
	}
	// The value is still recorded: the operator typed it, and a release that
	// teaches the phase to read it should not need the flag typed again.
	if got := settings.ScanningPace.Spidering.RateLimit; got != 5 {
		t.Fatalf("spidering.rate_limit = %d, want 5 (warned, not dropped)", got)
	}
}

func TestApplyPhasePaceOverridesSilentOnEnforcedField(t *testing.T) {
	opts := paceTestOptions()
	settings := &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}

	withPaceKnob(t, rateLimitKnob, "probe", 5)

	out := captureStderr(t, func() { applyPhasePaceOverrides(settings, opts) })

	if strings.Contains(out, "not enforced") {
		t.Fatalf("probe enforces rate_limit; no warning expected, got %q", out)
	}
	if got := settings.ScanningPace.Probe.RateLimit; got != 5 {
		t.Fatalf("probe.rate_limit = %d, want 5", got)
	}
}

// TestResolvedPaceTableOmitsPhasesThatEnforceNothing is the stream half: a
// driver reading scan.started used to be told spidering ran at 100 rps, 25
// workers and 40 per host, none of which the crawler can apply. It enforces no
// pace field at all, so it is omitted rather than reported as three zeros.
func TestResolvedPaceTableOmitsPhasesThatEnforceNothing(t *testing.T) {
	opts := paceTestOptions()
	settings := &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}
	// Even with its own values set, spidering must not appear.
	settings.ScanningPace.Spidering.Concurrency = 3
	settings.ScanningPace.Spidering.RateLimit = 9

	_, table := resolvedPaceTable(settings, opts)

	if entry, ok := table["spidering"]; ok {
		t.Fatalf("spidering should not be in the pace table, got %+v", entry)
	}
	// A phase that DOES enforce something is still reported.
	if _, ok := table["probe"]; !ok {
		// probe equals the global pace here, so this is only a sanity check that
		// the loop still produces entries at all.
		if len(table) == 0 {
			t.Fatal("the pace table is empty; the omission rule is too wide")
		}
	}
}

// TestResolvedPaceTableOmitsUnenforcedFields: a phase that enforces SOME fields
// reports only those.
func TestResolvedPaceTableOmitsUnenforcedFields(t *testing.T) {
	opts := paceTestOptions()
	settings := &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}
	settings.ScanningPace.KnownIssueScan.Concurrency = 3

	_, table := resolvedPaceTable(settings, opts)

	entry, ok := table["known-issue-scan"]
	if !ok {
		t.Fatalf("known-issue-scan missing from the pace table: %+v", table)
	}
	if entry.Concurrency != 3 {
		t.Errorf("concurrency = %d, want 3", entry.Concurrency)
	}
	// The known-issue scan honours only an EXPLICIT rate (section or
	// typed --rate-limit); the untyped global default no longer overrides its
	// own conservative 20 rps.
	if entry.RateLimit != config.KnownIssueScanDefaultRateLimit {
		t.Errorf("rate_limit = %d, want the phase default %d", entry.RateLimit, config.KnownIssueScanDefaultRateLimit)
	}
	opts.RateLimitExplicitlySet = true
	if _, typed := resolvedPaceTable(settings, opts); typed["known-issue-scan"].RateLimit != 100 {
		t.Errorf("typed --rate-limit 100 must reach the known-issue scan, got %d", typed["known-issue-scan"].RateLimit)
	}
	if entry.MaxPerHost != 0 {
		t.Errorf("max_per_host = %d, want 0 (not enforced)", entry.MaxPerHost)
	}
}

// TestResolvedPaceTableDiscoveryRateIsExplicitOnly pins the one field whose
// enforced value differs from its resolved value.
func TestResolvedPaceTableDiscoveryRateIsExplicitOnly(t *testing.T) {
	opts := paceTestOptions()
	settings := &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}
	settings.ScanningPace.Discovery.Concurrency = 3 // make the entry differ from global

	_, table := resolvedPaceTable(settings, opts)
	entry, ok := table["discovery"]
	if !ok {
		t.Fatalf("discovery missing from the pace table: %+v", table)
	}
	if entry.RateLimit != 0 {
		t.Errorf("discovery rate_limit = %d, want 0 — the global 100 rps default is not enforced", entry.RateLimit)
	}
	if entry.Concurrency != 3 {
		t.Errorf("discovery concurrency = %d, want 3", entry.Concurrency)
	}
	if entry.MaxPerHost != 0 {
		t.Errorf("discovery max_per_host = %d, want 0 (not enforced)", entry.MaxPerHost)
	}

	// An explicitly configured discovery rate IS reported, because it is applied.
	settings.ScanningPace.Discovery.RateLimit = 7
	_, table = resolvedPaceTable(settings, opts)
	if got := table["discovery"].RateLimit; got != 7 {
		t.Errorf("explicit discovery rate_limit = %d, want 7", got)
	}
}
