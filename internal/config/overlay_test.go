package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withOverlay(t *testing.T, raw ...string) {
	t.Helper()
	entries, err := ParseOverlay(raw)
	if err != nil {
		t.Fatalf("ParseOverlay(%v): %v", raw, err)
	}
	SetProcessOverlay(entries)
	t.Cleanup(func() { SetProcessOverlay(nil) })
}

// An unknown key is ErrUnknownKey naming it; a value the key cannot hold is
// ErrInvalidValue; `.add` is refused (the overlay re-applies per layer).
func TestParseOverlayRefusals(t *testing.T) {
	_, err := ParseOverlay([]string{"nope.not_a_key=1"})
	if !errors.Is(err, ErrUnknownKey) || !strings.Contains(err.Error(), "nope.not_a_key") {
		t.Errorf("unknown key: %v", err)
	}
	if _, err := ParseOverlay([]string{"scanning_pace.rate_limit=fast"}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("bad value: %v", err)
	}
	if _, err := ParseOverlay([]string{"scanning_pace.rate_limit"}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("no '=': %v", err)
	}
	if _, err := ParseOverlay([]string{"scope.host.include.add=a.example"}); !errors.Is(err, ErrInvalidValue) ||
		!strings.Contains(err.Error(), ".add") {
		t.Errorf(".add: %v", err)
	}
	got, err := ParseOverlay([]string{" scanning_pace.rate_limit = 7 ", "scope.host.include=[a.example,b.example]"})
	if err != nil || len(got) != 2 || got[0] != (OverlayEntry{Key: "scanning_pace.rate_limit", Value: "7"}) {
		t.Errorf("valid entries = %+v, %v", got, err)
	}
}

// The overlay outranks the config file, a scanning profile and a project
// overlay, applies on built-in defaults when there is no file, and never
// writes the file.
func TestProcessOverlayOutranksEveryLayer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	body := "scanning_pace:\n  rate_limit: 50\n  concurrency: 9\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	withOverlay(t, "scanning_pace.rate_limit=7", "scope.host.include=[a.example]")

	s, err := LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.ScanningPace.RateLimit != 7 || s.ScanningPace.Concurrency != 9 {
		t.Errorf("file layer: rate %d concurrency %d, want 7 and the file's 9", s.ScanningPace.RateLimit, s.ScanningPace.Concurrency)
	}
	if len(s.Scope.Host.Include) != 1 || s.Scope.Host.Include[0] != "a.example" {
		t.Errorf("scope.host.include = %v", s.Scope.Host.Include)
	}

	if err := ApplyProfileData(s, []byte("scanning_pace:\n  rate_limit: 30\n"), "test profile"); err != nil {
		t.Fatal(err)
	}
	if s.ScanningPace.RateLimit != 7 {
		t.Errorf("after a profile: rate %d, want the overlay's 7", s.ScanningPace.RateLimit)
	}

	if got, _ := os.ReadFile(path); string(got) != body {
		t.Errorf("the config file changed:\n%s", got)
	}

	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	d, err := LoadSettings("")
	if err != nil {
		t.Fatal(err)
	}
	if d.ScanningPace.RateLimit != 7 {
		t.Errorf("no config file: rate %d, want 7 on the defaults", d.ScanningPace.RateLimit)
	}

	SetProcessOverlay(nil)
	if s2, _ := LoadSettings(path); s2.ScanningPace.RateLimit != 50 {
		t.Errorf("cleared overlay: rate %d, want the file's 50", s2.ScanningPace.RateLimit)
	}
}

// UnenforcedPhasePace names the section values a phase does not read, for the
// phases given only; PhasePacePairs covers every phase × dial.
func TestUnenforcedPhasePace(t *testing.T) {
	c := DefaultScanningPaceConfig()
	c.Spidering.RateLimit = 5
	c.Spidering.Concurrency = 2
	c.DynamicAssessment.MaxPerHost = 3
	c.Probe.RateLimit = 4 // enforced: not reported
	got := c.UnenforcedPhasePace([]string{"probe", "spidering", "dynamic-assessment"})
	want := []PhaseDial{
		{"spidering", PaceFieldConcurrency}, {"spidering", PaceFieldRateLimit},
		{"dynamic-assessment", PaceFieldMaxPerHost},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if got := c.UnenforcedPhasePace([]string{"probe"}); len(got) != 0 {
		t.Errorf("phase not given is not reported: %+v", got)
	}

	pairs := PhasePacePairs()
	if len(pairs) != len(PhaseSectionNames())*len(PaceFields) {
		t.Fatalf("%d pairs", len(pairs))
	}
	for _, p := range pairs {
		if p.Enforced != PhasePaceSupports(p.Phase, p.Dial) {
			t.Errorf("%+v disagrees with PhasePaceSupports", p)
		}
	}
	if d := EnforcedPhaseDials(); len(d) == 0 || !strings.Contains(strings.Join(d, ","), "probe=max_per_host") {
		t.Errorf("EnforcedPhaseDials = %v", d)
	}
}
