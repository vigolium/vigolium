package output

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// allSeverities pairs each named severity with its expected symbol so screen
// formatting can be exercised table-driven across the full range.
var allSeverities = []struct {
	sev    severity.Severity
	name   string
	symbol string
}{
	{severity.Critical, "critical", terminal.CriticalSymbol()},
	{severity.High, "high", terminal.HighSymbol()},
	{severity.Medium, "medium", terminal.MediumSymbol()},
	{severity.Low, "low", terminal.LowSymbol()},
	{severity.Suspect, "suspect", terminal.SuspectSymbol()},
	{severity.Info, "info", terminal.InfoSeveritySymbol()},
}

func TestGetSeveritySymbol(t *testing.T) {
	for _, tc := range allSeverities {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.symbol, getSeveritySymbol(tc.sev))
		})
	}
	// Undefined severity yields no symbol.
	assert.Equal(t, "", getSeveritySymbol(severity.Undefined))
}

func TestSeverityColorContainsNameAndSymbol(t *testing.T) {
	for _, tc := range allSeverities {
		t.Run(tc.name, func(t *testing.T) {
			out := terminal.StripANSI(severityColor(tc.sev))
			// Color-stripped output is "<symbol> <name>".
			assert.True(t, strings.HasPrefix(out, tc.symbol), "expected leading symbol in %q", out)
			assert.Contains(t, out, tc.name, "severity name must appear in the colorless string")
		})
	}
}

func TestSeverityColorUndefinedReturnsBareName(t *testing.T) {
	// Undefined falls through default: bare String() with no symbol prefix.
	out := severityColor(severity.Undefined)
	assert.Equal(t, severity.Undefined.String(), out)
}

func TestModuleTypeColor(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"active", "active"},
		{"passive", "passive"},
		{"known-issue-scan", "known-issue-scan"}, // default branch: returned unchanged
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, terminal.StripANSI(moduleTypeColor(tc.in)))
		})
	}
}

func TestFormatScreenContainsCoreFields(t *testing.T) {
	w := &StandardWriter{}
	for _, tc := range allSeverities {
		t.Run(tc.name, func(t *testing.T) {
			ev := &ResultEvent{
				ModuleID:   "xss-reflected",
				ModuleType: "active",
				Info:       Info{Severity: tc.sev},
				Matched:    "https://example.com/q",
			}
			out := terminal.StripANSI(string(w.formatScreen(ev)))
			assert.Contains(t, out, "[xss-reflected]", "module id rendered in brackets")
			assert.Contains(t, out, "[active]", "module type rendered in brackets")
			assert.Contains(t, out, tc.name, "severity name rendered")
			assert.Contains(t, out, tc.symbol, "severity symbol rendered")
			assert.Contains(t, out, "https://example.com/q", "matched-at URL rendered")
		})
	}
}

func TestFormatScreenSuppressesModuleTypeMatchingPhase(t *testing.T) {
	// When ModuleType duplicates the phase tag it is suppressed to avoid noise.
	w := &StandardWriter{PhaseTag: "known-issue-scan"}
	ev := &ResultEvent{
		ModuleID:   "mod",
		ModuleType: "known-issue-scan",
		Info:       Info{Severity: severity.Medium},
		Matched:    "https://h/p",
	}
	out := terminal.StripANSI(string(w.formatScreen(ev)))
	// Phase tag appears once (from the prefix), not duplicated as a module type bracket.
	assert.Contains(t, out, "known-issue-scan")
	assert.NotContains(t, out, "[known-issue-scan]", "module type bracket suppressed when equal to phase tag")
}

func TestFormatScreenPhasePrefix(t *testing.T) {
	w := &StandardWriter{PhaseTag: "scan"}
	ev := &ResultEvent{
		ModuleID: "mod",
		Info:     Info{Severity: severity.Low},
		Matched:  "https://h/p",
	}
	out := terminal.StripANSI(string(w.formatScreen(ev)))
	assert.Contains(t, out, terminal.SymbolChevron)
	assert.Contains(t, out, "scan")
	assert.Contains(t, out, terminal.SymbolPipe)
}

func TestFormatScreenFallsBackToHostThenURL(t *testing.T) {
	w := &StandardWriter{}

	// No Matched, no URL -> Host is used.
	hostOnly := &ResultEvent{ModuleID: "m", Info: Info{Severity: severity.Info}, Host: "host.example"}
	assert.Contains(t, terminal.StripANSI(string(w.formatScreen(hostOnly))), "host.example")

	// No Matched but URL present -> URL is used.
	urlOnly := &ResultEvent{ModuleID: "m", Info: Info{Severity: severity.Info}, Host: "host.example", URL: "https://url.example/x"}
	out := terminal.StripANSI(string(w.formatScreen(urlOnly)))
	assert.Contains(t, out, "https://url.example/x")
}

func TestFormatScreenIncludesExtractedAndFuzzing(t *testing.T) {
	w := &StandardWriter{}
	ev := &ResultEvent{
		ModuleID:         "m",
		Info:             Info{Severity: severity.High},
		Matched:          "https://h/p",
		ExtractedResults: []string{"root", "admin"},
		IsFuzzingResult:  true,
		FuzzingParameter: "id",
	}
	out := terminal.StripANSI(string(w.formatScreen(ev)))
	assert.Contains(t, out, "root,admin", "extracted results joined and bracketed")
	assert.Contains(t, out, "[id]", "fuzzing parameter rendered")
}

func TestFormatScreenPrependsHTTPMethod(t *testing.T) {
	w := &StandardWriter{}
	ev := &ResultEvent{
		ModuleID: "m",
		Info:     Info{Severity: severity.High},
		Matched:  "https://h/login",
		Request:  "POST /login HTTP/1.1\r\nHost: h\r\n\r\n",
	}
	out := terminal.StripANSI(string(w.formatScreen(ev)))
	assert.Contains(t, out, "POST https://h/login", "HTTP method prepended to matched URL")
}
