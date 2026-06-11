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

func TestFormatScreenTruncationRespectsTTY(t *testing.T) {
	// A URL far longer than the 150-column TerminalWidth fallback.
	longURL := "https://example.com/" + strings.Repeat("a", 300)
	w := &StandardWriter{}
	ev := &ResultEvent{ModuleID: "m", Info: Info{Severity: severity.Info}, Matched: longURL}

	prev := terminal.IsTerminal()
	defer terminal.SetIsTerminal(prev)

	// Non-TTY (file/pipe, e.g. parallel-scan .console.log): full line, no ellipsis.
	terminal.SetIsTerminal(false)
	out := terminal.StripANSI(string(w.formatScreen(ev)))
	assert.Contains(t, out, longURL, "redirected output must keep the full URL")
	assert.NotContains(t, out, "…", "redirected output must not be truncated")

	// Interactive TTY: width-based truncation kicks in and clips with an ellipsis.
	terminal.SetIsTerminal(true)
	out = terminal.StripANSI(string(w.formatScreen(ev)))
	assert.NotContains(t, out, longURL, "terminal output should truncate a long URL")
	assert.Contains(t, out, "…", "terminal output should mark truncation with an ellipsis")
}

func TestFormatScreenNonTTYCapsSuffixKeepsURL(t *testing.T) {
	// A finding with an unbounded extracted-results suffix (e.g. unsafe-html-sink
	// emitting one snippet per match in a large JS bundle) must keep the full URL
	// in file/pipe output but cap the evidence suffix at maxFileSuffixWidth.
	longURL := "https://example.com/" + strings.Repeat("a", 300)
	snippets := make([]string, 20)
	for i := range snippets {
		snippets[i] = strings.Repeat("x", 150)
	}
	w := &StandardWriter{}
	ev := &ResultEvent{
		ModuleID:         "unsafe-html-sink",
		Info:             Info{Severity: severity.Low},
		Matched:          longURL,
		ExtractedResults: snippets,
	}

	prev := terminal.IsTerminal()
	defer terminal.SetIsTerminal(prev)
	terminal.SetIsTerminal(false)

	out := terminal.StripANSI(string(w.formatScreen(ev)))
	assert.Contains(t, out, longURL, "non-TTY output must keep the full URL")
	assert.Contains(t, out, "…", "oversized suffix must be truncated with an ellipsis")
	assert.LessOrEqual(t, len(out), len("[unsafe-html-sink] ")+len(terminal.LowSymbol())+len(" [ low] ")+len(longURL)+maxFileSuffixWidth+8,
		"suffix must be capped at maxFileSuffixWidth")

	// A modest suffix stays intact.
	ev.ExtractedResults = []string{"root", "admin"}
	out = terminal.StripANSI(string(w.formatScreen(ev)))
	assert.Contains(t, out, "[root,admin]")
	assert.NotContains(t, out, "…")
}

func TestFormatScreenSanitizesMultilineExtracted(t *testing.T) {
	// Snippets with embedded newlines (regex context windows over pretty-printed
	// JS) must collapse to a single line in every mode.
	w := &StandardWriter{}
	ev := &ResultEvent{
		ModuleID:         "unsafe-html-sink",
		Info:             Info{Severity: severity.Low},
		Matched:          "https://h/app.js",
		ExtractedResults: []string{"dropdownContent) {\n      dropdownContent.innerHTML = \"\";\r\n      next"},
	}

	prev := terminal.IsTerminal()
	defer terminal.SetIsTerminal(prev)
	for _, tty := range []bool{false, true} {
		terminal.SetIsTerminal(tty)
		out := terminal.StripANSI(string(w.formatScreen(ev)))
		assert.NotContains(t, out, "\n", "finding must render as one line (tty=%v)", tty)
		assert.Contains(t, out, `dropdownContent) { dropdownContent.innerHTML = ""; next`, "whitespace runs collapsed (tty=%v)", tty)
	}
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
