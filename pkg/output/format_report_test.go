package output

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yuin/goldmark"
)

// envelope mirrors the {type, data} shape buildReportData decodes from items.
type envelope struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func TestBuildReportDataCountsFindingsBySeverity(t *testing.T) {
	items := []any{
		envelope{"finding", map[string]any{"id": 1, "module_name": "XSS", "severity": "critical", "url": "https://a/1"}},
		envelope{"finding", map[string]any{"id": 2, "module_name": "SQLi", "severity": "high"}},
		envelope{"finding", map[string]any{"id": 3, "module_name": "SQLi", "severity": "high"}},
		envelope{"finding", map[string]any{"id": 4, "module_name": "Hdr", "severity": "medium"}},
		envelope{"finding", map[string]any{"id": 5, "module_name": "Cookie", "severity": "low"}},
		// Unknown severity falls into the Info bucket.
		envelope{"finding", map[string]any{"id": 6, "module_name": "Note", "severity": "whatever"}},
	}

	rd := buildReportData(items, "My Report", HTMLReportMeta{})

	assert.Equal(t, "My Report", rd.Title)
	assert.Equal(t, 6, rd.TotalFindings)
	assert.Equal(t, 1, rd.CriticalCount)
	assert.Equal(t, 2, rd.HighCount)
	assert.Equal(t, 1, rd.MediumCount)
	assert.Equal(t, 1, rd.LowCount)
	assert.Equal(t, 1, rd.InfoCount, "unknown severity buckets into Info")
	require.Len(t, rd.CriticalFindings, 1)
	require.Len(t, rd.HighFindings, 2)
	require.Len(t, rd.InfoFindings, 1)
	assert.NotEmpty(t, rd.GeneratedAt, "GeneratedAt defaults to now when meta omits it")
}

func TestBuildReportDataAggregatesScanModulesAndRecords(t *testing.T) {
	items := []any{
		envelope{"scan", map[string]any{"target": "https://target.example", "total_requests": 42}},
		envelope{"module", map[string]any{"id": "m1", "name": "Mod1", "type": "active", "enabled": true}},
		envelope{"module", map[string]any{"id": "m2", "name": "Mod2", "type": "passive", "enabled": true}},
		// Disabled modules are ignored.
		envelope{"module", map[string]any{"id": "m3", "name": "Mod3", "type": "active", "enabled": false}},
		envelope{"http_record", map[string]any{}},
		envelope{"http_record", map[string]any{}},
		// Unknown envelope types are skipped silently.
		envelope{"unknown", map[string]any{}},
	}

	rd := buildReportData(items, "T", HTMLReportMeta{})

	assert.Equal(t, "https://target.example", rd.Target, "scan target overrides meta target")
	// total_requests from scan (42) plus two http_record items.
	assert.Equal(t, 44, rd.TotalRequests)
	assert.Equal(t, 1, rd.ActiveModules)
	assert.Equal(t, 1, rd.PassiveModules)
	require.Len(t, rd.Modules, 2, "disabled module excluded from list")
}

func TestBuildReportDataUsesMetaDefaults(t *testing.T) {
	meta := HTMLReportMeta{
		GeneratedAt:  "2026-01-02 03:04 UTC",
		ScanDuration: "1m30s",
		ScanTarget:   "https://meta.example",
		Version:      "v9.9.9",
	}
	rd := buildReportData(nil, "T", meta)
	assert.Equal(t, "2026-01-02 03:04 UTC", rd.GeneratedAt)
	assert.Equal(t, "1m30s", rd.ScanDuration)
	assert.Equal(t, "https://meta.example", rd.Target)
	assert.Equal(t, "v9.9.9", rd.VigoliumVersion)
}

func TestParseFinding(t *testing.T) {
	md := goldmark.New()
	data := []byte(`{
		"id": 7,
		"module_id": "xss-reflected",
		"module_name": "Reflected XSS",
		"module_short": "XSS",
		"description": "## Summary\n\nReflected input.",
		"severity": "HIGH",
		"confidence": "firm",
		"cwe_id": "CWE-79",
		"cvss_score": 6.1,
		"url": "https://example.com/search",
		"tags": ["xss", "active"]
	}`)

	f := parseFinding(data, md)
	assert.Equal(t, 7, f.ID)
	assert.Equal(t, "xss-reflected", f.ModuleID)
	// module_short wins over module_name for display name.
	assert.Equal(t, "XSS", f.ModuleName)
	// Title combines name and URL.
	assert.Equal(t, "XSS — https://example.com/search", f.Title)
	assert.Equal(t, "high", f.Severity, "severity lowercased")
	assert.Equal(t, "CWE-79", f.CWE)
	assert.Equal(t, 6.1, f.CVSSScore)
	assert.Contains(t, string(f.DescriptionHTML), "<h2>Summary</h2>", "markdown rendered to HTML")
	assert.Equal(t, []string{"xss", "active"}, f.Tags)
}

func TestParseFindingFallsBackToModuleName(t *testing.T) {
	md := goldmark.New()
	data := []byte(`{"id": 1, "module_name": "Full Name", "severity": "low"}`)
	f := parseFinding(data, md)
	assert.Equal(t, "Full Name", f.ModuleName, "falls back to module_name when module_short empty")
	assert.Equal(t, "Full Name", f.Title, "no URL means title is just the name")
}

func TestTruncateStr(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"shorter than max", "hello", 10, "hello"},
		{"equal to max", "hello", 5, "hello"},
		{"longer than max", "hello world", 5, "hello..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, truncateStr(tc.in, tc.max))
		})
	}
}

func TestResolveReportSharedURL(t *testing.T) {
	// Explicit meta value takes precedence over the environment.
	t.Setenv("VIGOLIUM_REPORT_SHARED_URL", "https://env.example")
	assert.Equal(t, "https://explicit.example", resolveReportSharedURL(HTMLReportMeta{ReportSharedURL: "https://explicit.example"}))

	// Empty meta falls back to the environment variable.
	assert.Equal(t, "https://env.example", resolveReportSharedURL(HTMLReportMeta{}))

	// Neither set yields empty string.
	t.Setenv("VIGOLIUM_REPORT_SHARED_URL", "")
	assert.Equal(t, "", resolveReportSharedURL(HTMLReportMeta{}))
}

func TestWriteMarkdownHeader(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownHeader(w, ReportData{
		Title:           "Scan Report",
		VigoliumVersion: "v1.2.3",
		Target:          "https://t.example",
		ScanDuration:    "2m",
	})
	got := w.String()
	assert.True(t, strings.HasPrefix(got, "# Scan Report\n"), "title rendered as h1")
	assert.Contains(t, got, "**Generated:**")
	assert.Contains(t, got, "**Vigolium Version:** v1.2.3")
	assert.Contains(t, got, "**Target:** https://t.example")
	assert.Contains(t, got, "**Scan Duration:** 2m")
	assert.True(t, strings.HasSuffix(got, "\n---\n\n"), "header ends with a horizontal rule")
}

func TestWriteMarkdownHeaderOmitsEmptyFields(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownHeader(w, ReportData{Title: "Bare"})
	got := w.String()
	assert.Contains(t, got, "# Bare")
	assert.NotContains(t, got, "**Vigolium Version:**")
	assert.NotContains(t, got, "**Target:**")
	assert.NotContains(t, got, "**Scan Duration:**")
}

func TestWriteMarkdownTOC(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownTOC(w, ReportData{
		CriticalFindings: []ReportFinding{{ID: 1, Title: "crit"}},
		HighFindings:     []ReportFinding{{ID: 2, Title: "hi"}},
	})
	got := w.String()
	assert.Contains(t, got, "## Table of Contents")
	assert.Contains(t, got, "- [Executive Summary](#executive-summary)")
	assert.Contains(t, got, "- [Critical Findings (1)](#critical-findings)")
	assert.Contains(t, got, "- [High Findings (1)](#high-findings)")
	// Empty groups produce no TOC entry.
	assert.NotContains(t, got, "Medium Findings")
}

func TestWriteMarkdownExecutiveSummary(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownExecutiveSummary(w, ReportData{
		TotalFindings:  5,
		CriticalCount:  1,
		HighCount:      2,
		MediumCount:    2,
		TotalRequests:  100,
		ActiveModules:  10,
		PassiveModules: 5,
	})
	got := w.String()
	assert.Contains(t, got, "## Executive Summary")
	assert.Contains(t, got, "A total of **5 findings**")
	assert.Contains(t, got, "| Critical | 1 |")
	assert.Contains(t, got, "| High | 2 |")
	assert.Contains(t, got, "| Medium | 2 |")
	// Zero-count severities are omitted from the table.
	assert.NotContains(t, got, "| Low |")
	assert.Contains(t, got, "| **Total** | **5** |")
	assert.Contains(t, got, "**Total HTTP Requests:** 100")
	assert.Contains(t, got, "**Modules:** 10 active, 5 passive")
}

func TestWriteMarkdownFindings(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownFindings(w, "High", []ReportFinding{{
		ID:               42,
		Title:            "Reflected XSS",
		ModuleName:       "XSS",
		ModuleID:         "xss-reflected",
		Severity:         "high",
		Confidence:       "firm",
		CWE:              "CWE-79",
		CVSSScore:        6.1,
		URL:              "https://example.com/q",
		Description:      "Some details.",
		Remediation:      "Encode output.",
		MatchedAt:        []string{"https://example.com/q?x=1"},
		ExtractedResults: []string{"alert(1)"},
		Request:          "GET /q HTTP/1.1",
		Response:         "HTTP/1.1 200 OK",
		Tags:             []string{"xss"},
	}})
	got := w.String()
	assert.Contains(t, got, "## High Findings")
	assert.Contains(t, got, "### 42. Reflected XSS")
	assert.Contains(t, got, "**Module:** XSS (`xss-reflected`)")
	assert.Contains(t, got, "**Severity:** High", "severity title-cased")
	assert.Contains(t, got, "**Confidence:** firm")
	assert.Contains(t, got, "**CWE:** CWE-79")
	assert.Contains(t, got, "**CVSS:** 6.1")
	assert.Contains(t, got, "**URL:** `https://example.com/q`")
	assert.Contains(t, got, "Some details.")
	assert.Contains(t, got, "**Remediation:** Encode output.")
	assert.Contains(t, got, "- `https://example.com/q?x=1`")
	assert.Contains(t, got, "- `alert(1)`")
	assert.Contains(t, got, "<summary>HTTP Request</summary>")
	assert.Contains(t, got, "<summary>HTTP Response</summary>")
	assert.Contains(t, got, "**Tags:** xss")
	assert.True(t, strings.HasSuffix(got, "---\n\n"), "finding block terminated by a rule")
}

func TestWriteMarkdownFindingsEmpty(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownFindings(w, "Low", nil)
	assert.Empty(t, w.String(), "no output when no findings of the severity")
}
