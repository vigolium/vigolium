package types

import (
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	if o == nil {
		t.Fatal("DefaultOptions returned nil")
	}
	if o.Concurrency != 50 {
		t.Errorf("Concurrency = %d, want 50", o.Concurrency)
	}
	if o.MaxPerHost != 20 {
		t.Errorf("MaxPerHost = %d, want 20", o.MaxPerHost)
	}
	if o.Timeout != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", o.Timeout)
	}
	if o.MaxHostError != 30 {
		t.Errorf("MaxHostError = %d, want 30", o.MaxHostError)
	}
	if o.MaxFindingsPerModule != 10 {
		t.Errorf("MaxFindingsPerModule = %d, want 10", o.MaxFindingsPerModule)
	}
	if !o.ClusterRequests {
		t.Error("ClusterRequests = false, want true")
	}
	if o.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", o.ShutdownTimeout)
	}
	if len(o.PassiveModules) != 1 || o.PassiveModules[0] != "all" {
		t.Errorf("PassiveModules = %v, want [all]", o.PassiveModules)
	}
}

func TestShouldUseHostError(t *testing.T) {
	tests := []struct {
		name         string
		maxHostError int
		want         bool
	}{
		{"positive", 30, true},
		{"one", 1, true},
		{"zero disables", 0, false},
		{"negative disables", -1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{MaxHostError: tt.maxHostError}
			if got := o.ShouldUseHostError(); got != tt.want {
				t.Errorf("ShouldUseHostError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldFollowHTTPRedirects(t *testing.T) {
	tests := []struct {
		name       string
		follow     bool
		followHost bool
		want       bool
	}{
		{"neither", false, false, false},
		{"follow only", true, false, true},
		{"follow host only", false, true, true},
		{"both", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{FollowRedirects: tt.follow, FollowHostRedirects: tt.followHost}
			if got := o.ShouldFollowHTTPRedirects(); got != tt.want {
				t.Errorf("ShouldFollowHTTPRedirects() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasFormat(t *testing.T) {
	o := &Options{OutputFormats: []string{"console", "jsonl"}}
	if !o.HasFormat("jsonl") {
		t.Error("HasFormat(jsonl) = false, want true")
	}
	if !o.HasFormat("console") {
		t.Error("HasFormat(console) = false, want true")
	}
	if o.HasFormat("html") {
		t.Error("HasFormat(html) = true, want false")
	}
	empty := &Options{}
	if empty.HasFormat("jsonl") {
		t.Error("HasFormat on empty = true, want false")
	}
}

func TestStripFormatExtension(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"", ""},
		{"report.jsonl", "report"},
		{"report.html", "report"},
		{"report.json", "report"},
		{"report.pdf", "report"},
		{"report.JSONL", "report"}, // case-insensitive
		{"out/scan.jsonl", "out/scan"},
		{"report.txt", "report.txt"},    // unknown ext preserved
		{"report", "report"},            // no ext
		{"my.report.html", "my.report"}, // only last ext stripped
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := StripFormatExtension(tt.path); got != tt.want {
				t.Errorf("StripFormatExtension(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestFormatOutputPath(t *testing.T) {
	tests := []struct {
		base   string
		format string
		want   string
	}{
		{"", "jsonl", ""}, // empty base short-circuits
		{"report", "jsonl", "report.jsonl"},
		{"report", "html", "report.html"},
		{"report", "report", "report.report.html"},
		{"report", "pdf", "report.pdf"},
		{"report", "console", "report"}, // unknown format -> base unchanged
	}
	for _, tt := range tests {
		t.Run(tt.base+"_"+tt.format, func(t *testing.T) {
			if got := FormatOutputPath(tt.base, tt.format); got != tt.want {
				t.Errorf("FormatOutputPath(%q,%q) = %q, want %q", tt.base, tt.format, got, tt.want)
			}
		})
	}
}

func TestOutputPathForFormat(t *testing.T) {
	// Round-trip: an Output with one extension is restripped and reformatted.
	o := &Options{Output: "out/scan.html"}
	if got := o.OutputBasePath(); got != "out/scan" {
		t.Errorf("OutputBasePath() = %q, want out/scan", got)
	}
	if got := o.OutputPathForFormat("jsonl"); got != "out/scan.jsonl" {
		t.Errorf("OutputPathForFormat(jsonl) = %q, want out/scan.jsonl", got)
	}
}
