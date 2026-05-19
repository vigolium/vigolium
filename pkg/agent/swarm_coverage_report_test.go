package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestBuildSwarmCoverageReport_PrefixesSortedAndInFocusFlagged(t *testing.T) {
	plan := &SwarmPlan{
		ModuleTags: []string{"sqli", "auth-bypass"},
		ModuleIDs:  []string{"sqli-error-based"},
		FocusAreas: []string{"SQLi in /api/users"},
	}
	records := []*httpmsg.HttpRequestResponse{
		mkRecord(t, "POST", "/api/users/login"),
		mkRecord(t, "POST", "/api/users/profile"),
		mkRecord(t, "GET", "/admin/dashboard"),
	}
	report := BuildSwarmCoverageReport(CoverageReportInputs{
		AgenticScanUUID: "scan-uuid",
		TargetURL:       "https://t.test",
		Intensity:       "balanced",
		Plan:            plan,
		Records:         records,
	})

	if report.TotalRecords != 3 {
		t.Errorf("TotalRecords: want 3, got %d", report.TotalRecords)
	}
	// Sorted alphabetically: /admin/dashboard, /api/users
	if len(report.Prefixes) != 2 {
		t.Fatalf("Prefixes: want 2, got %d (%+v)", len(report.Prefixes), report.Prefixes)
	}
	if report.Prefixes[0].Prefix != "/admin/dashboard" {
		t.Errorf("Prefix 0: want /admin/dashboard, got %q", report.Prefixes[0].Prefix)
	}
	if report.Prefixes[0].InFocus {
		t.Errorf("/admin/dashboard should not be flagged as in-focus")
	}
	if report.Prefixes[1].Prefix != "/api/users" {
		t.Errorf("Prefix 1: want /api/users, got %q", report.Prefixes[1].Prefix)
	}
	if !report.Prefixes[1].InFocus {
		t.Errorf("/api/users should be flagged as in-focus")
	}
	if report.Prefixes[1].RecordCount != 2 {
		t.Errorf("/api/users record count: want 2, got %d", report.Prefixes[1].RecordCount)
	}

	// Plan filter applied because both ModuleTags and ModuleIDs are non-empty.
	if !report.Plan.ModuleFilterApplied {
		t.Error("ModuleFilterApplied should be true when plan emits tags/IDs")
	}
}

func TestBuildSwarmCoverageReport_NoModuleFilter(t *testing.T) {
	// Empty tags + IDs means the scan ran against the full registry. The
	// report should make that explicit so operators understand "all 246
	// modules ran" wasn't a misconfiguration.
	plan := &SwarmPlan{} // empty
	report := BuildSwarmCoverageReport(CoverageReportInputs{AgenticScanUUID: "u", Plan: plan})
	if report.Plan.ModuleFilterApplied {
		t.Error("ModuleFilterApplied should be false when plan has no tags/IDs")
	}
}

func TestBuildSwarmCoverageReport_FindingsPassThrough(t *testing.T) {
	byModule := map[string]int{"sqli-error-based": 3, "xss-dom": 1}
	byEndpoint := map[string]int{"https://t.test/api/users": 4}
	report := BuildSwarmCoverageReport(CoverageReportInputs{
		AgenticScanUUID:    "u",
		TargetURL:          "https://t.test",
		Intensity:          "deep",
		Plan:               &SwarmPlan{},
		TotalFindings:      4,
		FindingsByModule:   byModule,
		FindingsByEndpoint: byEndpoint,
		Warnings:           []string{"recon sweep failed"},
	})
	if report.FindingsByModule["sqli-error-based"] != 3 {
		t.Errorf("FindingsByModule sqli count: want 3, got %d", report.FindingsByModule["sqli-error-based"])
	}
	if report.FindingsByEndpoint["https://t.test/api/users"] != 4 {
		t.Errorf("FindingsByEndpoint URL count: want 4, got %d", report.FindingsByEndpoint["https://t.test/api/users"])
	}
	if len(report.Warnings) != 1 || report.Warnings[0] != "recon sweep failed" {
		t.Errorf("Warnings: want one entry, got: %+v", report.Warnings)
	}
}

func TestWriteSwarmCoverageReport_RoundTripsAndIsValidJSON(t *testing.T) {
	dir := t.TempDir()
	report := BuildSwarmCoverageReport(CoverageReportInputs{
		AgenticScanUUID: "u",
		TargetURL:       "https://t.test",
		Intensity:       "balanced",
		Plan: &SwarmPlan{
			ModuleTags: []string{"sqli"},
			FocusAreas: []string{"SQLi in /api/users"},
		},
		Records: []*httpmsg.HttpRequestResponse{mkRecord(t, "POST", "/api/users/login")},
	})
	path := WriteSwarmCoverageReport(dir, report)
	if path == "" {
		t.Fatal("WriteSwarmCoverageReport returned empty path")
	}
	if path != filepath.Join(dir, "coverage.json") {
		t.Errorf("unexpected coverage path: %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading coverage report: %v", err)
	}
	var roundTrip SwarmCoverageReport
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("coverage report is not valid JSON: %v", err)
	}
	if roundTrip.TotalRecords != 1 {
		t.Errorf("round-trip TotalRecords: want 1, got %d", roundTrip.TotalRecords)
	}
	if len(roundTrip.Plan.ModuleTags) != 1 || roundTrip.Plan.ModuleTags[0] != "sqli" {
		t.Errorf("round-trip ModuleTags: want [sqli], got %v", roundTrip.Plan.ModuleTags)
	}
}

func TestWriteSwarmCoverageReport_EmptySessionDirNoOp(t *testing.T) {
	if got := WriteSwarmCoverageReport("", &SwarmCoverageReport{}); got != "" {
		t.Errorf("expected empty path for empty session dir, got: %q", got)
	}
}
