package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/diagnostics"
)

// TestDoctorForOnlyNarrowsTheScopedReport: `--for scan --only chromium` asks
// about chromium alone, so the run skips the OAST network probe and the
// database open, and the verdict counts only the checks it names.
func TestDoctorForOnlyNarrowsTheScopedReport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalDB, filepath.Join(home, "doctor.sqlite"))
	swapGlobal(t, &globalJSON, true)
	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorStrict, false)
	swapGlobal(t, &doctorTarget, "")
	swapGlobal(t, &doctorFor, "scan")
	swapGlobal(t, &doctorOnly, []string{"chromium"})

	var got diagnostics.Deps
	swapGlobal(t, &doctorRunDiagnostics, func(d diagnostics.Deps) *diagnostics.Report {
		got = d
		return &diagnostics.Report{
			Status:   "not_ready",
			Config:   &diagnostics.CheckResult{Status: diagnostics.StatusOK},
			Database: &diagnostics.CheckResult{Status: diagnostics.StatusError, Message: "not opened"},
			Tools:    map[string]*diagnostics.ToolCheck{},
		}
	})
	if err := runDoctorCmd(doctorCmd, nil); err != nil && classifyExitCode(err) == ExitUsageError {
		t.Fatalf("doctor --for scan --only chromium: usage error %v", err)
	}
	if got.ProbeNetwork {
		t.Error("ProbeNetwork = true; --only chromium must not resolve the OAST server")
	}
	if got.DB != nil || got.DBErr != nil {
		t.Errorf("database opened (DB=%v, err=%v); --only chromium does not name it", got.DB, got.DBErr)
	}
	if got.Include == nil || !got.Include("chromium") || got.Include("jstangle") || got.Include("oast") {
		t.Error("Include does not follow --only chromium: jstangle and oast must not run")
	}

	if !doctorOnlyIncludes("chromium") || doctorOnlyIncludes("oast") || doctorOnlyIncludes("database") {
		t.Error("doctorOnlyIncludes does not follow --only chromium")
	}
	swapGlobal(t, &doctorOnly, nil)
	if !doctorOnlyIncludes("oast") {
		t.Error("without --only every check runs")
	}
}

func TestScopedReportNarrowRecomputesTheVerdict(t *testing.T) {
	r := &diagnostics.ScopedReport{
		For:    "scan",
		Status: diagnostics.Status("not_ready"),
		Checks: []diagnostics.ScopedCheck{
			{ID: "database", Status: diagnostics.ScopedNotReady, Counts: true},
			{ID: "chromium", Status: diagnostics.ScopedOK, Counts: true},
		},
	}
	r.Narrow(func(id string) bool { return id == "chromium" })
	if len(r.Checks) != 1 || r.Checks[0].ID != "chromium" {
		t.Fatalf("checks = %+v, want chromium only", r.Checks)
	}
	if r.Status != "ready" {
		t.Errorf("status = %q, want ready (the unnamed database check no longer counts)", r.Status)
	}
}

// Without --for, --only runs only its checks through the real diagnostics:
// the database it does not name is neither opened nor counted, so the verdict
// is about the named checks.
func TestDoctorOnlyRunsOnlyTheNamedChecks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalDB, filepath.Join(home, "doctor.sqlite"))
	swapGlobal(t, &globalJSON, true)
	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorStrict, false)
	swapGlobal(t, &doctorTarget, "")
	swapGlobal(t, &doctorFor, "")
	swapGlobal(t, &doctorOnly, []string{"config"})
	jsonResultEmitted = false

	var report *diagnostics.Report
	swapGlobal(t, &doctorRunDiagnostics, func(d diagnostics.Deps) *diagnostics.Report {
		report = diagnostics.Run(d)
		return report
	})
	var err error
	doc := emitCaptured(t, func() error { err = runDoctorCmd(doctorCmd, nil); return err })
	if err != nil {
		t.Fatalf("doctor --only config: %v", err)
	}
	if report.Database != nil || report.Tools["chromium"] != nil || len(report.EmbeddedBinaries) != 0 || report.Skill != nil {
		t.Errorf("unselected checks ran: database=%v chromium=%v embedded=%v skill=%v", report.Database, report.Tools["chromium"], report.EmbeddedBinaries, report.Skill)
	}
	if doc["status"] != "ready" {
		t.Errorf("status = %v, want ready: the unnamed database is not counted", doc["status"])
	}
	items, _ := doc["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != "config" {
		t.Errorf("items = %v, want the config check alone", items)
	}
}

// A typo in --only is refused before any check runs.
func TestDoctorOnlyTypoRefusedBeforeRunning(t *testing.T) {
	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorFor, "")
	swapGlobal(t, &doctorTarget, "")
	swapGlobal(t, &doctorOnly, []string{"chromiun"})
	ran := false
	swapGlobal(t, &doctorRunDiagnostics, func(diagnostics.Deps) *diagnostics.Report { ran = true; return &diagnostics.Report{} })
	err := runDoctorCmd(doctorCmd, nil)
	if classifyExitCode(err) != ExitUsageError || !strings.Contains(err.Error(), "chromium") {
		t.Fatalf("err = %v, want a usage error listing the valid checks", err)
	}
	if ran {
		t.Error("diagnostics ran for an invalid --only")
	}
}

// TestDoctorOnlyAcceptsScopedChecks: the checks only a --for report runs are
// --only tokens too, and target selects its target_* rows.
func TestDoctorOnlyAcceptsScopedChecks(t *testing.T) {
	for _, tok := range []string{"proxy", "disk", "fd_limit", "fd-limit", "target"} {
		swapGlobal(t, &doctorOnly, []string{tok})
		if err := validateDoctorOnly(doctorAllChecks()); err != nil {
			t.Errorf("--only %s refused: %v", tok, err)
		}
	}
	swapGlobal(t, &doctorOnly, []string{"target"})
	if !doctorOnlyIncludes(diagnostics.ScopedSelectorID("target_tls")) {
		t.Error("--only target does not keep target_tls")
	}
	if doctorOnlyIncludes(diagnostics.ScopedSelectorID("disk")) {
		t.Error("--only target keeps disk")
	}
}
