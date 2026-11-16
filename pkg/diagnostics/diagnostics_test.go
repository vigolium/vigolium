package diagnostics

import (
	"slices"
	"testing"
	"time"
)

func TestResolveAlias(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"chrome", "chromium"},
		{"nuclei", "nuclei-templates"},
		{"CHROME", "chromium"},            // case-insensitive
		{"  nuclei ", "nuclei-templates"}, // trimmed
		{"chromium", "chromium"},          // already canonical
		{"unknown", "unknown"},            // pass-through
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := resolveAlias(tt.in); got != tt.want {
				t.Errorf("resolveAlias(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestToolFailing(t *testing.T) {
	r := &Report{Tools: map[string]*ToolCheck{
		"ok":   {Status: StatusOK},
		"warn": {Status: StatusWarning},
		"err":  {Status: StatusError},
	}}
	if toolFailing(r, "missing") {
		t.Error("missing tool should not be reported as failing")
	}
	if toolFailing(r, "ok") {
		t.Error("StatusOK tool should not be failing")
	}
	if !toolFailing(r, "warn") {
		t.Error("StatusWarning tool should be failing")
	}
	if !toolFailing(r, "err") {
		t.Error("StatusError tool should be failing")
	}
}

func TestRoundedAge(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"just now", 30 * time.Second, "just now"},
		{"minutes", 5 * time.Minute, "5m ago"},
		{"hours", 3 * time.Hour, "3h ago"},
		{"days", 50 * time.Hour, "2d ago"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roundedAge(tt.d); got != tt.want {
				t.Errorf("roundedAge(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestComputeOverallStatus(t *testing.T) {
	t.Run("nil database is not_ready", func(t *testing.T) {
		if got := computeOverallStatus(&Report{}, true); got != "not_ready" {
			t.Errorf("got %q, want not_ready", got)
		}
	})
	t.Run("database error is not_ready", func(t *testing.T) {
		r := &Report{Database: &CheckResult{Status: StatusError}}
		if got := computeOverallStatus(r, true); got != "not_ready" {
			t.Errorf("got %q, want not_ready", got)
		}
	})
	t.Run("healthy is ready", func(t *testing.T) {
		r := &Report{Database: &CheckResult{Status: StatusOK}}
		if got := computeOverallStatus(r, true); got != "ready" {
			t.Errorf("got %q, want ready", got)
		}
	})
	t.Run("failing native dep degrades", func(t *testing.T) {
		r := &Report{
			Database:        &CheckResult{Status: StatusOK},
			NucleiTemplates: &CheckResult{Status: StatusError},
		}
		if got := computeOverallStatus(r, true); got != "degraded" {
			t.Errorf("got %q, want degraded", got)
		}
	})
	t.Run("failing embedded jstangle degrades", func(t *testing.T) {
		r := &Report{
			Database: &CheckResult{Status: StatusOK},
			EmbeddedBinaries: map[string]*CheckResult{
				"jstangle": {Status: StatusError},
			},
		}
		if got := computeOverallStatus(r, true); got != "degraded" {
			t.Errorf("got %q, want degraded", got)
		}
	})
	t.Run("failing embedded audit does not degrade", func(t *testing.T) {
		r := &Report{
			Database: &CheckResult{Status: StatusOK},
			EmbeddedBinaries: map[string]*CheckResult{
				"vigolium-audit": {Status: StatusError},
			},
		}
		if got := computeOverallStatus(r, true); got != "ready" {
			t.Errorf("got %q, want ready", got)
		}
	})
	t.Run("browser warning does not degrade", func(t *testing.T) {
		// A disabled browser (warning) is a user choice, not a failure.
		r := &Report{
			Database: &CheckResult{Status: StatusOK},
			Browser:  &CheckResult{Status: StatusWarning},
		}
		if got := computeOverallStatus(r, true); got != "ready" {
			t.Errorf("got %q, want ready (browser warning is not a failure)", got)
		}
	})
}

func TestAuditPathA(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		r := &Report{
			Tools: map[string]*ToolCheck{"claude": {Status: StatusOK}},
			Audit: &CheckResult{Status: StatusOK},
		}
		got := AuditPathA(r)
		if !got.OK || len(got.Reasons) != 0 {
			t.Errorf("expected OK with no reasons, got %+v", got)
		}
	})
	t.Run("missing claude and disabled audit", func(t *testing.T) {
		got := AuditPathA(&Report{Tools: map[string]*ToolCheck{}})
		if got.OK {
			t.Error("expected not OK")
		}
		if len(got.Reasons) != 2 {
			t.Errorf("expected 2 reasons (claude + audit), got %v", got.Reasons)
		}
	})
}

func TestAuditPathB(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		r := &Report{
			Tools:   map[string]*ToolCheck{"pi": {Status: StatusOK}},
			Piolium: &CheckResult{Status: StatusOK},
		}
		got := AuditPathB(r)
		if !got.OK || len(got.Reasons) != 0 {
			t.Errorf("expected OK with no reasons, got %+v", got)
		}
	})
	t.Run("missing pi and piolium", func(t *testing.T) {
		got := AuditPathB(&Report{Tools: map[string]*ToolCheck{}})
		if got.OK || len(got.Reasons) != 2 {
			t.Errorf("expected not OK with 2 reasons, got %+v", got)
		}
	})
}

func TestHasFixableIssues(t *testing.T) {
	if HasFixableIssues(nil) {
		t.Error("nil report should have no fixable issues")
	}
	// A failing nuclei-templates check is fixable regardless of claude/npm.
	r := &Report{NucleiTemplates: &CheckResult{Status: StatusError}}
	if !HasFixableIssues(r) {
		t.Error("failing nuclei-templates should be fixable")
	}
}

// Deps.Include runs only the checks it selects: an unselected check's probe
// (the chromium launch, jstangle, vigolium-audit, piolium) never runs, its row
// is absent, and the verdict counts only what ran.
func TestRunIncludeSkipsUnselectedProbes(t *testing.T) {
	var called []string
	withProbe(t, func(string) error { called = append(called, "chromium-launch"); return nil })
	swap := func(dst *func() *CheckResult, name string) {
		orig := *dst
		*dst = func() *CheckResult { called = append(called, name); return &CheckResult{Status: StatusOK} }
		t.Cleanup(func() { *dst = orig })
	}
	swap(&jstangleProbe, "jstangle")
	swap(&auditBinaryProbe, "vigolium-audit")
	swap(&pioliumProbe, "piolium")

	only := func(ids ...string) func(string) bool {
		return func(id string) bool { return slices.Contains(ids, id) }
	}
	r := Run(Deps{Include: only("config"), ProbeBrowserLaunch: true, ProbeNetwork: true})
	if len(called) != 0 {
		t.Errorf("unselected probes ran: %v", called)
	}
	if r.Config == nil || r.Database != nil || r.OAST != nil || r.Tools["chromium"] != nil || len(r.EmbeddedBinaries) != 0 || r.Piolium != nil {
		t.Errorf("unselected checks reported: %+v", r)
	}
	if r.Status != "ready" {
		t.Errorf("status = %q, want ready: the database was not asked about", r.Status)
	}
	for _, c := range r.Checks() {
		if c.ID == "database" || c.ID == "chromium" || c.ID == "jstangle" {
			t.Errorf("unselected check %q listed", c.ID)
		}
	}

	// audit is off by default, so selecting it probes nothing.
	called = nil
	r = Run(Deps{Include: only("jstangle", "audit")})
	if !slices.Equal(called, []string{"jstangle"}) {
		t.Errorf("probes = %v, want jstangle only", called)
	}
	if r.EmbeddedBinaries["jstangle"] == nil || r.EmbeddedBinaries["vigolium-audit"] != nil {
		t.Errorf("embedded binary rows = %+v, want jstangle only", r.EmbeddedBinaries)
	}
	if r.Status != "ready" {
		t.Errorf("status = %q, want ready", r.Status)
	}
}

func TestAllCheckIDsCoversTheReport(t *testing.T) {
	r := &Report{
		Config: &CheckResult{}, Scope: &CheckResult{}, Database: &CheckResult{}, Initialized: &CheckResult{},
		NucleiTemplates: &CheckResult{}, OAST: &CheckResult{}, Agent: &AgentCheck{}, SessionsDir: &CheckResult{},
		TemplatesDir: &CheckResult{}, Browser: &CheckResult{}, Audit: &CheckResult{}, Piolium: &CheckResult{}, Skill: &CheckResult{},
		EmbeddedBinaries: map[string]*CheckResult{"jstangle": {}, "vigolium-audit": {}},
		Tools:            map[string]*ToolCheck{},
	}
	for _, id := range []string{"chromium", "bun", "npm", "agent-browser", "pi", "claude", "codex"} {
		r.Tools[id] = &ToolCheck{}
	}
	ids := AllCheckIDs()
	for _, c := range r.Checks() {
		if !slices.Contains(ids, c.ID) {
			t.Errorf("check %q is missing from AllCheckIDs", c.ID)
		}
	}
}
