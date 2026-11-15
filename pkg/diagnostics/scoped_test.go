package diagnostics

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

func stubScoped(t *testing.T, free, fds uint64) {
	t.Helper()
	pf, pfd := scopedFreeBytes, scopedFDLimit
	scopedFreeBytes = func(string) (uint64, bool) { return free, true }
	scopedFDLimit = func() (uint64, bool) { return fds, true }
	t.Cleanup(func() { scopedFreeBytes, scopedFDLimit = pf, pfd })
}

func healthyReport() *Report {
	return &Report{
		Config:           &CheckResult{Status: StatusOK},
		Scope:            &CheckResult{Status: StatusOK},
		OAST:             &CheckResult{Status: StatusOK},
		Database:         &CheckResult{Status: StatusOK},
		Tools:            map[string]*ToolCheck{"chromium": {Status: StatusOK, Path: "/bin/chrome"}},
		NucleiTemplates:  &CheckResult{Status: StatusOK},
		EmbeddedBinaries: map[string]*CheckResult{"jstangle": {Status: StatusOK}},
		Agent:            &AgentCheck{Status: StatusOK, Name: "olium"},
		SessionsDir:      &CheckResult{Status: StatusOK},
		TemplatesDir:     &CheckResult{Status: StatusOK},
	}
}

func checkByID(r *ScopedReport, id string) *ScopedCheck {
	for i := range r.Checks {
		if r.Checks[i].ID == id {
			return &r.Checks[i]
		}
	}
	return nil
}

// TestScoped_Verdicts: the scoped verdict is the worst counted
// check; uncounted checks are reported only.
func TestScoped_Verdicts(t *testing.T) {
	settings := config.DefaultSettings()
	settings.KnownIssueScan.TemplatesDir = t.TempDir()

	stubScoped(t, 50<<30, 65535)
	r, err := Scoped(PurposeScan, healthyReport(), ScopedDeps{Settings: settings})
	if err != nil || r.Status != "ready" {
		t.Fatalf("healthy scan = %v %v %+v", r.Status, err, r.Checks)
	}

	stubScoped(t, 100<<20, 65535) // 100 MB free
	if r, _ := Scoped(PurposeScan, healthyReport(), ScopedDeps{Settings: settings}); r.Status != "not_ready" {
		t.Errorf("100 MB free = %s, want not_ready", r.Status)
	}
	stubScoped(t, 500<<20, 1024)
	r, _ = Scoped(PurposeScan, healthyReport(), ScopedDeps{Settings: settings})
	if r.Status != "degraded" || checkByID(r, "fd_limit").Status != ScopedDegraded || checkByID(r, "disk").Status != ScopedDegraded {
		t.Errorf("500 MB + fd 1024 = %s %+v, want degraded", r.Status, r.Checks)
	}

	stubScoped(t, 50<<30, 65535)
	bad := healthyReport()
	bad.Database = &CheckResult{Status: StatusError, Message: "locked"}
	if r, _ := Scoped(PurposeScan, bad, ScopedDeps{Settings: settings}); r.Status != "not_ready" {
		t.Errorf("db error = %s, want not_ready", r.Status)
	}
	r, _ = Scoped(PurposeScan, bad, ScopedDeps{Settings: settings, Stateless: true})
	if r.Status != "ready" || checkByID(r, "database").Status != ScopedSkipped {
		t.Errorf("-S with db error = %s, want ready with database skipped", r.Status)
	}

	// Missing templates degrade the scan.
	noTmpl := healthyReport()
	noTmpl.NucleiTemplates = &CheckResult{Status: StatusWarning, Message: "missing"}
	r, _ = Scoped(PurposeScan, noTmpl, ScopedDeps{Settings: settings})
	if r.Status != "degraded" {
		t.Errorf("missing templates = %s %+v", r.Status, r.Checks)
	}
	if fix := checkByID(r, "nuclei_templates").FixArgv; len(fix) == 0 {
		t.Error("missing templates carry no fix_argv")
	}

	// Stale templates are reported, not counted.
	old := scopedNow
	scopedNow = func() time.Time { return time.Now().Add(60 * 24 * time.Hour) }
	t.Cleanup(func() { scopedNow = old })
	r, _ = Scoped(PurposeScan, healthyReport(), ScopedDeps{Settings: settings})
	if c := checkByID(r, "nuclei_templates"); c.Status != ScopedWarning || c.Counts || r.Status != "ready" {
		t.Errorf("stale templates = %+v, verdict %s", c, r.Status)
	}
	scopedNow = old

	// A broken agent does not stop a scan, and does stop the agent.
	agentDown := healthyReport()
	agentDown.Agent = &AgentCheck{Status: StatusError, Name: "olium", Message: "no provider"}
	if r, _ := Scoped(PurposeScan, agentDown, ScopedDeps{Settings: settings}); r.Status != "ready" {
		t.Errorf("agent down for scan = %s, want ready", r.Status)
	}
	if r, _ := Scoped(PurposeAgent, agentDown, ScopedDeps{Settings: settings}); r.Status != "not_ready" {
		t.Errorf("agent down for agent = %s, want not_ready", r.Status)
	}

	if _, err := Scoped("bogus", healthyReport(), ScopedDeps{}); err == nil {
		t.Error("unknown purpose accepted")
	}
}

// TestScoped_TargetChecks: -t adds DNS/TCP/TLS rows; a name that does not
// resolve is not_ready.
func TestScoped_TargetChecks(t *testing.T) {
	stubScoped(t, 50<<30, 65535)
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	r, _ := Scoped(PurposeScan, healthyReport(), ScopedDeps{Settings: config.DefaultSettings(), Target: srv.URL})
	if c := checkByID(r, "target_tls"); c == nil || c.Status != ScopedOK {
		t.Fatalf("TLS check = %+v (%+v)", c, r.Checks)
	}

	prev := scopedLookupHost
	scopedLookupHost = func(context.Context, string) ([]string, error) { return nil, &net.DNSError{Err: "no such host"} }
	t.Cleanup(func() { scopedLookupHost = prev })
	r, _ = Scoped(PurposeScan, healthyReport(), ScopedDeps{Settings: config.DefaultSettings(), Target: "https://nope.invalid"})
	if c := checkByID(r, "target_dns"); c == nil || c.Status != ScopedNotReady || r.Status != "not_ready" {
		t.Fatalf("dns failure = %+v, verdict %s", c, r.Status)
	}
}

// TestScoped_EnvironmentProxy: a proxy from the environment is checked like
// --proxy and named with its variable; a NO_PROXY target is probed directly.
func TestScoped_EnvironmentProxy(t *testing.T) {
	stubScoped(t, 50<<30, 65535)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	env := map[string]string{"HTTPS_PROXY": "http://" + ln.Addr().String(), "NO_PROXY": "127.0.0.1"}
	deps := ScopedDeps{Settings: config.DefaultSettings(), Target: srv.URL, Getenv: func(k string) string { return env[k] }}
	r, _ := Scoped(PurposeScan, healthyReport(), deps)
	c := checkByID(r, "proxy")
	if c == nil || c.Status != ScopedOK || !strings.Contains(c.Message, "from HTTPS_PROXY") || !strings.Contains(c.Message, "NO_PROXY=127.0.0.1") {
		t.Fatalf("proxy check = %+v", c)
	}
	if c := checkByID(r, "target_tls"); c == nil || c.Status != ScopedOK {
		t.Fatalf("a NO_PROXY target is probed directly: %+v", r.Checks)
	}

	delete(env, "NO_PROXY")
	r, _ = Scoped(PurposeScan, healthyReport(), deps)
	if c := checkByID(r, "target_dns"); c == nil || c.Status != ScopedSkipped || !strings.Contains(c.Message, ln.Addr().String()) {
		t.Fatalf("a proxied target names its proxy: %+v", r.Checks)
	}
}
