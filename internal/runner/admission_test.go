package runner

import (
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func admissionScope(mut func(*config.ScopeConfig)) config.ScopeConfig {
	c := *config.DefaultScopeConfig()
	if mut != nil {
		mut(&c)
	}
	return c
}

func TestAdmitTargetsMixed(t *testing.T) {
	t.Parallel()
	scope := admissionScope(func(c *config.ScopeConfig) {
		c.Host = config.ScopeRule{Include: []string{"*.example.com"}}
		c.Path = config.ScopeRule{Include: []string{"*"}, Exclude: []string{"/logout*"}}
	})
	targets := []string{
		"https://app.example.com/",
		"https://other.test/",
		"api.example.com:8443/v1?x=1", // schemeless, port and query
		"https://app.example.com/logout",
		"https://app.example.com/logo.png",
	}
	adm := AdmitTargets(scope, targets)

	wantAdmitted := []string{"https://app.example.com/", "api.example.com:8443/v1?x=1"}
	if !reflect.DeepEqual(adm.Admitted, wantAdmitted) {
		t.Errorf("Admitted = %v, want %v", adm.Admitted, wantAdmitted)
	}
	wantRejected := []TargetVerdict{
		{Target: "https://other.test/", Host: "other.test", Rule: config.ScopeRuleHostInclude},
		{Target: "https://app.example.com/logout", Host: "app.example.com", Rule: config.ScopeRulePathExclude},
		{Target: "https://app.example.com/logo.png", Host: "app.example.com", Rule: config.ScopeRuleStaticFile},
	}
	if !reflect.DeepEqual(adm.Rejected, wantRejected) {
		t.Errorf("Rejected = %+v, want %+v", adm.Rejected, wantRejected)
	}
	if adm.Requested() != len(targets) || adm.NoneAdmitted() {
		t.Errorf("Requested=%d NoneAdmitted=%v", adm.Requested(), adm.NoneAdmitted())
	}
}

// Origin mode is built from the target list itself, so it can never reject one
// of those targets: every target's host is in the exact-host index.
func TestAdmitTargetsOriginModeNeverRejectsTargets(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"strict", "balanced", "relaxed"} {
		scope := admissionScope(func(c *config.ScopeConfig) { c.CLIOriginMode = mode })
		targets := []string{"https://a.example.com", "http://10.1.2.3:8080/x", "intranet:3000", "https://b.other.org/p"}
		adm := AdmitTargets(scope, targets)
		if len(adm.Rejected) != 0 {
			t.Errorf("mode %s: Rejected = %+v, want none", mode, adm.Rejected)
		}
	}
}

func TestAdmitTargetsHostExcludeBeatsOrigin(t *testing.T) {
	t.Parallel()
	scope := admissionScope(func(c *config.ScopeConfig) {
		c.CLIOriginMode = "strict"
		c.Host = config.ScopeRule{Include: []string{"*"}, Exclude: []string{"admin.example.com"}}
	})
	adm := AdmitTargets(scope, []string{"https://admin.example.com/"})
	if !adm.NoneAdmitted() {
		t.Fatalf("expected none admitted, got %+v", adm)
	}
	if got := adm.Rejected[0].Rule; got != config.ScopeRuleHostExclude {
		t.Errorf("Rule = %q, want %q", got, config.ScopeRuleHostExclude)
	}
}

// The admission must be the verdict the executor enforces: for every target,
// "admitted" iff the runner's matcher passes the executor's pre-send check.
func TestAdmitTargetsMatchesExecutorPreSendCheck(t *testing.T) {
	t.Parallel()
	scope := admissionScope(func(c *config.ScopeConfig) {
		c.Host = config.ScopeRule{Include: []string{"nomatch.example"}}
	})
	targets := []string{"http://127.0.0.1:8080/", "https://nomatch.example/a"}
	adm := AdmitTargets(scope, targets)
	matcher := config.NewScopeMatcher(scope, targets...)
	admitted := map[string]bool{}
	for _, a := range adm.Admitted {
		admitted[a] = true
	}
	for _, target := range targets {
		host, _, path, ok := admissionHostPath(target)
		if !ok {
			t.Fatalf("admissionHostPath(%q) failed", target)
		}
		if want := matcher.InScopeRequest(host, path, "", ""); admitted[target] != want {
			t.Errorf("%s: admitted=%v, executor pre-send check=%v", target, admitted[target], want)
		}
	}
	if len(adm.Rejected) != 1 || adm.Rejected[0].Rule != config.ScopeRuleHostInclude {
		t.Errorf("Rejected = %+v", adm.Rejected)
	}
}

func TestAdmitTargetsEmptyAndUnparseable(t *testing.T) {
	t.Parallel()
	scope := admissionScope(func(c *config.ScopeConfig) {
		c.Host = config.ScopeRule{Include: []string{"nomatch.example"}}
	})
	if adm := AdmitTargets(scope, nil); adm.Requested() != 0 || adm.NoneAdmitted() {
		t.Errorf("empty: %+v", adm)
	}
	// Unparseable targets are admitted: scope cannot judge them, and the input
	// error belongs to whoever parses the target next.
	adm := AdmitTargets(scope, []string{"http://[::1", "   "})
	if len(adm.Admitted) != 2 || len(adm.Rejected) != 0 {
		t.Errorf("unparseable: %+v", adm)
	}
}
