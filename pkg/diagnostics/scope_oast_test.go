package diagnostics

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestCheckScope(t *testing.T) {
	s := config.DefaultSettings()
	if got := checkScope(s); got.Status != StatusOK {
		t.Fatalf("default scope: %+v", got)
	}

	s.Scope.Host.Include = []string{"app.example.com"}
	if got := checkScope(s); got.Status != StatusWarning || len(got.Details) != 1 {
		t.Fatalf("restrictive include: %+v", got)
	}

	s.Scope.Host.Include = []string{`["app.example.com"`, `"api.example.com"]`}
	got := checkScope(s)
	if got.Status != StatusError || !strings.Contains(strings.Join(got.Details, "\n"), config.IssueScopePatternInvalid) {
		t.Fatalf("broken include: %+v", got)
	}
}

func TestComputeOverallStatusScope(t *testing.T) {
	ok := &CheckResult{Status: StatusOK}
	r := &Report{Database: ok, Scope: &CheckResult{Status: StatusError}}
	if got := computeOverallStatus(r, true); got != "degraded" {
		t.Fatalf("scope error: got %q, want degraded", got)
	}
	r.Scope = &CheckResult{Status: StatusWarning}
	if got := computeOverallStatus(r, true); got != "ready" {
		t.Fatalf("scope warning: got %q, want ready", got)
	}
	r.Scope = ok
	r.OAST = &CheckResult{Status: StatusWarning}
	if got := computeOverallStatus(r, true); got != "ready" {
		t.Fatalf("oast warning: got %q, want ready", got)
	}
}

// stubOASTNetwork replaces the probe's network seams for one test. dialed
// records the addresses dialled, so a test can assert no probe happened.
func stubOASTNetwork(t *testing.T, lookupErr, dialErr error) *[]string {
	t.Helper()
	var dialed []string
	prevLookup, prevDial := oastLookupHost, oastDialTLS
	oastLookupHost = func(ctx context.Context, host string) ([]string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("lookup without a deadline")
		}
		return []string{"192.0.2.1"}, lookupErr
	}
	oastDialTLS = func(ctx context.Context, addr, serverName string) error {
		dialed = append(dialed, addr+"|"+serverName)
		return dialErr
	}
	t.Cleanup(func() { oastLookupHost, oastDialTLS = prevLookup, prevDial })
	return &dialed
}

func TestCheckOAST(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		dialed := stubOASTNetwork(t, nil, nil)
		s := config.DefaultSettings()
		s.OAST.Enabled = false
		if got := checkOAST(s, true); got.Status != StatusWarning || !strings.Contains(got.Message, "disabled") {
			t.Fatalf("%+v", got)
		}
		if len(*dialed) != 0 {
			t.Fatalf("disabled OAST was probed: %v", *dialed)
		}
	})
	t.Run("fixed url is ok without probing", func(t *testing.T) {
		dialed := stubOASTNetwork(t, nil, errors.New("must not dial"))
		s := config.DefaultSettings()
		s.OAST.OastURL = "cb.example.test"
		if got := checkOAST(s, true); got.Status != StatusOK {
			t.Fatalf("%+v", got)
		}
		if len(*dialed) != 0 {
			t.Fatalf("fixed url was probed: %v", *dialed)
		}
	})
	t.Run("no probe when ProbeNetwork is off", func(t *testing.T) {
		dialed := stubOASTNetwork(t, nil, errors.New("must not dial"))
		if got := checkOAST(config.DefaultSettings(), false); got.Status != StatusOK || !strings.Contains(got.Message, "not probed") {
			t.Fatalf("%+v", got)
		}
		if len(*dialed) != 0 {
			t.Fatalf("probed with ProbeNetwork off: %v", *dialed)
		}
	})
	t.Run("reachable", func(t *testing.T) {
		dialed := stubOASTNetwork(t, nil, nil)
		s := config.DefaultSettings()
		s.OAST.ServerURL = "https://oast.example.test/"
		if got := checkOAST(s, true); got.Status != StatusOK {
			t.Fatalf("%+v", got)
		}
		if len(*dialed) != 1 || (*dialed)[0] != "oast.example.test:443|oast.example.test" {
			t.Fatalf("dialed %v", *dialed)
		}
	})
	t.Run("dns failure", func(t *testing.T) {
		stubOASTNetwork(t, errors.New("no such host"), nil)
		got := checkOAST(config.DefaultSettings(), true)
		if got.Status != StatusWarning || got.Tip != oastUnavailableTip {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("tls failure", func(t *testing.T) {
		dialed := stubOASTNetwork(t, nil, errors.New("connection refused"))
		s := config.DefaultSettings()
		s.OAST.ServerURL = "oast.example.test:8443"
		got := checkOAST(s, true)
		if got.Status != StatusWarning || !strings.Contains(got.Message, "oast.example.test:8443") {
			t.Fatalf("%+v", got)
		}
		if (*dialed)[0] != "oast.example.test:8443|oast.example.test" {
			t.Fatalf("dialed %v", *dialed)
		}
	})
}
