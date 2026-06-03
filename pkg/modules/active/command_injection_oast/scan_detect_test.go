package command_injection_oast

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// fakeOAST is a stand-in OAST provider that returns a fixed host and records the
// parameter names it was asked to generate URLs for.
type fakeOAST struct {
	host    string
	enabled bool
	mu      sync.Mutex
	params  []string
}

func (f *fakeOAST) GenerateURL(_, paramName, _, _, _ string) string {
	f.mu.Lock()
	f.params = append(f.params, paramName)
	f.mu.Unlock()
	return f.host
}
func (f *fakeOAST) Enabled() bool { return f.enabled }

// recordingServer captures the `cmd` query values it receives.
func recordingServer(seen *[]string, mu *sync.Mutex) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*seen = append(*seen, r.URL.Query().Get("cmd"))
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
}

// TestOAST_Param_InjectsHost: with OAST enabled, the module injects payloads that
// embed the unique OAST host into the parameter value.
func TestOAST_Param_InjectsHost(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := recordingServer(&seen, &mu)
	defer srv.Close()

	const host = "abc123unique.oast.example"
	oast := &fakeOAST{host: host, enabled: true}

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/run?cmd=1")
	ip := modtest.InsertionPoint(t, rr, "cmd")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{OASTProvider: oast})
	if err != nil {
		t.Fatalf("ScanPerInsertionPoint: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 synchronous findings (OAST is async), got %d", len(res))
	}

	mu.Lock()
	defer mu.Unlock()
	hostHits := 0
	for _, v := range seen {
		if strings.Contains(v, host) {
			hostHits++
		}
	}
	if hostHits == 0 {
		t.Fatalf("expected at least one request embedding the OAST host in cmd; saw %v", seen)
	}
	if len(oast.params) == 0 || oast.params[0] != "cmd" {
		t.Errorf("expected GenerateURL called for cmd, got %v", oast.params)
	}
}

// TestOAST_Disabled_NoOp: with no OAST provider, the module sends nothing.
func TestOAST_Disabled_NoOp(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := recordingServer(&seen, &mu)
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/run?cmd=1")
	ip := modtest.InsertionPoint(t, rr, "cmd")

	// nil provider
	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerInsertionPoint: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(res))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("expected no requests with OAST disabled, saw %d: %v", len(seen), seen)
	}
}
