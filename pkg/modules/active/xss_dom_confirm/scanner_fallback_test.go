package xss_dom_confirm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// echoProbe is a fake browser probe: it never launches a browser, it just
// reports a dialog whose message is the navigated URL. Because attempt() only
// calls Probe after the prefilter confirms the canary reflected, matchCanary
// (which substring-matches the canary in the dialog message) then succeeds.
func echoProbe(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
	return &spitolas.ProbeResult{
		Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: cfg.URL}},
	}, nil
}

func newTestModule() *Module {
	m := New()
	m.Probe = echoProbe
	return m
}

func scanCtx() *modkit.ScanContext {
	return &modkit.ScanContext{
		ParamFindings: &modkit.ParameterFindingRegistry{},
		WAFStack:      modkit.NewWAFRegistry(),
	}
}

// TestPlainAttemptStillSucceeds locks the pre-existing behavior: when the app
// reflects the canary directly, the plain attempt confirms with no WAF detour.
func TestPlainAttemptStillSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hi")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := newTestModule().ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding from the plain attempt, got %d", len(res))
	}
	if strings.Contains(res[0].Info.Description, "waf-bypass") {
		t.Fatalf("plain success must not carry a waf-bypass note: %q", res[0].Info.Description)
	}
}

// TestWAFFallbackConfirms exercises the new path: the un-mutated payload is
// blocked by a (simulated) Cloudflare WAF, but the backtick-mutated variant
// slips through and is confirmed.
func TestWAFFallbackConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// The backtick mutation rewrites alert(x) -> alert`x`; that variant is
		// allowed through and reflected, everything else is blocked.
		if strings.Contains(q, "alert`") {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>" + q + "</body></html>"))
			return
		}
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "deadbeef")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Attention Required! | Cloudflare"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hi")
	ip := modtest.InsertionPoint(t, rr, "q")

	sc := scanCtx()
	res, err := newTestModule().ScanPerInsertionPoint(rr, ip, client, sc)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected the WAF-bypass fallback to confirm 1 finding, got %d", len(res))
	}
	if !strings.Contains(res[0].Info.Description, "waf-bypass: cloudflare") {
		t.Fatalf("finding should note the cloudflare bypass: %q", res[0].Info.Description)
	}
	urlx, _ := rr.URL()
	if got := sc.DetectedWAF(urlx.Host); got != "cloudflare" {
		t.Fatalf("WAF should be recorded on the host registry, got %q", got)
	}
}

// TestNoWAFNoFallback confirms the fallback adds no behavior when the plain
// attempt fails on a clean (non-WAF) response: no finding, no detour.
func TestNoWAFNoFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>nothing reflected</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hi")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := newTestModule().ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding without reflection or WAF, got %d", len(res))
	}
}
