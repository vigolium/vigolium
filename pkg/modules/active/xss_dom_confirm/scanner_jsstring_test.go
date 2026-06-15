package xss_dom_confirm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// jsOpChainRe matches an operator-chaining breakout (decoded) carrying the canary.
var jsOpChainRe = regexp.MustCompile("[\\^-]alert\\(`(vig-x-[0-9a-f]+)`\\)[\\^-]")

// jsContextProbe models a browser on a page that reflects into a JS *expression*:
// it fires the alert only when navigated with an operator-chaining payload and
// stays silent for the universal HTML/svg payload, which can't execute there.
func jsContextProbe(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
	decoded, err := url.QueryUnescape(cfg.URL)
	if err != nil {
		decoded = cfg.URL
	}
	mm := jsOpChainRe.FindStringSubmatch(decoded)
	if len(mm) < 2 {
		return &spitolas.ProbeResult{}, nil
	}
	return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: mm[1]}}}, nil
}

// TestJSStringBreakoutFallbackConfirms exercises the new fallback: the canary
// reflects inside a single-quoted JS string in an expression (an array literal),
// where the universal svg payload can't execute. The operator-chaining breakout
// must then drive a browser-confirmed finding tagged [js-string-breakout].
func TestJSStringBreakoutFallbackConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>var cfg = ['` + q + `'];</script></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hi")
	ip := modtest.InsertionPoint(t, rr, "q")

	m := New()
	m.Probe = jsContextProbe

	res, err := m.ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected the js-string fallback to confirm 1 finding, got %d", len(res))
	}
	if !strings.Contains(res[0].Info.Description, "js-string-breakout") {
		t.Fatalf("finding should note the js-string breakout: %q", res[0].Info.Description)
	}
}
