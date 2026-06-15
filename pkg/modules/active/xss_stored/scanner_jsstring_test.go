package xss_stored

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// storedOpChainRe matches an operator-chaining breakout carrying the stored canary.
var storedOpChainRe = regexp.MustCompile("[\\^-]alert\\(`(vig-sx-[0-9a-f]+)`\\)[\\^-]")

// jsExecProbe models a real browser on a page that renders the stored value into
// a JS *expression*: it GETs the page and fires the alert ONLY when the rendered
// script carries an operator-chaining breakout. The universal svg payload (which
// can't execute inside an array literal) never pops.
func jsExecProbe(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
	resp, err := http.Get(cfg.URL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	mm := storedOpChainRe.FindSubmatch(b)
	if mm == nil {
		return &spitolas.ProbeResult{}, nil
	}
	return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: string(mm[1])}}}, nil
}

// jsStore is a guestbook that renders the stored value inside a single-quoted JS
// string in an array literal — an expression where only operator chaining runs.
type jsStore struct {
	mu     sync.Mutex
	stored string
}

func (s *jsStore) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == http.MethodPost {
			s.mu.Lock()
			s.stored = r.PostFormValue("c")
			s.mu.Unlock()
			_, _ = w.Write([]byte("<html><body>thanks</body></html>"))
			return
		}
		s.mu.Lock()
		v := s.stored
		s.mu.Unlock()
		_, _ = w.Write([]byte(`<html><body><script>var cfg = ['` + v + `'];</script></body></html>`))
	}
}

func TestStoredXSS_JSStringBreakoutFallback(t *testing.T) {
	srv := httptest.NewServer((&jsStore{}).handler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/comment", "c=hello")
	ip := modtest.InsertionPoint(t, rr, "c")

	m := New()
	m.Probe = jsExecProbe

	res, err := m.ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected the stored js-string fallback to confirm 1 finding, got %d", len(res))
	}
	if !strings.Contains(res[0].Info.Description, "STORED") {
		t.Fatalf("finding should be labelled stored: %q", res[0].Info.Description)
	}
	if !strings.Contains(res[0].Info.Description, "js-string-breakout") {
		t.Fatalf("finding should note the js-string breakout: %q", res[0].Info.Description)
	}
}
