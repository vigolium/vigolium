package xss_stored

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// fetchProbe is a fake browser probe: it GETs the navigated URL (forwarding any
// Cookie header) and returns the page body as the dialog message. This stands
// in for "the browser loaded the page and the stored script fired alert(canary)"
// — matchCanary then succeeds iff the canary is actually served at that URL.
func fetchProbe(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
	req, err := http.NewRequest("GET", cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return &spitolas.ProbeResult{
		Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: string(b)}},
	}, nil
}

func newTestModule() *Module {
	m := New()
	m.Probe = fetchProbe
	return m
}

func scanCtx() *modkit.ScanContext {
	return &modkit.ScanContext{ParamFindings: &modkit.ParameterFindingRegistry{}}
}

// guestbook is a tiny stored-input app: POST persists c, GET renders it.
type guestbook struct {
	mu           sync.Mutex
	stored       string
	persistOnGet bool // when false, GET renders nothing (so nothing is "stored")
	echoOnPost   bool // when true, the POST response reflects c (reflected-only)
}

func (g *guestbook) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == http.MethodPost {
			c := r.PostFormValue("c")
			g.mu.Lock()
			g.stored = c
			g.mu.Unlock()
			if g.echoOnPost {
				_, _ = w.Write([]byte("<html><body>posted " + c + "</body></html>"))
				return
			}
			_, _ = w.Write([]byte("<html><body>thanks</body></html>"))
			return
		}
		g.mu.Lock()
		s := g.stored
		g.mu.Unlock()
		if g.persistOnGet {
			_, _ = w.Write([]byte("<html><body>comment: " + s + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>no comments</body></html>"))
	}
}

func TestStoredXSSConfirmed(t *testing.T) {
	gb := &guestbook{persistOnGet: true}
	srv := httptest.NewServer(gb.handler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/comment", "c=hello")
	ip := modtest.InsertionPoint(t, rr, "c")

	res, err := newTestModule().ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 stored-XSS finding, got %d", len(res))
	}
	if !strings.Contains(res[0].Info.Description, "STORED") {
		t.Fatalf("finding should be labelled stored: %q", res[0].Info.Description)
	}
}

func TestStoredXSS_NotPersisted(t *testing.T) {
	// Value is accepted but never rendered back → not stored → no finding.
	gb := &guestbook{persistOnGet: false}
	srv := httptest.NewServer(gb.handler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/comment", "c=hello")
	ip := modtest.InsertionPoint(t, rr, "c")

	res, err := newTestModule().ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding when value is not persisted, got %d", len(res))
	}
}

func TestStoredXSS_ReflectedOnlyIsNotStored(t *testing.T) {
	// The POST response reflects the value (reflected XSS territory) but the GET
	// retrieval does not — so the stored module must NOT fire.
	gb := &guestbook{persistOnGet: false, echoOnPost: true}
	srv := httptest.NewServer(gb.handler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/comment", "c=hello")
	ip := modtest.InsertionPoint(t, rr, "c")

	res, err := newTestModule().ScanPerInsertionPoint(rr, ip, client, scanCtx())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("reflected-only must not be reported as stored, got %d", len(res))
	}
}
