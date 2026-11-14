package modtest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func get(t *testing.T, h http.Handler, target string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(body)
}

func TestSafeEchoEscapes(t *testing.T) {
	code, body := get(t, SafeEcho(), "/search?q="+url.QueryEscape(`<script>alert(1)</script>'"`))
	if code != 200 || strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("echo not escaped: %d %s", code, body)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(`{"a":"<b>"}`))
	req.Header.Set("Content-Type", "application/json")
	SafeEcho().ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("JSON echo content type %q", ct)
	}
}

func TestWAFBlock(t *testing.T) {
	h := WAFBlock()
	if code, _ := get(t, h, "/search?q=shoes"); code != 200 {
		t.Fatalf("clean request blocked: %d", code)
	}
	for _, p := range []string{"'", "1 union select 2", "../../etc/passwd", "{{7*7}}"} {
		if code, body := get(t, h, "/search?q="+url.QueryEscape(p)); code != 403 || !strings.Contains(body, "Cloudflare") {
			t.Errorf("payload %q not blocked: %d", p, code)
		}
	}
}

func TestSoft404(t *testing.T) {
	code, body := get(t, Soft404(), "/definitely-missing/.git/config")
	if code != 200 || !strings.Contains(body, "could not find") {
		t.Fatalf("soft 404: %d %s", code, body)
	}
}

func TestRandomContentChanges(t *testing.T) {
	h := RandomContent()
	_, a := get(t, h, "/")
	_, b := get(t, h, "/")
	if a == b {
		t.Fatal("random content repeated")
	}
}

func TestRateLimit429(t *testing.T) {
	h := RateLimit429(2)
	for i, want := range []int{200, 200, 429, 429} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?q=1", nil))
		if rec.Code != want {
			t.Fatalf("request %d: %d, want %d", i, rec.Code, want)
		}
		if want == 429 && rec.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
}

func TestSlowHost(t *testing.T) {
	start := time.Now()
	get(t, SlowHost(30*time.Millisecond, 10*time.Millisecond), "/?q=1")
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Fatalf("slow host answered in %v", d)
	}
}

// scopeModule records which scan methods RunActive calls.
type scopeModule struct {
	scopes modkit.ScanScope
	calls  []string
}

func (m *scopeModule) ID() string                   { return "scope-probe" }
func (m *scopeModule) ScanScopes() modkit.ScanScope { return m.scopes }
func (m *scopeModule) AllowedInsertionPointTypes() modkit.InsertionPointTypeSet {
	return modkit.AllInsertionPointTypes
}
func (m *scopeModule) ScanPerInsertionPoint(_ *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, _ *httpRequester.Requester, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	m.calls = append(m.calls, "ip:"+ip.Name())
	return nil, nil
}
func (m *scopeModule) ScanPerRequest(*httpmsg.HttpRequestResponse, *httpRequester.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error) {
	m.calls = append(m.calls, "request")
	return []*output.ResultEvent{{}}, nil
}
func (m *scopeModule) ScanPerHost(*httpmsg.HttpRequestResponse, *httpRequester.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error) {
	m.calls = append(m.calls, "host")
	return nil, nil
}

// RunActive runs every declared scope, as the executor does (the old harness
// dispatcher ran only the first one).
func TestRunActiveRunsEveryDeclaredScope(t *testing.T) {
	rr := Request(t, "http://example.test/search?q=1")
	m := &scopeModule{scopes: modkit.ScanScopeHost | modkit.ScanScopeRequest | modkit.ScanScopeInsertionPoint}
	events, err := RunActive(m, rr, nil, &modkit.ScanContext{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(m.calls, ",")
	if !strings.HasPrefix(joined, "host,request,") || !strings.Contains(joined, "ip:q") {
		t.Fatalf("calls = %v", m.calls)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}

	if _, err := RunActive(&scopeModule{}, rr, nil, &modkit.ScanContext{}); err == nil {
		t.Fatal("a module with no scan scope must be an error")
	}
}
