package fuzz

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/replay"
)

func TestLoadPayloads(t *testing.T) {
	got, err := LoadPayloads([]string{"fuzz"}, nil, []string{"custom-1", "custom-2", "custom-1"})
	if err != nil {
		t.Fatalf("LoadPayloads: %v", err)
	}
	if len(got) < 3 {
		t.Fatalf("expected builtin fuzz list + inline, got %d", len(got))
	}
	// Inline dedup: custom-1 appears once.
	var n int
	for _, p := range got {
		if p == "custom-1" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected custom-1 once (dedup), got %d", n)
	}

	// Class expansion (canonical + alias both resolve).
	sqli, err := LoadPayloads(nil, []string{"sqli"}, nil)
	if err != nil || len(sqli) == 0 {
		t.Fatalf("class sqli: got %d payloads, err=%v", len(sqli), err)
	}
	if _, err := LoadPayloads(nil, []string{"traversal"}, nil); err != nil {
		t.Fatalf("class alias traversal should resolve: %v", err)
	}
	if _, err := LoadPayloads(nil, []string{"not-a-class"}, nil); err == nil {
		t.Fatal("expected error for unknown class")
	}

	if _, err := LoadPayloads(nil, nil, nil); err == nil {
		t.Fatal("expected error when no payloads supplied")
	}
	if _, err := LoadPayloads([]string{"/no/such/wordlist/here"}, nil, nil); err == nil {
		t.Fatal("expected error for missing wordlist that is not a builtin")
	}
}

func TestNormalizeRawRequest(t *testing.T) {
	// Header-only request with the terminator stripped (stdin reader case).
	got := NormalizeRawRequest([]byte("GET /?q=1 HTTP/1.1\r\nHost: acme.test"))
	if !strings.HasSuffix(string(got), "\r\n\r\n") {
		t.Fatalf("expected re-appended terminator, got %q", got)
	}
	// Already-terminated request is unchanged (idempotent).
	full := []byte("GET / HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	if got := NormalizeRawRequest(full); string(got) != string(full) {
		t.Fatalf("terminated request should be unchanged, got %q", got)
	}
	// A request with a body (separator present) is left alone.
	body := []byte("POST / HTTP/1.1\r\nHost: acme.test\r\nContent-Length: 3\r\n\r\nabc")
	if got := NormalizeRawRequest(body); string(got) != string(body) {
		t.Fatalf("body request should be unchanged, got %q", got)
	}
}

func TestResolvePositionsMarkerWins(t *testing.T) {
	raw := []byte("GET /?q=FUZZ HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	pos, err := ResolvePositions(raw, Selectors{Mode: "headers"}) // marker present → overrides mode
	if err != nil {
		t.Fatalf("ResolvePositions: %v", err)
	}
	if len(pos) != 1 || pos[0].kind != kindMarker || pos[0].Label != "MARKER" {
		t.Fatalf("expected single marker position, got %+v", pos)
	}
}

func TestMarkerRequestLineEncoding(t *testing.T) {
	raw := []byte("GET /?q=FUZZ HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	pos := Position{Name: "FUZZ", Label: "MARKER", kind: kindMarker}
	// Spaces must be encoded (they'd break the request line); apostrophes stay
	// literal so the SQLi payload still reaches the parameter meaningfully.
	got := string(pos.build(raw, "' OR '1'='1"))
	if !strings.HasPrefix(got, "GET /?q='%20OR%20'1'='1 HTTP/1.1\r\n") {
		t.Fatalf("request-line payload not encoded safely: %q", got)
	}
	if _, err := http.ReadRequest(bufio.NewReader(strings.NewReader(got))); err != nil {
		t.Fatalf("encoded request should parse: %v", err)
	}
	// A marker in a header stays literal (spaces are legal there).
	rawH := []byte("GET / HTTP/1.1\r\nHost: acme.test\r\nX-T: FUZZ\r\n\r\n")
	posH := Position{Name: "FUZZ", kind: kindMarker}
	if !strings.Contains(string(posH.build(rawH, "a b c")), "X-T: a b c\r\n") {
		t.Fatalf("header marker should be literal")
	}
}

func TestResolvePositionsSelectors(t *testing.T) {
	raw := []byte("GET /?id=1&name=bob HTTP/1.1\r\nHost: acme.test\r\n\r\n")

	params, err := ResolvePositions(raw, Selectors{Mode: "params"})
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	if len(params) != 2 {
		t.Fatalf("expected 2 param positions, got %d (%+v)", len(params), params)
	}

	m, err := ResolvePositions(raw, Selectors{Mode: "method"})
	if err != nil {
		t.Fatalf("method: %v", err)
	}
	if len(m) != 1 || m[0].kind != kindMethod {
		t.Fatalf("expected method position, got %+v", m)
	}

	if _, err := ResolvePositions(raw, Selectors{Mode: "bogus"}); err == nil {
		t.Fatal("expected error for unknown selector")
	}
}

func TestKeepGate(t *testing.T) {
	body := []byte("hello world error")
	r := Result{Status: 500, Length: 100, Words: 3, Lines: 0}

	// Matcher: status 500 keeps.
	if !keep(r, body, Matchers{Status: []int{500}}, Filters{}) {
		t.Fatal("status matcher should keep 500")
	}
	// Matcher: status 200 only → drop.
	if keep(r, body, Matchers{Status: []int{200}}, Filters{}) {
		t.Fatal("status matcher 200 should drop 500")
	}
	// Filter: status 500 drops even with matching matcher.
	if keep(r, body, Matchers{AllStatus: true}, Filters{Status: []int{500}}) {
		t.Fatal("status filter should drop 500")
	}
	// Empty matcher = keep all (no filter).
	if !keep(r, body, Matchers{}, Filters{}) {
		t.Fatal("empty gate should keep")
	}
}

func TestCountWordsLines(t *testing.T) {
	body := []byte("a b c\nd e\n")
	if got := countWords(body); got != 5 {
		t.Fatalf("countWords = %d, want 5", got)
	}
	if got := countLines(body); got != 2 {
		t.Fatalf("countLines = %d, want 2", got)
	}
}

// TestRunEndToEnd exercises baseline + calibration + matcher gating against a
// live server: a catch-all body for unknown/calibration values (should be
// suppressed) and a distinctive 500 for the "boom" payload (should match).
func TestRunEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch {
		case q == "boom":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "SQL syntax error near 'boom' — a distinctive body that differs in size")
		case strings.Contains(q, "vglm-calibrate"):
			// Wildcard/catch-all: identical for every improbable value.
			_, _ = fmt.Fprint(w, "CATCHALL")
		default:
			_, _ = fmt.Fprint(w, "CATCHALL")
		}
	}))
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	raw := []byte("GET /?q=FUZZ HTTP/1.1\r\nHost: " + host + "\r\n\r\n")

	var (
		mu      sync.Mutex
		results []Result
	)
	job := Job{
		Raw:           raw,
		Scheme:        "http",
		Hostname:      host,
		Port:          port,
		Payloads:      []string{"boom", "harmless-1", "harmless-2"},
		Matchers:      Matchers{Status: []int{500}},
		AutoCalibrate: true,
		Client:        replay.NewDefaultClient(nil, 5*time.Second),
		Concurrency:   4,
		OnResult: func(r Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
	}
	positions, err := ResolvePositions(raw, Selectors{})
	if err != nil {
		t.Fatalf("ResolvePositions: %v", err)
	}
	job.Positions = positions

	report, err := Run(context.Background(), job)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Sent != 3 {
		t.Fatalf("Sent = %d, want 3", report.Sent)
	}

	var boomMatched, harmlessCalibrated int
	for _, r := range results {
		switch r.Payload {
		case "boom":
			if r.Status != 500 {
				t.Fatalf("boom status = %d, want 500", r.Status)
			}
			if r.Matched {
				boomMatched++
			}
		default:
			if r.Calibrated {
				harmlessCalibrated++
			}
		}
	}
	if boomMatched != 1 {
		t.Fatalf("expected boom to match once, got %d (results=%+v)", boomMatched, results)
	}
	if harmlessCalibrated == 0 {
		t.Fatal("expected the catch-all harmless payloads to be calibration-suppressed")
	}
}

func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return u.Hostname(), p
}
