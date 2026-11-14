package parammine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// hiddenApp serves endpoints with known hidden parameters:
//
//	/search  debug (adds a debug block: length), callback (JSONP: reflection),
//	         admin (302 to /login: status)
//	/random  alternates between two very different bodies (unstable)
//	/waf     429 for any request with more than one query parameter
//	/api     POST JSON; "isAdmin" adds a field to the answer (length)
func hiddenApp(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	page := strings.Repeat("<li>result row with some ordinary listing text</li>\n", 20)
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		q := r.URL.Query()
		if q.Has("admin") {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		body := "<html><body><ul>\n" + page + "</ul>"
		if q.Has("debug") {
			body += "<pre>" + strings.Repeat("DEBUG sql=SELECT * FROM items WHERE 1 timing=3ms\n", 12) + "</pre>"
		}
		body += "</body></html>"
		if cb := q.Get("callback"); cb != "" {
			body = cb + "(" + body + ")"
		}
		_, _ = io.WriteString(w, body)
	})
	var flip atomic.Int64
	mux.HandleFunc("/random", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Alternates between two renderings of very different size, like a
		// pool of mismatched backends behind one name.
		reps := 1 + 3*int(flip.Add(1)%2)
		_, _ = io.WriteString(w, "<html>"+strings.Repeat(page, reps)+"</html>")
	})
	mux.HandleFunc("/waf", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if len(r.URL.Query()) > 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "slow down")
			return
		}
		_, _ = io.WriteString(w, "<html>"+page+"</html>")
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		out := map[string]any{"ok": true, "items": strings.Split(strings.Repeat("alpha,", 30), ",")}
		if _, ok := in["isAdmin"]; ok {
			out["internal"] = strings.Repeat("secret-config-value ", 20)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

// httpSender sends through net/http without following redirects and returns
// the raw response, the shape the requester-backed Sender produces.
func httpSender(t *testing.T) Sender {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, rr *httpmsg.HttpRequestResponse) (*httpmsg.HttpResponse, error) {
		req := rr.Request()
		u := rr.Service().Protocol() + "://" + rr.Service().Host() + fmt.Sprintf(":%d", rr.Service().Port()) + req.Path()
		hreq, err := http.NewRequestWithContext(ctx, req.Method(), u, bytes.NewReader(req.Body()))
		if err != nil {
			return nil, err
		}
		for _, h := range req.Headers() {
			if strings.EqualFold(h.Name, "Host") || strings.EqualFold(h.Name, "Content-Length") {
				continue
			}
			hreq.Header.Set(h.Name, h.Value)
		}
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, err
		}
		return httpmsg.NewHttpResponse(raw), nil
	}
}

func baseRequest(t *testing.T, method, rawURL, contentType string, body []byte) *httpmsg.HttpRequestResponse {
	t.Helper()
	headers := map[string]string{}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	rr, err := httpmsg.GetRawRequestFromURLWithMethod(rawURL, method, headers, body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return rr
}

// fillerNames returns n distinct names that the test app ignores.
func fillerNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("filler%03d", i)
	}
	return out
}

func hitNames(res Result) map[string]Signal {
	out := make(map[string]Signal)
	for _, h := range res.Hits {
		out[h.Name] = h.Signal
	}
	return out
}

func TestMine_FindsHiddenParamsBySignal(t *testing.T) {
	srv, _ := hiddenApp(t)
	words := append(fillerNames(40), "debug", "callback", "admin")
	words = append(words, fillerNames(60)[40:]...)

	res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/search?q=shoes", "", nil), words, httpSender(t), Config{})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if res.Aborted != "" {
		t.Fatalf("aborted: %s", res.Aborted)
	}
	got := hitNames(res)
	want := map[string]Signal{"debug": SignalLength, "callback": SignalReflect, "admin": SignalStatus}
	if len(got) != len(want) {
		t.Fatalf("hits = %v, want %v", got, want)
	}
	for n, s := range want {
		if got[n] != s {
			t.Errorf("%s: signal %q, want %q (all: %v)", n, got[n], s, got)
		}
	}
	for _, h := range res.Hits {
		if h.Location != LocationQuery {
			t.Errorf("%s: location %q", h.Name, h.Location)
		}
		if h.Exchange == nil || !strings.Contains(h.Exchange.Request().Path(), h.Name+"=") {
			t.Errorf("%s: exchange does not carry the parameter", h.Name)
		}
		if !strings.Contains(h.Exchange.Request().Path(), "q=shoes") {
			t.Errorf("%s: exchange dropped the original query", h.Name)
		}
	}
	if res.Tested != len(words) {
		t.Errorf("tested %d names, want %d", res.Tested, len(words))
	}
	if res.Requests > DefaultMaxRequests {
		t.Errorf("requests %d exceed the budget", res.Requests)
	}
}

// TestMine_GoldenRequestCounts pins the bisection's request arithmetic: two
// baselines, one chunk, two requests per bisection level down to one name,
// then ConfirmRounds re-sends.
func TestMine_GoldenRequestCounts(t *testing.T) {
	srv, hits := hiddenApp(t)
	cases := []struct {
		name  string
		words []string
		want  int
	}{
		// 64 names, debug among them: 2 + 1 + 2*log2(64)=12 + 2 = 17.
		{"one length culprit in 64", append(fillerNames(63), "debug"), 17},
		// Reflection maps straight to the name: 2 + 1 + 2 confirms = 5.
		{"reflection needs no bisection", append(fillerNames(63), "callback"), 5},
		// Nothing hidden: 2 baselines + 1 chunk.
		{"clean list", fillerNames(64), 3},
		// 300 names split by the 256-name cap into two chunks: 2 + 2.
		{"chunk cap", fillerNames(300), 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := hits.Load()
			res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/search", "", nil), tc.words, httpSender(t), Config{})
			if err != nil {
				t.Fatalf("Mine: %v", err)
			}
			if res.Requests != tc.want {
				t.Errorf("requests = %d, want %d (hits %v)", res.Requests, tc.want, hitNames(res))
			}
			if sent := hits.Load() - before; sent != int64(res.Requests) {
				t.Errorf("server saw %d requests, Result says %d", sent, res.Requests)
			}
		})
	}
}

func TestMine_UnstableEndpointAborts(t *testing.T) {
	srv, hits := hiddenApp(t)
	before := hits.Load()
	res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/random", "", nil), append(fillerNames(50), "debug"), httpSender(t), Config{})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if res.Aborted != AbortUnstable {
		t.Fatalf("aborted = %q, want %q", res.Aborted, AbortUnstable)
	}
	if len(res.Hits) != 0 || res.Requests != 2 || hits.Load()-before != 2 {
		t.Errorf("unstable endpoint: hits %v, requests %d, server saw %d; want none after the 2 baselines", hitNames(res), res.Requests, hits.Load()-before)
	}
}

func TestMine_BlockBurstAborts(t *testing.T) {
	srv, _ := hiddenApp(t)
	res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/waf", "", nil), fillerNames(200), httpSender(t), Config{})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if res.Aborted != AbortBlocked {
		t.Fatalf("aborted = %q, want %q", res.Aborted, AbortBlocked)
	}
	// Baselines, then the chunk and both halves answer 429: three in a row.
	if res.Requests != 5 {
		t.Errorf("requests = %d, want 5", res.Requests)
	}
}

func TestMine_BudgetStopsMining(t *testing.T) {
	srv, _ := hiddenApp(t)
	res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/search", "", nil), append(fillerNames(63), "debug"), httpSender(t), Config{MaxRequests: 6})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	// The scan stops short of the budget (the rest is the confirmation
	// reserve); with nothing isolated yet the reserve goes unspent.
	if res.Aborted != AbortBudget || res.Requests > 6 {
		t.Errorf("aborted %q after %d requests, want %q within 6", res.Aborted, res.Requests, AbortBudget)
	}
}

func TestMine_JSONBody(t *testing.T) {
	srv, _ := hiddenApp(t)
	base := baseRequest(t, "POST", srv.URL+"/api", "application/json", []byte(`{"name":"x"}`))
	res, err := Mine(context.Background(), base, append(fillerNames(30), "isAdmin", "name"), httpSender(t), Config{})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if res.Location != LocationJSON {
		t.Fatalf("location = %q", res.Location)
	}
	got := hitNames(res)
	if len(got) != 1 || got["isAdmin"] != SignalLength {
		t.Fatalf("hits = %v, want isAdmin by length", got)
	}
	var sent map[string]any
	if err := json.Unmarshal(res.Hits[0].Exchange.Request().Body(), &sent); err != nil {
		t.Fatalf("exchange body is not JSON: %v", err)
	}
	if sent["name"] != "x" || sent["isAdmin"] == nil {
		t.Errorf("exchange body %v should keep name and add isAdmin", sent)
	}
	if res.Tested != 31 {
		t.Errorf("tested %d, want 31 (the existing name is skipped)", res.Tested)
	}
}

func TestChunkRespectsByteBudget(t *testing.T) {
	base := baseRequest(t, "GET", "http://example.test/p", "", nil)
	b, err := newBuilder(base, "")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 500)
	for i := range names {
		names[i] = fmt.Sprintf("parameter_name_%04d", i)
	}
	cfg := Config{MaxQueryBytes: 1024}.withDefaults()
	chunks := b.chunk(names, cfg)
	total := 0
	for _, c := range chunks {
		total += len(c)
		req, err := b.build(withCanaries(c))
		if err != nil {
			t.Fatal(err)
		}
		if l := len(req.Request().Path()); l > cfg.MaxQueryBytes {
			t.Errorf("chunk of %d names builds a %d-byte target, over %d", len(c), l, cfg.MaxQueryBytes)
		}
	}
	if total != len(names) {
		t.Errorf("chunks hold %d names, want %d", total, len(names))
	}
}

func TestMergeWordlists(t *testing.T) {
	got := MergeWordlists(0, []string{"b", "a", "bad name", "a"}, []string{"c", "b", "x=y"})
	if strings.Join(got, ",") != "b,a,c" {
		t.Errorf("merge = %v", got)
	}
	if got := MergeWordlists(2, []string{"a", "b", "c"}); len(got) != 2 {
		t.Errorf("max not applied: %v", got)
	}
}

func TestBuiltinWordlist(t *testing.T) {
	names, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if len(names) < 1000 || len(names) > 2500 {
		t.Errorf("built-in list has %d names, want ~1-2k", len(names))
	}
	seen := make(map[string]bool)
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate %q", n)
		}
		seen[n] = true
	}
	for _, must := range []string{"debug", "callback", "admin", "redirect_uri", "user_id"} {
		if !seen[must] {
			t.Errorf("built-in list lacks %q", must)
		}
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	if strings.Join(sorted, ",") == strings.Join(names, ",") {
		t.Error("built-in list is alphabetical; it should be ordered by likelihood")
	}
}
