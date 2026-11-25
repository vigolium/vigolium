package parammine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// headerApp reads three request headers no client sends: X-Debug adds a debug
// block (length), X-Forwarded-Host is echoed into a link (reflection),
// X-Original-URL reroutes to a login redirect (status).
func headerApp(t *testing.T) *httptest.Server {
	t.Helper()
	page := strings.Repeat("<li>ordinary listing row text</li>\n", 25)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Original-URL") != "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		body := "<html><ul>" + page + "</ul>"
		if r.Header.Get("X-Debug") != "" {
			body += "<pre>" + strings.Repeat("DEBUG handler=list db=12ms cache=miss\n", 15) + "</pre>"
		}
		if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
			body += `<a href="https://` + fh + `/next">next</a>`
		}
		_, _ = io.WriteString(w, body+"</html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMine_HeaderLocation(t *testing.T) {
	srv := headerApp(t)
	words := append(fillerHeaders(30), "X-Debug", "X-Forwarded-Host", "X-Original-URL")
	words = append(words, fillerHeaders(45)[30:]...)

	res, err := Mine(context.Background(), baseRequest(t, "GET", srv.URL+"/list", "", nil), words, httpSender(t),
		Config{Location: LocationHeader, MaxRequests: 80})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if res.Aborted != "" || res.Location != LocationHeader {
		t.Fatalf("result = %+v", res)
	}
	got := hitNames(res)
	want := map[string]Signal{"X-Debug": SignalLength, "X-Forwarded-Host": SignalReflect, "X-Original-URL": SignalStatus}
	if len(got) != len(want) {
		t.Fatalf("hits = %v, want %v", got, want)
	}
	for n, s := range want {
		if got[n] != s {
			t.Errorf("%s: signal %q, want %q", n, got[n], s)
		}
	}
	for _, h := range res.Hits {
		if h.Location != LocationHeader {
			t.Errorf("%s: location %q", h.Name, h.Location)
		}
		if h.Exchange == nil || h.Exchange.Request().Header(h.Name) == "" {
			t.Errorf("%s: confirming exchange does not carry the header", h.Name)
		}
		if strings.Contains(h.Exchange.Request().Path(), "?") {
			t.Errorf("%s: header mining touched the query: %s", h.Name, h.Exchange.Request().Path())
		}
	}
}

// Header names are tokens; framing, routing and session headers, and headers
// the request already sends (any case), are never mined.
func TestHeaderLocation_FiltersNames(t *testing.T) {
	base, err := httpmsg.GetRawRequestFromURLWithMethod("https://app.test/", "POST", map[string]string{"X-Api-Key": "k"}, []byte("a=1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBuilder(base, LocationHeader)
	if err != nil {
		t.Fatal(err)
	}
	got := b.filterExisting([]string{"Host", "content-length", "Cookie", "Transfer-Encoding", "x-api-key",
		"X-Debug", "x-debug", "Bad Name", "Bad:Name", "X-Ok_1"})
	if strings.Join(got, ",") != "X-Debug,X-Ok_1" {
		t.Fatalf("filtered = %v", got)
	}
	for _, s := range []string{"header", "headers", "Header"} {
		if loc, err := ParseLocation(s); err != nil || loc != LocationHeader {
			t.Errorf("ParseLocation(%q) = %q, %v", s, loc, err)
		}
	}
}

// A header chunk stays under the field-count and byte bounds servers enforce.
func TestHeaderLocation_ChunkBounds(t *testing.T) {
	b, err := newBuilder(baseRequest(t, "GET", "https://app.test/", "", nil), LocationHeader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.withDefaults()
	chunks := b.chunk(fillerHeaders(500), cfg)
	limit := DefaultMaxHeadersPerChunk - len(b.base.Request().Headers()) - 1
	total := 0
	for _, c := range chunks {
		size := 0
		for _, n := range c {
			size += b.pairCost(n)
		}
		if len(c) > limit || size > cfg.MaxHeaderBytes {
			t.Fatalf("chunk of %d names / %d bytes exceeds %d names / %d bytes", len(c), size, limit, cfg.MaxHeaderBytes)
		}
		total += len(c)
	}
	if total != 500 {
		t.Fatalf("chunked %d names, want 500", total)
	}
}

func TestBuiltinHeaders(t *testing.T) {
	names, err := BuiltinHeaders()
	if err != nil || len(names) < 100 {
		t.Fatalf("BuiltinHeaders = %d names, %v", len(names), err)
	}
	for _, n := range names {
		if !ValidHeaderName(n) {
			t.Errorf("built-in header %q is not minable", n)
		}
	}
}

func fillerHeaders(n int) []string {
	out := make([]string, n)
	for i, f := range fillerNames(n) {
		out[i] = "X-" + f
	}
	return out
}
