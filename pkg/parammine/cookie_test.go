package parammine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// cookieApp reads three cookies no client sends: debug adds a debug block
// (length), theme is echoed into the page (reflection), admin reroutes to a
// login redirect (status). It counts the requests that arrived without the
// session cookie the base request carries.
func cookieApp(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	page := strings.Repeat("<li>ordinary listing row text</li>\n", 25)
	var lostSession atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "s3cr3t" {
			lostSession.Add(1)
		}
		if _, err := r.Cookie("admin"); err == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		body := "<html><ul>" + page + "</ul>"
		if _, err := r.Cookie("debug"); err == nil {
			body += "<pre>" + strings.Repeat("DEBUG handler=list db=12ms cache=miss\n", 15) + "</pre>"
		}
		if c, err := r.Cookie("theme"); err == nil {
			body += `<body class="theme-` + c.Value + `">`
		}
		_, _ = io.WriteString(w, body+"</html>")
	}))
	t.Cleanup(srv.Close)
	return srv, &lostSession
}

func TestMine_CookieLocation(t *testing.T) {
	srv, lostSession := cookieApp(t)
	words := append(fillerNames(30), "debug", "theme", "admin")
	words = append(words, fillerNames(45)[30:]...)

	base, err := httpmsg.GetRawRequestFromURLWithMethod(srv.URL+"/list", "GET", map[string]string{"Cookie": "session=s3cr3t"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base = httpmsg.NewHttpRequestResponse(base.Request().WithHeader("Cookie", "session=s3cr3t"), nil)
	res, err := Mine(context.Background(), base, words, httpSender(t), Config{Location: LocationCookie, MaxRequests: 80})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if res.Aborted != "" || res.Location != LocationCookie {
		t.Fatalf("result = %+v", res)
	}
	got := hitNames(res)
	want := map[string]Signal{"debug": SignalLength, "theme": SignalReflect, "admin": SignalStatus}
	if len(got) != len(want) {
		t.Fatalf("hits = %v, want %v", got, want)
	}
	for n, s := range want {
		if got[n] != s {
			t.Errorf("%s: signal %q, want %q", n, got[n], s)
		}
	}
	if n := lostSession.Load(); n != 0 {
		t.Fatalf("%d request(s) arrived without the session cookie: mined names must join it, never replace it", n)
	}
	for _, h := range res.Hits {
		if h.Location != LocationCookie {
			t.Errorf("%s: location %q", h.Name, h.Location)
		}
		req := h.Exchange.Request()
		cookie := req.Header("Cookie")
		if !strings.HasPrefix(cookie, "session=s3cr3t; ") || !strings.Contains(cookie, "; "+h.Name+"=") {
			t.Errorf("%s: confirming exchange Cookie = %q", h.Name, cookie)
		}
		if req.Header(h.Name) != "" || strings.Contains(req.Path(), "?") {
			t.Errorf("%s: cookie mining touched a header or the query: %s", h.Name, req.Path())
		}
	}
}

// Cookie names are tokens, compared as sent; a name the request already
// carries as a cookie is never mined, and the header-location exclusion of
// the Cookie header does not apply.
func TestCookieLocation_FiltersAndMerges(t *testing.T) {
	base, err := httpmsg.GetRawRequestFromURLWithMethod("https://app.test/", "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := base.Request().WithAddedHeader("Cookie", "sid=abc; lang=en").WithAddedHeader("Cookie", "tz=UTC")
	b, err := newBuilder(httpmsg.NewHttpRequestResponse(req, nil), LocationCookie)
	if err != nil {
		t.Fatal(err)
	}
	got := b.filterExisting([]string{"sid", "SID", "lang", "debug", "debug", "bad name", "bad;name", "a=b", "cookie", "tz"})
	if strings.Join(got, ",") != "SID,debug,cookie" {
		t.Fatalf("filtered = %v", got)
	}
	rr, err := b.build([]pair{{name: "debug", value: "abc123xyz"}, {name: "role", value: "q1w2e3r4t"}})
	if err != nil {
		t.Fatal(err)
	}
	out := rr.Request()
	var lines []string
	for _, h := range out.Headers() {
		if strings.EqualFold(h.Name, "Cookie") {
			lines = append(lines, h.Value)
		}
	}
	if len(lines) != 1 || lines[0] != "sid=abc; lang=en; tz=UTC; debug=abc123xyz; role=q1w2e3r4t" {
		t.Fatalf("Cookie lines = %q", lines)
	}
	for _, s := range []string{"cookie", "cookies", "Cookie"} {
		if loc, err := ParseLocation(s); err != nil || loc != LocationCookie {
			t.Errorf("ParseLocation(%q) = %q, %v", s, loc, err)
		}
	}
}

// A cookie chunk keeps the whole Cookie header under the bound servers enforce,
// the request's own cookies counted.
func TestCookieLocation_ChunkBounds(t *testing.T) {
	session := "session=" + strings.Repeat("j", 3000)
	base, err := httpmsg.GetRawRequestFromURLWithMethod("https://app.test/", "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBuilder(httpmsg.NewHttpRequestResponse(base.Request().WithAddedHeader("Cookie", session), nil), LocationCookie)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{}.withDefaults()
	chunks := b.chunk(fillerNames(500), cfg)
	total := 0
	for _, c := range chunks {
		size := len(session) + b.pairCost(strings.Repeat("x", canaryLen))
		for _, n := range c {
			size += b.pairCost(n)
		}
		if size > DefaultMaxCookieHeaderBytes || len(c) > cfg.MaxNamesPerChunk {
			t.Fatalf("chunk of %d names makes a %d-byte Cookie header, over %d", len(c), size, DefaultMaxCookieHeaderBytes)
		}
		total += len(c)
	}
	if total != 500 {
		t.Fatalf("chunked %d names, want 500", total)
	}
}
