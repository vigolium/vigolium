package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

func TestResolveRedirectMode(t *testing.T) {
	tests := []struct {
		name string
		opts *types.Options
		want string
	}{
		{"nil options", nil, RedirectModeInScope},
		{"nothing set defaults to in-scope", &types.Options{}, RedirectModeInScope},
		{"explicit mode wins", &types.Options{RedirectMode: "same-apex"}, RedirectModeSameApex},
		{"explicit mode is case-insensitive", &types.Options{RedirectMode: "Same-Host"}, RedirectModeSameHost},
		{"legacy DisableRedirects maps to off", &types.Options{DisableRedirects: true}, RedirectModeOff},
		{"legacy FollowHostRedirects maps to same-host", &types.Options{FollowHostRedirects: true}, RedirectModeSameHost},
		{"explicit mode overrides the legacy bools", &types.Options{DisableRedirects: true, RedirectMode: "any"}, RedirectModeAny},
		// A library caller that hand-set a bad value must not silently get
		// "follow nothing"; the CLI rejects it up front instead.
		{"unknown value falls back to in-scope", &types.Options{RedirectMode: "sometimes"}, RedirectModeInScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveRedirectMode(tt.opts); got != tt.want {
				t.Errorf("ResolveRedirectMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMakeRedirectFunc(t *testing.T) {
	mustReq := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return &http.Request{URL: u}
	}

	tests := []struct {
		name   string
		mode   string
		from   string
		to     string
		follow bool
	}{
		{"off refuses even a same-host hop", RedirectModeOff, "https://a.example/", "https://a.example/x", false},
		{"any follows a cross-domain hop", RedirectModeAny, "https://a.example/", "https://other.test/", true},

		{"same-host follows the same host", RedirectModeSameHost, "https://a.example/", "https://a.example/x", true},
		{"same-host refuses a subdomain", RedirectModeSameHost, "https://a.example/", "https://www.a.example/", false},
		// Host comparison includes the port, so http->https on the same name is
		// a different host to this mode. That asymmetry is exactly why same-apex
		// exists.
		{"same-host refuses a port change", RedirectModeSameHost, "https://a.example:8443/", "https://a.example/", false},

		{"same-apex follows apex to www", RedirectModeSameApex, "https://example.test/", "https://www.example.test/", true},
		{"same-apex follows www to apex", RedirectModeSameApex, "https://www.example.test/", "https://example.test/", true},
		{"same-apex follows a scheme upgrade", RedirectModeSameApex, "http://example.test/", "https://example.test/", true},
		{"same-apex follows a port change within the domain", RedirectModeSameApex, "https://example.test/", "https://example.test:8443/", true},
		{"same-apex refuses a different registrable domain", RedirectModeSameApex, "https://example.test/", "https://tracker.other.test/", false},
		// The public-suffix list treats each *.github.io as its own registrable
		// domain, so two sibling pages are NOT the same apex. Getting this wrong
		// would make every shared-platform host look like one application.
		{"same-apex respects private suffixes", RedirectModeSameApex, "https://alice.github.io/", "https://bob.github.io/", false},
		// No resolvable apex on either side: fall back to exact-host equality
		// rather than treating "I could not tell" as permission.
		{"same-apex follows an IP to itself", RedirectModeSameApex, "http://127.0.0.1:8080/", "http://127.0.0.1:8080/x", true},
		{"same-apex refuses one IP to another", RedirectModeSameApex, "http://127.0.0.1/", "http://10.0.0.1/", false},
		{"same-apex refuses a single-label host to another", RedirectModeSameApex, "http://intranet/", "http://other/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := makeRedirectFunc(tt.mode, 10)
			err := fn(mustReq(tt.to), []*http.Request{mustReq(tt.from)})
			followed := err == nil
			if followed != tt.follow {
				t.Errorf("mode %q %s -> %s: followed=%v, want %v", tt.mode, tt.from, tt.to, followed, tt.follow)
			}
		})
	}
}

// TestMakeRedirectFuncHopCapAppliesToEveryMode locks in that the hop cap is
// checked before the mode: an unbounded same-host redirect loop is still a loop.
func TestMakeRedirectFuncHopCapAppliesToEveryMode(t *testing.T) {
	u, _ := url.Parse("https://a.example/")
	via := make([]*http.Request, 3)
	for i := range via {
		via[i] = &http.Request{URL: u}
	}
	for _, mode := range RedirectModes {
		if err := makeRedirectFunc(mode, 3)(&http.Request{URL: u}, via); !errors.Is(err, http.ErrUseLastResponse) {
			t.Errorf("mode %q: at the hop cap, got %v, want ErrUseLastResponse", mode, err)
		}
	}
}

// TestMakeRedirectFuncJudgesAgainstOrigin pins the via[0] choice. Judging each
// hop against its immediate predecessor would let a chain walk off its starting
// domain one plausible step at a time.
func TestMakeRedirectFuncJudgesAgainstOrigin(t *testing.T) {
	origin, _ := url.Parse("https://example.test/")
	middle, _ := url.Parse("https://cdn.other.test/")
	final, _ := url.Parse("https://cdn.other.test/final")

	fn := makeRedirectFunc(RedirectModeSameApex, 10)
	via := []*http.Request{{URL: origin}, {URL: middle}}
	if err := fn(&http.Request{URL: final}, via); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("hop within the SECOND domain must still be judged against the origin; got %v", err)
	}
}

// TestDoRequestKeepsFinalResponse is the regression test for the bug that made
// redirect following a no-op scanner-wide: doRequest used to walk the chain back
// to the OLDEST hop with Previous() and return it in that state, so every caller
// received the first 3xx instead of the page it redirected to.
func TestDoRequestKeepsFinalResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/two", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("arrived"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newTestRequester(t)
	// NoClustering for the same reason the executor sets it when hop recording
	// is on: the clusterer serves from a flattened snapshot with no redirect
	// linkage (see TestClusteringDropsRedirectLinkage).
	chain, _, err := r.Execute(makeTestRR(t, srv.URL+"/one"), Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer chain.Close()

	if got := chain.Response().StatusCode; got != http.StatusOK {
		t.Errorf("status = %d, want 200 (the chain must be left on the FINAL response)", got)
	}
	if got := chain.Request().URL.Path; got != "/end" {
		t.Errorf("request path = %q, want /end", got)
	}
	if body := string(chain.BodyBytes()); body != "arrived" {
		t.Errorf("body = %q, want the final page's body", body)
	}
	if !WasRedirected(chain) {
		t.Error("WasRedirected = false on a chain that followed two redirects")
	}
}

// TestRedirectChainHopsYieldsIntermediateHops covers the hop walk that backs
// --record-redirect-chain: oldest first, final response excluded, Location
// preserved on each.
func TestRedirectChainHopsYieldsIntermediateHops(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/two", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("arrived"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newTestRequester(t)
	chain, _, err := r.Execute(makeTestRR(t, srv.URL+"/one"), Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer chain.Close()

	// Order matters: the final request must be taken BEFORE the walk rewinds
	// the chain. This mirrors the executor.
	final := FinalRequestOf(chain, nil)
	if final != nil {
		t.Fatal("FinalRequestOf with a nil response must return nil")
	}

	hops := RedirectChainHops(chain)
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2 (the final 200 is the caller's, not a hop)", len(hops))
	}

	wantPaths := []string{"/one", "/two"}
	wantStatus := []int{http.StatusMovedPermanently, http.StatusFound}
	for i, hop := range hops {
		if got := hop.Request().Path(); got != wantPaths[i] {
			t.Errorf("hop %d path = %q, want %q (hops must be oldest-first)", i, got, wantPaths[i])
		}
		if got := hop.Response().StatusCode(); got != wantStatus[i] {
			t.Errorf("hop %d status = %d, want %d", i, got, wantStatus[i])
		}
		// Location is the entire point of recording a redirect hop.
		if got := hop.Response().Header("Location"); got == "" {
			t.Errorf("hop %d lost its Location header", i)
		}
	}
}

// TestRedirectChainHopsNilOnPlainResponse: a request that was never redirected
// must produce no hops, so hop recording costs nothing on the common path.
func TestRedirectChainHopsNilOnPlainResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	r := newTestRequester(t)
	chain, _, err := r.Execute(makeTestRR(t, srv.URL+"/"), Options{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer chain.Close()

	if WasRedirected(chain) {
		t.Error("WasRedirected = true on a direct 200")
	}
	if hops := RedirectChainHops(chain); hops != nil {
		t.Errorf("got %d hops on a non-redirected response, want none", len(hops))
	}
}

// TestClusteringDropsRedirectLinkage pins the reason the executor sets
// NoClustering whenever RecordRedirectChain is on.
//
// The clusterer caches a flattened SNAPSHOT of the response and rebuilds a
// fresh single-response chain from it, so resp.Request.Response — the only
// thing linking a response to the hop before it — is gone. Without the opt-out,
// hop recording would work for the first request to a URL and silently produce
// nothing for every repeat inside the cache TTL, which is far worse than not
// working at all. If this test ever starts failing because the cache learned to
// carry the chain, the executor's NoClustering can be reconsidered.
func TestClusteringDropsRedirectLinkage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("arrived"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newTestRequester(t)
	if r.Clusterer() == nil {
		t.Skip("clustering disabled on the test requester; nothing to pin")
	}

	chain, _, err := r.Execute(makeTestRR(t, srv.URL+"/one"), Options{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer chain.Close()

	// The final response still arrives intact — only the linkage is lost.
	if got := chain.Response().StatusCode; got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
	if WasRedirected(chain) {
		t.Error("clustered chain reports redirect linkage; the executor's NoClustering opt-out may no longer be needed")
	}
}

// TestMakeRedirectFuncStopsAtAuthWall pins the authentication gate. The three
// same-apex / same-host cases are the ones no host rule can express, and they
// are why the gate exists: without it a scan of the target reports findings
// about the identity provider's login page under the target's own URL.
func TestMakeRedirectFuncStopsAtAuthWall(t *testing.T) {
	tests := []struct {
		name   string
		from   string
		to     string
		follow bool
	}{
		{"internal IdP on the same apex", "https://app.example.test/", "https://login.example.test/oauth2/authorize?response_type=code", false},
		{"Azure EasyAuth on the same host", "https://app.example.test/", "https://app.example.test/.auth/login/aad", false},
		{"Cloudflare Access on the same host", "https://app.example.test/", "https://app.example.test/cdn-cgi/access/login", false},
		{"third-party IdP", "https://app.example.test/", "https://tenant.okta.com/app/x", false},
		{"bare IP to a login path on another port", "http://127.0.0.1:18094/", "http://127.0.0.1:18095/oauth2/authorize", false},
		// An operator who targets an IdP means to scan the IdP. Every hop of a
		// login flow matches the same signatures, so gating them would stop
		// such a scan on its first redirect.
		{"origin is itself an auth endpoint", "https://login.example.test/", "https://login.example.test/oauth2/authorize", true},
		{"ordinary same-host hop is untouched", "https://app.example.test/", "https://app.example.test/dashboard", true},
		{"ordinary cross-apex hop is untouched under any", "https://app.example.test/", "https://cdn.other.test/x", true},
	}

	mustReq := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return &http.Request{URL: u}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// RedirectModeAny: the gate must hold on the most permissive mode,
			// which is the default every non-probe scan runs with.
			err := makeRedirectFunc(RedirectModeAny, 10)(mustReq(tt.to), []*http.Request{mustReq(tt.from)})
			if followed := err == nil; followed != tt.follow {
				t.Errorf("%s -> %s: followed=%v, want %v", tt.from, tt.to, followed, tt.follow)
			}
		})
	}
}

// TestStoppedAtAuthWall pins the attribution helper against the same cases the
// policy decides on, so the two cannot drift into disagreeing about what an
// auth wall is.
func TestStoppedAtAuthWall(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		status   int
		location string
		wantDest string
	}{
		{"relative Location resolves against the request", "https://app.example.test/", 302, "/.auth/login/aad", "https://app.example.test/.auth/login/aad"},
		{"absolute Location to an IdP", "https://app.example.test/", 302, "https://tenant.okta.com/app/x", "https://tenant.okta.com/app/x"},
		{"non-login destination is not a wall", "https://app.example.test/", 301, "https://app.example.test/home", ""},
		{"a 200 is not a redirect", "https://app.example.test/", 200, "/login", ""},
		{"no Location", "https://app.example.test/", 302, "", ""},
		{"origin is itself an auth endpoint", "https://login.example.test/", 302, "/oauth2/authorize", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, ok := StoppedAtAuthWall(tt.url, tt.status, tt.location)
			if ok != (tt.wantDest != "") {
				t.Fatalf("ok = %v, want %v (dest %q)", ok, tt.wantDest != "", dest)
			}
			if dest != tt.wantDest {
				t.Errorf("dest = %q, want %q", dest, tt.wantDest)
			}
		})
	}
}

// TestAuthWallStopKeepsTheRedirectResponse is the end-to-end shape the gate
// promises: the caller gets the 3xx with its Location, not the login page and
// not an error. Everything downstream — the stored record, the attribution
// helper, the operator reading the output — depends on that.
func TestAuthWallStopKeepsTheRedirectResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oauth2/authorize?response_type=code", http.StatusFound)
	})
	mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body><input type="password"></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newTestRequester(t)
	chain, _, err := r.Execute(makeTestRR(t, srv.URL+"/"), Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer chain.Close()

	if got := chain.Response().StatusCode; got != http.StatusFound {
		t.Fatalf("status = %d, want 302 (the gate must surface the redirect, not the login page)", got)
	}
	loc := chain.Response().Header.Get("Location")
	if loc == "" {
		t.Fatal("Location was dropped; callers cannot name the wall")
	}
	if _, ok := StoppedAtAuthWall(srv.URL+"/", chain.Response().StatusCode, loc); !ok {
		t.Errorf("StoppedAtAuthWall did not recognise the stop it was built to attribute (location %q)", loc)
	}
}

// makeRedirectFunc is makeScopedRedirectFunc with no scope known.
func makeRedirectFunc(mode string, maxRedirects int) func(*http.Request, []*http.Request) error {
	return makeScopedRedirectFunc(mode, maxRedirects, nil, nil)
}
