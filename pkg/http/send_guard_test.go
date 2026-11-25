package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func scopedRequester(t *testing.T, mode string, scope config.ScopeConfig, targets ...string) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Timeout = 3 * time.Second
	opts.RedirectMode = mode
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{Options: opts, SendScope: config.NewScopeMatcher(scope, targets...)}
	svc.Egress = egress.New(egress.Config{})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	t.Cleanup(r.CloseIdleConnections)
	return r
}

func scopeWith(edit func(*config.ScopeConfig)) config.ScopeConfig {
	cfg := *config.DefaultScopeConfig()
	edit(&cfg)
	return cfg
}

// A target that redirects to a host outside the scope is stopped at the hop:
// the out-of-scope host gets nothing and the caller gets the 3xx, in the
// default in-scope mode.
func TestSendGuard_RedirectToOutOfScopeHostStoppedAtHop(t *testing.T) {
	var outHits atomic.Int64
	out := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outHits.Add(1) }))
	defer out.Close()
	outURL := strings.Replace(out.URL, "127.0.0.1", "localhost", 1)
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outURL+"/elsewhere", http.StatusFound)
	}))
	defer in.Close()

	r := scopedRequester(t, RedirectModeInScope, scopeWith(func(c *config.ScopeConfig) {
		c.Host = config.ScopeRule{Include: []string{"127.0.0.1"}}
	}))
	rr, _ := httpmsg.GetRawRequestFromURL(in.URL + "/start")
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer resp.Close()
	if code := resp.Response().StatusCode; code != http.StatusFound {
		t.Errorf("status = %d, want the 302 itself", code)
	}
	if outHits.Load() != 0 {
		t.Errorf("out-of-scope hop host got %d requests, want 0", outHits.Load())
	}
}

// A redirect hop to a port scope.port refuses is stopped even under
// --redirect-mode any, which otherwise follows every host.
func TestSendGuard_AnyModeHopStillHeldToPortRule(t *testing.T) {
	var outHits atomic.Int64
	out := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outHits.Add(1) }))
	defer out.Close()
	in := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, out.URL+"/x", http.StatusFound)
	}))
	defer in.Close()
	inPort := strings.TrimPrefix(in.URL, "http://127.0.0.1:")

	r := scopedRequester(t, RedirectModeAny, scopeWith(func(c *config.ScopeConfig) {
		c.Port = config.ScopeRule{Include: []string{inPort}}
	}))
	rr, _ := httpmsg.GetRawRequestFromURL(in.URL + "/")
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer resp.Close()
	if outHits.Load() != 0 {
		t.Errorf("hop to an excluded port got %d requests, want 0", outHits.Load())
	}
}

// A request to a destination the scope refuses is not sent: the error is a
// ScopeRefusal matching ErrHostOutOfScope, and the server sees nothing.
func TestSendGuard_RequestRefusedBeforeSend(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	r := scopedRequester(t, RedirectModeInScope, scopeWith(func(c *config.ScopeConfig) {
		c.Host = config.ScopeRule{Include: []string{"*.example.com"}}
	}))
	rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	for _, raw := range []bool{false, true} {
		_, _, err := r.Execute(rr, Options{NoClustering: true, RawRequest: raw})
		var refusal *ScopeRefusal
		if !errors.As(err, &refusal) || !errors.Is(err, ErrHostOutOfScope) {
			t.Fatalf("raw=%v: err = %v, want a ScopeRefusal", raw, err)
		}
		if refusal.Rule != config.ScopeRuleHostInclude {
			t.Errorf("raw=%v: rule = %q", raw, refusal.Rule)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("refused destination got %d requests", hits.Load())
	}
}

// A loopback lab named as the CLI target is reached.
func TestSendGuard_LoopbackTargetNamedInScope(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	r := scopedRequester(t, RedirectModeInScope, *config.DefaultScopeConfig(), srv.URL)
	rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	resp.Close()
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

// The instance-metadata address is refused at the hop in every mode without an
// explicit scope entry; judged without any network traffic.
func TestSendGuard_MetadataHopRefusedWithoutRule(t *testing.T) {
	guard := newSendGuard(&services.Services{SendScope: config.NewScopeMatcher(*config.DefaultScopeConfig())}, nil)
	origin, _ := http.NewRequest(http.MethodGet, "http://a.example.com/start", nil)
	for _, loc := range []string{"http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/", "http://[fd00:ec2::254]/"} {
		hop, _ := http.NewRequest(http.MethodGet, loc, nil)
		if err := makeScopedRedirectFunc(RedirectModeAny, 10, guard, nil)(hop, []*http.Request{origin}); !errors.Is(err, http.ErrUseLastResponse) {
			t.Errorf("hop to %s followed (err %v)", loc, err)
		}
	}
	lifted := newSendGuard(&services.Services{SendScope: config.NewScopeMatcher(scopeWith(func(c *config.ScopeConfig) {
		c.CIDR = config.ScopeRule{Include: []string{"169.254.169.254"}}
	}))}, nil)
	hop, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/", nil)
	if err := makeScopedRedirectFunc(RedirectModeAny, 10, lifted, nil)(hop, []*http.Request{origin}); err != nil {
		t.Errorf("hop with an explicit CIDR entry refused: %v", err)
	}
}

// A name is judged on the addresses it resolves to: an in-scope name resolving
// to a private address no rule names is refused; to the metadata address,
// refused under any scope. The resolver is consulted once per name.
func TestSendGuard_ResolvedAddressesJudged(t *testing.T) {
	var lookups atomic.Int64
	resolve := func(host string) []netip.Addr {
		lookups.Add(1)
		switch host {
		case "intranet.example.com":
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}
		case "rebind.example.com":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	}
	g := newSendGuard(&services.Services{SendScope: config.NewScopeMatcher(scopeWith(func(c *config.ScopeConfig) {
		c.Host = config.ScopeRule{Include: []string{"*.example.com"}}
	}))}, resolve)
	u, _ := url.Parse("https://intranet.example.com/")
	var refusal *ScopeRefusal
	if err := g.checkURL(u, true); !errors.As(err, &refusal) || refusal.Rule != config.ScopeRulePrivateAddress || refusal.Port != 443 {
		t.Fatalf("private resolution: %v", err)
	}
	_ = g.checkURL(u, true)
	if err := g.check("rebind.example.com", 80, "/", true); !errors.As(err, &refusal) || refusal.Rule != config.ScopeRuleMetadataAddress {
		t.Fatalf("metadata resolution: %v", err)
	}
	if err := g.check("www.example.com", 443, "/", true); err != nil {
		t.Fatalf("public resolution refused: %v", err)
	}
	if lookups.Load() != 3 {
		t.Errorf("lookups = %d, want one per name (3)", lookups.Load())
	}
}
