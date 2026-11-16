package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func newCrossHostRequester(t *testing.T, mode string, hopScope func(string) bool, extraHeaders ...string) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Timeout = 3 * time.Second
	opts.RedirectMode = mode
	opts.Headers = append([]string{"X-API-Key: secret-key", "Authorization: Bearer secret-token"}, extraHeaders...)
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{Options: opts, HopScope: hopScope}
	svc.Egress = egress.New(egress.Config{})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	t.Cleanup(r.CloseIdleConnections)
	return r
}

// A followed redirect to a different host:port carries none of the
// operator / session headers, in every mode; under in-scope with a scope that
// excludes the hop host the hop is not sent at all and the caller gets the 3xx.
func TestRedirect_CrossHostStripsHeadersAndHonoursScope(t *testing.T) {
	var hits atomic.Int64
	var gotKey, gotAuth, gotUA atomic.Value
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotKey.Store(r.Header.Get("X-API-Key"))
		gotAuth.Store(r.Header.Get("Authorization"))
		gotUA.Store(r.Header.Get("User-Agent"))
	}))
	defer b.Close()
	// Hop to "localhost:<port>": a different host from 127.0.0.1.
	bURL := strings.Replace(b.URL, "127.0.0.1", "localhost", 1)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bURL+"/landing", http.StatusFound)
	}))
	defer a.Close()

	t.Run("any mode strips", func(t *testing.T) {
		hits.Store(0)
		r := newCrossHostRequester(t, RedirectModeAny, nil)
		rr, _ := httpmsg.GetRawRequestFromURL(a.URL + "/start")
		resp, _, err := r.Execute(rr, Options{NoClustering: true})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		resp.Close()
		if hits.Load() != 1 {
			t.Fatalf("hop hits = %d, want 1", hits.Load())
		}
		if v := gotKey.Load().(string); v != "" {
			t.Errorf("X-API-Key leaked to the hop host: %q", v)
		}
		if v := gotAuth.Load().(string); v != "" {
			t.Errorf("Authorization leaked to the hop host: %q", v)
		}
		if v := gotUA.Load().(string); v == "" {
			t.Error("User-Agent must survive a cross-host hop")
		}
	})

	t.Run("in-scope refuses an out-of-scope hop", func(t *testing.T) {
		hits.Store(0)
		r := newCrossHostRequester(t, "", func(h string) bool { return h == "127.0.0.1" })
		rr, _ := httpmsg.GetRawRequestFromURL(a.URL + "/start")
		resp, _, err := r.Execute(rr, Options{NoClustering: true})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		defer resp.Close()
		if got := resp.Response().StatusCode; got != http.StatusFound {
			t.Errorf("status = %d, want the 302", got)
		}
		if hits.Load() != 0 {
			t.Errorf("out-of-scope hop host received %d requests, want 0", hits.Load())
		}
	})
}

// Same host:port keeps every header (a same-host hop is the same server).
func TestRedirect_SameHostKeepsHeaders(t *testing.T) {
	var gotKey atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/landing", http.StatusFound)
	})
	mux.HandleFunc("/landing", func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("X-API-Key"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	r := newCrossHostRequester(t, "", nil)
	rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/start")
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	resp.Close()
	if v, _ := gotKey.Load().(string); v != "secret-key" {
		t.Errorf("same-host hop X-API-Key = %q, want it kept", v)
	}
}

// A program's identification header typed with -H is a rule of engagement:
// it follows a cross-host hop the scope admits (www., http→https, a sibling
// in scope), while -H credentials stay with the origin they were given for.
// With no scope admitting the hop host it is stripped like everything else.
func TestRedirect_InScopeHopKeepsOperatorIdentificationHeader(t *testing.T) {
	var hits atomic.Int64
	var gotBounty, gotKey, gotAuth atomic.Value
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotBounty.Store(r.Header.Get("X-Bug-Bounty"))
		gotKey.Store(r.Header.Get("X-API-Key"))
		gotAuth.Store(r.Header.Get("Authorization"))
	}))
	defer b.Close()
	bURL := strings.Replace(b.URL, "127.0.0.1", "localhost", 1)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bURL+"/landing", http.StatusFound)
	}))
	defer a.Close()
	both := func(h string) bool { return h == "127.0.0.1" || h == "localhost" }

	run := func(t *testing.T, mode string, scope func(string) bool) {
		t.Helper()
		hits.Store(0)
		gotBounty.Store("")
		r := newCrossHostRequester(t, mode, scope, "X-Bug-Bounty: researcher-42")
		rr, _ := httpmsg.GetRawRequestFromURL(a.URL + "/start")
		resp, _, err := r.Execute(rr, Options{NoClustering: true})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		resp.Close()
		if hits.Load() != 1 {
			t.Fatalf("hop hits = %d, want 1", hits.Load())
		}
	}

	t.Run("scope admits the hop: identification kept, credentials stripped", func(t *testing.T) {
		run(t, "", both)
		if v := gotBounty.Load().(string); v != "researcher-42" {
			t.Errorf("X-Bug-Bounty on the in-scope hop = %q, want it kept", v)
		}
		if v := gotKey.Load().(string); v != "" {
			t.Errorf("X-API-Key reached the hop host: %q", v)
		}
		if v := gotAuth.Load().(string); v != "" {
			t.Errorf("Authorization reached the hop host: %q", v)
		}
	})

	t.Run("no scope admits the hop: everything stripped", func(t *testing.T) {
		run(t, RedirectModeAny, nil)
		if v := gotBounty.Load().(string); v != "" {
			t.Errorf("X-Bug-Bounty followed a hop no scope admitted: %q", v)
		}
	})
}

func TestOperatorHopHeadersExcludeCredentials(t *testing.T) {
	got := operatorHopHeaders([]string{
		"x-bug-bounty: a", "Authorization: Bearer b", "Cookie: c=1", "X-Auth-Token: t", "X-Program: p",
		// Credentials outside the old narrow list: the shared classifier
		// (redact.IsSensitiveHeader) flags -secret/-signature suffixes and
		// auth/secret keywords, so none of these may follow a hop.
		"X-Client-Secret: s", "X-Signature: sig", "X-Auth: a", "Api-Secret: s",
	})
	if !got["X-Bug-Bounty"] || !got["X-Program"] || len(got) != 2 {
		t.Errorf("operatorHopHeaders = %v, want only X-Bug-Bounty and X-Program", got)
	}
}

// Credential-shaped -H headers the shared classifier flags are stripped on a
// cross-host hop the scope admits, while the identification header survives.
func TestRedirect_InScopeHopStripsSecretSignatureAuthHeaders(t *testing.T) {
	credentials := []string{"X-Client-Secret", "X-Signature", "X-Auth", "Api-Secret"}
	got := map[string]string{}
	var gotBounty atomic.Value
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBounty.Store(r.Header.Get("X-Bug-Bounty"))
		for _, name := range credentials {
			if v := r.Header.Get(name); v != "" {
				got[name] = v
			}
		}
	}))
	defer b.Close()
	bURL := strings.Replace(b.URL, "127.0.0.1", "localhost", 1)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bURL+"/landing", http.StatusFound)
	}))
	defer a.Close()
	extra := []string{"X-Bug-Bounty: researcher-42"}
	for _, name := range credentials {
		extra = append(extra, name+": secret-"+name)
	}
	r := newCrossHostRequester(t, "", func(h string) bool { return h == "127.0.0.1" || h == "localhost" }, extra...)
	rr, _ := httpmsg.GetRawRequestFromURL(a.URL + "/start")
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	resp.Close()
	if v, _ := gotBounty.Load().(string); v != "researcher-42" {
		t.Errorf("X-Bug-Bounty on the in-scope hop = %q, want it kept", v)
	}
	if len(got) != 0 {
		t.Errorf("credential headers followed the cross-host hop: %v", got)
	}
}

// A cross-host hop with no operator headers to keep does not consult the scope
// a second time: outside the in-scope mode it is never read at all.
func TestRedirect_CrossHostHopSkipsScopeWithoutOperatorHeaders(t *testing.T) {
	var reads, calls int
	scope := func() func(string) bool {
		reads++
		return func(string) bool { calls++; return true }
	}
	origin, _ := http.NewRequest(http.MethodGet, "http://a.example.com/start", nil)
	hop, _ := http.NewRequest(http.MethodGet, "http://b.example.com/landing", nil)

	if err := makeScopedRedirectFunc(RedirectModeAny, 10, scope, nil)(hop, []*http.Request{origin}); err != nil {
		t.Fatalf("any-mode hop refused: %v", err)
	}
	if reads != 0 || calls != 0 {
		t.Errorf("any mode without operator headers read the scope %d times, called it %d times; want 0/0", reads, calls)
	}

	reads, calls = 0, 0
	if err := makeScopedRedirectFunc(RedirectModeInScope, 10, scope, map[string]bool{"X-Bug-Bounty": true})(hop, []*http.Request{origin}); err != nil {
		t.Fatalf("in-scope hop refused: %v", err)
	}
	if calls != 1 {
		t.Errorf("in-scope hop called the scope %d times, want 1 (the host rule only)", calls)
	}

	reads, calls = 0, 0
	if err := makeScopedRedirectFunc(RedirectModeAny, 10, scope, map[string]bool{"X-Bug-Bounty": true})(hop, []*http.Request{origin}); err != nil {
		t.Fatalf("any-mode hop refused: %v", err)
	}
	if calls != 1 {
		t.Errorf("any-mode hop with operator headers called the scope %d times, want 1", calls)
	}
}
