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

func newCrossHostRequester(t *testing.T, mode string, hopScope func(string) bool) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Timeout = 3 * time.Second
	opts.RedirectMode = mode
	opts.Headers = []string{"X-API-Key: secret-key", "Authorization: Bearer secret-token"}
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
