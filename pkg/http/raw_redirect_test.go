package http

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestRawRequest_NeverFollowsRedirect pins SAFE-1: rawhttp's Dor follows one
// hop even at MaxRedirects 0 and re-sends every header (session, -H) to the
// Location host. A raw request must be exactly one round trip and return the
// 3xx, with and without NoRedirects.
func TestRawRequest_NeverFollowsRedirect(t *testing.T) {
	var bHits atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer b.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/landing", http.StatusFound)
	}))
	defer a.Close()

	r := newTestRequester(t)
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"follow-mode", Options{RawRequest: true, NoClustering: true}},
		{"no-redirects", Options{RawRequest: true, NoRedirects: true, NoClustering: true}},
		{"raw-target", Options{RawRequestTarget: "/start", NoClustering: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := httpmsg.GetRawRequestFromURL(a.URL + "/start")
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			resp, _, err := r.Execute(rr, tc.opts)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			defer resp.Close()
			if got := resp.Response().StatusCode; got != http.StatusFound {
				t.Errorf("status = %d, want 302 (the redirect itself)", got)
			}
		})
	}
	if n := bHits.Load(); n != 0 {
		t.Errorf("redirect target received %d requests, want 0", n)
	}
}
