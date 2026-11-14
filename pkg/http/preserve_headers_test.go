package http

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func newHeaderRequester(t *testing.T, headers ...string) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Timeout = 3 * time.Second
	opts.Headers = headers
	if err := network.Init(opts); err != nil {
		t.Fatal(err)
	}
	svc := &services.Services{Options: opts}
	svc.Egress = egress.New(egress.Config{})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.CloseIdleConnections)
	return r
}

func echoHeaderServer(t *testing.T, name string, got *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get(name))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sendRaw(t *testing.T, r *Requester, srv *httptest.Server, extraHeader string, opts Options) {
	t.Helper()
	raw := "GET /x HTTP/1.1\r\nHost: " + srv.Listener.Addr().String() + "\r\n"
	if extraHeader != "" {
		raw += extraHeader + "\r\n"
	}
	raw += "\r\n"
	rr := httpmsg.NewRequestResponseRaw([]byte(raw), serviceFor(t, srv.URL))
	opts.NoClustering = true
	resp, _, err := r.Execute(rr, opts)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	resp.Close()
}

// A module-set header survives -H / session overwrite when preserved.
func TestPreserveHeaders_ModuleValueWins(t *testing.T) {
	var got atomic.Value
	srv := echoHeaderServer(t, "Authorization", &got)
	r := newHeaderRequester(t, "Authorization: Bearer good")

	sendRaw(t, r, srv, "Authorization: Bearer forged", Options{})
	if v := got.Load(); v != "Bearer good" {
		t.Fatalf("without preserve: got %v, want the -H value (control)", v)
	}
	preserving := r.WithPreservedHeaders([]string{"Authorization"})
	sendRaw(t, preserving, srv, "Authorization: Bearer forged", Options{})
	if v := got.Load(); v != "Bearer forged" {
		t.Errorf("WithPreservedHeaders: got %v, want the module's forged value", v)
	}
	// Never adds a missing header: a request without one gets the -H value.
	sendRaw(t, preserving, srv, "", Options{})
	if v := got.Load(); v != "Bearer good" {
		t.Errorf("missing header: got %v, want the -H value", v)
	}
}

// A preserved cookie is spliced into the session cookie string.
func TestPreserveHeaders_CookieSplice(t *testing.T) {
	var got atomic.Value
	srv := echoHeaderServer(t, "Cookie", &got)
	r := newHeaderRequester(t, "Cookie: session=s1; TrackingId=orig")
	sendRaw(t, r.WithPreservedHeaders([]string{"cookie:trackingid"}), srv, "Cookie: TrackingId=P", Options{})
	if v := got.Load(); v != "session=s1; TrackingId=P" {
		t.Errorf("Cookie = %v, want session=s1; TrackingId=P", v)
	}
}

// Preserving views get their own response-cache partition, shared by views
// preserving the same keys.
func TestPreserveHeaders_ClusterScope(t *testing.T) {
	r := newHeaderRequester(t)
	a := r.WithPreservedHeaders([]string{"Authorization"})
	b := r.WithPreservedHeaders([]string{" authorization "})
	if a.preservedScope == "" || a.preservedScope != b.preservedScope {
		t.Errorf("scopes %q / %q, want equal and non-empty", a.preservedScope, b.preservedScope)
	}
	if r.preservedScope != "" {
		t.Errorf("the receiver's scope changed: %q", r.preservedScope)
	}
}
