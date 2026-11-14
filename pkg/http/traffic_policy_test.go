package http

import (
	"errors"
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

// A read-only policy refuses DELETE (and a smuggled override) before
// anything is sent; the priority lane (login) is exempt.
func TestTrafficPolicy_RequesterChokepoint(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()

	opts := types.DefaultOptions()
	opts.Timeout = 3 * time.Second
	opts.TrafficPolicy = types.NewTrafficPolicy([]string{"GET", "HEAD"})
	if err := network.Init(opts); err != nil {
		t.Fatal(err)
	}
	svc := &services.Services{Options: opts}
	svc.Egress = egress.New(egress.Config{})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer r.CloseIdleConnections()
	host := srv.Listener.Addr().String()
	svcFor := serviceFor(t, srv.URL)

	del := httpmsg.NewRequestResponseRaw([]byte("DELETE /items/1 HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), svcFor)
	if _, _, err := r.Execute(del, Options{NoClustering: true}); !errors.Is(err, ErrMethodDenied) {
		t.Fatalf("DELETE: err = %v, want ErrMethodDenied", err)
	}
	override := httpmsg.NewRequestResponseRaw([]byte("GET /items/1 HTTP/1.1\r\nHost: "+host+"\r\nX-HTTP-Method-Override: DELETE\r\n\r\n"), svcFor)
	if _, _, err := r.Execute(override, Options{NoClustering: true}); !errors.Is(err, ErrMethodDenied) {
		t.Fatalf("override: err = %v, want ErrMethodDenied", err)
	}
	if _, _, err := r.Execute(del, Options{NoClustering: true, RawBytes: []byte("DELETE /x HTTP/1.1\r\nHost: " + host + "\r\n\r\n")}); !errors.Is(err, ErrMethodDenied) {
		t.Fatalf("raw bytes DELETE: err = %v, want ErrMethodDenied", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("server hits = %d, want 0", hits.Load())
	}
	get, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/ok")
	resp, _, err := r.Execute(get, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Close()
	// Priority lane (session login) is exempt.
	post := httpmsg.NewRequestResponseRaw([]byte("POST /login HTTP/1.1\r\nHost: "+host+"\r\nContent-Length: 0\r\n\r\n"), svcFor)
	resp, _, err = r.WithLane(egress.LanePriority).Execute(post, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("priority POST: %v", err)
	}
	resp.Close()
	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2 (GET + priority login)", hits.Load())
	}
}

func TestTrafficPolicy_Type(t *testing.T) {
	if types.NewTrafficPolicy(nil) != nil {
		t.Error("empty methods must mean no policy")
	}
	ro := types.NewTrafficPolicy([]string{"get", "head"})
	if !ro.ReadOnly() || ro.AllowsSubmitForms() || ro.AllowsUploads() || ro.AllowsLoginAttempts() {
		t.Error("GET/HEAD policy must be read-only with interactions off")
	}
	rw := types.NewTrafficPolicy([]string{"GET", "POST"})
	if rw.ReadOnly() || !rw.AllowsSubmitForms() || rw.AllowsMethod("DELETE") || !rw.AllowsMethod("post") {
		t.Error("GET/POST policy semantics wrong")
	}
	var nilPol *types.TrafficPolicy
	if !nilPol.AllowsMethod("DELETE") || nilPol.ReadOnly() {
		t.Error("nil policy allows everything")
	}
}
