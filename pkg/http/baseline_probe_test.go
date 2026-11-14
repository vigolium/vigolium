package http

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// A host that silently drops payloads (a WAF) trips the breaker.
// The recovery probe used to be whichever payload arrived, so it failed too
// and the host stayed quarantined; with a baseline the probe is the record's
// own request, which the host answers, and the breaker closes.
func TestBaselineProbe_RecoversHostThatDropsPayloads(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "PAYLOAD") {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	defer close(release)

	run := func(withBaseline bool) hosterrors.State {
		opts := types.DefaultOptions()
		opts.Timeout = 100 * time.Millisecond
		opts.Retries = 0
		if err := network.Init(opts); err != nil {
			t.Fatal(err)
		}
		breaker := hosterrors.NewWithConfig(hosterrors.Config{MaxHostError: 3, Cooldown: 150 * time.Millisecond, MaxTrips: -1})
		defer breaker.Close()
		svc := &services.Services{Options: opts, HostErrors: breaker}
		svc.Egress = egress.New(egress.Config{Breaker: breaker})
		r, err := NewRequester(opts, svc)
		if err != nil {
			t.Fatal(err)
		}
		defer r.CloseIdleConnections()

		base, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/item?q=1")
		payload, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/item?q=PAYLOAD")
		key := net.JoinHostPort(base.Service().Host(), strconv.Itoa(base.Service().Port()))
		client := r
		if withBaseline {
			client = r.WithBaseline(base)
		}
		for i := 0; i < 3; i++ {
			_, _, _ = client.Execute(payload, Options{NoClustering: true})
		}
		if st := breaker.State(key); st != hosterrors.StateOpen {
			t.Fatalf("breaker = %v after 3 dropped payloads, want open", st)
		}
		time.Sleep(200 * time.Millisecond)
		_, _, _ = client.Execute(payload, Options{NoClustering: true})
		return breaker.State(key)
	}

	if st := run(true); st != hosterrors.StateClosed {
		t.Errorf("with baseline: breaker = %v after the recovery probe, want closed", st)
	}
	if st := run(false); st == hosterrors.StateClosed {
		t.Errorf("control without baseline: breaker closed — the payload probe should have failed")
	}
}
