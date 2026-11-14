package modkit

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// MISS-14: with a 1 rps limiter the second and third sends wait ~1s each for a
// token; SendTimed must report the server's latency, not that wait. Identical
// probes must all reach the server (no clustering).
func TestSendTimed_ExcludesQueueWaitAndNeverClusters(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	opts := types.DefaultOptions()
	opts.Timeout = 5 * time.Second
	opts.ClusterRequests = true
	if err := network.Init(opts); err != nil {
		t.Fatal(err)
	}
	lim := rate.NewLimiter(1, 1)
	svc := &services.Services{Options: opts, RateLimiter: lim}
	svc.Egress = egress.New(egress.Config{Rate: lim})
	client, err := vighttp.NewRequester(opts, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()

	for i := 0; i < 3; i++ {
		rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/same?x=1")
		resp, elapsed, err := SendTimed(client, rr, vighttp.Options{})
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		resp.Close()
		if elapsed >= 100*time.Millisecond {
			t.Errorf("send %d: elapsed %v includes the rate-limit wait", i, elapsed)
		}
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("server hits = %d, want 3 (identical timing probes must not be clustered)", n)
	}
}
