package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// A client timeout is host distress. A host that stops answering
// used to read as "scan shutdown" (context.DeadlineExceeded) and never backed
// off; the limit must fall to the floor.
func TestTimeoutsCountAsDistress(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	opts := types.DefaultOptions()
	opts.Timeout = 50 * time.Millisecond
	opts.Retries = 0
	if err := network.Init(opts); err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.NewHostRateLimiter(ratelimit.HostRateLimiterConfig{MaxPerHost: 10, Adaptive: true, MinPerHost: 1})
	defer func() { _ = lim.Close() }()
	svc := &services.Services{Options: opts, HostLimiter: lim}
	svc.Egress = egress.New(egress.Config{Hosts: lim})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer r.CloseIdleConnections()

	rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/hang")
	host := rr.Service().Host()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, _, _ = r.ExecuteContext(context.Background(), rr, Options{NoClustering: true})
		if limit, _ := lim.CurrentLimit(host); limit == 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	limit, _ := lim.CurrentLimit(host)
	t.Fatalf("limit = %d after repeated timeouts, want the floor (1)", limit)
}
