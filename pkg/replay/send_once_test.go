package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
)

// A supplied request with no mutation is sent once and carries no diff;
// SendBaseline restores the baseline send and the diff.
func TestDoSendsSuppliedRequestOnce(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	raw := []byte("POST /echo HTTP/1.1\r\nHost: " + u.Host + "\r\nContent-Length: 7\r\n\r\nu=admin")

	opts := Options{BaselineRequest: raw, Scheme: "http", Hostname: u.Hostname(), Port: port, Client: NewDefaultClient(nil, 0)}
	res, err := Do(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 || res.Baseline != nil || res.Diff != nil || res.Replay == nil || res.Replay.Status != 200 {
		t.Fatalf("hits=%d baseline=%v diff=%v replay=%+v", hits.Load(), res.Baseline, res.Diff, res.Replay)
	}

	hits.Store(0)
	opts.SendBaseline = true
	res, err = Do(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || res.Baseline == nil || res.Diff == nil {
		t.Fatalf("with SendBaseline: hits=%d baseline=%v diff=%v", hits.Load(), res.Baseline, res.Diff)
	}
}
