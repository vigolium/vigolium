package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// SAFE-14: a WithHostFilter view (the JS extension requester) refuses
// out-of-scope hosts before anything is sent.
func TestWithHostFilter(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	r := newTestRequester(t)
	rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/x")

	denied := r.WithHostFilter(func(string) bool { return false })
	if _, _, err := denied.Execute(rr, Options{NoClustering: true}); !errors.Is(err, ErrHostOutOfScope) {
		t.Fatalf("err = %v, want ErrHostOutOfScope", err)
	}
	if hits.Load() != 0 {
		t.Fatal("refused request reached the server")
	}
	allowed := r.WithHostFilter(func(h string) bool { return h == "127.0.0.1" })
	resp, _, err := allowed.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}
