package http

import (
	"bytes"
	"compress/gzip"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// MISS-25: rawhttp gunzips the body but keeps Content-Encoding: gzip, and the
// response chain decoded it again, losing the first buffer chunk. The raw path
// must hand back the exact plaintext.
func TestRawRequest_GzipBodyIntact(t *testing.T) {
	plain := make([]byte, 10240)
	copy(plain, "HEADMARK")
	rng := rand.New(rand.NewSource(1))
	for i := 8; i < len(plain); i++ {
		plain[i] = byte('a' + rng.Intn(26))
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(plain)
	_ = zw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(gz.Bytes())
	}))
	defer srv.Close()

	r := newTestRequester(t)
	rr, err := httpmsg.GetRawRequestFromURL(srv.URL + "/z")
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := r.Execute(rr, Options{RawRequest: true, NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer resp.Close()
	body := resp.BodyBytes()
	if !bytes.HasPrefix(body, []byte("HEADMARK")) {
		n := min(len(body), 16)
		t.Errorf("body starts %q, want HEADMARK", body[:n])
	}
	if len(body) != len(plain) {
		t.Errorf("body length = %d, want %d", len(body), len(plain))
	}
}
