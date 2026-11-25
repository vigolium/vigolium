package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/requesttransform"
)

type seenRequest struct {
	host, path, query, body string
	header                  http.Header
}

func recordingServer(t *testing.T) (*httptest.Server, func() seenRequest) {
	t.Helper()
	var mu sync.Mutex
	var last seenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		last = seenRequest{host: req.Host, path: req.URL.EscapedPath(), query: req.URL.RawQuery, body: string(b), header: req.Header.Clone()}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() seenRequest { mu.Lock(); defer mu.Unlock(); return last }
}

// TestRequestTransform_SignsFinalBytesOnItsHostOnly sends one request to a
// host a transform names and one to a host it does not: the first arrives
// signed over its method, target, timestamp, nonce and body (vector 1's
// shape) at the same host, the second arrives as it was built.
func TestRequestTransform_SignsFinalBytesOnItsHostOnly(t *testing.T) {
	signed, lastSigned := recordingServer(t)
	plain, lastPlain := recordingServer(t)
	signedURL, _ := url.Parse(signed.URL)

	t.Setenv(requesttransform.KeyEnvName("api-signing-key"), "s3cr3t-signing-key")
	set, err := requesttransform.Parse([]byte(`{"id":"api-sign","applies":{"host":"`+signedURL.Host+`","pathPrefix":"/v2/"},"ops":[
		{"op":"timestamp","name":"ts","unit":"s"},
		{"op":"nonce","name":"n","length":16,"alphabet":"hex"},
		{"op":"set-header","header":"X-Ts","value":"{{var:ts}}"},
		{"op":"set-header","header":"X-Nonce","value":"{{var:n}}"},
		{"op":"hmac-header","header":"X-Signature","alg":"sha256","key":{"credential":"api-signing-key"},"over":["method","target","ts","nonce","body"],"join":"\n","encoding":"hex"}]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	requesttransform.Activate(set)
	t.Cleanup(func() { requesttransform.Activate(nil) })

	r := newTestRequester(t)
	send := func(rawURL string) {
		t.Helper()
		rr, err := httpmsg.GetRawRequestFromURLWithMethod(rawURL, "POST", map[string]string{"Content-Type": "application/json"}, []byte(`{"qty":1}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, _, err := r.Execute(rr, Options{NoClustering: true})
		if err != nil {
			t.Fatalf("Execute %s: %v", rawURL, err)
		}
		resp.Close()
	}

	send(signed.URL + "/v2/orders?limit=5")
	got := lastSigned()
	if got.host != signedURL.Host || got.path != "/v2/orders" || got.query != "limit=5" || got.body != `{"qty":1}` {
		t.Fatalf("the signed request moved or changed: %+v", got)
	}
	ts, n := got.header.Get("X-Ts"), got.header.Get("X-Nonce")
	if ts == "" || len(n) != 16 {
		t.Fatalf("ts %q nonce %q", ts, n)
	}
	mac := hmac.New(sha256.New, []byte("s3cr3t-signing-key"))
	mac.Write([]byte(strings.Join([]string{"POST", "/v2/orders?limit=5", ts, n, `{"qty":1}`}, "\n")))
	if want := hex.EncodeToString(mac.Sum(nil)); got.header.Get("X-Signature") != want {
		t.Fatalf("X-Signature = %q, want %q", got.header.Get("X-Signature"), want)
	}

	send(plain.URL + "/v2/orders")
	if other := lastPlain(); other.header.Get("X-Signature") != "" || other.header.Get("X-Ts") != "" {
		t.Fatalf("a host no transform names was signed: %v", other.header)
	}
}

// TestRequestTransform_UnresolvedKeyFailsTheRequest holds that a transform
// that cannot be evaluated never lets the request out unsigned.
func TestRequestTransform_UnresolvedKeyFailsTheRequest(t *testing.T) {
	srv, last := recordingServer(t)
	u, _ := url.Parse(srv.URL)
	set, err := requesttransform.Parse([]byte(`{"id":"k","applies":{"host":"`+u.Host+`"},"ops":[
		{"op":"hmac-header","header":"X-S","alg":"sha256","key":{"credential":"absent-key"},"over":["method"],"encoding":"hex"}]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	requesttransform.Activate(set)
	t.Cleanup(func() { requesttransform.Activate(nil) })

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newTestRequester(t).Execute(rr, Options{NoClustering: true, NoRetry: true}); err == nil || !strings.Contains(err.Error(), "key-unresolved") {
		t.Fatalf("err = %v, want key-unresolved", err)
	}
	if got := last(); got.path != "" {
		t.Fatalf("the request left unsigned: %+v", got)
	}
}
