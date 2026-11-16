package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendRawExactAndRedirects(t *testing.T) {
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("done"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	hostname, port := host[:strings.LastIndex(host, ":")], host[strings.LastIndex(host, ":")+1:]
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	client := NewDefaultClient(nil, 5*time.Second)
	raw := []byte("GET /start HTTP/1.1\r\nHost: " + host + "\r\n\r\n")

	sum := sendRawHTTPWith(context.Background(), client, raw, sendTarget{scheme: "http", hostname: hostname, port: p, exact: true}, false, 0)
	if sum.Error != "" {
		t.Fatal(sum.Error)
	}
	if sum.Redirects != 1 || !strings.HasSuffix(sum.FinalURL, "/end") {
		t.Errorf("final_url %q redirects %d", sum.FinalURL, sum.Redirects)
	}
	mu.Lock()
	first := seen[0]
	mu.Unlock()
	if first.Get("User-Agent") != "" || first.Get("Accept-Encoding") != "" {
		t.Errorf("exact send added headers: UA %q AE %q", first.Get("User-Agent"), first.Get("Accept-Encoding"))
	}

	sum = SendRaw(context.Background(), client, raw, "http", hostname, p, true, 0)
	if sum.Redirects != 0 || !strings.HasSuffix(sum.FinalURL, "/start") || sum.Status != http.StatusFound {
		t.Errorf("no-redirects: %+v", sum)
	}

	var dumped string
	TrafficDump = func(method, url string, _ []byte, _ *http.Response, _ error, _ time.Duration) {
		dumped = method + " " + url
	}
	defer func() { TrafficDump = nil }()
	_ = SendRaw(context.Background(), client, raw, "http", hostname, p, true, 0)
	if !strings.HasPrefix(dumped, "GET http://") {
		t.Errorf("dump hook = %q", dumped)
	}
}

func TestFindingEvidenceIdenticalIsReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("same")) }))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	hostname := host[:strings.LastIndex(host, ":")]
	p := 0
	for _, c := range host[strings.LastIndex(host, ":")+1:] {
		p = p*10 + int(c-'0')
	}
	req := []byte("GET /x HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nsame")
	res, err := Do(context.Background(), Options{
		BaselineRequest: req, BaselineResponse: resp, BaselineStatus: 200,
		Scheme: "http", Hostname: hostname, Port: p, Client: NewDefaultClient(nil, 5*time.Second),
		BaselineIsEvidence: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Diff == nil || !strings.Contains(res.Diff.Interpretation, "reproduced") {
		t.Errorf("interpretation = %+v", res.Diff)
	}
}

// The caller's CheckRedirect (fuzz --max-redirs) bounds the per-send client:
// a redirect loop stops at its limit, not at the replay default of 10.
func TestSendRawHonorsClientRedirectLimit(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()
	host, port := splitAddr(t, srv.Listener.Addr().String())
	client := NewDefaultClient(nil, 5*time.Second)
	client.CheckRedirect = RedirectLimit(2)
	raw := []byte("GET /loop HTTP/1.1\r\nHost: " + srv.Listener.Addr().String() + "\r\n\r\n")
	sum := sendRawHTTPWith(context.Background(), client, raw, sendTarget{scheme: "http", hostname: host, port: port}, false, 0)
	if !strings.Contains(sum.Error, "stopped after 2 redirects") {
		t.Fatalf("want the caller's redirect limit to stop the loop, got error %q", sum.Error)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2 (net/http counts the first request in via)", got)
	}
}
