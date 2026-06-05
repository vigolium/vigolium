package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/server/mitm"
)

const mitmMarker = "MITM-RECORDED-BODY-7f3a91"

// newTLSUpstream starts an HTTPS test server that echoes a known marker for any
// request, so tests can assert the proxy decrypted and recorded the body.
func newTLSUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"path":"`+r.URL.Path+`","marker":"`+mitmMarker+`"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startProxy runs the ingest proxy on a random local port and returns its URL.
func startProxy(t *testing.T, srv *http.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

// TestIngestProxy_MITMRecordsHTTPS is the core regression guard for HTTPS
// interception: an https:// request routed through the proxy (with a MITM CA)
// must complete end-to-end AND land a decrypted record in the database.
func TestIngestProxy_MITMRecordsHTTPS(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up TLS listeners")
	}
	ctx := context.Background()
	db, repo := newPinnedTestDB(t)
	if err := repo.CreateProject(ctx, &database.Project{
		UUID: database.DefaultProjectUUID, Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	upstream := newTLSUpstream(t)

	ca, err := mitm.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	// upstreamInsecure=true: the httptest server uses a self-signed cert, so the
	// proxy must skip verification when re-originating.
	proxySrv := newIngestProxy("127.0.0.1:0", db, repo, nil, nil,
		func() *config.ScopeMatcher { return nil }, ca, true)
	proxyURL := startProxy(t, proxySrv)

	client := proxyClientTrusting(t, proxyURL, caCertPool(t, ca))
	defer client.CloseIdleConnections()

	resp, err := client.Get(upstream.URL + "/api/content")
	if err != nil {
		t.Fatalf("proxied https GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), mitmMarker) {
		t.Fatalf("client did not receive upstream body: %s", body)
	}

	rec := waitForHostRecord(t, ctx, repo, "127.0.0.1")
	if rec == nil {
		t.Fatal("MITM proxy did not record the intercepted HTTPS request")
	}
	if !strings.Contains(rec.Path, "/api/content") {
		t.Errorf("recorded path = %q, want it to contain /api/content", rec.Path)
	}
	if !strings.Contains(string(rec.RawResponse), mitmMarker) {
		t.Errorf("recorded response is not the decrypted body; got %q", rec.RawResponse)
	}
}

// TestIngestProxy_NoMITM_DoesNotRecordHTTPS guards the opt-in boundary: without
// a MITM CA the CONNECT tunnel is pass-through, so HTTPS traffic flows but is
// never recorded.
func TestIngestProxy_NoMITM_DoesNotRecordHTTPS(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up TLS listeners")
	}
	ctx := context.Background()
	db, repo := newPinnedTestDB(t)
	if err := repo.CreateProject(ctx, &database.Project{
		UUID: database.DefaultProjectUUID, Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	upstream := newTLSUpstream(t)

	// No MITM CA → plain CONNECT tunnel.
	proxySrv := newIngestProxy("127.0.0.1:0", db, repo, nil, nil,
		func() *config.ScopeMatcher { return nil }, nil, false)
	proxyURL := startProxy(t, proxySrv)

	// In tunnel mode the client speaks TLS directly to the upstream, so it must
	// trust the upstream's own self-signed cert (not a MITM CA).
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	client := proxyClientTrusting(t, proxyURL, upstreamPool)
	defer client.CloseIdleConnections()

	resp, err := client.Get(upstream.URL + "/api/content")
	if err != nil {
		t.Fatalf("tunneled https GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), mitmMarker) {
		t.Fatalf("tunnel did not pass traffic through: status %d body %s", resp.StatusCode, body)
	}

	// Give any (erroneous) async write a chance to land, then assert none did.
	time.Sleep(150 * time.Millisecond)
	recs, err := repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, "127.0.0.1", 10)
	if err != nil {
		t.Fatalf("query records: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("tunnel mode must not record HTTPS, but found %d record(s)", len(recs))
	}
}

// proxyClientTrusting builds an HTTP client that routes through proxyURL and
// trusts the given CA pool for the TLS leg.
func proxyClientTrusting(t *testing.T, proxyURL string, pool *x509.CertPool) *http.Client {
	t.Helper()
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(parsed),
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// caCertPool reads the CA cert from disk into a pool.
func caCertPool(t *testing.T, ca *mitm.CA) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(ca.CertPath())
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("failed to append CA cert to pool")
	}
	return pool
}

// waitForHostRecord polls for an http_record captured for the given hostname.
func waitForHostRecord(t *testing.T, ctx context.Context, repo *database.Repository, hostname string) *database.HTTPRecord {
	t.Helper()
	for i := 0; i < 100; i++ {
		recs, err := repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, hostname, 10)
		if err == nil && len(recs) > 0 {
			return recs[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}
