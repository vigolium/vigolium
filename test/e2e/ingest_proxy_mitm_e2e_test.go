//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// These tests are the end-to-end regression guard for the ingest-proxy TLS
// interception (MITM) feature: `vigolium server --ingest-proxy-port N
// --proxy-mitm [--scan-on-receive]`. They drive the REAL exported server
// wiring (server.NewServer builds the CA and the intercepting proxy), so they
// fail if the CA generation, the handleConnect interception path, or the
// scan-on-receive plumbing regresses.
//
// The companion in-process unit tests live in pkg/server/proxy_mitm_test.go
// (proxy handler) and pkg/server/mitm/ca_test.go (CA). These go one level up:
// a real HTTP client routed through a real running server, over real TLS.

const mitmE2EMarker = "MITM-E2E-DECRYPTED-9c1f2a"

// mitmProxyEnv is a running server with HTTPS interception enabled plus an
// upstream HTTPS target to drive traffic at.
type mitmProxyEnv struct {
	db       *database.DB
	repo     *database.Repository
	proxyURL string
	caPath   string
	upstream *httptest.Server
}

// startMITMProxyEnv boots a real vigolium server with --ingest-proxy-port and
// --proxy-mitm against a self-signed HTTPS upstream, and returns a handle.
func startMITMProxyEnv(t *testing.T) *mitmProxyEnv {
	t.Helper()

	db, repo := setupTestDBSingleConn(t)
	require.NoError(t, repo.CreateProject(context.Background(), &database.Project{
		UUID: database.DefaultProjectUUID, Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}))

	// Upstream HTTPS target: serves a known marker in an HTML body and omits
	// security headers (so the scan-on-receive pipeline test has something to
	// flag), 404 elsewhere so active probing finishes quickly.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<!doctype html><html><body>`+mitmE2EMarker+`</body></html>`)
	}))
	t.Cleanup(upstream.Close)

	tmpDir := t.TempDir()
	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	serviceAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", getFreePort(t))

	srv := server.NewServer(server.ServerConfig{
		ServiceAddr:          serviceAddr,
		IngestProxyAddr:      proxyAddr,
		IngestProxyMITM:      true,
		IngestProxyInsecure:  true, // upstream is self-signed (httptest)
		IngestProxyCADir:     t.TempDir(),
		NoAuth:               true,
		NoAgent:              true,
		NoSwagger:            true,
		DisableFetchResponse: true,
		Version:              "test",
	}, taskQueue, db, repo, config.DefaultSettings(), nil, nil)

	caPath := srv.ProxyCACertPath()
	require.NotEmpty(t, caPath, "server must generate a MITM CA when IngestProxyMITM is set")

	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Wait for the API to come up (proxy starts alongside it).
	require.NoError(t, waitForEndpoint("http://"+serviceAddr+"/health", 10*time.Second))

	return &mitmProxyEnv{
		db:       db,
		repo:     repo,
		proxyURL: "http://" + proxyAddr,
		caPath:   caPath,
		upstream: upstream,
	}
}

// client builds an HTTP client that trusts the server's MITM CA and routes
// through the intercepting proxy.
func (e *mitmProxyEnv) client(t *testing.T) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(e.caPath)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "append MITM CA to pool")

	proxyParsed, err := url.Parse(e.proxyURL)
	require.NoError(t, err)

	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyParsed),
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// TestIngestProxyMITM_CapturesHTTPS_E2E proves a real server with --proxy-mitm
// decrypts and records an HTTPS request sent through --ingest-proxy-port.
func TestIngestProxyMITM_CapturesHTTPS_E2E(t *testing.T) {
	env := startMITMProxyEnv(t)
	ctx := context.Background()

	resp := getThroughProxy(t, env.client(t), env.upstream.URL+"/")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), mitmE2EMarker,
		"client must receive the real upstream body through the tunnel")

	rec := waitForProxyRecord(t, ctx, env.repo)
	require.NotNil(t, rec, "the intercepted HTTPS request must be recorded in the DB")
	assert.Equal(t, database.RecordSourceIngestProxy, rec.Source,
		"captured record must be tagged source=ingest-proxy")
	assert.Contains(t, string(rec.RawResponse), mitmE2EMarker,
		"recorded response must be the DECRYPTED body — proof the proxy terminated TLS")
}

// TestIngestProxyMITM_ScanOnReceivePipeline_E2E proves the user's full
// scenario: HTTPS captured via the MITM proxy is scanned by the scan-on-receive
// runner and yields a passive finding on the decrypted response.
func TestIngestProxyMITM_ScanOnReceivePipeline_E2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	env := startMITMProxyEnv(t)

	// Create the scan record up front (server.go normally does this for
	// scan-on-receive; the runner advances the cursor on opts.ScanUUID).
	scan := &database.Scan{
		UUID:        "scan-mitm-sor-e2e",
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "mitm-scan-on-receive",
		Status:      "running",
		Target:      env.upstream.URL,
		ScanSource:  "scan-on-receive",
		ScanMode:    "incremental",
		StartedAt:   time.Now(),
	}
	require.NoError(t, env.repo.CreateScanWithCursor(ctx, scan))

	// Drive one HTTPS request through the intercepting proxy so a decrypted
	// ingest-proxy record exists for the runner to pick up.
	resp := getThroughProxy(t, env.client(t), env.upstream.URL+"/")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	require.NotNil(t, waitForProxyRecord(t, ctx, env.repo),
		"capture must land before the scan-on-receive runner starts")

	// Run the scan-on-receive runner over the captured record.
	opts := newServerRunnerOptionsForTest()
	opts.ScanOnReceive = true
	opts.SkipIngestion = true
	opts.ScanUUID = scan.UUID
	opts.ScanOnReceiveIdleTimeout = 3 * time.Second
	opts.Concurrency = 10
	opts.MaxPerHost = 100
	opts.Targets = []string{env.upstream.URL}

	q, err := queue.NewDiskQueue(queue.DiskQueueConfig{BaseDir: t.TempDir(), MaxRecordsPerSegment: 100})
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	r, err := runner.NewWithInputSource(opts, queue.NewQueueInputSource(q))
	require.NoError(t, err)
	r.SetSettings(config.DefaultSettings())
	r.SetRepository(env.repo)

	go func() { _ = r.RunNativeScan() }()
	t.Cleanup(func() { r.Close() })

	// Poll for the passive finding produced from the decrypted HTTPS response.
	sawFinding := false
	var passiveIDs []string
	pollDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(pollDeadline) {
		var findings []*database.Finding
		if err := env.db.NewSelect().Model(&findings).Scan(ctx); err == nil {
			passiveIDs = passiveIDs[:0]
			for _, f := range findings {
				if f.ModuleType == "passive" {
					passiveIDs = append(passiveIDs, f.ModuleID)
				}
				if f.ModuleID == "security-headers-missing" {
					sawFinding = true
				}
			}
			if sawFinding {
				break
			}
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("context cancelled while polling for findings")
		}
	}

	assert.True(t, sawFinding,
		"scan-on-receive must produce a finding from the MITM-decrypted HTTPS "+
			"response (security-headers-missing). If absent, the HTTPS capture or "+
			"the scan-on-receive pipeline over ingest-proxy records regressed. "+
			"passive findings seen: %v", passiveIDs)
}

// waitForProxyRecord polls for an ingest-proxy http_record captured for the
// upstream host (always 127.0.0.1 for httptest).
func waitForProxyRecord(t *testing.T, ctx context.Context, repo *database.Repository) *database.HTTPRecord {
	t.Helper()
	for i := 0; i < 100; i++ {
		recs, err := repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, "127.0.0.1", 20)
		if err == nil {
			for _, rec := range recs {
				if rec.Source == database.RecordSourceIngestProxy {
					return rec
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// getThroughProxy issues an HTTPS GET via the intercepting proxy, retrying
// briefly while the proxy finishes coming up. Returns the response (the caller
// owns Body) or fails the test.
func getThroughProxy(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			return resp
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("GET %s through proxy never succeeded: %v", url, lastErr)
	return nil
}
