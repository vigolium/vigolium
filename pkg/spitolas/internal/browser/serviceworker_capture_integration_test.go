//go:build integration && (linux || darwin)

package browser

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

// These tests exercise the native service-worker network capture added to
// network.Capture (Target.setAutoAttach to service-worker targets + Network.enable
// on their sessions). They launch a REAL headless browser, so they are gated
// behind the `integration` tag and unix-only (the zombie check uses syscall.Kill).
// Run with: go test -tags=integration -run TestServiceWorker ./pkg/spitolas/internal/browser/...

// swCaptureSink is a network.Writer that records every captured request URL.
type swCaptureSink struct {
	mu   sync.Mutex
	urls []string
}

func (s *swCaptureSink) Write(e *network.TrafficEntry) error {
	s.mu.Lock()
	s.urls = append(s.urls, e.Request.URL)
	s.mu.Unlock()
	return nil
}

func (s *swCaptureSink) Close() error { return nil }

func (s *swCaptureSink) has(substr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.urls {
		if strings.Contains(u, substr) {
			return true
		}
	}
	return false
}

func (s *swCaptureSink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.urls...)
}

// newPWAServer serves a minimal Progressive Web App whose service worker fetches
// /precached-by-sw.js — an asset referenced ONLY from inside the worker, never
// linked in the page HTML. Capturing it therefore proves the service worker's own
// (separate-session) traffic was recorded, not page traffic. localhost is a secure
// context for Chrome, so the worker registers over plain HTTP from httptest.
func newPWAServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>pwa</title></head><body>
<script>if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js'); }</script>
</body></html>`))
	})
	mux.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// On install, fetch an asset from the worker context. waitUntil keeps the
		// worker alive until the fetch resolves so the request is actually made.
		_, _ = w.Write([]byte(`
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(fetch('/precached-by-sw.js').catch(() => {}));
});
self.addEventListener('activate', (event) => { event.waitUntil(self.clients.claim()); });
`))
	})
	mux.HandleFunc("/precached-by-sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("// asset fetched only by the service worker\n"))
	})
	return httptest.NewServer(mux)
}

// serverHost returns the hostname of an httptest server URL — the value the
// capture uses for its cross-origin log filter.
func serverHost(s *httptest.Server) string {
	u, err := url.Parse(s.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// newSWTestBrowser builds a headless browser for these tests, skipping the test
// (rather than failing) if no browser binary can be obtained in the environment.
func newSWTestBrowser(t *testing.T, serverURL string) *Browser {
	t.Helper()
	cfg, err := config.New(serverURL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	b, err := New(cfg)
	if err != nil {
		t.Skipf("no usable browser in this environment: %v", err)
	}
	return b
}

// startSWCapture wires a network.Capture (with the service-worker auto-attach) to
// the browser and returns the capture plus the sink collecting captured URLs.
func startSWCapture(t *testing.T, b *Browser, host string) (*network.Capture, *swCaptureSink) {
	t.Helper()
	sink := &swCaptureSink{}
	// silent + noColor: no stderr noise during tests; capture still writes to sink.
	cap := network.New(sink, true, true, false, false, false, host, "sw-test")
	if err := cap.Start(b.RodBrowser()); err != nil {
		t.Fatalf("capture.Start: %v", err)
	}
	// Let subscribeEvents register its callbacks and set auto-attach before any
	// navigation triggers a service-worker registration.
	time.Sleep(300 * time.Millisecond)
	return cap, sink
}

// TestServiceWorkerPrecacheCaptured is the core functional test: the service
// worker's own fetch (of an asset the page never links) must be captured.
func TestServiceWorkerPrecacheCaptured(t *testing.T) {
	server := newPWAServer()
	defer server.Close()

	host := serverHost(server)

	b := newSWTestBrowser(t, server.URL)
	defer b.Close()

	cap, sink := startSWCapture(t, b, host)
	defer func() { _ = cap.Close() }()

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := page.Navigate(server.URL + "/"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	// The service worker installs asynchronously after navigation; poll for its
	// precache fetch.
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if sink.has("/precached-by-sw.js") {
			return // success: SW-only asset was captured
		}
		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("service-worker precache asset /precached-by-sw.js was not captured.\ncaptured URLs:\n  %s",
		strings.Join(sink.snapshot(), "\n  "))
}

// processAlive reports whether a process with pid currently exists. Signal 0 does
// permission/existence checking without delivering a signal: nil or EPERM => the
// PID exists; ESRCH => no such process (terminated and reaped).
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// waitProcessGone polls until the process is gone or the timeout elapses.
func waitProcessGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return !processAlive(pid)
}

// TestServiceWorkerCaptureNoZombieBrowser is the safety test the capability was
// requested with: with service-worker auto-attach active and a worker actually
// registered (and paused-on-start), a normal Close() must terminate the browser
// process — no zombie left behind, and Close() must not hang.
func TestServiceWorkerCaptureNoZombieBrowser(t *testing.T) {
	server := newPWAServer()
	defer server.Close()

	host := serverHost(server)

	b := newSWTestBrowser(t, server.URL)
	pid := b.launcher.PID()
	if pid <= 0 {
		t.Fatalf("could not determine browser PID (got %d)", pid)
	}
	if !processAlive(pid) {
		t.Fatalf("browser process %d not alive right after launch", pid)
	}

	cap, _ := startSWCapture(t, b, host)

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := page.Navigate(server.URL + "/"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	// Give the service worker time to register and auto-attach (exercising the
	// WaitForDebuggerOnStart pause + onWorkerAttached resume path) before teardown.
	time.Sleep(2 * time.Second)

	_ = cap.Close()

	// Close() must return promptly (guard against a teardown hang).
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("browser.Close returned error: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("browser.Close hung for >30s (PID %d) — possible zombie/stuck session", pid)
	}

	if !waitProcessGone(pid, 20*time.Second) {
		t.Fatalf("browser process %d still alive 20s after Close() — zombie browser", pid)
	}
}

// TestServiceWorkerCaptureLaunchCloseLoop stresses repeated launch/teardown with
// the service-worker capture active, asserting every browser is reaped. A leak in
// the auto-attach / paused-worker / capture-goroutine path would surface here as a
// lingering process or a Close() hang.
func TestServiceWorkerCaptureLaunchCloseLoop(t *testing.T) {
	const rounds = 3
	server := newPWAServer()
	defer server.Close()

	host := serverHost(server)

	for i := 0; i < rounds; i++ {
		b := newSWTestBrowser(t, server.URL)
		pid := b.launcher.PID()

		cap, _ := startSWCapture(t, b, host)
		page, err := b.NewPage()
		if err != nil {
			_ = cap.Close()
			_ = b.Close()
			t.Fatalf("round %d: NewPage: %v", i, err)
		}
		if err := page.Navigate(server.URL + "/"); err != nil {
			_ = cap.Close()
			_ = b.Close()
			t.Fatalf("round %d: Navigate: %v", i, err)
		}
		time.Sleep(1500 * time.Millisecond) // let the SW attach

		_ = cap.Close()
		if err := b.Close(); err != nil {
			t.Fatalf("round %d: Close: %v", i, err)
		}
		if pid > 0 && !waitProcessGone(pid, 20*time.Second) {
			t.Fatalf("round %d: browser process %d still alive after Close() — zombie", i, pid)
		}
	}
}
