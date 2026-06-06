package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// These tests exercise the full streaming agent stack end to end — a real HTTP
// client over a real TCP listener → the Fiber handler → the olium engine → a
// mock OpenAI-compatible provider — to lock in the SSE client-disconnect
// behavior: when the client goes away mid-run, the run must still finalize its
// DB status (not hang on "running") and runtime.log must keep being written.
// See drainAgentPipeToSSE / sseSink and the io.MultiWriter(logFile, pw) ordering
// in the SSE handlers.

// chatProviderBehavior controls the mock provider's streaming. content is sent
// as OpenAI content deltas. If gate is non-nil the provider sends the first
// delta, signals started (if non-nil), blocks until gate is closed, then sends
// the rest + [DONE] — letting a test disconnect the *vigolium* client while the
// run is provably in flight.
type chatProviderBehavior struct {
	content []string
	started chan struct{}
	gate    chan struct{}
}

// newMockChatProvider starts an httptest server that speaks the minimal OpenAI
// Chat Completions SSE wire format the olium openai-compatible provider expects.
func newMockChatProvider(t *testing.T, b chatProviderBehavior) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("mock provider: ResponseWriter is not a Flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		writeDelta := func(s string) {
			_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", s)
			flusher.Flush()
		}

		content := b.content
		if len(content) == 0 {
			content = []string{"ok"}
		}

		if b.gate != nil {
			// Stream the first delta, announce the run is in flight, then hold
			// the provider stream open until the test releases the gate.
			writeDelta(content[0])
			if b.started != nil {
				close(b.started)
			}
			select {
			case <-b.gate:
			case <-r.Context().Done():
				return
			}
			for _, c := range content[1:] {
				writeDelta(c)
			}
		} else {
			for _, c := range content {
				writeDelta(c)
			}
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// pointHandlersAtMockProvider rewires h's olium config to dispatch through the
// openai-compatible provider at the mock server.
func pointHandlersAtMockProvider(h *Handlers, mockURL string) {
	h.settings.Agent.Olium.Provider = "openai-compatible"
	h.settings.Agent.Olium.Model = "mock-model"
	h.settings.Agent.Olium.CustomProvider.BaseURL = mockURL + "/v1"
	h.settings.Agent.Olium.CustomProvider.ModelID = "mock-model"
	h.settings.Agent.Olium.CustomProvider.APIKey = ""
	h.settings.Agent.Olium.CallTimeoutSec = 60
}

// startAgentTestServer serves the agent endpoints on a real localhost TCP port
// so a real http.Client can connect and disconnect mid-stream (app.Test buffers
// the whole response and can't simulate that). Returns the base URL.
func startAgentTestServer(t *testing.T, h *Handlers) string {
	t.Helper()
	app := newAgentTestApp(h)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() { _ = app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(2 * time.Second) })
	return "http://" + ln.Addr().String()
}

func waitForRunUUID(t *testing.T, sessionsDir string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir(sessionsDir)
		for _, e := range entries {
			if e.IsDir() {
				return e.Name()
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run session dir never appeared under %s", sessionsDir)
	return ""
}

func waitForTerminalStatus(t *testing.T, repo *database.Repository, uuid string, timeout time.Duration) *database.AgenticScan {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last *database.AgenticScan
	for time.Now().Before(deadline) {
		run, err := repo.GetAgenticScan(context.Background(), uuid)
		if err == nil && run != nil {
			last = run
			if isTerminalAgentStatus(run.Status) {
				return run
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	status := "<nil>"
	if last != nil {
		status = last.Status
	}
	t.Fatalf("run %s never reached terminal status within %s (last status=%q)", uuid, timeout, status)
	return nil
}

// TestAgentSSE_QueryHappyPath_RealListener is the baseline that proves the full
// stack streams to a connected client and finalizes the DB row + runtime.log.
func TestAgentSSE_QueryHappyPath_RealListener(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up a TCP server and runs the agent engine; skipped under -short")
	}
	h, repo, sessionsDir := newAgentTestHandlers(t)
	mock := newMockChatProvider(t, chatProviderBehavior{content: []string{"hello ", "world"}})
	pointHandlersAtMockProvider(h, mock.URL)
	baseURL := startAgentTestServer(t, h)

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/agent/run/query",
		strings.NewReader(`{"prompt":"hi","stream":true}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain the SSE stream; collect chunk text and confirm a terminal event.
	var sawDone bool
	var streamed strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if strings.Contains(payload, `"type":"done"`) {
			sawDone = true
		}
		streamed.WriteString(payload)
	}
	if !sawDone {
		t.Errorf("expected a done event over SSE, got: %q", streamed.String())
	}

	uuid := waitForRunUUID(t, sessionsDir, 5*time.Second)
	run := waitForTerminalStatus(t, repo, uuid, 10*time.Second)
	if run.Status != "completed" {
		t.Errorf("expected status=completed, got %q (error=%q)", run.Status, run.ErrorMessage)
	}
	assertRuntimeLogContains(t, sessionsDir, uuid, "hello")
}

// TestAgentSSE_ClientDisconnectFinalizesRunAndLog is the regression guard for
// the reported bug: with stream:true, when the SSE client disconnects mid-run,
// runtime.log froze and the DB row was stuck on "running" forever while the
// agent kept going. The fix (drainAgentPipeToSSE keeps draining to EOF; log
// file first in the MultiWriter) means the run finalizes and the log is written
// regardless of the client. The provider gate guarantees the disconnect happens
// while the run is genuinely in flight.
func TestAgentSSE_ClientDisconnectFinalizesRunAndLog(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up a TCP server and runs the agent engine; skipped under -short")
	}
	h, repo, sessionsDir := newAgentTestHandlers(t)

	started := make(chan struct{})
	gate := make(chan struct{})
	releaseOnce := func() func() {
		done := false
		return func() {
			if !done {
				done = true
				close(gate)
			}
		}
	}()
	defer releaseOnce() // ensure the provider/engine is never left blocked

	// First delta announces the run is in flight; after the disconnect the
	// provider streams a large payload so the server keeps writing to the now
	// dead socket — that's what surfaces the SSE write error the drain must
	// survive (keep draining to EOF rather than bailing before finalization).
	// Many small deltas (each well under any SSE line-length limit) instead of
	// one huge one.
	postChunks := make([]string, 0, 128)
	for i := 0; i < 128; i++ {
		postChunks = append(postChunks, strings.Repeat("x", 2048))
	}
	mock := newMockChatProvider(t, chatProviderBehavior{
		content: append([]string{"partial "}, postChunks...),
		started: started,
		gate:    gate,
	})
	pointHandlersAtMockProvider(h, mock.URL)
	baseURL := startAgentTestServer(t, h)

	// Capture the client's TCP connection so we can hard-close it (RST) — a
	// clean FIN can leave small writes buffered without ever erroring, which
	// wouldn't exercise the disconnect path.
	var connMu sync.Mutex
	var clientConn net.Conn
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err == nil {
				connMu.Lock()
				clientConn = c
				connMu.Unlock()
			}
			return c, err
		},
	}

	reqCtx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/api/agent/run/query",
		strings.NewReader(`{"prompt":"hi","stream":true}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}

	// Wait until the run is provably in flight (the provider was called and the
	// first delta sent), then hard-disconnect the client mid-run.
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		_ = resp.Body.Close()
		t.Fatal("agent run never reached the provider; engine wiring problem")
	}

	_ = resp.Body.Close()
	connMu.Lock()
	if tcp, ok := clientConn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0) // force RST on close
	}
	if clientConn != nil {
		_ = clientConn.Close()
	}
	connMu.Unlock()

	// Let the run finish now that the client is gone; the server will try to
	// stream the large payload into the dead socket.
	releaseOnce()

	// The invariant the bug violated: the run still finalizes and the log is
	// still written even though the client vanished.
	uuid := waitForRunUUID(t, sessionsDir, 5*time.Second)
	run := waitForTerminalStatus(t, repo, uuid, 15*time.Second)
	if run.Status == "running" || run.Status == "pending" {
		t.Fatalf("run stuck on %q after client disconnect — the freeze bug regressed", run.Status)
	}
	assertRuntimeLogContains(t, sessionsDir, uuid, "partial")
}

func assertRuntimeLogContains(t *testing.T, sessionsDir, uuid, want string) {
	t.Helper()
	logPath := filepath.Join(sessionsDir, uuid, config.RuntimeLogFilename)
	// The log is flushed as the run completes; give it a brief moment.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(stripANSI(string(data)), want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	data, _ := os.ReadFile(logPath)
	t.Errorf("runtime.log %s did not contain %q after run; got %q", logPath, want, string(data))
}
