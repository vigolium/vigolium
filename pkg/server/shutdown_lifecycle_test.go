package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
)

// TestHandlersRunContextCancelledByClose locks in the server-lifecycle wiring:
// background agent runs derive their per-run context from h.runContext(), and
// Close() (called by Server.Shutdown) must cancel it so in-flight runs stop and
// release their streaming connections. Before this wiring, runs used a detached
// context.Background() that shutdown could never cancel.
func TestHandlersRunContextCancelledByClose(t *testing.T) {
	h := NewHandlers(&fakeQueue{}, nil, nil, nil,
		ServerConfig{NoAgent: true}, config.DefaultSettings(), nil, nil)

	runCtx := h.runContext()
	select {
	case <-runCtx.Done():
		t.Fatal("runContext was already cancelled before Close")
	default:
	}

	h.Close() // idempotent cancel + channel close; called exactly once here

	select {
	case <-runCtx.Done():
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("runContext was not cancelled by Close")
	}
}

// TestHandlersRunContextNilSafe verifies the fallback: a Handlers built directly
// (e.g. in tests) without NewHandlers wiring runCtx still returns a usable,
// non-nil parent context so callers never pass nil to context.WithTimeout.
func TestHandlersRunContextNilSafe(t *testing.T) {
	h := &Handlers{}
	if h.runContext() == nil {
		t.Fatal("runContext() returned nil for a directly-constructed Handlers")
	}
}

// TestServerShutdownHonorsContextDeadline is the regression test for the
// Ctrl+C-can't-stop-the-server hang: an in-flight (non-idle) connection used to
// make graceful shutdown block forever because Server.Shutdown called the
// Fiber app's Shutdown() without a deadline. With ShutdownWithContext(ctx) the
// 30s CLI deadline is honored — shutdown force-closes the stuck connection and
// returns instead of spinning until SIGKILL.
func TestServerShutdownHonorsContextDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("binds a TCP listener and holds a connection open; skipped under -short")
	}

	s := NewServer(ServerConfig{NoAgent: true}, &fakeQueue{}, nil, nil, nil, nil, nil)

	// A handler that stays in-flight (and thus keeps its connection non-idle)
	// for the whole test. closeIdleConns() can't reap it, so the only way out
	// of fasthttp's shutdown loop is the context deadline.
	inFlight := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.serviceApp.Get("/__test_block", func(c fiber.Ctx) error {
		select {
		case <-inFlight:
		default:
			close(inFlight)
		}
		select {
		case <-release:
		case <-time.After(30 * time.Second):
		}
		return nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() { _ = s.serviceApp.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()

	// Occupy a connection with the blocking handler. We never read the
	// response — the request is force-closed when shutdown fires.
	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		req, reqErr := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/__test_block", nil)
		if reqErr != nil {
			return
		}
		resp, doErr := client.Do(req)
		if doErr == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-inFlight:
	case <-time.After(10 * time.Second):
		t.Fatal("blocking handler never received the request")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	shutdownErr := s.Shutdown(shutdownCtx)
	elapsed := time.Since(start)

	// The decisive assertion: shutdown returned. Before the fix it looped
	// forever and this test would fail via the package test timeout. A 25s
	// ceiling leaves generous slack over the 2s deadline without masking a hang.
	if elapsed > 25*time.Second {
		t.Fatalf("Server.Shutdown blocked for %s despite a 2s deadline (deadline not honored)", elapsed)
	}
	// A connection was still busy at the deadline, so shutdown should surface
	// the deadline error rather than a clean nil.
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded from forced shutdown, got %v (elapsed %s)", shutdownErr, elapsed)
	}
}
