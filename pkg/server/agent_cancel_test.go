package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
)

func newCancelTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	// NoAgent so NewHandlers doesn't spin up the engine / cleanup goroutine; the
	// cancel registry and agenticScanStatus map are still initialized.
	return NewHandlers(&fakeQueue{}, nil, nil, nil,
		ServerConfig{NoAgent: true}, config.DefaultSettings(), nil, nil)
}

// TestCancelRun_RegistryLifecycle covers register → cancel → unregister: a
// registered run's context is cancelled and cancelRun reports it; unknown and
// unregistered UUIDs report false without panicking.
func TestCancelRun_RegistryLifecycle(t *testing.T) {
	h := newCancelTestHandlers(t)

	if h.cancelRun("unknown") {
		t.Error("cancelRun returned true for an unregistered UUID")
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.registerRunCancel("run-1", cancel)

	if !h.cancelRun("run-1") {
		t.Fatal("cancelRun returned false for a registered run")
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("registered run's context was not cancelled")
	}

	h.unregisterRunCancel("run-1")
	if h.cancelRun("run-1") {
		t.Error("cancelRun returned true after unregister")
	}
}

// TestCancelRun_FlipsInMemoryStatus verifies the cancel surfaces immediately as
// a "cancelling" status (the run's own finalization later writes "cancelled").
func TestCancelRun_FlipsInMemoryStatus(t *testing.T) {
	h := newCancelTestHandlers(t)
	_, cancel := context.WithCancel(context.Background())
	h.registerRunCancel("run-2", cancel)
	h.agentMu.Lock()
	h.agenticScanStatus["run-2"] = &AgenticScanStatusResponse{AgenticScanUUID: "run-2", Status: "running"}
	h.agentMu.Unlock()

	h.cancelRun("run-2")

	h.agentMu.Lock()
	got := h.agenticScanStatus["run-2"].Status
	h.agentMu.Unlock()
	if got != "cancelling" {
		t.Errorf("expected in-memory status 'cancelling', got %q", got)
	}
}

func TestHandleAgentCancel_NotFound(t *testing.T) {
	h := newCancelTestHandlers(t)
	app := fiber.New()
	app.Post("/api/agent/scans/:uuid/cancel", h.HandleAgentCancel)

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/api/agent/scans/missing/cancel", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown run, got %d", resp.StatusCode)
	}
}

func TestHandleAgentCancel_CancelsRunningRun(t *testing.T) {
	h := newCancelTestHandlers(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.registerRunCancel("run-9", cancel)

	app := fiber.New()
	app.Post("/api/agent/scans/:uuid/cancel", h.HandleAgentCancel)

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/api/agent/scans/run-9/cancel", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var out AgenticScanResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, body)
	}
	if out.Status != "cancelling" {
		t.Errorf("expected status 'cancelling', got %q", out.Status)
	}

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("run context was not cancelled by the endpoint")
	}
}
