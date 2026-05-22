package work

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestNewWithModules(t *testing.T) {
	req := &httpmsg.HttpRequestResponse{}
	mods := []string{"xss", "sqli"}
	w := NewWithModules(req, mods)
	if w.Request != req {
		t.Error("Request not set")
	}
	if len(w.EnableModules) != 2 {
		t.Errorf("EnableModules = %v, want 2 entries", w.EnableModules)
	}
	// No callback: Complete must be a safe no-op.
	w.Complete()
}

func TestNewWithCallback(t *testing.T) {
	req := &httpmsg.HttpRequestResponse{}
	called := 0
	w := NewWithCallback(req, nil, func() { called++ })
	if w.Request != req {
		t.Error("Request not set")
	}
	w.Complete()
	if called != 1 {
		t.Errorf("onComplete called %d times, want 1", called)
	}
	// Idempotency is not guaranteed by the type, but a second Complete must
	// still invoke the callback (documented behavior: it just calls onComplete).
	w.Complete()
	if called != 2 {
		t.Errorf("onComplete called %d times after second Complete, want 2", called)
	}
}

func TestCompleteNilCallbackSafe(t *testing.T) {
	// A zero-value WorkItem has a nil callback; Complete must not panic.
	w := &WorkItem{}
	w.Complete()
}
