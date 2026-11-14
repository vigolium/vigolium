package runner

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
)

// TestRunnerPauseDoesNotBlockOnStuckWorker: Pause returns at once even while a
// worker is stuck mid-dispatch, and PauseState reports "pausing" until it
// releases. The server handler calls Pause under its scan lock, so a
// blocking Pause hung stop/status for every project.
func TestRunnerPauseDoesNotBlockOnStuckWorker(t *testing.T) {
	r := &Runner{pauseCtrl: core.NewPauseController()}
	r.pauseCtrl.AcquireWorker()

	done := make(chan struct{})
	go func() {
		r.Pause()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Runner.Pause blocked behind a worker mid-dispatch")
	}
	if got := r.PauseState(); got != PauseStatePausing {
		t.Fatalf("PauseState = %q, want %q", got, PauseStatePausing)
	}
	r.pauseCtrl.ReleaseWorker()
	if got := r.PauseState(); got != PauseStatePaused {
		t.Fatalf("PauseState = %q, want %q", got, PauseStatePaused)
	}

	closed := make(chan struct{})
	go func() {
		r.Resume()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Resume blocked")
	}
	if got := r.PauseState(); got != PauseStateRunning {
		t.Fatalf("PauseState = %q, want %q", got, PauseStateRunning)
	}
}
