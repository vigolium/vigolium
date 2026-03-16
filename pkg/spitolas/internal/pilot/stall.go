package pilot

import (
	"sync"
	"time"
)

// stallTimer detects when the ACP agent stops making tool calls.
// It watches a time.Timer and calls a cancel function if no Reset()
// is received within the timeout duration.
type stallTimer struct {
	mu       sync.Mutex
	timeout  time.Duration
	timer    *time.Timer
	cancelFn func()
	fired    bool
	stopped  bool
}

// newStallTimer creates and starts a stall timer.
// If Reset() is not called within timeout, cancelFn is invoked.
func newStallTimer(timeout time.Duration, cancelFn func()) *stallTimer {
	st := &stallTimer{
		timeout:  timeout,
		timer:    time.NewTimer(timeout),
		cancelFn: cancelFn,
	}
	go func() {
		<-st.timer.C
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.stopped {
			return
		}
		st.fired = true
		st.cancelFn()
	}()
	return st
}

// Reset restarts the timer. Called on every MCP tool call to signal
// that the agent is still actively working.
func (st *stallTimer) Reset() {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.stopped || st.fired {
		return
	}
	if !st.timer.Stop() {
		select {
		case <-st.timer.C:
		default:
		}
	}
	st.timer.Reset(st.timeout)
}

// Stop disarms the timer and returns whether it had already fired.
func (st *stallTimer) Stop() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.stopped = true
	st.timer.Stop()
	return st.fired
}
