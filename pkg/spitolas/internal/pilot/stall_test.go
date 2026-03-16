package pilot

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestStallTimer_FiresAfterTimeout(t *testing.T) {
	var cancelled atomic.Bool
	cancel := func() { cancelled.Store(true) }

	st := newStallTimer(20*time.Millisecond, cancel)
	defer st.Stop()

	time.Sleep(50 * time.Millisecond)
	if !cancelled.Load() {
		t.Error("stall timer should have fired")
	}
	if !st.Stop() {
		t.Error("Stop() should return true after firing")
	}
}

func TestStallTimer_ResetPreventsFirering(t *testing.T) {
	var cancelled atomic.Bool
	cancel := func() { cancelled.Store(true) }

	st := newStallTimer(30*time.Millisecond, cancel)
	defer st.Stop()

	// Reset before it fires
	time.Sleep(15 * time.Millisecond)
	st.Reset()
	time.Sleep(15 * time.Millisecond)
	st.Reset()
	time.Sleep(15 * time.Millisecond)

	if cancelled.Load() {
		t.Error("stall timer should not have fired — Reset() was called")
	}
}

func TestStallTimer_StopPreventsFirering(t *testing.T) {
	var cancelled atomic.Bool
	cancel := func() { cancelled.Store(true) }

	st := newStallTimer(20*time.Millisecond, cancel)

	fired := st.Stop()
	if fired {
		t.Error("Stop() should return false when timer hasn't fired")
	}

	time.Sleep(50 * time.Millisecond)
	if cancelled.Load() {
		t.Error("cancel should not be called after Stop()")
	}
}

func TestStallTimer_StopReturnsFiredState(t *testing.T) {
	var cancelled atomic.Bool
	cancel := func() { cancelled.Store(true) }

	st := newStallTimer(10*time.Millisecond, cancel)

	// Wait for it to fire
	time.Sleep(30 * time.Millisecond)

	fired := st.Stop()
	if !fired {
		t.Error("Stop() should return true when timer already fired")
	}
	if !cancelled.Load() {
		t.Error("cancel should have been called")
	}
}

func TestStallTimer_ResetAfterStopIsNoop(t *testing.T) {
	cancel := func() {}
	st := newStallTimer(50*time.Millisecond, cancel)
	st.Stop()

	// Reset after Stop should not panic
	st.Reset()
}

func TestStallTimer_ResetAfterFiredIsNoop(t *testing.T) {
	var cancelled atomic.Bool
	cancel := func() { cancelled.Store(true) }

	st := newStallTimer(10*time.Millisecond, cancel)
	time.Sleep(30 * time.Millisecond)

	// Reset after firing should not panic or re-arm
	st.Reset()
	st.Stop()
}
