package stats

import (
	"context"
	"testing"
	"time"
)

func TestNew_SilentReturnsNil(t *testing.T) {
	if New(10, true) != nil {
		t.Fatal("New with silent=true should return nil")
	}
}

func TestNew_NonSilent(t *testing.T) {
	tr := New(42, false)
	if tr == nil {
		t.Fatal("New with silent=false should return a tracker")
	}
	if tr.Total() != 42 {
		t.Fatalf("Total() = %d, want 42", tr.Total())
	}
	if tr.Processed() != 0 {
		t.Fatalf("Processed() = %d, want 0", tr.Processed())
	}
}

func TestTracker_Counters(t *testing.T) {
	tr := New(0, false)

	for i := 0; i < 5; i++ {
		tr.Increment()
	}
	tr.IncrementFindings()
	tr.IncrementFindings()
	tr.IncrementBlocked()

	if got := tr.Processed(); got != 5 {
		t.Errorf("Processed() = %d, want 5", got)
	}
	if got := tr.Findings(); got != 2 {
		t.Errorf("Findings() = %d, want 2", got)
	}
	if got := tr.Blocked(); got != 1 {
		t.Errorf("Blocked() = %d, want 1", got)
	}
	if got := tr.Total(); got != 0 {
		t.Errorf("Total() = %d, want 0 (unknown)", got)
	}
}

func TestTracker_CountersConcurrent(t *testing.T) {
	tr := New(0, false)

	const workers, perWorker = 8, 1000
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < perWorker; i++ {
				tr.Increment()
			}
			done <- struct{}{}
		}()
	}
	for w := 0; w < workers; w++ {
		<-done
	}

	if got := tr.Processed(); got != workers*perWorker {
		t.Fatalf("Processed() = %d, want %d", got, workers*perWorker)
	}
}

func TestTracker_StartStop(t *testing.T) {
	tr := New(0, false)

	// printInterval is 5s, so no stats line prints during this fast test;
	// we only assert Start spawns a goroutine that Stop joins without hanging.
	tr.Start(context.Background())

	done := make(chan struct{})
	go func() {
		tr.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m30s"},
		{time.Hour + time.Minute + time.Second, "1h1m1s"},
		{2*time.Hour + 30*time.Minute, "2h30m0s"},
		{500 * time.Millisecond, "1s"}, // Round(time.Second) rounds half up
		{400 * time.Millisecond, "0s"},
	}
	for _, tc := range tests {
		if got := formatDuration(tc.in); got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
