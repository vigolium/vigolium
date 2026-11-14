package network

import (
	"context"
	"testing"
)

// TestActiveMemGuardianRunsMonitor is RES-10: StartActiveMemGuardian starts a
// monitor (it used to have no caller and never ran Run, so IsLowOnMemory was
// always false), Stop tears it down, and a second Start in the same process
// gets a working monitor again.
func TestActiveMemGuardianRunsMonitor(t *testing.T) {
	for i := 0; i < 2; i++ {
		StartActiveMemGuardian(context.Background())
		if !activeMemGuardianRunning() {
			t.Fatalf("start %d: no monitor running", i+1)
		}
		StopActiveMemGuardian()
		if activeMemGuardianRunning() {
			t.Fatalf("stop %d: monitor still registered", i+1)
		}
	}

	reset := SetLowMemoryForTest(true)
	if !IsLowOnMemory() {
		t.Fatal("override low → IsLowOnMemory false")
	}
	reset()
}
