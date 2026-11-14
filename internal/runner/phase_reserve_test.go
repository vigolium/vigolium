package runner

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// With a total scan budget, an early phase's deadline leaves the reserves of
// the phases after it unspent (ECON-5).
func TestPhaseDeadlineReserved(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ctx, c := phaseDeadlineReserved(parent, 0, 0.6)
	defer c()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("reserve must impose a deadline under a total budget")
	}
	if left := time.Until(dl); left > 4500*time.Millisecond || left < 3*time.Second {
		t.Fatalf("phase got %v of a 10s budget with 60%% reserved, want ~4s", left)
	}

	ctx2, c2 := phaseDeadlineReserved(parent, time.Second, 0.6)
	defer c2()
	if dl, _ := ctx2.Deadline(); time.Until(dl) > 1100*time.Millisecond {
		t.Fatal("a shorter phase max must still win")
	}

	ctx3, c3 := phaseDeadlineReserved(context.Background(), 0, 0.6)
	defer c3()
	if _, ok := ctx3.Deadline(); ok {
		t.Fatal("no total budget: no reserve deadline")
	}
}

func TestReserveAfter(t *testing.T) {
	r := &Runner{options: &types.Options{KnownIssueScanEnabled: true}, settings: &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}}
	for phase, want := range map[NativePhase]float64{
		PhaseDiscovery:         0.6,
		PhaseSpidering:         0.6,
		PhaseDynamicAssessment: 0.1,
		PhaseKnownIssueScan:    0,
	} {
		if got := r.reserveAfter(string(phase)); got < want-1e-9 || got > want+1e-9 {
			t.Errorf("reserveAfter(%s) = %v, want %v", phase, got, want)
		}
	}
	r.options.KnownIssueScanEnabled = false
	if got := r.reserveAfter(string(PhaseDiscovery)); got != 0.5 {
		t.Errorf("without KIS, discovery reserves %v, want 0.5", got)
	}
}
