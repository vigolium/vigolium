package core

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/stats"
)

// After 50 completed calls the per-module timeout follows the module's own
// p99 × 3, clamped to [30s, 300s]; before that, and whenever the operator set
// a timeout, the configured/default value applies (ECON-7).
func TestAdaptiveActiveTimeout(t *testing.T) {
	e := &Executor{moduleMetrics: &stats.ModuleMetrics{}}
	if got := e.adaptiveActiveTimeout("m"); got != defaultActiveModuleTimeout {
		t.Fatalf("no samples: %v, want default %v", got, defaultActiveModuleTimeout)
	}
	for i := 0; i < 49; i++ {
		e.moduleMetrics.For("m").RecordCompletedDuration(time.Second)
	}
	if got := e.adaptiveActiveTimeout("m"); got != defaultActiveModuleTimeout {
		t.Fatalf("49 samples: %v, want default", got)
	}
	e.moduleMetrics.For("m").RecordCompletedDuration(time.Second)
	if got := e.adaptiveActiveTimeout("m"); got != adaptiveTimeoutMin {
		t.Fatalf("p99≈1s: %v, want the 30s floor", got)
	}

	for i := 0; i < 100; i++ {
		e.moduleMetrics.For("slow").RecordCompletedDuration(40*time.Second)
	}
	if got := e.adaptiveActiveTimeout("slow"); got < 120*time.Second || got > adaptiveTimeoutMax {
		t.Fatalf("p99≈40s: %v, want ~3x within the 300s cap", got)
	}
	for i := 0; i < 100; i++ {
		e.moduleMetrics.For("slower").RecordCompletedDuration(200*time.Second)
	}
	if got := e.adaptiveActiveTimeout("slower"); got != adaptiveTimeoutMax {
		t.Fatalf("p99≈200s: %v, want the 300s cap", got)
	}

	e.cfg.ActiveModuleTimeout = 90 * time.Second
	if got := e.adaptiveActiveTimeout("m"); got != 90*time.Second {
		t.Fatalf("configured timeout overridden: %v", got)
	}
}
