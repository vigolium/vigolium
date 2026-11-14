package config

import (
	"testing"
	"time"
)

// Discovery has a phase ceiling, default --discover-max-time ×
// min(targets, 3); an explicit value wins and "0" disables it.
func TestDiscoveryPhaseMaxDuration(t *testing.T) {
	var c DiscoveryConfig
	if got := c.PhaseMaxDurationValue(time.Hour, 1000); got != 3*time.Hour {
		t.Errorf("1000 targets: %v, want 3h", got)
	}
	if got := c.PhaseMaxDurationValue(time.Hour, 2); got != 2*time.Hour {
		t.Errorf("2 targets: %v, want 2h", got)
	}
	if got := c.PhaseMaxDurationValue(0, 5); got != 0 {
		t.Errorf("no per-target budget: %v, want 0", got)
	}
	c.PhaseMaxDuration = "45m"
	if got := c.PhaseMaxDurationValue(time.Hour, 9); got != 45*time.Minute {
		t.Errorf("explicit: %v, want 45m", got)
	}
	c.PhaseMaxDuration = "0"
	if got := c.PhaseMaxDurationValue(time.Hour, 9); got != 0 {
		t.Errorf("0 disables: %v", got)
	}
}
