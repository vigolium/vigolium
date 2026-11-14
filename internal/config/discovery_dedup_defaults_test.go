package config

import (
	"slices"
	"testing"
)

// MISS-7: auth walls are kept per path by default (capped at 25 per host);
// only 429 still collapses to one record per host.
func TestDeparosDedupDefaults(t *testing.T) {
	var c DeparosDedupConfig
	if got := c.KeepOneStatuses(); !slices.Equal(got, []int{429}) {
		t.Errorf("KeepOneStatuses = %v, want [429]", got)
	}
	if got := c.KeepPerPathStatuses(); !slices.Equal(got, []int{401, 403, 405, 415, 422}) {
		t.Errorf("KeepPerPathStatuses = %v", got)
	}
	if got := c.AuthWallCapValue(); got != 25 {
		t.Errorf("AuthWallCapValue = %d, want 25", got)
	}
	c.AuthWallCap = -1
	if got := c.AuthWallCapValue(); got != 0 {
		t.Errorf("negative auth_wall_cap = %d, want 0 (use per_path_cap)", got)
	}
}
