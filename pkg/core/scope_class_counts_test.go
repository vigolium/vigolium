package core

import "testing"

func TestScopeClassCountsSince(t *testing.T) {
	var c scopeClassCounts
	c.add("status_code")
	base := c.snapshot()
	c.add("status_code")
	c.add("path")
	c.add("")
	got := c.since(base)
	if got["status_code"] != 1 || got["path"] != 1 || len(got) != 2 {
		t.Fatalf("since = %v", got)
	}
}
