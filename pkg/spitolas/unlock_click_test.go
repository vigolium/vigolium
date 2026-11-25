package spitolas

import (
	"strings"
	"testing"
)

func TestUnlockTriggerKind(t *testing.T) {
	cases := []struct {
		label, attrs, tag, href, want string
	}{
		{"Search", "type=submit", "button", "", unlockTriggerSearch},
		{"", "type=search", "input", "", unlockTriggerSearch},
		{"查询", "", "button", "", unlockTriggerSearch},
		{"Apply filters", "", "button", "", unlockTriggerFilter},
		{"View", "", "a", "/users/1", unlockTriggerView},
		{"详情", "", "a", "", unlockTriggerView},
		{"Edit", "", "button", "", unlockTriggerEdit},
		{"Export CSV", "", "button", "", unlockTriggerExport},
		{"Download details", "", "a", "/report", unlockTriggerExport},
		{"Users", "role=tab", "div", "", unlockTriggerList},
		{"Orders", "", "a", "/admin/orders", unlockTriggerList},
		{"Next", "", "button", "", unlockTriggerList},
		{"Toggle", "", "button", "", unlockTriggerOther},
		{"Reviewer", "", "button", "", unlockTriggerOther},
	}
	for _, tc := range cases {
		if got := unlockTriggerKind(tc.label, tc.attrs, tc.tag, tc.href); got != tc.want {
			t.Errorf("unlockTriggerKind(%q, %q) = %q, want %q", tc.label, tc.attrs, got, tc.want)
		}
	}
}

// One click per trigger kind first, so each module yields one request shape
// per action: twenty "View" rows spend one click, not twenty.
func TestPlanUnlockClicks(t *testing.T) {
	cand := func(kind, label string) unlockClickCandidate { return unlockClickCandidate{kind: kind, label: label} }
	cands := []unlockClickCandidate{
		cand(unlockTriggerList, "Users"),
		cand(unlockTriggerView, "View"), cand(unlockTriggerView, "View"), cand(unlockTriggerView, "View"),
		cand(unlockTriggerEdit, "Edit"), cand(unlockTriggerEdit, "Edit"),
		cand(unlockTriggerExport, "Export"),
		cand(unlockTriggerSearch, "Search"),
		cand(unlockTriggerFilter, "Filter"),
		cand(unlockTriggerOther, "Refresh"), cand(unlockTriggerOther, "refresh"),
		cand(unlockTriggerList, "Orders"),
	}
	labels := func(plan []unlockClickCandidate) string {
		var out []string
		for _, c := range plan {
			out = append(out, c.label)
		}
		return strings.Join(out, ",")
	}
	if got := labels(planUnlockClicks(cands, 30)); got != "Search,Filter,View,Edit,Export,Users,Refresh,Orders" {
		t.Errorf("plan = %s", got)
	}
	if got := labels(planUnlockClicks(cands, 3)); got != "Search,Filter,View" {
		t.Errorf("capped plan = %s", got)
	}
	if got := planUnlockClicks(cands, 0); got != nil {
		t.Errorf("a zero cap clicks nothing: %v", got)
	}
}

// The walk refuses to click when writes are allowed: a click under a write
// grant becomes a real write.
func TestUnlockClickRefusedUnderWriteGrant(t *testing.T) {
	w, _ := newTestWalk(t, `{"origin":"http://app.test","maxClicksPerRoute":10}`, true)
	if n, reason := w.clickBudget(); n != 0 || reason != "writes_allowed" {
		t.Fatalf("clickBudget with writes allowed = %d %q, want 0 writes_allowed", n, reason)
	}
	if c := w.newClicker(); c != nil {
		t.Fatalf("a clicker was built under a write grant")
	}

	w, _ = newTestWalk(t, `{"origin":"http://app.test","maxClicksPerRoute":10}`, false)
	if n, reason := w.clickBudget(); n != 10 || reason != "" {
		t.Errorf("clickBudget = %d %q, want 10", n, reason)
	}
	w, _ = newTestWalk(t, `{"origin":"http://app.test","maxClicksPerRoute":0}`, true)
	if n, reason := w.clickBudget(); n != 0 || reason != "" {
		t.Errorf("a profile that turns clicks off is not a refusal: %d %q", n, reason)
	}
}
