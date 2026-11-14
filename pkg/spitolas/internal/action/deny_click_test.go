package action

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// SAFE-9: the default destructive-click guard drops "Sign out", an href to
// /account/delete and an aria-label "Delete item", keeps "Next", exempts
// hover, and an empty pattern disables it.
func TestDenyClickPattern_DefaultGuard(t *testing.T) {
	cfg, err := config.New("https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	e := NewCandidateElementExtractor(cfg)
	cands := []*CandidateElement{
		{Text: "Sign out", EventType: EventTypeClick},
		{Text: "My account", Href: "/account/delete", EventType: EventTypeClick},
		{Text: "", Attributes: "aria-label=Delete item class=icon-btn", EventType: EventTypeClick},
		{Text: "Next", Href: "/page/2", Attributes: "class=pager title=Next page", EventType: EventTypeClick},
		{Text: "Remove filters menu", EventType: EventTypeHover},
	}
	var kept []string
	for _, c := range cands {
		if !e.deniedByPattern(c) {
			kept = append(kept, c.Text)
		}
	}
	if len(kept) != 2 || kept[0] != "Next" || kept[1] != "Remove filters menu" {
		t.Errorf("kept = %q, want [Next, hover candidate]", kept)
	}
	if n := e.SkippedDestructive(); n != 3 {
		t.Errorf("SkippedDestructive = %d, want 3", n)
	}
	if tab := e.ForTab(); tab.SkippedDestructive() != 3 || !tab.deniedByPattern(cands[0]) {
		t.Error("ForTab copies must share the guard and its counter")
	}

	cfg.DenyClickPattern = ""
	off := NewCandidateElementExtractor(cfg)
	if off.deniedByPattern(cands[0]) {
		t.Error("an empty deny_click_pattern disables the guard")
	}
}

func TestDenyAttrValues(t *testing.T) {
	got := denyAttrValues("aria-label=Delete item class=x title=Go now value=Sign out")
	want := []string{"Delete item", "Go now", "Sign out"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
