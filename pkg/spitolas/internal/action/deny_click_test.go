package action

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// The default destructive-click guard drops "Sign out", an href to
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
		if !e.deniedByPattern(c, nil) {
			kept = append(kept, c.Text)
		}
	}
	if len(kept) != 2 || kept[0] != "Next" || kept[1] != "Remove filters menu" {
		t.Errorf("kept = %q, want [Next, hover candidate]", kept)
	}
	if n := e.SkippedDestructive(); n != 3 {
		t.Errorf("SkippedDestructive = %d, want 3", n)
	}
	if tab := e.ForTab(); tab.SkippedDestructive() != 3 || !tab.deniedByPattern(cands[0], nil) {
		t.Error("ForTab copies must share the guard and its counter")
	}

	cfg.DenyClickPattern = ""
	off := NewCandidateElementExtractor(cfg)
	if off.deniedByPattern(cands[0], nil) {
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

// With auth configured the crawl never clicks a logout control, even
// when the destructive-click guard is turned off.
func TestAuthenticatedCrawlNeverClicksLogout(t *testing.T) {
	cfg, err := config.New("https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DenyClickPattern = ""
	cfg.ExtraHeaders = map[string]string{"Authorization": "Bearer x"}
	e := NewCandidateElementExtractor(cfg)
	if !e.deniedByPattern(&CandidateElement{Text: "Sign out", EventType: EventTypeClick}, nil) {
		t.Error("logout must be denied in an authenticated crawl")
	}
	if e.deniedByPattern(&CandidateElement{Text: "Delete", EventType: EventTypeClick}, nil) {
		t.Error("with the guard off only logout is denied")
	}
}

// spidering.deny_click_extra only widens the guard: it applies on top of the
// default, and still applies when deny_click_pattern turned the default off.
// Every refusal is sampled by name with the rule that refused it.
func TestDenyClickExtraWidensAndSamples(t *testing.T) {
	cfg, err := config.New("https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DenyClickExtra = "(?:redeem[-_ ]?voucher)|(?:escalate)"
	e := NewCandidateElementExtractor(cfg)
	at := func() string { return "https://app.example.com/billing" }
	redeem := &CandidateElement{Text: "Redeem voucher", EventType: EventTypeClick, Identification: NewIdentification(HowXPath, "/html/body/button[2]")}
	if !e.deniedByPattern(redeem, at) {
		t.Fatal("an extra term must be refused")
	}
	if !e.deniedByPattern(&CandidateElement{Text: "Pay now", EventType: EventTypeClick}, at) {
		t.Fatal("the default (with commit actions) still applies alongside the extras")
	}
	if e.deniedByPattern(&CandidateElement{Text: "View invoice", EventType: EventTypeClick}, at) {
		t.Fatal("an unrelated control must stay clickable")
	}
	got := e.SkippedControls()
	if len(got) != 2 {
		t.Fatalf("sample = %+v, want 2 controls", got)
	}
	if got[0].Label != "Redeem voucher" || got[0].Reason != "deny_click_extra" || got[0].Selector != "/html/body/button[2]" ||
		got[0].URL != "https://app.example.com/billing" || got[0].Match != "Redeem voucher" {
		t.Errorf("first sample = %+v", got[0])
	}
	if got[1].Reason != "deny_click" || got[1].Match != "Pay now" {
		t.Errorf("second sample = %+v", got[1])
	}
	if tab := e.ForTab(); len(tab.SkippedControls()) != 2 {
		t.Error("ForTab copies must share the sample")
	}

	cfg.DenyClickPattern = ""
	off := NewCandidateElementExtractor(cfg)
	if !off.deniedByPattern(&CandidateElement{Text: "Escalate", EventType: EventTypeClick}, nil) {
		t.Error("extras must apply with the default guard turned off")
	}
	if off.deniedByPattern(&CandidateElement{Text: "Delete", EventType: EventTypeClick}, nil) {
		t.Error("with the default off only the extras apply")
	}
}

// The sample is bounded; the count is not.
func TestSkippedControlSampleIsBounded(t *testing.T) {
	cfg, err := config.New("https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	e := NewCandidateElementExtractor(cfg)
	for i := 0; i < scanevents.MaxSkippedControlSample+15; i++ {
		e.deniedByPattern(&CandidateElement{Text: fmt.Sprintf("Delete item %d", i), EventType: EventTypeClick}, nil)
	}
	if n := len(e.SkippedControls()); n != scanevents.MaxSkippedControlSample {
		t.Errorf("sample = %d, want %d", n, scanevents.MaxSkippedControlSample)
	}
	if n := e.SkippedDestructive(); n != int64(scanevents.MaxSkippedControlSample+15) {
		t.Errorf("count = %d, want %d", n, scanevents.MaxSkippedControlSample+15)
	}
}
