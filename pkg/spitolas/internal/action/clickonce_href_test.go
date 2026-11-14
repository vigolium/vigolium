package action

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// MISS-28b: a navigable link is clicked once per crawl, whatever state shows
// it; a non-link element (a wizard "Next" button) stays per-state.
func TestClickOnce_NavigableLinkAcrossStates(t *testing.T) {
	cfg, err := config.New("https://app.test/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ClickOnce = true
	e := NewCandidateElementExtractor(cfg)
	link := func(xpath string) *CandidateElement {
		return &CandidateElement{TagName: "a", Href: "/products", EventType: EventTypeClick,
			Identification: NewIdentification(HowXPath, xpath)}
	}
	button := &CandidateElement{TagName: "button", Text: "Next", EventType: EventTypeClick,
		Identification: NewIdentification(HowXPath, "/html/body/button")}

	e.SetCurrentState("s1")
	if !e.markChecked(link("/html/body/nav/a[1]")) || !e.markChecked(button) {
		t.Fatal("first sighting must be new")
	}
	e.SetCurrentState("s2")
	if e.markChecked(link("/html/body/div/nav/a[3]")) {
		t.Error("the same link in another state must not be re-clicked")
	}
	if !e.markChecked(button) {
		t.Error("a non-link element stays per-state")
	}
	abs := &CandidateElement{TagName: "a", Href: "https://app.test/products#top", EventType: EventTypeClick,
		Identification: NewIdentification(HowXPath, "/x")}
	if e.markChecked(abs) {
		t.Error("absolute href to the same URL (fragment ignored) must dedup with the root-relative one")
	}
}
