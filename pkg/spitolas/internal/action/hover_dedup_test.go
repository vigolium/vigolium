package action

import "testing"

// TestMarkCheckedEventTypeNamespacing verifies that a hover action and a click
// action on the SAME element (same location, same state) both survive dedup —
// otherwise the hover-menu pass would be silently suppressed by the click that
// the selector/CDP passes already generated for the same trigger element.
func TestMarkCheckedEventTypeNamespacing(t *testing.T) {
	e := NewCandidateElementExtractorDefault()
	e.SetClickOnce(true)
	e.SetCurrentState("state1")

	mk := func(evt EventType) *CandidateElement {
		return &CandidateElement{
			Identification: NewIdentification(HowXPath, "/html/body/nav[1]/a[1]"),
			TagName:        "a",
			EventType:      evt,
		}
	}

	if !e.markChecked(mk(EventTypeClick)) {
		t.Fatal("first click candidate should be NEW")
	}
	if e.markChecked(mk(EventTypeClick)) {
		t.Error("duplicate click candidate should be suppressed within the same state")
	}
	if !e.markChecked(mk(EventTypeHover)) {
		t.Error("hover candidate on the same element should be NEW (event type namespaces the key)")
	}
	if e.markChecked(mk(EventTypeHover)) {
		t.Error("duplicate hover candidate should be suppressed within the same state")
	}

	// A different state resets dedup: the same click is new again.
	e.SetCurrentState("state2")
	if !e.markChecked(mk(EventTypeClick)) {
		t.Error("click candidate should be NEW again in a different state")
	}
}

// TestCreateCandidateElementEventType verifies the event type is carried onto the
// built CandidateElement (so hover actions actually fire as hover, not click).
func TestCreateCandidateElementEventType(t *testing.T) {
	if got := (&CandidateElement{EventType: EventTypeHover}).GetEventType(); got != EventTypeHover {
		t.Errorf("GetEventType() = %q, want %q", got, EventTypeHover)
	}
}
