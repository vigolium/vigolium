package state

import "testing"

// fakeCandidate is a minimal in-test implementation of CandidateElementIface
// used to exercise State's candidate-tracking logic without the action package
// (and without any browser).
type fakeCandidate struct {
	how          string
	value        string
	explored     bool
	directAccess bool
}

func (f *fakeCandidate) GetIdentificationPair() (string, string) { return f.how, f.value }
func (f *fakeCandidate) WasExplored() bool                       { return f.explored }
func (f *fakeCandidate) SetDirectAccess(direct bool)             { f.directAccess = direct }

func TestStateClusterAccessors(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)
	s.SetCluster(42)
	if s.GetCluster() != 42 {
		t.Errorf("GetCluster() = %d, want 42", s.GetCluster())
	}
}

func TestStateSetHasNearDuplicate(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)
	s.SetHasNearDuplicate(true)
	if !s.IsNearDuplicate {
		t.Error("IsNearDuplicate should be true after SetHasNearDuplicate(true)")
	}
	s.SetHasNearDuplicate(false)
	if s.IsNearDuplicate {
		t.Error("IsNearDuplicate should be false after SetHasNearDuplicate(false)")
	}
}

func TestStateOnURLAndRootFragmentHash(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)
	if s.OnURL {
		t.Error("OnURL should default to false")
	}
	s.SetOnURL(true)
	if !s.OnURL {
		t.Error("OnURL should be true")
	}
	s.SetRootFragmentHash("abc123")
	if s.RootFragmentHash != "abc123" {
		t.Errorf("RootFragmentHash = %q, want %q", s.RootFragmentHash, "abc123")
	}
}

func TestStateUnexploredActionsDefault(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)
	// No candidates set yet => assume unexplored.
	if !s.HasUnexploredActions() {
		t.Error("fresh state with no candidates should report unexplored actions")
	}

	// Explicitly clear the flag.
	s.SetUnexploredActions(false)
	if s.HasUnexploredActions() {
		t.Error("after SetUnexploredActions(false), should report no unexplored actions")
	}
}

func TestStateHasUnexploredActionsWithCandidates(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)

	all := []CandidateElementIface{
		&fakeCandidate{how: "xpath", value: "/a", explored: true},
		&fakeCandidate{how: "xpath", value: "/b", explored: false},
	}
	s.SetElementsFound(all)

	// One candidate is unexplored => true.
	if !s.HasUnexploredActions() {
		t.Error("should report unexplored when at least one candidate is unexplored")
	}

	// All explored => false (and the flag is cached off).
	explored := []CandidateElementIface{
		&fakeCandidate{how: "xpath", value: "/a", explored: true},
		&fakeCandidate{how: "xpath", value: "/b", explored: true},
	}
	s.SetElementsFound(explored)
	if s.HasUnexploredActions() {
		t.Error("should report no unexplored actions when all candidates explored")
	}
}

func TestStateSetElementsFoundAndXPathLookup(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)

	c1 := &fakeCandidate{how: "xpath", value: "/html/body/a"}
	c2 := &fakeCandidate{how: "xpath", value: "/html/body/a"} // same xpath
	c3 := &fakeCandidate{how: "xpath", value: "/html/body/button"}
	empty := &fakeCandidate{how: "xpath", value: ""} // skipped from xpath map

	s.SetElementsFound([]CandidateElementIface{c1, c2, c3, empty})

	if got := len(s.GetCandidateElements()); got != 4 {
		t.Errorf("GetCandidateElements len = %d, want 4", got)
	}

	// First match for an xpath.
	if s.GetCandidateElementByXPath("/html/body/a") != c1 {
		t.Error("GetCandidateElementByXPath should return the first candidate for the xpath")
	}
	// All matches for an xpath.
	all := s.GetCandidateElementsByXPath("/html/body/a")
	if len(all) != 2 {
		t.Errorf("GetCandidateElementsByXPath len = %d, want 2", len(all))
	}
	// Unknown xpath returns nil.
	if s.GetCandidateElementByXPath("/unknown") != nil {
		t.Error("unknown xpath should return nil candidate")
	}
	if s.GetCandidateElementsByXPath("/unknown") != nil {
		t.Error("unknown xpath should return nil slice")
	}
}

func TestStateGetCandidateElementByXPathNilMap(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)
	// No SetElementsFound call => xpathCandidateMap is nil.
	if s.GetCandidateElementByXPath("/x") != nil {
		t.Error("should return nil when no elements found")
	}
	if s.GetCandidateElementsByXPath("/x") != nil {
		t.Error("should return nil slice when no elements found")
	}
}

func TestStateSetDirectAccessByXPath(t *testing.T) {
	ResetCounter()
	s := New("http://test.com", "", "dom", 0)

	// Calling on a nil map should be a no-op (no panic).
	s.SetDirectAccessByXPath("/x")

	c1 := &fakeCandidate{how: "xpath", value: "/html/body/a"}
	c2 := &fakeCandidate{how: "xpath", value: "/html/body/a"}
	s.SetElementsFound([]CandidateElementIface{c1, c2})

	s.SetDirectAccessByXPath("/html/body/a")
	if !c1.directAccess || !c2.directAccess {
		t.Error("SetDirectAccessByXPath should mark all matching candidates")
	}

	// Unknown xpath is a no-op.
	s.SetDirectAccessByXPath("/missing")
}
