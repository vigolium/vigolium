package state

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

func TestNewStateMachine(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()
	idx := New("http://test.com/", "", "DOM-INDEX", 0)
	g.AddState(idx)

	sm := NewStateMachine(g, idx)
	if sm.GetCurrentState() != idx {
		t.Error("current state should be the initial state")
	}
	if sm.GetInitialState() != idx {
		t.Error("initial state mismatch")
	}
	if sm.GetGraph() != g {
		t.Error("graph mismatch")
	}
	// Initial state is seeded into onURLSet.
	if sm.OnURLSetSize() != 1 {
		t.Errorf("OnURLSetSize() = %d, want 1", sm.OnURLSetSize())
	}
}

func TestNewStateMachineWithOnURLSet(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()
	idx := New("http://test.com/", "", "DOM-INDEX", 0)
	other := New("http://test.com/x", "", "DOM-X", 1)
	g.AddState(idx)
	g.AddState(other)

	sm := NewStateMachineWithOnURLSet(g, idx, []*State{idx, other})
	if sm.OnURLSetSize() != 2 {
		t.Errorf("OnURLSetSize() = %d, want 2", sm.OnURLSetSize())
	}

	// Empty inherited set falls back to seeding the initial state.
	sm2 := NewStateMachineWithOnURLSet(g, idx, nil)
	if sm2.OnURLSetSize() != 1 {
		t.Errorf("OnURLSetSize() = %d, want 1 (seeded)", sm2.OnURLSetSize())
	}
}

func TestStateMachineSetCurrentState(t *testing.T) {
	ResetCounter()
	g := NewGraph()
	idx := New("http://test.com/", "", "DOM-INDEX", 0)
	next := New("http://test.com/p", "", "DOM-P", 1)
	g.AddState(idx)
	sm := NewStateMachine(g, idx)

	sm.SetCurrentState(next)
	if sm.GetCurrentState() != next {
		t.Error("SetCurrentState did not update current state")
	}
}

func TestStateMachineOnURLSet(t *testing.T) {
	ResetCounter()
	g := NewGraph()
	idx := New("http://test.com/", "", "DOM-INDEX", 0)
	g.AddState(idx)
	sm := NewStateMachine(g, idx)

	s2 := New("http://test.com/two", "", "DOM-TWO", 1)
	sm.AddToOnURLSet(s2)
	if sm.OnURLSetSize() != 2 {
		t.Errorf("OnURLSetSize() = %d, want 2", sm.OnURLSetSize())
	}

	// Adding the same ID again is a no-op.
	sm.AddToOnURLSet(s2)
	if sm.OnURLSetSize() != 2 {
		t.Errorf("duplicate add: OnURLSetSize() = %d, want 2", sm.OnURLSetSize())
	}

	// Nil add is ignored.
	sm.AddToOnURLSet(nil)
	if sm.OnURLSetSize() != 2 {
		t.Errorf("nil add: OnURLSetSize() = %d, want 2", sm.OnURLSetSize())
	}

	if !sm.IsInOnURLSet(idx) || !sm.IsInOnURLSet(s2) {
		t.Error("IsInOnURLSet should be true for seeded and added states")
	}
	notAdded := New("http://test.com/none", "", "DOM-NONE", 1)
	if sm.IsInOnURLSet(notAdded) {
		t.Error("IsInOnURLSet should be false for an unseen state")
	}
	if sm.IsInOnURLSet(nil) {
		t.Error("IsInOnURLSet(nil) should be false")
	}

	// GetOnURLSet returns a defensive copy.
	set := sm.GetOnURLSet()
	if len(set) != 2 {
		t.Fatalf("GetOnURLSet len = %d, want 2", len(set))
	}
	set[0] = nil
	if sm.OnURLSetSize() != 2 {
		t.Error("mutating GetOnURLSet result affected internal set")
	}
	if len(sm.GetOnURLSetSlice()) != 2 {
		t.Error("GetOnURLSetSlice should mirror GetOnURLSet")
	}
}

func TestStateMachineChangeState(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()
	s1 := New("http://test.com/a", "", "DOM-A", 0)
	s2 := New("http://test.com/b", "", "DOM-B", 1)
	g.AddState(s1)
	g.AddState(s2)
	g.AddEdge(s1.ID, s2.ID, createTestEventable("/body/a"))

	sm := NewStateMachine(g, s1)

	// Nil target rejected.
	if sm.ChangeState(nil) {
		t.Error("ChangeState(nil) should return false")
	}

	// Target not in graph rejected.
	ghost := New("http://test.com/ghost", "", "DOM-GHOST", 1)
	if sm.ChangeState(ghost) {
		t.Error("ChangeState to a state not in the graph should return false")
	}

	// Reachable target accepted.
	if !sm.ChangeState(s2) {
		t.Error("ChangeState to a connected state should return true")
	}
	if sm.GetCurrentState() != s2 {
		t.Error("current state should be s2 after ChangeState")
	}

	// No edge between s2 and a fresh disconnected state => rejected.
	s3 := New("http://test.com/c", "", "DOM-C", 2)
	g.AddState(s3)
	if sm.ChangeState(s3) {
		t.Error("ChangeState to disconnected state should return false")
	}
}

func TestStateMachineChangeStateSameID(t *testing.T) {
	ResetCounter()
	g := NewGraph()
	s1 := New("http://test.com/a", "", "DOM-A", 0)
	g.AddState(s1)
	sm := NewStateMachine(g, s1)

	// Changing to the same state ID is allowed even without an edge.
	if !sm.ChangeState(s1) {
		t.Error("ChangeState to the same state should return true")
	}
}

func TestStateMachineSwitchToStateAndCheckIfClone(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()
	s1 := New("http://test.com/a", "", "DOM-A", 0)
	g.AddState(s1)
	sm := NewStateMachine(g, s1)

	// Nil newState.
	if existing, isClone := sm.SwitchToStateAndCheckIfClone(nil, nil); existing != nil || isClone {
		t.Error("nil newState should return (nil, false)")
	}

	// Brand-new state.
	s2 := New("http://test.com/b", "", "DOM-B", 1)
	existing, isClone := sm.SwitchToStateAndCheckIfClone(s2, createTestEventable("/body/a"))
	if existing != nil || isClone {
		t.Errorf("new state should return (nil, false), got (%v, %v)", existing, isClone)
	}
	if sm.GetCurrentState() != s2 {
		t.Error("should have switched to the new state")
	}

	// A state with an existing ID is a clone.
	clone := New("http://test.com/b-again", "", "DOM-B", 5) // same StrippedDOM => same ID as s2
	existing, isClone = sm.SwitchToStateAndCheckIfClone(clone, createTestEventable("/body/b"))
	if !isClone {
		t.Error("a state with a duplicate ID should be detected as a clone")
	}
	if existing == nil || existing.ID != s2.ID {
		t.Error("clone should resolve to the existing state")
	}
}

func TestStateMachineRewind(t *testing.T) {
	ResetCounter()
	g := NewGraph()
	idx := New("http://test.com/", "", "DOM-INDEX", 0)
	other := New("http://test.com/x", "", "DOM-X", 1)
	g.AddState(idx)
	sm := NewStateMachine(g, idx)

	sm.SetCurrentState(other)
	sm.Rewind()
	if sm.GetCurrentState() != idx {
		t.Error("Rewind should restore the initial state")
	}
}

func TestStateMachineFindClosestOnURLState(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()
	idx := New("http://test.com/", "", "DOM-INDEX", 0)
	mid := New("http://test.com/mid", "", "DOM-MID", 1)
	target := New("http://test.com/target", "", "DOM-TARGET", 2)
	g.AddState(idx)
	g.AddState(mid)
	g.AddState(target)
	g.AddEdge(idx.ID, mid.ID, createTestEventable("/body/a"))
	g.AddEdge(mid.ID, target.ID, createTestEventable("/body/b"))

	sm := NewStateMachine(g, idx) // onURLSet = {idx}

	// Nil target.
	if sm.FindClosestOnURLState(nil) != nil {
		t.Error("FindClosestOnURLState(nil) should return nil")
	}

	// target itself is not URL-reachable, but idx can reach it.
	closest := sm.FindClosestOnURLState(target)
	if closest != idx {
		t.Errorf("FindClosestOnURLState returned %v, want idx", closest)
	}

	// If the target is itself in onURLSet, it returns the target.
	sm.AddToOnURLSet(target)
	if sm.FindClosestOnURLState(target) != target {
		t.Error("FindClosestOnURLState should return the target when it is URL-reachable")
	}
}
