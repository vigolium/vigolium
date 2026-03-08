package state

import (
	"fmt"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// createTestEventable creates an Eventable for testing.
func createTestEventable(actionID string) *action.Eventable {
	return &action.Eventable{
		ID:             action.NextEventableID(),
		EventType:      action.EventTypeClick,
		Identification: action.NewIdentification(action.HowXPath, actionID),
	}
}

func TestNewGraph(t *testing.T) {
	g := NewGraph()

	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	if g.StateCount() != 0 {
		t.Errorf("StateCount() = %d, want 0", g.StateCount())
	}
	if g.EdgeCount() != 0 {
		t.Errorf("EdgeCount() = %d, want 0", g.EdgeCount())
	}
	if g.GetIndexState() != nil {
		t.Error("GetIndexState() should return nil for empty graph")
	}
}

func TestGraphAddState(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)

	// Add first state
	added := g.AddState(s1)
	if !added {
		t.Error("first AddState should return true")
	}
	if g.StateCount() != 1 {
		t.Errorf("StateCount() = %d, want 1", g.StateCount())
	}

	// Add second state
	added = g.AddState(s2)
	if !added {
		t.Error("second AddState should return true")
	}
	if g.StateCount() != 2 {
		t.Errorf("StateCount() = %d, want 2", g.StateCount())
	}

	// Add duplicate (same ID)
	s3 := New("http://other.com", "", "DOM A", 5) // Same DOM = same ID
	added = g.AddState(s3)
	if added {
		t.Error("duplicate AddState should return false")
	}
	if g.StateCount() != 2 {
		t.Errorf("StateCount() after duplicate = %d, want 2", g.StateCount())
	}
}

func TestGraphAddStateIndex(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	// Add index state
	index := NewIndex("http://test.com", "", "Index DOM")
	g.AddState(index)

	if g.GetIndexState() == nil {
		t.Error("GetIndexState() should return the index state")
	}
	if g.GetIndexState().Name != "index" {
		t.Errorf("index state Name = %q, want 'index'", g.GetIndexState().Name)
	}

	// Regular state at depth 0 should also be marked as index
	ResetCounter()
	g2 := NewGraph()
	s := New("http://test.com", "", "DOM", 0)
	g2.AddState(s)

	if g2.GetIndexState() == nil {
		t.Error("state at depth 0 should be index")
	}
}

func TestGraphGetState(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s := New("http://test.com", "", "DOM content", 1)
	g.AddState(s)

	// Get existing state
	found, ok := g.GetState(s.ID)
	if !ok {
		t.Error("GetState should return true for existing state")
	}
	if found == nil {
		t.Fatal("GetState should return non-nil state")
	}
	if found.ID != s.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, s.ID)
	}

	// GetState returns a clone
	if found == s {
		t.Error("GetState should return a clone, not the same pointer")
	}

	// Get non-existing state
	_, ok = g.GetState("nonexistent")
	if ok {
		t.Error("GetState should return false for non-existing state")
	}
}

func TestGraphHasState(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s := New("http://test.com", "", "DOM", 0)
	g.AddState(s)

	if !g.HasState(s.ID) {
		t.Error("HasState should return true for existing state")
	}
	if g.HasState("nonexistent") {
		t.Error("HasState should return false for non-existing state")
	}
}

func TestGraphAddEdge(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	g.AddState(s1)
	g.AddState(s2)

	eventable := createTestEventable("/body/div[1]")
	edge := g.AddEdge(s1.ID, s2.ID, eventable)

	if edge == nil {
		t.Fatal("AddEdge should return non-nil edge")
	}
	if edge.SourceStateID != s1.ID {
		t.Errorf("edge.SourceStateID = %q, want %q", edge.SourceStateID, s1.ID)
	}
	if edge.TargetStateID != s2.ID {
		t.Errorf("edge.TargetStateID = %q, want %q", edge.TargetStateID, s2.ID)
	}
	if g.EdgeCount() != 1 {
		t.Errorf("EdgeCount() = %d, want 1", g.EdgeCount())
	}
}

func TestGraphAllStates(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)

	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	states := g.AllStates()

	if len(states) != 3 {
		t.Errorf("len(AllStates) = %d, want 3", len(states))
	}

	// Check discovery order is preserved
	if states[0].ID != s1.ID {
		t.Error("AllStates should preserve discovery order")
	}
	if states[1].ID != s2.ID {
		t.Error("AllStates should preserve discovery order")
	}
	if states[2].ID != s3.ID {
		t.Error("AllStates should preserve discovery order")
	}

	// Check states are clones
	for _, s := range states {
		if s == s1 || s == s2 || s == s3 {
			t.Error("AllStates should return clones")
		}
	}
}

func TestGraphAllEdges(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	g.AddEdge(s1.ID, s2.ID, createTestEventable("act1"))
	g.AddEdge(s1.ID, s3.ID, createTestEventable("act2"))
	g.AddEdge(s2.ID, s3.ID, createTestEventable("act3"))

	edges := g.AllEdges()

	if len(edges) != 3 {
		t.Errorf("len(AllEdges) = %d, want 3", len(edges))
	}
}

func TestGraphOutgoingEdges(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	g.AddEdge(s1.ID, s2.ID, createTestEventable("act1"))
	g.AddEdge(s1.ID, s3.ID, createTestEventable("act2"))
	g.AddEdge(s2.ID, s3.ID, createTestEventable("act3"))

	// s1 has 2 outgoing edges
	out1 := g.OutgoingEdges(s1.ID)
	if len(out1) != 2 {
		t.Errorf("s1 outgoing edges = %d, want 2", len(out1))
	}

	// s2 has 1 outgoing edge
	out2 := g.OutgoingEdges(s2.ID)
	if len(out2) != 1 {
		t.Errorf("s2 outgoing edges = %d, want 1", len(out2))
	}

	// s3 has 0 outgoing edges
	out3 := g.OutgoingEdges(s3.ID)
	if len(out3) != 0 {
		t.Errorf("s3 outgoing edges = %d, want 0", len(out3))
	}

	// non-existing state has 0 outgoing edges
	outNone := g.OutgoingEdges("nonexistent")
	if len(outNone) != 0 {
		t.Errorf("nonexistent outgoing edges = %d, want 0", len(outNone))
	}
}

func TestGraphIncomingEdges(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	g.AddEdge(s1.ID, s2.ID, createTestEventable("act1"))
	g.AddEdge(s1.ID, s3.ID, createTestEventable("act2"))
	g.AddEdge(s2.ID, s3.ID, createTestEventable("act3"))

	// s1 has 0 incoming edges
	in1 := g.IncomingEdges(s1.ID)
	if len(in1) != 0 {
		t.Errorf("s1 incoming edges = %d, want 0", len(in1))
	}

	// s2 has 1 incoming edge
	in2 := g.IncomingEdges(s2.ID)
	if len(in2) != 1 {
		t.Errorf("s2 incoming edges = %d, want 1", len(in2))
	}

	// s3 has 2 incoming edges
	in3 := g.IncomingEdges(s3.ID)
	if len(in3) != 2 {
		t.Errorf("s3 incoming edges = %d, want 2", len(in3))
	}
}

func TestGraphRemoveEdge(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	g.AddState(s1)
	g.AddState(s2)

	g.AddEdge(s1.ID, s2.ID, createTestEventable("act1"))
	if g.EdgeCount() != 1 {
		t.Errorf("EdgeCount before remove = %d, want 1", g.EdgeCount())
	}

	g.RemoveEdge(s1.ID, s2.ID)

	if g.EdgeCount() != 0 {
		t.Errorf("EdgeCount after remove = %d, want 0", g.EdgeCount())
	}
	if len(g.OutgoingEdges(s1.ID)) != 0 {
		t.Error("outgoing edges should be empty after remove")
	}
	if len(g.IncomingEdges(s2.ID)) != 0 {
		t.Error("incoming edges should be empty after remove")
	}

	// Removing non-existing edge should not panic
	g.RemoveEdge("nonexistent", "also-nonexistent")
}

func TestGraphFindStateByDOM(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "Unique DOM A", 0)
	s2 := New("http://test.com/b", "", "Unique DOM B", 1)
	g.AddState(s1)
	g.AddState(s2)

	// Find existing
	found := g.FindStateByDOM("Unique DOM A")
	if found == nil {
		t.Fatal("should find state by DOM")
	}
	if found.ID != s1.ID {
		t.Errorf("found ID = %q, want %q", found.ID, s1.ID)
	}

	// Find non-existing
	notFound := g.FindStateByDOM("Nonexistent DOM")
	if notFound != nil {
		t.Error("should not find non-existing DOM")
	}
}

func TestGraphGetNeighbors(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	g.AddEdge(s1.ID, s2.ID, createTestEventable("act1"))
	g.AddEdge(s1.ID, s3.ID, createTestEventable("act2"))

	neighbors := g.GetNeighbors(s1.ID)

	if len(neighbors) != 2 {
		t.Errorf("len(neighbors) = %d, want 2", len(neighbors))
	}

	// s2 and s3 have no neighbors
	if len(g.GetNeighbors(s2.ID)) != 0 {
		t.Error("s2 should have no neighbors")
	}
}

func TestGraphGetParents(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	g.AddEdge(s1.ID, s3.ID, createTestEventable("act1"))
	g.AddEdge(s2.ID, s3.ID, createTestEventable("act2"))

	parents := g.GetParents(s3.ID)

	if len(parents) != 2 {
		t.Errorf("len(parents) = %d, want 2", len(parents))
	}

	// s1 has no parents
	if len(g.GetParents(s1.ID)) != 0 {
		t.Error("s1 should have no parents")
	}
}

func TestGraphShortestPath(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	// Create a simple graph:
	// s1 -> s2 -> s3
	//  \--> s4 ----^

	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)
	s4 := New("http://test.com/d", "", "DOM D", 1)
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)
	g.AddState(s4)

	g.AddEdge(s1.ID, s2.ID, createTestEventable("act1"))
	g.AddEdge(s2.ID, s3.ID, createTestEventable("act2"))
	g.AddEdge(s1.ID, s4.ID, createTestEventable("act3"))
	g.AddEdge(s4.ID, s3.ID, createTestEventable("act4"))

	// Path from s1 to s3 (should be 2 edges)
	path := g.ShortestPath(s1.ID, s3.ID)
	if path == nil {
		t.Fatal("expected path from s1 to s3")
	}
	if len(path) != 2 {
		t.Errorf("path length = %d, want 2", len(path))
	}

	// Path to self should be empty
	selfPath := g.ShortestPath(s1.ID, s1.ID)
	if selfPath == nil {
		t.Fatal("self path should not be nil")
	}
	if len(selfPath) != 0 {
		t.Errorf("self path length = %d, want 0", len(selfPath))
	}

	// Path to unreachable state should be nil
	s5 := New("http://test.com/e", "", "DOM E", 3)
	g.AddState(s5)
	unreachablePath := g.ShortestPath(s1.ID, s5.ID)
	if unreachablePath != nil {
		t.Error("path to unreachable state should be nil")
	}
}

func TestGraphShortestPathComplex(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	// Create a more complex graph to test path finding
	// A -> B -> C -> D
	//  \-> E -------^

	sA := New("http://test.com/a", "", "A", 0)
	sB := New("http://test.com/b", "", "B", 1)
	sC := New("http://test.com/c", "", "C", 2)
	sD := New("http://test.com/d", "", "D", 3)
	sE := New("http://test.com/e", "", "E", 1)

	g.AddState(sA)
	g.AddState(sB)
	g.AddState(sC)
	g.AddState(sD)
	g.AddState(sE)

	g.AddEdge(sA.ID, sB.ID, createTestEventable("a1"))
	g.AddEdge(sB.ID, sC.ID, createTestEventable("a2"))
	g.AddEdge(sC.ID, sD.ID, createTestEventable("a3"))
	g.AddEdge(sA.ID, sE.ID, createTestEventable("a4"))
	g.AddEdge(sE.ID, sD.ID, createTestEventable("a5"))

	// Shortest path from A to D should be A->E->D (2 edges) not A->B->C->D (3 edges)
	path := g.ShortestPath(sA.ID, sD.ID)
	if len(path) != 2 {
		t.Errorf("shortest path length = %d, want 2", len(path))
	}
}

func TestGraphKShortestPaths(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	// Create graph with multiple paths
	// A -> B -> D
	// A -> C -> D
	// A ------> D (direct)

	sA := New("http://test.com/a", "", "A", 0)
	sB := New("http://test.com/b", "", "B", 1)
	sC := New("http://test.com/c", "", "C", 1)
	sD := New("http://test.com/d", "", "D", 2)

	g.AddState(sA)
	g.AddState(sB)
	g.AddState(sC)
	g.AddState(sD)

	g.AddEdge(sA.ID, sD.ID, createTestEventable("direct")) // Direct: length 1
	g.AddEdge(sA.ID, sB.ID, createTestEventable("ab"))     // Via B: length 2
	g.AddEdge(sB.ID, sD.ID, createTestEventable("bd"))
	g.AddEdge(sA.ID, sC.ID, createTestEventable("ac")) // Via C: length 2
	g.AddEdge(sC.ID, sD.ID, createTestEventable("cd"))

	// Find 3 shortest paths
	paths := g.KShortestPaths(sA.ID, sD.ID, 3)

	if paths == nil {
		t.Fatal("expected paths")
	}
	if len(paths) < 1 {
		t.Fatal("expected at least 1 path")
	}

	// First path should be the shortest (length 1)
	if len(paths[0]) != 1 {
		t.Errorf("first path length = %d, want 1", len(paths[0]))
	}

	// Second and third paths should be length 2 (if they exist)
	if len(paths) >= 2 && len(paths[1]) != 2 {
		t.Errorf("second path length = %d, want 2", len(paths[1]))
	}
	if len(paths) >= 3 && len(paths[2]) != 2 {
		t.Errorf("third path length = %d, want 2", len(paths[2]))
	}
}

func TestGraphKShortestPathsEdgeCases(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	sA := New("http://test.com/a", "", "A", 0)
	sB := New("http://test.com/b", "", "B", 1)
	g.AddState(sA)
	g.AddState(sB)

	// k = 0 should return nil
	if g.KShortestPaths(sA.ID, sB.ID, 0) != nil {
		t.Error("k=0 should return nil")
	}

	// Same source and target
	paths := g.KShortestPaths(sA.ID, sA.ID, 1)
	if paths == nil {
		t.Fatal("same source/target should return paths")
	}
	if len(paths) != 1 || len(paths[0]) != 0 {
		t.Error("same source/target should return empty path")
	}

	// No path exists
	paths = g.KShortestPaths(sA.ID, sB.ID, 1)
	if paths != nil {
		t.Error("no path should return nil")
	}
}

func TestGraphConcurrency(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	// Pre-create states outside of goroutines
	states := make([]*State, 100)
	for i := 0; i < 100; i++ {
		states[i] = New("http://test.com", "", "DOM "+string(rune('A'+i%26)), i)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Concurrent adds
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			g.AddState(states[i])
		}
	}()

	go func() {
		defer wg.Done()
		for i := 50; i < 100; i++ {
			g.AddState(states[i])
		}
	}()

	// Concurrent reads
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			g.StateCount()
			g.AllStates()
		}
	}()

	wg.Wait()

	// Graph should be in a valid state
	if g.StateCount() == 0 {
		t.Error("graph should have states after concurrent operations")
	}
}

func TestGraphEdgeConcurrency(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	s1 := New("http://test.com/a", "", "A", 0)
	s2 := New("http://test.com/b", "", "B", 1)
	g.AddState(s1)
	g.AddState(s2)

	var wg sync.WaitGroup
	wg.Add(2)

	// Concurrent edge operations
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			g.AddEdge(s1.ID, s2.ID, createTestEventable(fmt.Sprintf("act_%d", i)))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			g.EdgeCount()
			g.AllEdges()
		}
	}()

	wg.Wait()

	if g.EdgeCount() != 50 {
		t.Errorf("EdgeCount = %d, want 50", g.EdgeCount())
	}
}

func TestResetEventableIDCounter(t *testing.T) {
	e1 := createTestEventable("act1")
	e2 := createTestEventable("act2")

	// IDs should be sequential
	if e1.ID == e2.ID {
		t.Error("eventables should have different IDs")
	}

	action.ResetEventableIDCounter()

	e3 := createTestEventable("act3")
	if e3.ID != 1 {
		t.Errorf("after reset, eventable ID = %d, want 1", e3.ID)
	}
}

func BenchmarkGraphAddState(b *testing.B) {
	ResetCounter()
	g := NewGraph()

	states := make([]*State, b.N)
	for i := 0; i < b.N; i++ {
		states[i] = New("http://test.com", "", "DOM content "+string(rune(i)), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.AddState(states[i])
	}
}

func BenchmarkGraphShortestPath(b *testing.B) {
	ResetCounter()
	action.ResetEventableIDCounter()
	g := NewGraph()

	// Create a linear graph with 100 states
	states := make([]*State, 100)
	for i := 0; i < 100; i++ {
		states[i] = New("http://test.com", "", "DOM "+string(rune(i)), i)
		g.AddState(states[i])
		if i > 0 {
			g.AddEdge(states[i-1].ID, states[i].ID, createTestEventable("act"))
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.ShortestPath(states[0].ID, states[99].ID)
	}
}

// ============================================================================
// CRAWLJAX PARITY: StateFlowGraphTest
// ============================================================================

func TestDuplicationAdding(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	index := NewIndex("http://test.com", "", "<table><div>index</div></table>")
	state2 := New("http://test.com", "", "<table><div>state2</div></table>", 1)
	state3 := New("http://test.com", "", "<table><div>state3</div></table>", 1)
	state4 := New("http://test.com", "", "<table><div>state4</div></table>", 1)
	state5 := New("http://test.com", "", "<table><div>state5</div></table>", 1)

	g := NewGraph()
	g.AddState(index)

	// Adding index again should return false (duplicate)
	if g.AddState(index) {
		t.Error("re-adding index should return false")
	}

	// Adding new states should return true
	if !g.AddState(state2) {
		t.Error("adding state2 should return true")
	}
	if !g.AddState(state3) {
		t.Error("adding state3 should return true")
	}
	if !g.AddState(state4) {
		t.Error("adding state4 should return true")
	}
	if !g.AddState(state5) {
		t.Error("adding state5 should return true")
	}

	// Add edges
	g.AddEdge(index.ID, state2.ID, createTestEventable("/body/div[4]"))
	g.AddEdge(state2.ID, index.ID, createTestEventable("/body/div[89]"))
	g.AddEdge(state2.ID, state3.ID, createTestEventable("/home/a"))
	g.AddEdge(index.ID, state4.ID, createTestEventable("/body/div[2]/div"))
	g.AddEdge(state2.ID, state5.ID, createTestEventable("/body/div[5]"))

	// Outgoing from state2
	outgoing := g.OutgoingEdges(state2.ID)
	if len(outgoing) != 3 {
		t.Errorf("state2 outgoing edges = %d, want 3", len(outgoing))
	}

	// Incoming to state2
	incoming := g.IncomingEdges(state2.ID)
	if len(incoming) != 1 {
		t.Errorf("state2 incoming edges = %d, want 1", len(incoming))
	}

	// ToString should not be empty
	if g.StateCount() == 0 {
		t.Error("graph should have states")
	}

	// State2 equals check (same DOM = same ID)
	state2Clone := New("http://test.com", "", "<table><div>state2</div></table>", 99)
	if state2.ID != state2Clone.ID {
		t.Error("states with same DOM should have same ID")
	}

	// canGoTo checks via path finding
	path23 := g.ShortestPath(state2.ID, state3.ID)
	if path23 == nil {
		t.Error("should be able to go from state2 to state3")
	}

	path25 := g.ShortestPath(state2.ID, state5.ID)
	if path25 == nil {
		t.Error("should be able to go from state2 to state5")
	}

	path24 := g.ShortestPath(state2.ID, state4.ID)
	// state2 can reach state4 through: state2 -> index -> state4
	if path24 == nil {
		t.Error("should be able to reach state4 from state2 via index")
	}
	if path24 != nil && len(path24) != 2 {
		t.Errorf("path from state2 to state4 via index = %d edges, want 2", len(path24))
	}

	path2i := g.ShortestPath(state2.ID, index.ID)
	if path2i == nil {
		t.Error("should be able to go from state2 to index")
	}

	// Dijkstra shortest path from index to state3
	list := g.ShortestPath(index.ID, state3.ID)
	if len(list) != 2 {
		t.Errorf("shortest path index->state3 = %d edges, want 2", len(list))
	}

	// Outgoing states from index
	neighbors := g.GetNeighbors(index.ID)
	if len(neighbors) != 2 {
		t.Errorf("index neighbors = %d, want 2", len(neighbors))
	}

	// Total states
	allStates := g.AllStates()
	if len(allStates) != 5 {
		t.Errorf("total states = %d, want 5", len(allStates))
	}
}

func TestCloneStates(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	index := NewIndex("http://test.com", "", "<table><div>index</div></table>")
	state2 := New("http://test.com", "", "<table><div>state2</div></table>", 1)
	state4 := New("http://test.com", "", "<table><div>state4</div></table>", 1)
	// state3clone2 has same DOM as state2, so same ID
	state3clone2 := New("http://test.com", "", "<table><div>state2</div></table>", 1)

	g := NewGraph()
	g.AddState(index)

	if !g.AddState(state2) {
		t.Error("adding state2 should succeed")
	}
	if !g.AddState(state4) {
		t.Error("adding state4 should succeed")
	}

	g.AddEdge(index.ID, state2.ID, createTestEventable("/body/div[4]"))

	// Adding edge to state3clone2 (which has same ID as state2)
	g.AddEdge(state4.ID, state3clone2.ID, createTestEventable("/home/a"))

	// Verify the edge was added
	if g.EdgeCount() != 2 {
		t.Errorf("edge count = %d, want 2", g.EdgeCount())
	}
}

func TestDoubleEvents(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	index := NewIndex("http://test.com", "", "<table><div>index</div></table>")
	state2 := New("http://test.com", "", "<table><div>state2</div></table>", 1)

	g := NewGraph()
	g.AddState(index)
	g.AddState(state2)

	// Add two different edges between same states
	g.AddEdge(index.ID, state2.ID, createTestEventable("/body/div[4]"))
	g.AddEdge(index.ID, state2.ID, createTestEventable("/body/div[4]/div[2]"))

	// Both edges should exist
	if g.EdgeCount() != 2 {
		t.Errorf("edge count = %d, want 2", g.EdgeCount())
	}
}

func TestGraphCanGoTo(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	s1 := New("http://test.com", "", "A", 0)
	s2 := New("http://test.com", "", "B", 1)
	s3 := New("http://test.com", "", "C", 2)

	g := NewGraph()
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	g.AddEdge(s1.ID, s2.ID, createTestEventable("a1"))

	// Can go s1 -> s2
	if path := g.ShortestPath(s1.ID, s2.ID); path == nil {
		t.Error("should be able to go from s1 to s2")
	}

	// Cannot go s2 -> s3 (no edge)
	if path := g.ShortestPath(s2.ID, s3.ID); path != nil {
		t.Error("should NOT be able to go from s2 to s3")
	}

	// Cannot go s1 -> s3 (no path)
	if path := g.ShortestPath(s1.ID, s3.ID); path != nil {
		t.Error("should NOT be able to go from s1 to s3")
	}
}

func TestGraphWithCycles(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	s1 := New("http://test.com", "", "A", 0)
	s2 := New("http://test.com", "", "B", 1)
	s3 := New("http://test.com", "", "C", 2)

	g := NewGraph()
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	// Create cycle: s1 -> s2 -> s3 -> s1
	g.AddEdge(s1.ID, s2.ID, createTestEventable("a1"))
	g.AddEdge(s2.ID, s3.ID, createTestEventable("a2"))
	g.AddEdge(s3.ID, s1.ID, createTestEventable("a3"))

	// Shortest path should still work
	path := g.ShortestPath(s1.ID, s3.ID)
	if path == nil {
		t.Fatal("should find path in cyclic graph")
	}
	if len(path) != 2 {
		t.Errorf("shortest path length = %d, want 2", len(path))
	}

	// Back to s1 from s3
	pathBack := g.ShortestPath(s3.ID, s1.ID)
	if pathBack == nil {
		t.Fatal("should find path back")
	}
	if len(pathBack) != 1 {
		t.Errorf("path back length = %d, want 1", len(pathBack))
	}
}

func TestGraphSelfLoop(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()

	s1 := New("http://test.com", "", "A", 0)

	g := NewGraph()
	g.AddState(s1)

	// Add self-loop
	g.AddEdge(s1.ID, s1.ID, createTestEventable("self"))

	if g.EdgeCount() != 1 {
		t.Errorf("edge count = %d, want 1", g.EdgeCount())
	}

	outgoing := g.OutgoingEdges(s1.ID)
	if len(outgoing) != 1 {
		t.Errorf("outgoing edges = %d, want 1", len(outgoing))
	}
	if outgoing[0].TargetStateID != s1.ID {
		t.Error("self-loop target should be same state")
	}
}
