package state

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// newTestEventable builds an Eventable with source/target state IDs for path tests.
func newTestEventable(id int64, source, target string) *action.Eventable {
	e := action.NewEventable(action.NewIdentification(action.HowXPath, "/html/body/a"), action.EventTypeClick)
	e.ID = id
	e.SourceStateID = source
	e.TargetStateID = target
	e.Element = &action.Element{Tag: "a", Text: "link"}
	return e
}

func TestNewCrawlPath(t *testing.T) {
	cp := NewCrawlPath("target-1")
	if cp.GetBacktrackTarget() != "target-1" {
		t.Errorf("BacktrackTarget = %q, want %q", cp.GetBacktrackTarget(), "target-1")
	}
	if !cp.IsEmpty() {
		t.Error("new path should be empty")
	}
	if cp.IsBacktrackSuccess() {
		t.Error("new path should not be backtrack success")
	}
	if cp.IsReachedNearDup() != "" {
		t.Errorf("ReachedNearDup = %q, want empty", cp.IsReachedNearDup())
	}
	if cp.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}
}

func TestNewCrawlPathFromListAndCopyOf(t *testing.T) {
	events := []*action.Eventable{
		newTestEventable(1, "s0", "s1"),
		newTestEventable(2, "s1", "s2"),
	}
	cp := NewCrawlPathFromList(events, "tgt")
	if cp.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", cp.Size())
	}
	// Mutating the source slice must not affect the path (defensive copy).
	events[0] = nil
	if cp.Get(0) == nil {
		t.Error("path should hold its own copy of the slice")
	}

	cp2 := CopyOf([]*action.Eventable{newTestEventable(3, "a", "b")}, "tgt2")
	if cp2.Size() != 1 || cp2.GetBacktrackTarget() != "tgt2" {
		t.Errorf("CopyOf produced unexpected path: size=%d target=%q", cp2.Size(), cp2.GetBacktrackTarget())
	}
}

func TestCrawlPathAddGetLastSize(t *testing.T) {
	cp := NewCrawlPath("t")
	e1 := newTestEventable(1, "s0", "s1")
	e2 := newTestEventable(2, "s1", "s2")
	cp.Add(e1)
	cp.Add(e2)

	if cp.Size() != 2 || cp.Len() != 2 {
		t.Errorf("Size/Len = %d/%d, want 2", cp.Size(), cp.Len())
	}
	if cp.IsEmpty() {
		t.Error("path with 2 events should not be empty")
	}
	if cp.Get(0) != e1 || cp.Get(1) != e2 {
		t.Error("Get returned wrong eventable")
	}
	if cp.Get(-1) != nil || cp.Get(99) != nil {
		t.Error("Get out of range should return nil")
	}
	if cp.Last() != e2 {
		t.Error("Last should return the last appended eventable")
	}
}

func TestCrawlPathLastEmpty(t *testing.T) {
	cp := NewCrawlPath("t")
	if cp.Last() != nil {
		t.Error("Last on empty path should be nil")
	}
}

func TestCrawlPathRemove(t *testing.T) {
	cp := NewCrawlPath("t")
	e1 := newTestEventable(1, "s0", "s1")
	e2 := newTestEventable(2, "s1", "s2")
	e3 := newTestEventable(3, "s2", "s3")
	cp.Add(e1)
	cp.Add(e2)
	cp.Add(e3)

	removed := cp.Remove(1)
	if removed != e2 {
		t.Error("Remove(1) should return e2")
	}
	if cp.Size() != 2 {
		t.Errorf("Size after remove = %d, want 2", cp.Size())
	}
	if cp.Get(0) != e1 || cp.Get(1) != e3 {
		t.Error("remaining elements out of order after Remove")
	}

	if cp.Remove(-1) != nil || cp.Remove(99) != nil {
		t.Error("Remove out of range should return nil")
	}
}

func TestCrawlPathRemoveLast(t *testing.T) {
	cp := NewCrawlPath("t")
	if cp.RemoveLast() != nil {
		t.Error("RemoveLast on empty path should be nil")
	}
	e1 := newTestEventable(1, "s0", "s1")
	e2 := newTestEventable(2, "s1", "s2")
	cp.Add(e1)
	cp.Add(e2)
	if cp.RemoveLast() != e2 {
		t.Error("RemoveLast should return e2")
	}
	if cp.Size() != 1 || cp.Last() != e1 {
		t.Error("RemoveLast did not trim correctly")
	}
}

func TestCrawlPathBacktrackStateFlags(t *testing.T) {
	cp := NewCrawlPath("t")

	cp.SetBacktrackTarget("new-target")
	if cp.GetBacktrackTarget() != "new-target" {
		t.Errorf("BacktrackTarget = %q, want %q", cp.GetBacktrackTarget(), "new-target")
	}

	cp.SetBacktrackSuccess(true)
	if !cp.IsBacktrackSuccess() {
		t.Error("IsBacktrackSuccess should be true")
	}

	cp.SetReachedNearDup("nd-1")
	if cp.IsReachedNearDup() != "nd-1" {
		t.Errorf("ReachedNearDup = %q, want %q", cp.IsReachedNearDup(), "nd-1")
	}
}

func TestCrawlPathMarkHelpers(t *testing.T) {
	cp := NewCrawlPath("t")

	cp.SetReachedNearDup("stale")
	cp.MarkSuccess()
	if !cp.IsBacktrackSuccess() {
		t.Error("MarkSuccess should set BacktrackSuccess = true")
	}
	if cp.IsReachedNearDup() != "" {
		t.Error("MarkSuccess should clear ReachedNearDup")
	}

	cp.MarkFailed()
	if cp.IsBacktrackSuccess() {
		t.Error("MarkFailed should set BacktrackSuccess = false")
	}

	cp.MarkNearDuplicate("nd-9")
	if cp.IsBacktrackSuccess() {
		t.Error("MarkNearDuplicate should set BacktrackSuccess = false")
	}
	if cp.IsReachedNearDup() != "nd-9" {
		t.Errorf("ReachedNearDup = %q, want %q", cp.IsReachedNearDup(), "nd-9")
	}
}

func TestCrawlPathImmutableCopy(t *testing.T) {
	cp := NewCrawlPath("t")
	cp.Add(newTestEventable(1, "s0", "s1"))
	cp.Add(newTestEventable(2, "s1", "s2"))
	cp.SetBacktrackSuccess(true)
	cp.SetReachedNearDup("nd")

	copyAll := cp.ImmutableCopy()
	if copyAll.Size() != 2 {
		t.Errorf("ImmutableCopy size = %d, want 2", copyAll.Size())
	}
	if !copyAll.IsBacktrackSuccess() || copyAll.IsReachedNearDup() != "nd" {
		t.Error("ImmutableCopy should preserve backtrack flags")
	}
	// The clone holds different Eventable pointers (deep copy).
	if copyAll.Get(0) == cp.Get(0) {
		t.Error("ImmutableCopy should deep-copy eventables")
	}

	copyWithoutLast := cp.ImmutableCopyWithoutLast()
	if copyWithoutLast.Size() != 1 {
		t.Errorf("ImmutableCopyWithoutLast size = %d, want 1", copyWithoutLast.Size())
	}
}

func TestCrawlPathImmutableCopyEmpty(t *testing.T) {
	cp := NewCrawlPath("origin")
	copyAll := cp.ImmutableCopy()
	if copyAll.Size() != 0 {
		t.Errorf("empty ImmutableCopy size = %d, want 0", copyAll.Size())
	}
	if copyAll.GetBacktrackTarget() != "origin" {
		t.Errorf("BacktrackTarget = %q, want %q", copyAll.GetBacktrackTarget(), "origin")
	}
}

func TestCrawlPathGetEventables(t *testing.T) {
	cp := NewCrawlPath("t")
	cp.Add(newTestEventable(1, "s0", "s1"))
	events := cp.GetEventables()
	if len(events) != 1 {
		t.Fatalf("GetEventables len = %d, want 1", len(events))
	}
	// Mutating the returned slice should not change the path's internal slice.
	events[0] = nil
	if cp.Get(0) == nil {
		t.Error("GetEventables should return a copy")
	}
}

func TestCrawlPathGetSourceAndTargetStates(t *testing.T) {
	cp := NewCrawlPath("t")
	cp.Add(newTestEventable(1, "s0", "s1"))
	cp.Add(newTestEventable(2, "s1", "s2"))
	cp.Add(newTestEventable(3, "s0", "s2")) // duplicate source s0 and target s2

	sources := cp.GetSourceStates()
	if len(sources) != 2 {
		t.Errorf("GetSourceStates = %v, want 2 unique", sources)
	}
	targets := cp.GetTargetStates()
	if len(targets) != 2 {
		t.Errorf("GetTargetStates = %v, want 2 unique", targets)
	}
}

func TestCrawlPathAsStackTrace(t *testing.T) {
	cp := NewCrawlPath("t")
	cp.Add(newTestEventable(1, "s0", "s1"))
	cp.Add(newTestEventable(2, "s1", "s2"))

	trace := cp.AsStackTrace()
	if len(trace) != 2 {
		t.Fatalf("AsStackTrace len = %d, want 2", len(trace))
	}
	// Trace is reverse-ordered; each entry should be non-empty.
	for i, line := range trace {
		if line == "" {
			t.Errorf("trace[%d] is empty", i)
		}
	}
}

func TestCrawlPathString(t *testing.T) {
	cp := NewCrawlPath("st1")
	cp.SetBacktrackSuccess(true)
	cp.Add(newTestEventable(7, "s0", "s1"))

	s := cp.String()
	if s == "" {
		t.Fatal("String() returned empty")
	}
	// Successful path encodes "success".
	if want := "BT-statest1:success:"; len(s) < len(want) || s[:len(want)] != want {
		t.Errorf("String() = %q, want prefix %q", s, want)
	}

	// Failed path encodes "failed" and "-1" for empty near-dup.
	cp2 := NewCrawlPath("st2")
	s2 := cp2.String()
	if want := "BT-statest2:failed:-1"; s2 != want {
		t.Errorf("String() = %q, want %q", s2, want)
	}
}

func TestCrawlPathDurationAndClose(t *testing.T) {
	cp := NewCrawlPath("t")
	// Before Close, Duration is measured from StartTime (non-negative).
	if cp.Duration() < 0 {
		t.Error("Duration should be non-negative")
	}
	cp.Close()
	d := cp.Duration()
	if d < 0 {
		t.Error("Duration after Close should be non-negative")
	}
	// Close is idempotent: a second Close must not move EndTime.
	end := cp.EndTime
	time.Sleep(time.Millisecond)
	cp.Close()
	if !cp.EndTime.Equal(end) {
		t.Error("Close should be idempotent")
	}
}
