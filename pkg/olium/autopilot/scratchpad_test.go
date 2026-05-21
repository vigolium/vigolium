package autopilot

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScratchpadSeedsFromPipelinePlan(t *testing.T) {
	dir := t.TempDir()
	autoDir := filepath.Join(dir, "autopilot")
	if err := os.MkdirAll(autoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{
		"tasks": []map[string]any{
			{"id": "b", "type": "validate", "priority": 2, "reason": "confirm findings"},
			{"id": "a", "type": "auth", "priority": 1, "reason": "log in"},
		},
		"stop_criteria": []string{"all findings triaged"},
	}
	blob, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(autoDir, "plan.json"), blob, 0o644); err != nil {
		t.Fatal(err)
	}

	sp := NewScratchpadContext(dir)
	if len(sp.plan) != 2 {
		t.Fatalf("expected 2 seeded plan items, got %d", len(sp.plan))
	}
	// Sorted by priority: auth (1) before validate (2).
	if sp.plan[0].ID != "a" || sp.plan[1].ID != "b" {
		t.Errorf("plan not sorted by priority: %+v", sp.plan)
	}
	if sp.plan[0].Status != planPending {
		t.Errorf("seeded item should be pending, got %q", sp.plan[0].Status)
	}
	if len(sp.stopCriteria) != 1 {
		t.Errorf("stop criteria not seeded: %+v", sp.stopCriteria)
	}
}

func TestScratchpadDigest(t *testing.T) {
	dir := t.TempDir()
	sp := NewScratchpadContext(dir)

	// Empty scratchpad: digest stays empty so the engine hook doesn't
	// append noise during a warm-up turn.
	if got := sp.Digest(); got != "" {
		t.Errorf("empty digest should be empty, got %q", got)
	}

	sp.plan = []PlanItem{
		{ID: "a", Task: "probe auth flows", Status: planDone},
		{ID: "b", Task: "test SQLi in /search", Status: planInProgress},
		{ID: "c", Task: "review IDOR candidates", Status: planPending},
	}
	got := sp.Digest()
	// Status boxes present.
	for _, want := range []string{"[x] a", "[~] b", "[ ] c"} {
		if !strings.Contains(got, want) {
			t.Errorf("digest missing %q in:\n%s", want, got)
		}
	}
	// In-progress item gets its task text inlined (that's what the agent
	// is currently working on); done/pending stay short.
	if !strings.Contains(got, "test SQLi in /search") {
		t.Errorf("in-progress task text should be inlined, got:\n%s", got)
	}
	if strings.Contains(got, "probe auth flows") {
		t.Errorf("done task text should NOT be inlined (keeps digest small), got:\n%s", got)
	}
	// Bounded size — this is the whole point of digest vs render.
	if len(got) > 600 {
		t.Errorf("digest grew too large (%d bytes), defeats the purpose", len(got))
	}

	sp.notes = []Note{{Text: "auth scheme = JWT bearer"}}
	if !strings.Contains(sp.Digest(), "notes=1") {
		t.Errorf("digest should report note count")
	}
}

func TestUpdatePlanReplaceRecallAndPersist(t *testing.T) {
	dir := t.TempDir()
	sp := NewScratchpadContext(dir)
	tl := NewUpdatePlanTool(sp)

	res, _ := tl.Execute(context.Background(), map[string]any{
		"plan": []any{
			map[string]any{"task": "probe auth", "status": "in_progress"},
			map[string]any{"id": "idor", "task": "test idor"},
		},
	}, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content)
	}
	if !strings.Contains(res.Content, "probe auth") || !strings.Contains(res.Content, "[~]") {
		t.Errorf("rendered plan missing in_progress item:\n%s", res.Content)
	}

	// Recall (no args) returns current state without mutation.
	recall, _ := tl.Execute(context.Background(), map[string]any{}, nil)
	if !strings.Contains(recall.Content, "test idor") {
		t.Errorf("recall missing item:\n%s", recall.Content)
	}

	// Persisted to disk and reloaded by a fresh context.
	if _, err := os.Stat(filepath.Join(dir, "autopilot", scratchpadFile)); err != nil {
		t.Fatalf("scratchpad not persisted: %v", err)
	}
	sp2 := NewScratchpadContext(dir)
	if len(sp2.plan) != 2 || sp2.plan[1].ID != "idor" {
		t.Errorf("reload mismatch: %+v", sp2.plan)
	}

	// Invalid status rejected.
	bad, _ := tl.Execute(context.Background(), map[string]any{
		"plan": []any{map[string]any{"task": "x", "status": "bogus"}},
	}, nil)
	if !bad.IsError {
		t.Error("expected error for invalid status")
	}
}

func TestRememberAppendUpsertAndRecall(t *testing.T) {
	sp := NewScratchpadContext("") // in-memory fallback
	tl := NewRememberTool(sp)

	_, _ = tl.Execute(context.Background(), map[string]any{"note": "uses JWT", "key": "auth", "tags": []any{"auth"}}, nil)
	_, _ = tl.Execute(context.Background(), map[string]any{"note": "viewer reaches /admin", "tags": []any{"idor"}}, nil)
	// Upsert the keyed slot — must not append a second copy.
	_, _ = tl.Execute(context.Background(), map[string]any{"note": "uses JWT alg=HS256", "key": "auth"}, nil)

	if len(sp.notes) != 2 {
		t.Fatalf("expected 2 notes after upsert, got %d: %+v", len(sp.notes), sp.notes)
	}
	var authNote string
	for _, n := range sp.notes {
		if n.Key == "auth" {
			authNote = n.Text
		}
	}
	if authNote != "uses JWT alg=HS256" {
		t.Errorf("upsert did not replace keyed note, got %q", authNote)
	}

	// Tag-filtered recall.
	rec, _ := tl.Execute(context.Background(), map[string]any{"recall": true, "tags": []any{"idor"}}, nil)
	if !strings.Contains(rec.Content, "viewer reaches /admin") || strings.Contains(rec.Content, "uses JWT") {
		t.Errorf("tag recall wrong:\n%s", rec.Content)
	}

	// Missing note without recall is an error.
	e, _ := tl.Execute(context.Background(), map[string]any{}, nil)
	if !e.IsError {
		t.Error("expected error when note missing and recall not set")
	}
}

func TestScratchpadNoteEviction(t *testing.T) {
	sp := NewScratchpadContext("")
	sp.notes = append(sp.notes, Note{Key: "pinned", Text: "keep me"})
	for i := 0; i < scratchpadNoteSoftCap+10; i++ {
		sp.notes = append(sp.notes, Note{Text: "ephemeral"})
	}
	sp.evictIfNeeded()
	if len(sp.notes) != scratchpadNoteSoftCap {
		t.Fatalf("expected eviction to cap at %d, got %d", scratchpadNoteSoftCap, len(sp.notes))
	}
	if sp.notes[0].Key != "pinned" {
		t.Errorf("keyed note must survive eviction, first note is %+v", sp.notes[0])
	}
}
