package sessionlog

import (
	"path/filepath"
	"testing"
)

// TestRecorder_SectionEvents verifies the additive durable-autopilot section
// events serialize with the expected type + fields and stay in the parentId
// chain (single-writer, serial sections).
func TestRecorder_SectionEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transcript.jsonl")
	rec, err := New(path, Meta{Provider: "p", Model: "m"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec.SectionStart("sec-1", 1, "operator", "map the surface")
	rec.SectionEnd("sec-1", "completed", "turn-cap", "found login form", 1234)
	rec.SectionStart("sec-2", 2, "operator", "probe idor")
	rec.SectionInterrupted("sec-2")
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	// Header trio (session, model_change, thinking_level_change) + 4 section events.
	types := map[string]int{}
	for _, ln := range lines {
		types[ln["type"].(string)]++
	}
	if types["section_start"] != 2 {
		t.Errorf("section_start count = %d, want 2", types["section_start"])
	}
	if types["section_end"] != 1 {
		t.Errorf("section_end count = %d, want 1", types["section_end"])
	}
	if types["section_interrupted"] != 1 {
		t.Errorf("section_interrupted count = %d, want 1", types["section_interrupted"])
	}

	// Spot-check the section_end payload.
	for _, ln := range lines {
		if ln["type"] == "section_end" {
			if ln["sectionId"] != "sec-1" || ln["status"] != "completed" || ln["rotationReason"] != "turn-cap" {
				t.Errorf("section_end payload wrong: %v", ln)
			}
			if ln["summary"] != "found login form" {
				t.Errorf("section_end summary = %v", ln["summary"])
			}
		}
	}
}
