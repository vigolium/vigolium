package browser

import (
	"testing"
	"time"
)

func TestRecordDialogAppendsAndReads(t *testing.T) {
	p := &Page{}

	p.recordDialog(DialogEvent{Type: "alert", Message: "one", URL: "u1", At: time.Now()})
	p.recordDialog(DialogEvent{Type: "confirm", Message: "two", URL: "u2", At: time.Now()})

	got := p.DialogEvents()
	if len(got) != 2 {
		t.Fatalf("DialogEvents len = %d, want 2", len(got))
	}
	if got[0].Message != "one" || got[1].Message != "two" {
		t.Fatalf("unexpected dialog messages: %+v", got)
	}

	// Returned slice must be a copy: mutating it must not affect Page state.
	got[0].Message = "MUTATED"
	again := p.DialogEvents()
	if again[0].Message != "one" {
		t.Fatalf("DialogEvents returned a shared slice; got %q after mutation", again[0].Message)
	}
}

func TestRecordDialogCapsAtMax(t *testing.T) {
	p := &Page{}
	for i := 0; i < maxRecordedDialogs+10; i++ {
		p.recordDialog(DialogEvent{Type: "alert", Message: "m", URL: "u", At: time.Now()})
	}
	if got := len(p.DialogEvents()); got != maxRecordedDialogs {
		t.Fatalf("dialog log size = %d, want capped at %d", got, maxRecordedDialogs)
	}
}

func TestDrainDialogsClears(t *testing.T) {
	p := &Page{}
	p.recordDialog(DialogEvent{Type: "alert", Message: "a"})
	p.recordDialog(DialogEvent{Type: "alert", Message: "b"})

	drained := p.DrainDialogs()
	if len(drained) != 2 {
		t.Fatalf("DrainDialogs returned %d, want 2", len(drained))
	}
	if got := p.DialogEvents(); len(got) != 0 {
		t.Fatalf("after drain, DialogEvents len = %d, want 0", len(got))
	}

	if again := p.DrainDialogs(); again != nil {
		t.Fatalf("second drain returned %d events, want nil", len(again))
	}
}
