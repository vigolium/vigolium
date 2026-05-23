package spitolas

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

func TestConvertDialogsEmpty(t *testing.T) {
	if got := convertDialogs(nil); got != nil {
		t.Errorf("convertDialogs(nil) = %v, want nil", got)
	}
	if got := convertDialogs([]browser.DialogEvent{}); got != nil {
		t.Errorf("convertDialogs(empty) = %v, want nil", got)
	}
}

func TestConvertDialogs(t *testing.T) {
	now := time.Now()
	in := []browser.DialogEvent{
		{Type: "alert", Message: "xss", URL: "http://t/a", At: now},
		{Type: "confirm", Message: "ok?", URL: "http://t/b", At: now.Add(time.Second)},
	}

	out := convertDialogs(in)
	if len(out) != 2 {
		t.Fatalf("convertDialogs len = %d, want 2", len(out))
	}
	for i := range in {
		if out[i].Type != in[i].Type ||
			out[i].Message != in[i].Message ||
			out[i].URL != in[i].URL ||
			!out[i].At.Equal(in[i].At) {
			t.Errorf("dialog[%d] mismatch: got %+v, want %+v", i, out[i], in[i])
		}
	}
}
