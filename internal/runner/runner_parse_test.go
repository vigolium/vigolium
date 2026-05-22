package runner

import (
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/core"
)

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  map[string]string
	}{
		{
			name:  "nil input",
			input: nil,
			want:  map[string]string{},
		},
		{
			name:  "single valid pair",
			input: []string{"X-Api-Key: secret"},
			want:  map[string]string{"X-Api-Key": "secret"},
		},
		{
			name:  "multiple valid pairs",
			input: []string{"Authorization: Bearer token", "Accept: application/json"},
			want: map[string]string{
				"Authorization": "Bearer token",
				"Accept":        "application/json",
			},
		},
		{
			name:  "surrounding whitespace trimmed from key and value",
			input: []string{"  X-Trace  :   abc123  "},
			want:  map[string]string{"X-Trace": "abc123"},
		},
		{
			name:  "value containing colon kept intact (SplitN=2)",
			input: []string{"X-Url: https://example.com:8080/path"},
			want:  map[string]string{"X-Url": "https://example.com:8080/path"},
		},
		{
			name:  "malformed entry without colon is skipped",
			input: []string{"NotAHeader", "Valid: yes"},
			want:  map[string]string{"Valid": "yes"},
		},
		{
			name:  "empty value allowed",
			input: []string{"X-Empty:"},
			want:  map[string]string{"X-Empty": ""},
		},
		{
			name:  "empty string entry skipped",
			input: []string{""},
			want:  map[string]string{},
		},
		{
			name:  "duplicate keys: last wins",
			input: []string{"X-Dup: first", "X-Dup: second"},
			want:  map[string]string{"X-Dup": "second"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHeaders(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseHeaders(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseVariables(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  map[string]string
	}{
		{
			name:  "nil input",
			input: nil,
			want:  map[string]string{},
		},
		{
			name:  "single valid pair",
			input: []string{"host=example.com"},
			want:  map[string]string{"host": "example.com"},
		},
		{
			name:  "multiple valid pairs",
			input: []string{"a=1", "b=2"},
			want:  map[string]string{"a": "1", "b": "2"},
		},
		{
			name:  "surrounding whitespace trimmed",
			input: []string{"  key  =  value  "},
			want:  map[string]string{"key": "value"},
		},
		{
			name:  "value containing equals kept intact (SplitN=2)",
			input: []string{"token=abc=def=ghi"},
			want:  map[string]string{"token": "abc=def=ghi"},
		},
		{
			name:  "malformed entry without equals is skipped",
			input: []string{"noequals", "ok=yes"},
			want:  map[string]string{"ok": "yes"},
		},
		{
			name:  "empty value allowed",
			input: []string{"empty="},
			want:  map[string]string{"empty": ""},
		},
		{
			name:  "empty string entry skipped",
			input: []string{""},
			want:  map[string]string{},
		},
		{
			name:  "duplicate keys: last wins",
			input: []string{"k=first", "k=second"},
			want:  map[string]string{"k": "second"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVariables(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseVariables(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestRunnerPauseControl exercises the Pause/Resume/IsPaused state machine
// delegated to the PauseController. The full Runner is too heavy to construct
// via New(), but these methods only touch r.pauseCtrl (and an optional, nil-safe
// scanLogger), so a minimal struct literal is sufficient.
func TestRunnerPauseControl(t *testing.T) {
	r := &Runner{pauseCtrl: core.NewPauseController()}

	if r.IsPaused() {
		t.Fatal("a fresh Runner should not be paused")
	}

	r.Pause()
	if !r.IsPaused() {
		t.Fatal("Runner should be paused after Pause()")
	}

	// Pause is idempotent — calling again must not change the observable state
	// or deadlock.
	r.Pause()
	if !r.IsPaused() {
		t.Fatal("Runner should remain paused after a second Pause()")
	}

	r.Resume()
	if r.IsPaused() {
		t.Fatal("Runner should not be paused after Resume()")
	}

	// Resume on an already-resumed controller is a no-op (must not double-unlock).
	r.Resume()
	if r.IsPaused() {
		t.Fatal("Runner should remain unpaused after a redundant Resume()")
	}

	// State machine survives a second pause/resume cycle.
	r.Pause()
	if !r.IsPaused() {
		t.Fatal("Runner should be paused after second Pause cycle")
	}
	r.Resume()
	if r.IsPaused() {
		t.Fatal("Runner should not be paused after second Resume cycle")
	}
}

// TestRunnerPauseControlNilCtrl verifies the methods are nil-safe: a Runner
// without a pauseCtrl reports unpaused and Pause/Resume are no-ops rather than
// panicking.
func TestRunnerPauseControlNilCtrl(t *testing.T) {
	r := &Runner{}

	if r.IsPaused() {
		t.Fatal("Runner with nil pauseCtrl should report not paused")
	}
	// These must not panic.
	r.Pause()
	r.Resume()
	if r.IsPaused() {
		t.Fatal("Runner with nil pauseCtrl should still report not paused after Pause/Resume")
	}
}
