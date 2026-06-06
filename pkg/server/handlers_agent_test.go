package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsTerminalAgentStatus(t *testing.T) {
	cases := map[string]bool{
		"completed": true,
		"failed":    true,
		"cancelled": true,
		"timeout":   true,
		"error":     true,
		"running":   false,
		"queued":    false,
		"":          false,
	}
	for status, want := range cases {
		if got := isTerminalAgentStatus(status); got != want {
			t.Errorf("isTerminalAgentStatus(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestTailSessionLog_ExistingContent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	payload := "phase one\nphase two\n"
	if err := os.WriteFile(logPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, logPath, func() bool { return true }, 10*time.Millisecond, time.Second, false)
	_ = w.Flush()

	out := buf.String()
	if !strings.Contains(out, "phase one") || !strings.Contains(out, "phase two") {
		t.Errorf("expected log payload in SSE output, got: %q", out)
	}
	if !strings.Contains(out, `"type":"chunk"`) {
		t.Errorf("expected chunk event, got: %q", out)
	}
	if !strings.Contains(out, `"type":"done"`) {
		t.Errorf("expected done event, got: %q", out)
	}
}

func TestTailSessionLog_MissingFile(t *testing.T) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, filepath.Join(t.TempDir(), "nope.log"), func() bool { return true }, 10*time.Millisecond, time.Second, false)
	_ = w.Flush()

	out := buf.String()
	if !strings.Contains(out, `"type":"error"`) {
		t.Errorf("expected error event for missing file, got: %q", out)
	}
}

func TestTailSessionLog_PollsUntilDone(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	if err := os.WriteFile(logPath, []byte("first\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	// isDone flips true after a short delay, simulating a run that
	// finishes while the client is tailing.
	var done atomic.Bool
	go func() {
		time.Sleep(30 * time.Millisecond)
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		_, _ = f.WriteString("second\n")
		_ = f.Close()
		time.Sleep(20 * time.Millisecond)
		done.Store(true)
	}()

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, logPath, func() bool { return done.Load() }, 10*time.Millisecond, 2*time.Second, false)
	_ = w.Flush()

	out := buf.String()
	if !strings.Contains(out, "first") {
		t.Errorf("expected 'first' chunk in output, got: %q", out)
	}
	if !strings.Contains(out, "second") {
		t.Errorf("expected 'second' chunk (appended during poll) in output, got: %q", out)
	}
	if !strings.Contains(out, `"type":"done"`) {
		t.Errorf("expected done event after isDone flipped, got: %q", out)
	}
}

func TestTailSessionLog_SafetyTimeout(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	if err := os.WriteFile(logPath, []byte("only line\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	start := time.Now()
	tailSessionLog(w, logPath, func() bool { return false }, 10*time.Millisecond, 50*time.Millisecond, false)
	_ = w.Flush()

	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("safety timeout did not fire, elapsed=%v", elapsed)
	}
	if !strings.Contains(buf.String(), `"type":"done"`) {
		t.Errorf("expected done event after safety timeout, got: %q", buf.String())
	}
}

func TestTailSessionLog_StripANSI(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	// Red "hello" wrapped in SGR escapes plus a plain tail.
	payload := "\x1b[31mhello\x1b[0m world\n"
	if err := os.WriteFile(logPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, logPath, func() bool { return true }, 10*time.Millisecond, time.Second, true)
	_ = w.Flush()

	out := buf.String()
	// JSON encodes \x1b as \u001b; neither the raw nor encoded form should appear.
	if strings.Contains(out, "\\u001b") || strings.Contains(out, "\x1b[") {
		t.Errorf("expected ANSI codes stripped, got: %q", out)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected payload text after strip, got: %q", out)
	}
}

func TestSnapshotAgentRawOutput(t *testing.T) {
	t.Run("missing dir returns empty", func(t *testing.T) {
		if got := snapshotAgentRawOutput(nil, ""); got != "" {
			t.Errorf("expected empty for blank dir, got %q", got)
		}
	})

	t.Run("missing log file returns empty", func(t *testing.T) {
		if got := snapshotAgentRawOutput(nil, t.TempDir()); got != "" {
			t.Errorf("expected empty for missing log, got %q", got)
		}
	})

	t.Run("strips ANSI from runtime.log", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "runtime.log")
		payload := "\x1b[31mfailed\x1b[0m: boom\n"
		if err := os.WriteFile(logPath, []byte(payload), 0o644); err != nil {
			t.Fatalf("write log: %v", err)
		}
		got := snapshotAgentRawOutput(nil, dir)
		if got != "failed: boom\n" {
			t.Errorf("expected ANSI stripped, got %q", got)
		}
	})

	t.Run("head-truncates oversized logs", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "runtime.log")
		// Build a payload > the 200 KiB cap with a unique tail marker.
		head := strings.Repeat("a", maxAgentRawOutputBytes+1024)
		tail := "TAIL_MARKER\n"
		if err := os.WriteFile(logPath, []byte(head+tail), 0o644); err != nil {
			t.Fatalf("write log: %v", err)
		}
		got := snapshotAgentRawOutput(nil, dir)
		if !strings.HasPrefix(got, "...[truncated head]...") {
			t.Errorf("expected head-truncation marker, got prefix %q", got[:min(40, len(got))])
		}
		if !strings.HasSuffix(got, tail) {
			t.Errorf("expected tail preserved, got suffix %q", got[max(0, len(got)-len(tail)-10):])
		}
		// Truncation marker plus the cap is the hard upper bound.
		if len(got) > maxAgentRawOutputBytes+len("...[truncated head]...\n") {
			t.Errorf("snapshot overshot the cap: %d bytes", len(got))
		}
	})
}

// errWriter fails every Write, simulating a dead SSE client connection.
type errWriter struct{ err error }

func (e *errWriter) Write(p []byte) (int, error) { return 0, e.err }

func TestDrainAgentPipeToSSE_ForwardsChunks(t *testing.T) {
	pr, pw := io.Pipe()
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)

	go func() {
		_, _ = pw.Write([]byte("hello "))
		_, _ = pw.Write([]byte("world"))
		_ = pw.Close()
	}()

	connected := drainAgentPipeToSSE(newSSESink(w), pr, nil)
	_ = w.Flush()

	if !connected {
		t.Errorf("expected clientConnected=true for a healthy client")
	}
	out := buf.String()
	if !strings.Contains(out, "hello ") || !strings.Contains(out, "world") {
		t.Errorf("expected forwarded chunks, got: %q", out)
	}
	if !strings.Contains(out, `"type":"chunk"`) {
		t.Errorf("expected chunk events, got: %q", out)
	}
}

// TestDrainAgentPipeToSSE_KeepsDrainingAfterClientDisconnect is the regression
// guard for the "log freezes / status stuck on running" bug: when the SSE
// client goes away, the drain must keep reading the pipe so the agent's writer
// (io.MultiWriter(logFile, pw)) never blocks and the caller's finalization
// still runs. If the loop stopped reading after the first write error, the
// writer goroutine below would block forever on pw.Write and the test would
// hit its timeout.
//
// It also pins the disconnect-cancels-run behavior: onDisconnect must fire
// exactly once, the moment the client is first detected gone, so callers can
// cancel the run's context and stop burning budget for a vanished client.
func TestDrainAgentPipeToSSE_KeepsDrainingAfterClientDisconnect(t *testing.T) {
	pr, pw := io.Pipe()
	w := bufio.NewWriter(&errWriter{err: io.ErrClosedPipe})

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		// More chunks than the drain would ever buffer; each blocks until the
		// drain reads it.
		for i := 0; i < 8; i++ {
			if _, err := pw.Write([]byte("chunk-payload")); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()

	// onDisconnect runs in the same goroutine as the synchronous drain call, so
	// the counter needs no synchronization.
	disconnectCalls := 0
	connected := drainAgentPipeToSSE(newSSESink(w), pr, func() { disconnectCalls++ })
	if connected {
		t.Errorf("expected clientConnected=false after SSE write error")
	}
	if disconnectCalls != 1 {
		t.Errorf("expected onDisconnect to fire exactly once on disconnect, got %d", disconnectCalls)
	}

	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("writer goroutine blocked: drain loop stopped reading after client disconnect")
	}
}

// TestSSESink_ConcurrentSends is the regression guard for the swarm SSE data
// race: phase/progress callbacks fire writeSSE from runner goroutines while the
// chunk-drain loop writes too. With everything routed through one sseSink, the
// writes are serialized. Run under `go test -race` (make test-race) this fails
// loudly if the lock is removed; it also asserts no event is interleaved
// (every line is a complete, parseable SSE frame).
func TestSSESink_ConcurrentSends(t *testing.T) {
	pr, pw := io.Pipe()
	sink := newSSESink(bufio.NewWriter(pw))

	const producers = 8
	const perProducer = 50
	var wg sync.WaitGroup

	// Drain the pipe concurrently so writes don't block, and collect output.
	var collected bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = io.Copy(&collected, pr)
	}()

	wg.Add(producers)
	for p := 0; p < producers; p++ {
		go func(p int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				// Mix the event shapes the swarm handler actually emits
				// concurrently: phase, progress, and chunk.
				switch i % 3 {
				case 0:
					_ = sink.send(sseEvent{Type: "phase", Phase: "scan"})
				case 1:
					_ = sink.send(sseEvent{Type: "chunk", Text: "payload"})
				default:
					_ = sink.send(sseEvent{Type: "progress"})
				}
			}
		}(p)
	}
	wg.Wait()
	_ = pw.Close()
	<-readDone

	out := collected.String()
	// Every SSE frame is "data: <json>\n\n". Splitting on the blank-line
	// separator, each non-empty record must be a complete data line whose JSON
	// parses — proof no two concurrent sends interleaved mid-frame.
	frames := strings.Split(out, "\n\n")
	count := 0
	for _, f := range frames {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		payload, ok := strings.CutPrefix(f, "data: ")
		if !ok {
			t.Fatalf("frame missing 'data: ' prefix (interleaved write?): %q", f)
		}
		var evt sseEvent
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			t.Fatalf("frame is not valid JSON (interleaved write?): %q: %v", payload, err)
		}
		count++
	}
	if want := producers * perProducer; count != want {
		t.Errorf("expected %d complete SSE frames, got %d", want, count)
	}
}

func TestStripANSI(t *testing.T) {
	cases := map[string]string{
		"\x1b[31mred\x1b[0m":               "red",
		"plain text":                       "plain text",
		"\x1b[1;32mbold green\x1b[0m tail": "bold green tail",
		"mix \x1b[33myellow\x1b[0m and \x1b[34mblue\x1b[0m end": "mix yellow and blue end",
	}
	for in, want := range cases {
		if got := stripANSI(in); got != want {
			t.Errorf("stripANSI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBoolParam(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "yes", "y", "on"}
	falsy := []string{"", "0", "false", "no", "nope", "maybe"}
	for _, v := range truthy {
		if !parseBoolParam(v) {
			t.Errorf("parseBoolParam(%q) = false, want true", v)
		}
	}
	for _, v := range falsy {
		if parseBoolParam(v) {
			t.Errorf("parseBoolParam(%q) = true, want false", v)
		}
	}
}
