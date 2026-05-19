package agent

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

// streamGroup serializes line-flushes from multiple concurrent
// prefixedStreamWriters onto a single underlying writer. It exists because
// safeWriter (mutex around byte-level Write) doesn't actually prevent
// terminal garbage when 3 goroutines stream tokens at once — the chars
// interleave per-write-call, not per-line.
//
// Use newStreamGroup(out) to wrap a stream sink, then call .writer(prefix)
// per goroutine. Each writer buffers internally and flushes whole lines
// (prefixed with [tag]) under the group's mutex. Trailing partial lines are
// drained by calling .Flush() on the writer.
type streamGroup struct {
	mu  sync.Mutex
	out io.Writer
}

// newStreamGroup wraps an underlying writer; returns nil if out is nil so
// callers can pass-through the no-stream case.
func newStreamGroup(out io.Writer) *streamGroup {
	if out == nil {
		return nil
	}
	return &streamGroup{out: out}
}

// writer returns a prefix-tagged stream writer. The prefix is rendered as
// "[prefix] " before each emitted line.
func (g *streamGroup) writer(prefix string) *prefixedStreamWriter {
	if g == nil {
		return nil
	}
	return &prefixedStreamWriter{group: g, prefix: prefix}
}

// prefixedStreamWriter buffers tokens until newline, then flushes the whole
// line atomically through the group mutex. Tokens within a single line stay
// contiguous; lines from different writers never interleave mid-line.
type prefixedStreamWriter struct {
	group  *streamGroup
	prefix string

	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends bytes to the per-writer buffer and flushes any complete
// lines. Always reports the full input length as written (we never drop).
func (w *prefixedStreamWriter) Write(p []byte) (int, error) {
	if w == nil || w.group == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	w.flushCompleteLinesLocked()
	return len(p), nil
}

// Flush drains any trailing partial line. Call after the producer goroutine
// finishes so the last incomplete chunk reaches the user's terminal.
func (w *prefixedStreamWriter) Flush() {
	if w == nil || w.group == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() == 0 {
		return
	}
	w.group.mu.Lock()
	_, _ = fmt.Fprintf(w.group.out, "[%s] %s\n", w.prefix, w.buf.String())
	w.group.mu.Unlock()
	w.buf.Reset()
}

// flushCompleteLinesLocked emits every \n-terminated chunk currently in the
// buffer. Caller must hold w.mu.
func (w *prefixedStreamWriter) flushCompleteLinesLocked() {
	for {
		data := w.buf.Bytes()
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			return
		}
		line := make([]byte, idx+1)
		copy(line, data[:idx+1])
		w.buf.Next(idx + 1)

		w.group.mu.Lock()
		_, _ = fmt.Fprintf(w.group.out, "[%s] %s", w.prefix, line)
		w.group.mu.Unlock()
	}
}
