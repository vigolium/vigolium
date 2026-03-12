package runner

import (
	"io"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// teeWriter wraps an io.Writer (typically os.Stderr) and captures every
// complete line written, stripping ANSI codes and forwarding them to a
// ScanLogger as trace-level entries. This enables raw console output to be
// stored in the scan_logs table for later retrieval via the API.
type teeWriter struct {
	inner      io.Writer
	scanLogger *database.ScanLogger
	phase      string // current scan phase, updated via SetPhase
	buf        []byte // partial-line accumulator
	mu         sync.Mutex
}

// newTeeWriter creates a teeWriter that writes to inner and logs lines
// via scanLogger. If scanLogger is nil, behaves as a plain passthrough.
func newTeeWriter(inner io.Writer, scanLogger *database.ScanLogger) *teeWriter {
	return &teeWriter{
		inner:      inner,
		scanLogger: scanLogger,
	}
}

// SetPhase updates the current phase tag used for trace log entries.
func (t *teeWriter) SetPhase(phase string) {
	t.mu.Lock()
	t.phase = phase
	t.mu.Unlock()
}

// Write implements io.Writer. It always writes all bytes to the inner writer,
// then buffers and extracts complete lines for trace logging.
func (t *teeWriter) Write(p []byte) (n int, err error) {
	// Always write to the real output first.
	n, err = t.inner.Write(p)

	if t.scanLogger == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.buf = append(t.buf, p[:n]...)

	// Extract and log complete lines.
	for {
		idx := indexByte(t.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(t.buf[:idx])
		t.buf = t.buf[idx+1:]

		plain := terminal.StripANSI(line)
		plain = strings.TrimSpace(plain)
		if plain == "" {
			continue
		}
		t.scanLogger.Trace(t.phase, plain)
	}

	return
}

// Flush logs any remaining partial line in the buffer.
func (t *teeWriter) Flush() {
	if t.scanLogger == nil {
		return
	}
	t.mu.Lock()
	remaining := string(t.buf)
	t.buf = nil
	phase := t.phase
	t.mu.Unlock()

	plain := terminal.StripANSI(remaining)
	plain = strings.TrimSpace(plain)
	if plain != "" {
		t.scanLogger.Trace(phase, plain)
	}
}

// indexByte returns the index of the first occurrence of c in b, or -1.
func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
