package agent

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestStreamGroupLineBuffering(t *testing.T) {
	var out bytes.Buffer
	g := newStreamGroup(&out)
	a := g.writer("a")

	// Partial tokens stay buffered.
	_, _ = a.Write([]byte("hel"))
	_, _ = a.Write([]byte("lo "))
	if out.Len() != 0 {
		t.Fatalf("expected no flush before newline, got %q", out.String())
	}

	// Newline triggers flush of full line with prefix.
	_, _ = a.Write([]byte("world\n"))
	if got := out.String(); got != "[a] hello world\n" {
		t.Fatalf("expected '[a] hello world\\n', got %q", got)
	}

	// Trailing partial line drained by Flush.
	out.Reset()
	_, _ = a.Write([]byte("partial"))
	if out.Len() != 0 {
		t.Fatalf("expected partial line buffered, got %q", out.String())
	}
	a.Flush()
	if got := out.String(); got != "[a] partial\n" {
		t.Fatalf("expected '[a] partial\\n' after flush, got %q", got)
	}
}

// TestStreamGroupNoInterleave confirms that two writers streaming concurrent
// token chunks never produce mid-line interleave on the underlying sink.
func TestStreamGroupNoInterleave(t *testing.T) {
	var out bytes.Buffer
	g := newStreamGroup(&out)
	a := g.writer("a")
	b := g.writer("b")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Stream 100 lines of 'A's in many small chunks.
		for i := 0; i < 100; i++ {
			_, _ = a.Write([]byte("A"))
			_, _ = a.Write([]byte("AA"))
			_, _ = a.Write([]byte("AAA"))
			_, _ = a.Write([]byte("\n"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_, _ = b.Write([]byte("B"))
			_, _ = b.Write([]byte("BB"))
			_, _ = b.Write([]byte("BBB"))
			_, _ = b.Write([]byte("\n"))
		}
	}()
	wg.Wait()
	a.Flush()
	b.Flush()

	// Every line should be entirely "[a] AAAAAA" or "[b] BBBBBB" — no mixed letters.
	for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "[a] "):
			body := strings.TrimPrefix(line, "[a] ")
			if strings.Trim(body, "A") != "" {
				t.Fatalf("interleaved line under [a]: %q", line)
			}
		case strings.HasPrefix(line, "[b] "):
			body := strings.TrimPrefix(line, "[b] ")
			if strings.Trim(body, "B") != "" {
				t.Fatalf("interleaved line under [b]: %q", line)
			}
		default:
			t.Fatalf("unprefixed line: %q", line)
		}
	}
}

// TestStreamGroupNilSafe ensures nil-receiver paths don't panic when the
// caller didn't supply an underlying writer (no-stream mode).
func TestStreamGroupNilSafe(t *testing.T) {
	var g *streamGroup // simulate newStreamGroup(nil)
	w := g.writer("a")
	// Should not panic; Write returns full length, Flush is a no-op.
	if n, err := w.Write([]byte("hello\n")); n != 6 || err != nil {
		t.Fatalf("nil writer.Write returned (%d,%v), want (6,nil)", n, err)
	}
	w.Flush()
}
