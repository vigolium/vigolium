package clicommon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// --input-read-timeout was registered on scan, run, and ingest, documented as
// "Timeout for reading input from stdin or file", defaulted to 3m, and read by
// nothing. It was assigned into Options.InputReadTimeout and no consumer ever
// looked at that field, so the control was inert repo-wide:
//
//	( sleep 30 ) | vigolium scan --input-read-timeout 2s
//
// blocked for the full 30 seconds. Fourteen call sites reached for a bare
// io.ReadAll(os.Stdin), which has neither a deadline nor a size bound, so a
// producer that never closes its end hung the process forever with no way for
// the caller to bound it. For an agent driving vigolium from a shell tool that
// is unrecoverable: the tool call never returns.
//
// ReadBounded is the one reader. io.ReadAll cannot be cancelled once it is
// blocked in read(2), so the read runs on its own goroutine and the deadline is
// enforced by the caller side of a channel. The goroutine is left blocked on
// timeout rather than being forced to unwind: it holds only a buffer, the
// process is on its way to reporting the failure, and there is no portable way
// to interrupt a pending read on a pipe.

// DefaultStdinLimit bounds a single stdin read. It is deliberately generous —
// a HAR or a Burp export piped in can be large, and the deadline, not the size
// cap, is what protects against a producer that never finishes. The cap exists
// so a runaway or hostile producer cannot drive the process out of memory.
const DefaultStdinLimit = 512 << 20 // 512 MiB

// ErrStdinTimeout marks input that did not arrive within the deadline.
var ErrStdinTimeout = errors.New("timed out reading stdin")

// ErrStdinTooLarge marks input that exceeded the size bound.
var ErrStdinTooLarge = errors.New("stdin input exceeds the size limit")

type stdinResult struct {
	n   int64
	err error
}

// ReadStdinBounded reads all of stdin subject to a size limit and a deadline.
//
// A zero or negative timeout means no deadline, preserving the previous
// behavior for callers that have not been given a timeout to honor. A zero or
// negative limit falls back to DefaultStdinLimit.
//
// On timeout it returns what the deadline is, not a generic I/O error: the
// caller is expected to surface --input-read-timeout as the dial that changes
// it, because "vigolium hung" is otherwise indistinguishable from "the producer
// is slow".
func ReadStdinBounded(limit int64, timeout time.Duration) ([]byte, error) {
	return ReadBounded(os.Stdin, "stdin", limit, timeout)
}

// ReadBounded applies the same bounds to an arbitrary reader, for the file
// branches that sit beside a stdin branch and should fail the same way.
//
// It is ReadBoundedWait with no first-byte deadline: the whole read, measured
// from the start, is bounded by timeout.
func ReadBounded(r io.Reader, name string, limit int64, timeout time.Duration) ([]byte, error) {
	return ReadBoundedWait(r, name, limit, 0, timeout)
}

// ErrStdinNoData marks an input that produced no byte at all within the
// first-byte window. It is distinct from ErrStdinTimeout: nothing arrived, so
// the input was most likely an inherited pipe nobody writes to, not a slow
// producer that started and stalled.
var ErrStdinNoData = errors.New("no data on stdin")

// ReadBoundedWait reads r subject to a size limit, a first-byte deadline and a
// total deadline.
//
// An inherited stdin is indistinguishable from a piped one: a CI runner, an
// agent harness or a supervisor hands the child a pipe it never writes to, and
// fileutil.HasStdin reports it as "piped". A command that drains stdin only
// because it MIGHT carry input then sat for the full --input-read-timeout
// before failing with "no targets". firstByte bounds that guess: when it is
// positive and no byte (and no EOF) arrives within it, the read gives up with
// ErrStdinNoData. Once the first byte (or EOF) arrives the producer is real,
// and total — measured from that first byte — bounds the rest.
//
// A zero or negative firstByte disables the first-byte phase, and total is then
// measured from the start; that is ReadBounded. A zero or negative total means
// no overall deadline. An EOF with zero bytes returns an empty slice and no
// error at once: an empty pipe is an answer, not a stall.
//
// NOTE for a future caller: on a deadline the read goroutine is left blocked.
// Every caller today is one-shot and on its way to reporting the failure and
// exiting, so the abandoned goroutine and its buffer live for microseconds. A
// long-lived caller that times out repeatedly would leak one goroutine per
// timeout.
func ReadBoundedWait(r io.Reader, name string, limit int64, firstByte, total time.Duration) ([]byte, error) {
	var data []byte
	if err := boundedRead(r, name, limit, firstByte, total, func(lr io.Reader) (int64, error) {
		var err error
		data, err = io.ReadAll(lr)
		return int64(len(data)), err
	}); err != nil {
		return nil, err
	}
	return data, nil
}

// CopyBounded is ReadBounded streaming into w rather than into memory, for a
// caller that spools the input to a file: the size limit and the deadline
// apply the same way, and nothing larger than a copy buffer is held.
func CopyBounded(w io.Writer, r io.Reader, name string, limit int64, timeout time.Duration) error {
	return boundedRead(r, name, limit, 0, timeout, func(lr io.Reader) (int64, error) {
		return io.Copy(w, lr)
	})
}

// boundedRead runs consume over r in a goroutine, limited to one byte past
// limit, and applies the first-byte and total deadlines (see ReadBoundedWait).
func boundedRead(r io.Reader, name string, limit int64, firstByte, total time.Duration, consume func(io.Reader) (int64, error)) error {
	if limit <= 0 {
		limit = DefaultStdinLimit
	}

	fr := &firstByteReader{r: r, started: make(chan struct{})}
	done := make(chan stdinResult, 1)
	go func() {
		// Read one byte past the limit so exceeding it is detectable rather
		// than silently truncating the caller's input into a parse error.
		n, err := consume(io.LimitReader(fr, limit+1))
		done <- stdinResult{n: n, err: err}
	}()

	finish := func(res stdinResult) error {
		if res.err != nil {
			return fmt.Errorf("failed to read %s: %w", name, res.err)
		}
		if res.n > limit {
			return fmt.Errorf("%w: %s exceeds %d bytes", ErrStdinTooLarge, name, limit)
		}
		return nil
	}

	if firstByte > 0 {
		timer := time.NewTimer(firstByte)
		select {
		case res := <-done:
			timer.Stop()
			return finish(res)
		case <-fr.started:
			timer.Stop()
		case <-timer.C:
			return fmt.Errorf("%w: nothing arrived on %s within %s", ErrStdinNoData, name, firstByte)
		}
	}

	// A nil channel blocks forever, which is exactly what "no deadline" means —
	// so the select below covers both cases without a second copy of its first
	// arm.
	var deadline <-chan time.Time
	if total > 0 {
		timer := time.NewTimer(total)
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case res := <-done:
		return finish(res)
	case <-deadline:
		return fmt.Errorf("%w after %s: no complete input arrived on %s "+
			"(raise or disable the deadline with --input-read-timeout)",
			ErrStdinTimeout, total, name)
	}
}

// firstByteReader closes started on the first read that returns data or an
// error (EOF included), so the caller can tell "the producer has begun" from
// "nothing has happened yet" without consuming a byte itself.
type firstByteReader struct {
	r       io.Reader
	started chan struct{}
	once    sync.Once
}

func (f *firstByteReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if n > 0 || err != nil {
		f.once.Do(func() { close(f.started) })
	}
	return n, err
}
