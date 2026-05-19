package cli

import (
	"os"
	"sync"

	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// transcriptCapture mirrors everything the scanner prints to stdout and stderr
// — banner, scan summary, phase progress, and result lines — into a file while
// still passing the original (colored) bytes through to the real terminal. The
// file copy is ANSI-stripped so it is a clean, greppable transcript.
//
// It is used by stateless scans invoked with -o and the default console format
// so the output file is a faithful record of the verbose console session,
// rather than the minimal per-record line export.
//
// Capture works by reassigning the os.Stdout / os.Stderr package variables to
// pipe write-ends and rebuilding the global zap logger so its console core
// follows the redirected stderr. This keeps the implementation portable (no
// fd-level dup2) at the cost of TerminalWidth() falling back to its default
// while capture is active.
type transcriptCapture struct {
	file       *os.File
	origStdout *os.File
	origStderr *os.File
	outR, outW *os.File
	errR, errW *os.File
	mu         sync.Mutex // serializes interleaved stdout/stderr writes to file
	wg         sync.WaitGroup
}

// startTranscriptCapture begins mirroring stdout/stderr to path. The caller
// must invoke Stop on the returned capture (typically via defer) to restore the
// standard streams and flush the file.
func startTranscriptCapture(path string) (*transcriptCapture, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = f.Close()
		_ = outR.Close()
		_ = outW.Close()
		return nil, err
	}

	tc := &transcriptCapture{
		file:       f,
		origStdout: os.Stdout,
		origStderr: os.Stderr,
		outR:       outR, outW: outW,
		errR: errR, errW: errW,
	}

	os.Stdout = outW
	os.Stderr = errW
	// Rebuild the global logger so zap's console core writes to the redirected
	// stderr and is therefore captured in the transcript too.
	initLogger(globalVerbose, globalSilent, globalDebug, globalDumpTraffic, globalLogFile)

	tc.wg.Add(2)
	go tc.pump(outR, tc.origStdout)
	go tc.pump(errR, tc.origStderr)
	return tc, nil
}

// pump copies bytes from a redirected stream to the real terminal (colors
// preserved) and to the transcript file (ANSI-stripped).
func (tc *transcriptCapture) pump(r *os.File, passthrough *os.File) {
	defer tc.wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = passthrough.Write(chunk)
			stripped := terminal.StripANSI(string(chunk))
			tc.mu.Lock()
			_, _ = tc.file.WriteString(stripped)
			tc.mu.Unlock()
		}
		if readErr != nil {
			return
		}
	}
}

// Stop restores os.Stdout/os.Stderr and the logger, drains the pumps, and
// closes the transcript file. Safe to call once.
func (tc *transcriptCapture) Stop() {
	// Flush any buffered zap logs into the pipe before tearing down.
	_ = zap.L().Sync()

	// Restore the standard streams, then rebuild the logger so later output
	// (and other deferred cleanup) goes back to the real terminal.
	os.Stdout = tc.origStdout
	os.Stderr = tc.origStderr
	initLogger(globalVerbose, globalSilent, globalDebug, globalDumpTraffic, globalLogFile)

	// Closing the write ends unblocks the pumps so they drain remaining data.
	_ = tc.outW.Close()
	_ = tc.errW.Close()
	tc.wg.Wait()
	_ = tc.outR.Close()
	_ = tc.errR.Close()
	_ = tc.file.Close()
}
