package cli

import (
	"io"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/internal/config"
)

// teeToRuntimeLog returns a writer that mirrors w to
// {sessionDir}/runtime.log, so that `vigolium log <uuid>` and
// `vigolium log ls` can tail/show the session's output later. If the file
// can't be opened (or sessionDir is empty), w is returned unchanged and
// the returned closer is nil. The caller must defer-close any non-nil
// closer so the file flushes on exit.
func teeToRuntimeLog(w io.Writer, sessionDir string) (io.Writer, io.Closer) {
	if sessionDir == "" {
		return w, nil
	}
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return w, nil
	}
	logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return w, nil
	}
	if w == nil {
		return f, f
	}
	return io.MultiWriter(w, f), f
}
