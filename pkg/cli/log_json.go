package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `log <uuid> -j` used to print the text transcript under -j: the one command
// in the log family a program could not parse. It now prints one read
// envelope whose items are the log's lines (the same --tail/--full window the
// text view shows), with the session's identity and liveness at the top level.
// --follow is a text stream with no end, so it has no -j form: poll
// `scan status <uuid> -j` or read the scan's --events stream instead.

// logLineView is one line of a session log under -j.
type logLineView struct {
	// Text is the line without its trailing newline and ANSI codes. For an
	// agentic transcript it is one verbatim transcript.jsonl line.
	Text string `json:"text"`
	// Time, Level and Phase are set for a line read back from the scan_logs
	// table (a native scan whose runtime.log was not persisted).
	Time  string `json:"time,omitempty"`
	Level string `json:"level,omitempty"`
	Phase string `json:"phase,omitempty"`
}

// logShowExtras are the top-level keys of `log <uuid> -j`.
type logShowExtras struct {
	UUID string `json:"uuid"`
	// SessionKind is native or agentic.
	SessionKind     string   `json:"session_kind"`
	Status          string   `json:"status"`
	EffectiveStatus string   `json:"effective_status"`
	Stale           bool     `json:"stale"`
	LastWriteAt     *string  `json:"last_write_at"`
	LivenessSources []string `json:"liveness_sources"`
	// Source is file (runtime.log), transcript (an agentic transcript.jsonl)
	// or database (the scan_logs table).
	Source string `json:"source"`
	// Path is the file read; empty for the database source.
	Path string `json:"path,omitempty"`
	// Tail is the window applied: the last N lines, or -1 for the whole log.
	Tail int `json:"tail"`
	// Truncated says the window dropped earlier lines.
	Truncated bool `json:"truncated"`
}

// emitLogJSON is `log <uuid> -j`.
func emitLogJSON(cmd *cobra.Command, uuid string) error {
	if logFollow {
		return usageErrorf("log -j prints one document; --follow is a text stream with no end. " +
			"Poll `vigolium scan status <uuid> -j`, or run the scan with --events ndjson")
	}
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}
	src, err := resolveLogSource(uuid, settings)
	if err != nil {
		return err
	}

	tail := logTailLines
	if logFull || tail < 0 {
		tail = -1
	}

	var (
		lines     []logLineView
		truncated bool
		source    = "file"
		path      = src.filePath
	)
	switch {
	case src.transcriptPath != "":
		// The transcript is the agentic session's record (the text view
		// replays it); its lines are JSON objects, kept verbatim.
		source, path = "transcript", src.transcriptPath
		lines, truncated, err = readLogFileLines(path, tail)
	case src.fromDB:
		source, path = "database", ""
		lines, truncated, err = readDBLogLines(src.scanUUID, tail)
	default:
		lines, truncated, err = readLogFileLines(path, tail)
	}
	if err != nil {
		return err
	}

	sources := src.liveness.Sources
	if sources == nil {
		sources = []string{}
	}
	stale := src.status == "running" && src.liveness.Stale
	if path != "" {
		path = config.ContractPath(path)
	}
	return emitRead(cmd, "", lines, int64(len(lines)), 0, len(lines),
		withExtra("uuid", uuid),
		withExtra("session_kind", src.kind),
		withExtra("status", src.status),
		withExtra("effective_status", effectiveStatus(src.status, src.errorMessage, src.liveness)),
		withExtra("stale", stale),
		withExtra("last_write_at", formatLivenessTime(src.liveness.LastWriteAt)),
		withExtra("liveness_sources", sources),
		withExtra("source", source),
		withExtra("path", path),
		withExtra("tail", tail),
		withExtra("truncated", truncated),
	)
}

// readLogFileLines reads the last tail lines of a log file (tail < 0: all),
// ANSI-stripped. 0 is an empty window, as in the text view.
func readLogFileLines(path string, tail int) ([]logLineView, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = f.Close() }()

	lines := []logLineView{}
	if tail == 0 {
		return lines, fileHasContent(f), nil
	}
	start := int64(0)
	if tail > 0 {
		start = tailStartOffset(path, tail)
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return nil, false, fmt.Errorf("failed to seek log file: %w", err)
		}
	}
	r := bufio.NewReader(f)
	// tailStartOffset lands just past a newline; should the file have changed
	// in between, a partial first line is dropped rather than shown.
	if start > 0 && !precededByNewline(path, start) {
		_, _ = r.ReadString('\n')
	}
	for {
		line, readErr := r.ReadString('\n')
		if line != "" {
			lines = append(lines, logLineView{Text: terminal.StripANSI(strings.TrimRight(line, "\r\n"))})
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, false, readErr
		}
	}
	truncated := start > 0
	if tail > 0 && len(lines) > tail {
		lines, truncated = lines[len(lines)-tail:], true
	}
	return lines, truncated, nil
}

// precededByNewline reports whether the byte before offset is a newline, so
// the line starting at offset is whole.
func precededByNewline(path string, offset int64) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, offset-1); err != nil {
		return false
	}
	return b[0] == '\n'
}

func fileHasContent(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Size() > 0
}

// readDBLogLines reads a scan's scan_logs rows, the last tail of them.
func readDBLogLines(scanUUID string, tail int) ([]logLineView, bool, error) {
	db, err := openReadDB(globDBSkipSet{Records: true})
	if err != nil {
		return nil, false, err
	}
	const pageLimit = 10000
	logs, err := fetchScanLogsRetry(context.Background(), database.NewRepository(db), scanUUID, pageLimit, 0, 10)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch scan logs: %w", err)
	}
	if len(logs) == 0 {
		return nil, false, fmt.Errorf("no logs found in database for scan %s", scanUUID)
	}
	truncated := false
	if tail >= 0 && len(logs) > tail {
		logs, truncated = logs[len(logs)-tail:], true
	}
	lines := make([]logLineView, 0, len(logs))
	for _, l := range logs {
		lines = append(lines, logLineView{
			Text:  terminal.StripANSI(l.Message),
			Time:  scanevents.FormatTime(l.CreatedAt),
			Level: strings.ToLower(l.Level),
			Phase: l.Phase,
		})
	}
	return lines, truncated, nil
}
