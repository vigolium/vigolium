package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	logTailLines int
	logFull      bool
	logFollow    bool
	logStripANSI bool
)

var logCmd = &cobra.Command{
	Use:   "log [uuid]",
	Short: "View raw logs for a native scan or agentic scan",
	Long: `Show raw console logs for a native scan or agentic scan.

Without a UUID argument, lists all available sessions (same as "vigolium log ls").
With a UUID, streams that session's log.

Native scan logs are read from the session directory configured via
scanning_strategy.scan_logs.sessions_dir (default ~/.vigolium/native-sessions/).
When scanning_strategy.scan_logs.persist_logs is disabled or the runtime.log file is
missing, output falls back to the scan_logs database table.

Agentic scan logs are read from agent.sessions_dir/{uuid}/runtime.log.

Pass --tui to open the interactive picker.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runLogShow,
}

var logLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List native scan and agentic scan sessions",
	Long:  "Print every native scan and agentic scan session that has a stored log, sorted by most recent first. Each row shows the session UUID, kind, start time, and source — pass the UUID to 'vigolium log <uuid>' to view its log.",
	RunE:  runLogLs,
}

func init() {
	rootCmd.AddCommand(logCmd)
	logCmd.AddCommand(logLsCmd)

	logCmd.Flags().IntVarP(&logTailLines, "tail", "n", 200, "Show the last N lines (0 = none, -1 = all)")
	logCmd.Flags().BoolVar(&logFull, "full", false, "Show the full log (shortcut for --tail -1)")
	logCmd.Flags().BoolVarP(&logFollow, "follow", "f", false, "Follow log output as it is written (tail -f)")
	logCmd.Flags().BoolVar(&logStripANSI, "strip-ansi", false, "Strip ANSI color codes from output")
	tui.AddFlags(logCmd, &logLsTUI, &logLsNoTUI)
	tui.AddFlags(logLsCmd, &logLsTUI, &logLsNoTUI)
}

// sessionRow is a normalized view of a scan log session (native or agentic)
// used by `log ls` for merged listing.
type sessionRow struct {
	kind      string // "native" or "agentic"
	uuid      string
	status    string
	target    string
	createdAt time.Time
	logPath   string // may be empty if no file on disk
	logSize   int64
	hasLog    bool // true when a runtime.log (or legacy run.log) file exists
}

func runLogLs(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	ctx := context.Background()
	if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
		return fmt.Errorf("failed to create schema: %w", schemaErr)
	}
	repo := database.NewRepository(db)

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	rows := collectNativeRows(ctx, repo, projectUUID, settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir())
	rows = append(rows, collectAgenticRows(ctx, repo, projectUUID, settings.Agent.EffectiveSessionsDir())...)

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].createdAt.After(rows[j].createdAt)
	})

	if active, tuiErr := tui.Active(logLsTUI, logLsNoTUI, globalJSON); tuiErr != nil {
		return tuiErr
	} else if active {
		if len(rows) == 0 {
			fmt.Printf("%s No scan or agent sessions found.\n", terminal.InfoSymbol())
			return nil
		}
		return pickLogLsTUI(rows)
	}

	if globalJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		out := make([]map[string]interface{}, 0, len(rows))
		for _, r := range rows {
			out = append(out, map[string]interface{}{
				"kind":       r.kind,
				"uuid":       r.uuid,
				"status":     r.status,
				"target":     r.target,
				"created_at": r.createdAt,
				"log_path":   r.logPath,
				"log_size":   r.logSize,
				"has_log":    r.hasLog,
			})
		}
		return enc.Encode(out)
	}

	if len(rows) == 0 {
		fmt.Printf("%s No scan or agent sessions found.\n", terminal.InfoSymbol())
		return nil
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "KIND", "UUID", "STATUS", "TARGET", "LOG", "SIZE", "CREATED")
	for _, r := range rows {
		kindCol := r.kind
		switch r.kind {
		case "native":
			kindCol = terminal.Cyan(r.kind)
		case "agentic":
			kindCol = terminal.Purple(r.kind)
		}

		logCol := terminal.Gray("db-only")
		sizeCol := ""
		if r.hasLog {
			logCol = terminal.Green("file")
			sizeCol = formatFileSize(r.logSize)
		} else if r.kind == "agentic" {
			logCol = terminal.Gray("missing")
		}

		target := r.target
		if len(target) > 40 {
			target = target[:37] + "..."
		}

		tbl.AddRow(
			kindCol,
			terminal.Gray(r.uuid),
			colorRunStatus(r.status),
			target,
			logCol,
			terminal.Gray(sizeCol),
			terminal.Gray(r.createdAt.Format("2006-01-02 15:04")),
		)
	}
	tbl.Print()

	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n\n",
		terminal.TipPrefix(),
		terminal.Gray("run"),
		terminal.HiCyan("vigolium log <uuid>"),
		terminal.Gray("to view session logs (add -f to follow)"))
	return nil
}

func collectNativeRows(ctx context.Context, repo *database.Repository, projectUUID, sessionsDir string) []sessionRow {
	scans, _, err := repo.ListScans(ctx, projectUUID, 200, 0)
	if err != nil {
		return nil
	}
	rows := make([]sessionRow, 0, len(scans))
	for _, s := range scans {
		row := sessionRow{
			kind:      "native",
			uuid:      s.UUID,
			status:    s.Status,
			target:    s.Target,
			createdAt: s.StartedAt,
		}
		if logPath := resolveSessionLogPath(filepath.Join(sessionsDir, s.UUID)); logPath != "" {
			if fi, statErr := os.Stat(logPath); statErr == nil {
				row.logPath = logPath
				row.logSize = fi.Size()
				row.hasLog = true
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func collectAgenticRows(ctx context.Context, repo *database.Repository, projectUUID, sessionsDir string) []sessionRow {
	runs, _, err := repo.ListAgenticScans(ctx, projectUUID, "", 200, 0)
	if err != nil {
		return nil
	}
	rows := make([]sessionRow, 0, len(runs))
	for _, r := range runs {
		target := r.TargetURL
		if target == "" && r.SourcePath != "" {
			target = terminal.ShortenHome(r.SourcePath)
		}
		row := sessionRow{
			kind:      "agentic",
			uuid:      r.UUID,
			status:    r.Status,
			target:    target,
			createdAt: r.CreatedAt,
		}
		sessionDir := r.SessionDir
		if sessionDir == "" {
			sessionDir = filepath.Join(sessionsDir, r.UUID)
		}
		if logPath := resolveSessionLogPath(sessionDir); logPath != "" {
			if fi, statErr := os.Stat(logPath); statErr == nil {
				row.logPath = logPath
				row.logSize = fi.Size()
				row.hasLog = true
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// resolveSessionLogPath returns the first existing log file within sessionDir,
// preferring runtime.log but falling back to the legacy run.log filename so
// older sessions still resolve.
func resolveSessionLogPath(sessionDir string) string {
	for _, name := range []string{config.RuntimeLogFilename, "run.log"} {
		candidate := filepath.Join(sessionDir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func runLogShow(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Zero args: behave like `vigolium log ls` — list sessions (or open the
	// TUI picker when --tui is set). Passing a UUID falls through to the
	// streaming path below.
	if len(args) == 0 {
		return runLogLs(cmd, args)
	}

	uuid := strings.TrimSpace(args[0])
	if uuid == "" {
		return errors.New("uuid argument is required")
	}

	return showLogForUUID(uuid, cmd.Flags().Changed("follow"))
}

// showLogForUUID resolves the log source for a UUID and streams it to stdout,
// following when the session is still running (unless followOverride is true,
// in which case the explicit --follow/no-follow flag value is honored).
func showLogForUUID(uuid string, followExplicit bool) error {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	src, err := resolveLogSource(uuid, settings)
	if err != nil {
		return err
	}

	// Auto-follow when the session is still running, unless the user explicitly
	// set --follow=false on the command line.
	follow := logFollow
	if !followExplicit && src.status == "running" {
		follow = true
	}

	printLogBanner(src, follow)

	if src.fromDB {
		return streamLogFromDB(src, follow)
	}
	return streamLogFile(src.filePath, follow)
}

// logSource describes where a log for a given UUID lives and whether the
// underlying scan/agent run is still active.
type logSource struct {
	kind     string // "native" or "agentic"
	status   string // run status from DB (running, completed, failed, ...)
	filePath string // absolute path to runtime.log (empty when fromDB)
	fromDB   bool   // true when falling back to scan_logs table
	scanUUID string // UUID used for DB queries
}

func (s *logSource) originLabel() string {
	if s.fromDB {
		return fmt.Sprintf("database (scan_logs for %s)", s.scanUUID)
	}
	return terminal.ShortenHome(s.filePath)
}

// resolveLogSource locates a log source for the given UUID. It prefers an
// on-disk runtime.log (native first, then agentic) and falls back to the
// scan_logs DB table for native scans where persist_logs was disabled. Also
// accepts the legacy run.log filename for backwards compatibility.
func resolveLogSource(uuid string, settings *config.Settings) (*logSource, error) {
	nativeDir := filepath.Join(settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), uuid)
	agenticDir := filepath.Join(settings.Agent.EffectiveSessionsDir(), uuid)
	nativeLog := resolveSessionLogPath(nativeDir)
	agenticLog := resolveSessionLogPath(agenticDir)

	db, dbErr := getDB()
	var repo *database.Repository
	ctx := context.Background()
	if dbErr == nil {
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			return nil, fmt.Errorf("failed to create schema: %w", schemaErr)
		}
		repo = database.NewRepository(db)
	}

	nativeStatus := func() string {
		if repo == nil {
			return ""
		}
		if scan, err := repo.GetScanByUUID(ctx, uuid); err == nil && scan != nil {
			return scan.Status
		}
		return ""
	}
	agenticStatus := func() string {
		if repo == nil {
			return ""
		}
		if run, err := repo.GetAgenticScan(ctx, uuid); err == nil && run != nil {
			return run.Status
		}
		return ""
	}

	if nativeLog != "" {
		return &logSource{kind: "native", status: nativeStatus(), filePath: nativeLog, scanUUID: uuid}, nil
	}
	if agenticLog != "" {
		return &logSource{kind: "agentic", status: agenticStatus(), filePath: agenticLog, scanUUID: uuid}, nil
	}

	// Neither convention path (~/.vigolium/agent-sessions/<uuid>/) has a
	// runtime.log. This is expected for nested archon children whose UUID
	// doesn't match any on-disk directory: their SessionDir column points
	// at the parent's session directory. Consult the DB row and retry.
	if repo != nil {
		if run, err := repo.GetAgenticScan(ctx, uuid); err == nil && run != nil && run.SessionDir != "" && run.SessionDir != agenticDir {
			if altLog := resolveSessionLogPath(run.SessionDir); altLog != "" {
				return &logSource{kind: "agentic", status: run.Status, filePath: altLog, scanUUID: uuid}, nil
			}
		}
	}

	// Expected-but-missing paths for error messages.
	expectedNative := filepath.Join(nativeDir, config.RuntimeLogFilename)
	expectedAgentic := filepath.Join(agenticDir, config.RuntimeLogFilename)

	// No file on disk — fall back to DB (native scans only).
	if dbErr != nil {
		return nil, fmt.Errorf("no log file found at %s or %s; database fallback unavailable: %w",
			terminal.ShortenHome(expectedNative), terminal.ShortenHome(expectedAgentic), dbErr)
	}
	if scan, err := repo.GetScanByUUID(ctx, uuid); err == nil && scan != nil {
		return &logSource{kind: "native", status: scan.Status, fromDB: true, scanUUID: uuid}, nil
	}
	if run, err := repo.GetAgenticScan(ctx, uuid); err == nil && run != nil {
		// Prefer the DB-stored SessionDir (handles custom paths), fall back
		// to the conventional location.
		sessionDir := run.SessionDir
		if sessionDir == "" {
			sessionDir = agenticDir
		}
		if _, statErr := os.Stat(sessionDir); os.IsNotExist(statErr) {
			return nil, fmt.Errorf("agent session %s: session directory %s does not exist on disk (may have been deleted)",
				uuid, terminal.ShortenHome(sessionDir))
		}
		// Directory exists but no runtime.log — most likely a session that
		// ran before runtime.log persistence was wired in. Stream was only
		// printed to the terminal; no recovery is possible.
		return nil, fmt.Errorf("agent session %s: no %s in %s — this session likely predates runtime.log support, so there is no log to replay",
			uuid, config.RuntimeLogFilename, terminal.ShortenHome(sessionDir))
	}
	return nil, fmt.Errorf("no scan or agent session found for uuid %s", uuid)
}

// printLogBanner prints a one-line header identifying the log source and mode.
func printLogBanner(src *logSource, follow bool) {
	mode := "reading"
	if follow {
		mode = "following"
	}
	status := src.status
	if status == "" {
		status = "unknown"
	}
	fmt.Fprintf(os.Stderr, "%s %s %s %s %s %s %s\n",
		terminal.InfoSymbol(),
		terminal.Gray(mode),
		terminal.Gray(src.kind+" log from"),
		terminal.HiCyan(src.originLabel()),
		terminal.Gray("—"),
		terminal.Gray("status:"),
		colorRunStatus(status),
	)
	if follow {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), terminal.Gray("(Ctrl+C to stop)"))
	}
}

// printPersistLogsTip nudges the user toward enabling persist_logs so the
// DB-contention path can be avoided for future scans.
func printPersistLogsTip() {
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n",
		terminal.TipPrefix(),
		terminal.Gray("set"),
		terminal.HiCyan("scanning_strategy.scan_logs.persist_logs: true"),
		terminal.Gray("to tail runtime.log directly and avoid DB contention"))
}

// streamLogFile prints the tail/full contents of a log file, optionally
// continuing to follow further writes until interrupted.
func streamLogFile(path string, follow bool) error {
	tailLines := logTailLines
	if logFull {
		tailLines = -1
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Seek to an approximate starting position for --tail N.
	startOffset := int64(0)
	if tailLines > 0 {
		startOffset = tailStartOffset(path, tailLines)
	}
	if startOffset > 0 {
		if _, seekErr := f.Seek(startOffset, io.SeekStart); seekErr != nil {
			return fmt.Errorf("failed to seek log file: %w", seekErr)
		}
	}

	writer := os.Stdout
	reader := bufio.NewReader(f)
	// Consume up through the first newline so we don't print a partial line
	// when we've seeked into the middle of one.
	if startOffset > 0 {
		_, _ = reader.ReadString('\n')
	}

	if err := copyLines(writer, reader); err != nil {
		return err
	}

	if !follow {
		return nil
	}

	// Follow mode: poll for new writes until interrupted.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			return nil
		case <-ticker.C:
			if err := copyLines(writer, reader); err != nil {
				return err
			}
		}
	}
}

// copyLines drains reader line-by-line to w, optionally stripping ANSI codes.
// Returns nil on transient EOF (so the caller can retry in follow mode).
func copyLines(w io.Writer, reader *bufio.Reader) error {
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			out := line
			if logStripANSI {
				out = terminal.StripANSI(out)
			}
			if _, werr := io.WriteString(w, out); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// tailStartOffset returns a byte offset into the file such that reading from
// it yields (approximately) the last `lines` lines. The caller is responsible
// for discarding the first partial line.
func tailStartOffset(path string, lines int) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return 0
	}
	size := fi.Size()

	const chunkSize = 8 * 1024
	var newlines int
	offset := size
	buf := make([]byte, chunkSize)
	for offset > 0 {
		readSize := int64(chunkSize)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize
		if _, err := f.ReadAt(buf[:readSize], offset); err != nil && !errors.Is(err, io.EOF) {
			return 0
		}
		for i := int(readSize) - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				newlines++
				// We want `lines` lines AFTER this newline.
				if newlines > lines {
					return offset + int64(i) + 1
				}
			}
		}
	}
	return 0
}

// isSQLiteBusy reports whether an error is a transient SQLITE_BUSY
// ("database is locked") from the sqlite driver — expected when a scan is
// actively writing to scan_logs while we poll it.
func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "database is locked") ||
		strings.Contains(s, "SQLITE_BUSY") ||
		strings.Contains(s, "(5)")
}

// fetchScanLogsRetry calls ListScanLogs, retrying on SQLITE_BUSY with a
// short backoff. Returns the first non-busy error.
func fetchScanLogsRetry(ctx context.Context, repo *database.Repository, scanUUID string, limit, offset int, attempts int) ([]*database.ScanLog, error) {
	backoff := 50 * time.Millisecond
	var lastErr error
	for i := 0; i < attempts; i++ {
		logs, _, err := repo.ListScanLogs(ctx, scanUUID, "", "", limit, offset)
		if err == nil {
			return logs, nil
		}
		if !isSQLiteBusy(err) {
			return nil, err
		}
		lastErr = err
		time.Sleep(backoff)
		if backoff < 500*time.Millisecond {
			backoff *= 2
		}
	}
	return nil, lastErr
}

// streamLogFromDB replays scan_logs entries to stdout in the same raw-text
// format as runtime.log, used as a fallback when persist_logs was disabled for a
// native scan. When follow is true it polls the scan_logs table for new rows
// appended after the initial snapshot until interrupted. Tolerates transient
// SQLITE_BUSY errors while the scan is still writing.
func streamLogFromDB(src *logSource, follow bool) error {
	tailLines := logTailLines
	if logFull {
		tailLines = -1
	}

	db, err := getDB()
	if err != nil {
		return err
	}
	ctx := context.Background()
	repo := database.NewRepository(db)

	// Tip: suggest enabling persist_logs so future runs tail a file instead
	// of polling the DB under contention.
	printPersistLogsTip()

	// Fetch initial snapshot, retrying on SQLITE_BUSY.
	const pageLimit = 10000
	logs, err := fetchScanLogsRetry(ctx, repo, src.scanUUID, pageLimit, 0, 10)
	if err != nil {
		if follow && isSQLiteBusy(err) {
			// Proceed with empty snapshot; follow loop will pick up rows later.
			logs = nil
		} else {
			return fmt.Errorf("failed to fetch scan logs: %w", err)
		}
	}
	totalSoFar := len(logs)
	if totalSoFar == 0 && !follow {
		return fmt.Errorf("no logs found in database for scan %s", src.scanUUID)
	}

	display := logs
	if tailLines > 0 && len(display) > tailLines {
		display = display[len(display)-tailLines:]
	}

	w := bufio.NewWriter(os.Stdout)
	for _, l := range display {
		writeDBLogLine(w, l)
	}
	_ = w.Flush()

	if !follow {
		return nil
	}

	// Follow mode: poll for new rows. ListScanLogs returns rows ordered by
	// created_at ASC, so offset-by-seen-count reliably yields only new entries.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			return nil
		case <-ticker.C:
			newLogs, _, fetchErr := repo.ListScanLogs(ctx, src.scanUUID, "", "", pageLimit, totalSoFar)
			if fetchErr != nil {
				// Transient lock while the scan writes — wait for next tick.
				if isSQLiteBusy(fetchErr) {
					continue
				}
				return fmt.Errorf("failed to fetch scan logs: %w", fetchErr)
			}
			if len(newLogs) == 0 {
				continue
			}
			for _, l := range newLogs {
				writeDBLogLine(w, l)
			}
			_ = w.Flush()
			totalSoFar += len(newLogs)
		}
	}
}

// writeDBLogLine formats a scan_logs row the same way for the initial snapshot
// and incremental follow updates.
func writeDBLogLine(w io.Writer, l *database.ScanLog) {
	ts := l.CreatedAt.Format("15:04:05.000")
	line := fmt.Sprintf("[%s] %-5s %s %s\n", ts, strings.ToUpper(l.Level), l.Phase, l.Message)
	if logStripANSI {
		line = terminal.StripANSI(line)
	}
	_, _ = io.WriteString(w, line)
}
