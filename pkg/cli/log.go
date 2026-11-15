package cli

import (
	"bufio"
	"context"
	"database/sql"
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
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/cli/tui"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	logTailLines int
	logFull      bool
	logFollow    bool
	logStripANSI bool
	logRaw       bool
	logLsReap    bool
	logLsFrom    string
	logLsTo      string
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

Agentic scan logs are read from agent.sessions_dir/{uuid}/. Completed agentic
sessions render their Pi-style transcript (transcript.jsonl) as a conversation
replay — assistant prose, thinking, tool cards, and results — with long lines
truncated for the terminal. Pass --raw for the verbatim JSONL, or --follow to
tail the live runtime.log stream of a still-running session instead.

Pass --tui to open the interactive picker.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runLogShow,
}

var logLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List native scan and agentic scan sessions",
	Long: `Print every native scan and agentic scan session that has a stored log, sorted by most recent first. Each row shows the session UUID, kind, start time, and source — pass the UUID to 'vigolium log <uuid>' to view its log.

--reap cleans up after scans that died: every native scan row of the project
that still says "running" but is abandoned (nothing has written for 2 minutes,
or its process on this host is gone) is finalized as failed with
stop_reason "abandoned", and status.json heartbeat files older than
scanning_strategy.scan_logs.status_retention_days (default 30, 0 = keep) are
removed. --reap writes the store, so it is refused under --read-only and on a
-S/--glob-db read.`,
	Example: FormatExamples(
		"# Sessions, newest first, with liveness",
		"vigolium log ls -j",
		"# Finalize dead running rows and prune old status.json files",
		"vigolium log ls --reap",
	),
	RunE: runLogLs,
}

func init() {
	rootCmd.AddCommand(logCmd)
	logCmd.AddCommand(logLsCmd)

	logCmd.Flags().IntVarP(&logTailLines, "tail", "n", 200, "Show the last N lines (0 = none, -1 = all)")
	logCmd.Flags().BoolVar(&logFull, "full", false, "Show the full log (shortcut for --tail -1)")
	logCmd.Flags().BoolVarP(&logFollow, "follow", "f", false, "Follow log output as it is written (tail -f)")
	logCmd.Flags().BoolVar(&logStripANSI, "strip-ansi", false, "Strip ANSI color codes from output")
	logCmd.Flags().BoolVar(&logRaw, "raw", false, "For agentic sessions, print the raw transcript JSONL verbatim instead of the rendered replay")
	tui.AddFlags(logCmd, &logLsTUI, &logLsNoTUI)
	tui.AddFlags(logLsCmd, &logLsTUI, &logLsNoTUI)
	registerTimeRangeFlags(logLsCmd, &logLsFrom, &logLsTo, "sessions started")
	logLsCmd.Flags().BoolVar(&logLsReap, "reap", false, "Finalize abandoned running scan rows as failed (stop_reason abandoned) and prune expired status.json files; writes the store")
	registerRowShapingFlags(logLsCmd.Flags())
	registerTSVFlags(logLsCmd.Flags())
	registerInMemoryOffsetFlag(logLsCmd.Flags())
}

// logLsShaping is log ls' --fields vocabulary; --compact drops the liveness
// detail and the log path.
var logLsShaping = rowShaping{
	supported:   contract.JSONFieldNames(logRowView{}),
	compactDrop: []string{"liveness_sources", "log_path", "log_size", "has_log"},
	defaultTSV:  []string{"kind", "uuid", "effective_status", "target", "created_at"},
}

// logLsExtras are the top-level keys `log ls -j --reap` adds.
type logLsExtras struct {
	// Reaped lists the scan UUIDs this run finalized as abandoned.
	Reaped []string `json:"reaped,omitempty"`
	// StatusFilesRemoved counts the expired status.json files pruned.
	StatusFilesRemoved *int `json:"status_files_removed,omitempty"`
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
	// errorMessage is the row's error text, which tells a cancelled native scan
	// (stored failed with "cancelled") from a failed one.
	errorMessage string
	// liveness is the shared verdict (sessionLiveness) on whether a "running"
	// session is still writing.
	liveness Liveness
}

// stale reports whether a session the store still calls running has stopped
// writing. Always false for a terminal session: staleness only qualifies
// "running".
func (r sessionRow) stale() bool {
	return r.status == "running" && r.liveness.Stale
}

// logRowView is one `log ls -j` row. status is the stored value, unchanged for
// compatibility; effective_status is what to act on (abandoned when a running
// row is stale). last_write_at is null when no liveness signal exists.
type logRowView struct {
	Kind            string    `json:"kind"`
	UUID            string    `json:"uuid"`
	Status          string    `json:"status"`
	EffectiveStatus string    `json:"effective_status"`
	Stale           bool      `json:"stale"`
	LastWriteAt     *string   `json:"last_write_at"`
	LivenessSources []string  `json:"liveness_sources"`
	Target          string    `json:"target"`
	CreatedAt       time.Time `json:"created_at"`
	LogPath         string    `json:"log_path"`
	LogSize         int64     `json:"log_size"`
	HasLog          bool      `json:"has_log"`
}

func (r sessionRow) view() logRowView {
	sources := r.liveness.Sources
	if sources == nil {
		sources = []string{}
	}
	return logRowView{
		Kind:            r.kind,
		UUID:            r.uuid,
		Status:          r.status,
		EffectiveStatus: effectiveStatus(r.status, r.errorMessage, r.liveness),
		Stale:           r.stale(),
		LastWriteAt:     formatLivenessTime(r.liveness.LastWriteAt),
		LivenessSources: sources,
		Target:          r.target,
		CreatedAt:       r.createdAt,
		LogPath:         r.logPath,
		LogSize:         r.logSize,
		HasLog:          r.hasLog,
	}
}

// formatLivenessTime renders a liveness timestamp the way event lines do, nil
// for an unknown (zero) time.
func formatLivenessTime(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := scanevents.FormatTime(t)
	return &s
}

func runLogLs(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()
	readFormat, err := logLsShaping.prepare(cmd)
	if err != nil {
		return err
	}

	startedFrom, startedTo, err := parseDateRangeFlags(logLsFrom, logLsTo, timeFilterFromLabel, timeFilterToLabel)
	if err != nil {
		return err
	}
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	// openReadDB, not getDB: `vigolium log` is a read command, so a shell pinned
	// with $VIGOLIUM_DB_PATH (or an explicit -S --db) must reach that session's
	// database with project scoping off, exactly like finding/traffic. Reading
	// through getDB was what left `log` outside the pinning contract — and what
	// made -S an "unknown shorthand flag" there.
	//
	// Records:true because `log` reads scans, agentic_scans and scan_logs and
	// never touches http_records; under --glob-db that skip is the difference
	// between merging a session listing and copying every file's whole corpus.
	//
	// No CreateSchema: `log` opens the read pool (db_intent.go), whose opener
	// checks the schema with catalog reads and never takes the write lock — a
	// listing must not queue behind the scan it is listing.
	//
	// --reap writes (dbWriteFlags flips the intent), so it opens the shared
	// store itself: a -S/--glob-db read is a scratch copy nobody would see the
	// finalized rows in.
	var db *database.DB
	if logLsReap {
		if globalStateless || strings.TrimSpace(globalGlobDB) != "" {
			return usageErrorf("--reap finalizes rows in the store; it cannot run on a -S/--glob-db read")
		}
		db, err = getDB()
	} else {
		db, err = openReadDB(globDBSkipSet{Records: true})
	}
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	ctx := context.Background()
	repo := database.NewRepository(db)

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	sessionsDir := settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
	var extras *logLsExtras
	if logLsReap {
		reaped, reapErr := reapAbandonedScans(ctx, repo, projectUUID, sessionsDir)
		if reapErr != nil {
			return fmt.Errorf("reap abandoned scans: %w", reapErr)
		}
		removed, pruneErr := pruneSessionStatusForSettings(settings)
		if pruneErr != nil {
			zap.L().Warn("Some expired status.json files could not be removed", zap.Error(pruneErr))
		}
		extras = &logLsExtras{Reaped: reaped, StatusFilesRemoved: &removed}
		if !globalJSON && !globalSilent {
			fmt.Fprintf(os.Stderr, "%s Reaped %d abandoned scan(s); removed %d expired status file(s)\n",
				terminal.InfoSymbol(), len(reaped), removed)
		}
	}

	rows := collectNativeRows(ctx, repo, projectUUID, sessionsDir)
	rows = append(rows, collectAgenticRows(ctx, repo, projectUUID, settings.Agent.EffectiveSessionsDir())...)

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].createdAt.After(rows[j].createdAt)
	})
	rows = filterSessionRowsByTime(rows, startedFrom, startedTo)

	if active, tuiErr := tui.Active(logLsTUI, logLsNoTUI, globalJSON); tuiErr != nil {
		return tuiErr
	} else if active {
		if len(rows) == 0 {
			fmt.Printf("%s No scan or agent sessions found.\n", terminal.InfoSymbol())
			return nil
		}
		return pickLogLsTUI(rows)
	}

	if readFormat == "tsv" {
		out := make([]logRowView, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.view())
		}
		page, err := pageFromOffset(out, inMemoryOffset)
		if err != nil {
			return err
		}
		return logLsShaping.emitTSV(page)
	}

	if globalJSON {
		out := make([]logRowView, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.view())
		}
		// This used to emit a BARE ARRAY, the one -j surface that broke the
		// "parse .items" rule the envelope exists to establish. A contract with a
		// documented hole is one every consumer special-cases forever.
		page, err := pageFromOffset(out, inMemoryOffset)
		if err != nil {
			return err
		}
		items, err := logLsShaping.apply(page)
		if err != nil {
			return err
		}
		env := newMachineEnvelope(cmd, kindRead, "rows", items, int64(len(out)), inMemoryOffset, len(page))
		env.DBPath = resolvedReadDBPath()
		if extras != nil {
			if extras.Reaped == nil {
				extras.Reaped = []string{}
			}
			env.With("reaped", extras.Reaped).With("status_files_removed", *extras.StatusFilesRemoved)
		}
		if len(out) > 0 {
			env.WithQuery("log", rows[0].uuid)
		}
		return writeAgentJSON(env)
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
			sizeCol = clicommon.FormatFileSize(r.logSize)
		} else if r.kind == "agentic" {
			logCol = terminal.Gray("missing")
		}

		target := r.target
		if len(target) > 40 {
			target = target[:37] + "..."
		}

		statusCol := colorRunStatus(r.status)
		if r.stale() {
			statusCol += terminal.Gray(fmt.Sprintf(" (stale %s)", fmtStaleAge(r.liveness.LastWriteAt)))
		}

		tbl.AddRow(
			kindCol,
			terminal.Gray(r.uuid),
			statusCol,
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
	lastLogs := lastScanLogTimes(ctx, repo, scans)
	rows := make([]sessionRow, 0, len(scans))
	for _, s := range scans {
		row := sessionRow{
			kind:         "native",
			uuid:         s.UUID,
			status:       s.Status,
			target:       s.Target,
			createdAt:    s.StartedAt,
			errorMessage: s.ErrorMessage,
		}
		if logPath := resolveSessionLogPath(filepath.Join(sessionsDir, s.UUID)); logPath != "" {
			if fi, statErr := os.Stat(logPath); statErr == nil {
				row.logPath = logPath
				row.logSize = fi.Size()
				row.hasLog = true
			}
		}
		row.liveness = sessionLiveness(s, runner.SessionStatusPath(sessionsDir, s.UUID), row.logPath, lastLogs[s.UUID])
		rows = append(rows, row)
	}
	return rows
}

// lastScanLogTimes reads MAX(scan_logs.created_at) for every listed scan that
// still says running, in one GROUP BY. Terminal rows are left out on purpose:
// their liveness is moot, and scan_logs carries every trace line a scan ever
// wrote, so reading it for a whole listing costs a pass over the project's
// entire log history to answer a question nobody asked. A failed read is an
// absent signal, not an error: the listing still has the others.
func lastScanLogTimes(ctx context.Context, repo *database.Repository, scans []*database.Scan) map[string]time.Time {
	var uuids, projects []string
	seenProject := map[string]bool{}
	for _, s := range scans {
		if s == nil || s.Status != "running" {
			continue
		}
		uuids = append(uuids, s.UUID)
		if s.ProjectUUID != "" && !seenProject[s.ProjectUUID] {
			seenProject[s.ProjectUUID] = true
			projects = append(projects, s.ProjectUUID)
		}
	}
	if len(uuids) == 0 || repo == nil {
		return nil
	}
	out, err := repo.LastScanLogTimes(ctx, projects, uuids)
	if err != nil {
		return nil
	}
	return out
}

// agenticLiveness is the liveness of an agentic session, which has no
// heartbeat: its runtime.log and transcript are the only signals. The row's
// start time is deliberately not one — a long run that logs to the database
// only would read as abandoned two minutes after it began.
func agenticLiveness(logPath, transcriptPath string) Liveness {
	var newest time.Time
	for _, p := range []string{logPath, transcriptPath} {
		if p == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return livenessFromSignals(livenessSignals{logMTime: newest})
}

// fmtStaleAge renders how long ago a stale session last wrote ("14m"), or
// "unknown" when no signal ever wrote.
func fmtStaleAge(last time.Time) string {
	if last.IsZero() {
		return "no writes"
	}
	age := livenessNow().Sub(last).Round(time.Minute)
	if age < time.Minute {
		return "<1m"
	}
	return strings.TrimSuffix(age.String(), "0s")
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
		row.liveness = agenticLiveness(row.logPath, resolveTranscriptPath(sessionDir))
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
		return runLogLs(logLsCmd, args)
	}

	uuid := strings.TrimSpace(args[0])
	if uuid == "" {
		return usageErrorf("uuid argument is required")
	}
	uuid, err := resolveLogRef(uuid)
	if err != nil {
		return err
	}

	if globalJSON {
		return emitLogJSON(cmd, uuid)
	}
	return showLogForUUID(uuid, cmd.Flags().Changed("follow"))
}

// showLogForUUID resolves the log source for a UUID and streams it to stdout,
// following when the session is still running (unless followOverride is true,
// in which case the explicit --follow/no-follow flag value is honored).
func showLogForUUID(uuid string, followExplicit bool) error {
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	src, err := resolveLogSource(uuid, settings)
	if err != nil {
		return err
	}

	// Auto-follow when the session is still running — but only for an interactive
	// reader.
	//
	// A scan reaped by a deadline or SIGKILL leaves its row saying "running"
	// forever, so an omitted --follow used to park the read until the CALLER's
	// own timeout, on precisely the runs that already timed out. That turned a
	// bounded log read into a multi-minute stall on the sweeps that most needed
	// reading. Two gates fix it: a non-TTY stdout (a pipe — i.e. a program, which
	// wants the log and an exit) never auto-follows, and a row whose scan is no
	// longer live (sessionLiveness) is not treated as running even on a TTY.
	// An explicitly typed --follow still wins in both directions.
	follow := logFollow
	if !followExplicit && src.status == "running" && terminal.IsTerminal() && !globalJSON && !src.liveness.Stale {
		follow = true
	}

	// Agentic sessions render their Pi-style transcript as a conversation
	// replay by default (assistant prose, ⋈ thinking, ▶ tool cards, ✓/✗
	// results) — closest to what the operator saw live. `--raw` prints the
	// verbatim JSONL. Live follow stays on the runtime.log stream below, since
	// the transcript is flushed at turn boundaries and isn't meant for tailing.
	if src.transcriptPath != "" && !follow {
		printTranscriptBanner(src.transcriptPath, src.status, logRaw)
		if logRaw {
			return dumpFile(src.transcriptPath)
		}
		return renderTranscriptFile(src.transcriptPath)
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
	kind           string // "native" or "agentic"
	status         string // run status from DB (running, completed, failed, ...)
	filePath       string // absolute path to runtime.log (empty when fromDB)
	transcriptPath string // absolute path to transcript.jsonl (agentic only, "" when absent)
	fromDB         bool   // true when falling back to scan_logs table
	scanUUID       string // UUID used for DB queries
	// liveness says whether a "running" session is still writing. A status
	// column alone cannot — a process killed by a deadline or SIGKILL leaves it
	// saying running forever. Computed by sessionLiveness for every branch,
	// including the file-less DB fallback, which used to have no signal at all.
	liveness Liveness
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

	db, dbErr := openReadDB(globDBSkipSet{Records: true})
	var repo *database.Repository
	ctx := context.Background()
	if dbErr == nil {
		repo = database.NewRepository(db)
	}

	statusFile := runner.SessionStatusPath(settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), uuid)
	// nativeLiveness is the shared verdict for a native scan, with or without a
	// log file: the row's heartbeat, status.json, the log's mtime and the
	// newest scan_logs line all count.
	nativeLiveness := func(scan *database.Scan, logFile string) Liveness {
		var lastLog time.Time
		if repo != nil && scan != nil && scan.Status == "running" {
			lastLog = lastScanLogTimes(ctx, repo, []*database.Scan{scan})[uuid]
		}
		return sessionLiveness(scan, statusFile, logFile, lastLog)
	}
	nativeRow := func() *database.Scan {
		if repo == nil {
			return nil
		}
		if scan, err := repo.GetScanByUUID(ctx, uuid); err == nil && scan != nil {
			return scan
		}
		return nil
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
		scan := nativeRow()
		status := ""
		if scan != nil {
			status = scan.Status
		}
		return &logSource{kind: "native", status: status, liveness: nativeLiveness(scan, nativeLog), filePath: nativeLog, scanUUID: uuid}, nil
	}
	if agenticLog != "" {
		transcript := resolveTranscriptPath(agenticDir)
		return &logSource{kind: "agentic", status: agenticStatus(), liveness: agenticLiveness(agenticLog, transcript), filePath: agenticLog, transcriptPath: transcript, scanUUID: uuid}, nil
	}

	// Neither convention path (~/.vigolium/agent-sessions/<uuid>/) has a
	// runtime.log. This is expected for nested audit children whose UUID
	// doesn't match any on-disk directory: their SessionDir column points
	// at the parent's session directory. Consult the DB row and retry.
	if repo != nil {
		if run, err := repo.GetAgenticScan(ctx, uuid); err == nil && run != nil && run.SessionDir != "" && run.SessionDir != agenticDir {
			if altLog := resolveSessionLogPath(run.SessionDir); altLog != "" {
				transcript := resolveTranscriptPath(run.SessionDir)
				return &logSource{kind: "agentic", status: run.Status, liveness: agenticLiveness(altLog, transcript), filePath: altLog, transcriptPath: transcript, scanUUID: uuid}, nil
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
	if scan := nativeRow(); scan != nil {
		return &logSource{kind: "native", status: scan.Status, liveness: nativeLiveness(scan, ""), fromDB: true, scanUUID: uuid}, nil
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
		// WAF notices fire early, so the tail is the wrong end of the log for
		// them. Surface any that the window elided rather than requiring --full.
		printElidedNotices(path, startOffset)
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

// fetchScanLogsRetry calls ListScanLogs under database.RetryBusy: a scan that
// is writing scan_logs while we poll it can hold the lock past busy_timeout, and
// that is worth a short, bounded wait rather than an error. When the budget runs
// out the error is a *database.LockedError (database_locked).
func fetchScanLogsRetry(ctx context.Context, repo *database.Repository, scanUUID string, limit, offset int, attempts int) ([]*database.ScanLog, error) {
	var logs []*database.ScanLog
	err := database.RetryBusy(ctx, func() error {
		var err error
		logs, _, err = repo.ListScanLogs(ctx, scanUUID, "", "", limit, offset)
		return err
	}, database.RetryPolicy{
		Op:          "read scan logs",
		MaxAttempts: attempts,
		BaseDelay:   50 * time.Millisecond,
		MaxDelay:    500 * time.Millisecond,
	})
	return logs, err
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

	db, err := openReadDB(globDBSkipSet{Records: true})
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
		if follow && database.IsBusy(err) {
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
				if database.IsBusy(fetchErr) {
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

// filterSessionRowsByTime keeps the sessions that started within [from, to];
// a nil bound is open.
func filterSessionRowsByTime(rows []sessionRow, from, to *time.Time) []sessionRow {
	if from == nil && to == nil {
		return rows
	}
	kept := rows[:0]
	for _, r := range rows {
		if from != nil && r.createdAt.Before(*from) {
			continue
		}
		if to != nil && r.createdAt.After(*to) {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// logRefMinPrefix is the shortest UUID prefix `log <ref>` resolves, the same
// floor record references use.
const logRefMinPrefix = 8

// resolveLogRef turns a session UUID prefix of 8+ characters into the full
// UUID of the one native scan or agent run it names, in the project the read
// is scoped to. A full UUID, a shorter value, or a store that cannot be
// opened passes through unchanged for resolveLogSource to look up. No match
// also passes through: a session directory can exist without a row.
func resolveLogRef(ref string) (string, error) {
	if len(ref) >= 36 || len(ref) < logRefMinPrefix {
		return ref, nil
	}
	db, err := openReadDB(globDBSkipSet{Records: true})
	if err != nil {
		return ref, nil
	}
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return "", err
	}
	repo := database.NewRepository(db)
	ctx := context.Background()
	var matches []string
	for _, table := range []string{"scans", "agentic_scans"} {
		full, candidates, rerr := repo.ResolveUUIDPrefix(ctx, table, projectUUID, ref)
		switch {
		case errors.Is(rerr, sql.ErrNoRows):
		case rerr != nil:
			// A store without the agentic table still resolves native scans.
			continue
		case full != "":
			matches = append(matches, full)
		default:
			matches = append(matches, candidates...)
		}
	}
	switch len(matches) {
	case 0:
		return ref, nil
	case 1:
		return matches[0], nil
	}
	return "", clicommon.CLIError{
		Err:  fmt.Errorf("session reference %q is ambiguous: it prefixes %s", ref, strings.Join(matches, ", ")),
		Code: apicontract.CodeAmbiguousID,
		Hint: "Give more characters of the UUID (vigolium log ls lists them)",
	}
}
