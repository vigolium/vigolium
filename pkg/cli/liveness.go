package cli

import (
	"context"
	"os"
	"time"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/procutil"
)

// livenessStaleAfter is how long a "running" session may go without any write
// before it is treated as abandoned rather than live.
//
// Two minutes: a live scan beats every 10s (runner.HeartbeatInterval) and also
// writes phase lines, its log and findings continuously, so a live run is never
// silent this long, while a run killed by a deadline or SIGKILL is silent
// forever. Erring long is the safe direction — the cost of guessing "still
// running" on a live scan is nothing, and the cost of guessing it on a dead one
// is the unbounded stall this exists to prevent.
const livenessStaleAfter = 2 * time.Minute

// Liveness source names, as reported in liveness.sources / liveness_sources.
const (
	livenessSourceStatusFile = "status_file"
	livenessSourceLogFile    = "log_file"
	livenessSourceHeartbeat  = "db_heartbeat"
	livenessSourceScanLogs   = "scan_logs"
	livenessSourceRow        = "row_updated_at"
)

// Liveness is what every reader that asks "is this session still running?"
// gets: the newest write any signal shows, which signals contributed, and the
// verdict.
type Liveness struct {
	// LastWriteAt is the newest write across every signal; zero when there is
	// none.
	LastWriteAt time.Time
	// Sources names the signals that were present, newest-first is not implied.
	Sources []string
	// Stale: no signal has advanced within livenessStaleAfter, or the writing
	// process is confirmed gone. Only meaningful for a session whose status is
	// still "running".
	Stale bool
	// ProcessGone is set when the runner's PID could be checked — it ran on this
	// host — and says whether that process has exited. Nil when it could not be
	// checked (another host, or no PID recorded).
	ProcessGone *bool
}

// Seams for tests: a fake clock, a fixed hostname, a scripted PID check.
var (
	livenessNow      = time.Now
	livenessHostname = os.Hostname
	livenessPIDAlive = procutil.IsProcessAlive
)

// livenessSignals are the raw observations a liveness verdict is built from.
type livenessSignals struct {
	status       *runner.SessionStatus // parsed status.json, nil when absent
	statusMTime  time.Time             // status.json mtime, the fallback when its heartbeat_at is unset
	logMTime     time.Time             // runtime.log (or transcript) mtime
	heartbeatAt  time.Time             // scans.heartbeat_at
	rowUpdatedAt time.Time             // scans.updated_at (agentic: started_at)
	lastLogAt    time.Time             // MAX(scan_logs.created_at)
	pid          int
	host         string
}

// scanRowLiveness is sessionLiveness for one scan uuid: its row (may be nil),
// its status.json under sessionsDir, logFile ("" when there is none), and —
// while the row reads running and a repository is open — its newest
// scan_logs line. The single-scan readers (`log <uuid>`, `scan status`,
// --resume-scan's live-scan refusal) all set up the verdict here.
func scanRowLiveness(ctx context.Context, repo *database.Repository, row *database.Scan, sessionsDir, uuid, logFile string) Liveness {
	var lastLog time.Time
	if repo != nil && row != nil && row.Status == "running" {
		lastLog = lastScanLogTimes(ctx, repo, []*database.Scan{row})[uuid]
	}
	return sessionLiveness(row, runner.SessionStatusPath(sessionsDir, uuid), logFile, lastLog)
}

// sessionLiveness is the single liveness function: `log`, `log ls`, `scan
// status` and `scan wait` all decide "running vs abandoned" here, so none of
// them can disagree with another about the same scan.
//
// row may be nil (a -S or --db-isolate scan whose row is not in this store);
// statusFile and logFile may be "" or missing; lastLogAt is the newest
// scan_logs line, zero when unknown.
func sessionLiveness(row *database.Scan, statusFile, logFile string, lastLogAt time.Time) Liveness {
	sig := livenessSignals{lastLogAt: lastLogAt}
	if statusFile != "" {
		if st, err := runner.ReadSessionStatus(statusFile); err == nil && st != nil {
			sig.status = st
			if info, statErr := os.Stat(statusFile); statErr == nil {
				sig.statusMTime = info.ModTime()
			}
		}
	}
	if logFile != "" {
		if info, err := os.Stat(logFile); err == nil {
			sig.logMTime = info.ModTime()
		}
	}
	if row != nil {
		if row.HeartbeatAt != nil {
			sig.heartbeatAt = *row.HeartbeatAt
		}
		sig.rowUpdatedAt = row.UpdatedAt
		sig.pid, sig.host = row.PID, row.RunnerHost
	}
	return livenessFromSignals(sig)
}

// livenessFromSignals is sessionLiveness without the I/O.
func livenessFromSignals(sig livenessSignals) Liveness {
	var lv Liveness
	consider := func(t time.Time, source string) {
		if t.IsZero() {
			return
		}
		lv.Sources = append(lv.Sources, source)
		if t.After(lv.LastWriteAt) {
			lv.LastWriteAt = t
		}
	}

	pid, host := sig.pid, sig.host
	if st := sig.status; st != nil {
		beat := st.HeartbeatAt
		if beat.IsZero() {
			beat = sig.statusMTime
		}
		consider(beat, livenessSourceStatusFile)
		if pid == 0 {
			pid, host = st.PID, st.Host
		}
	}
	consider(sig.logMTime, livenessSourceLogFile)
	consider(sig.heartbeatAt, livenessSourceHeartbeat)
	consider(sig.lastLogAt, livenessSourceScanLogs)
	consider(sig.rowUpdatedAt, livenessSourceRow)

	if !lv.LastWriteAt.IsZero() && livenessNow().Sub(lv.LastWriteAt) > livenessStaleAfter {
		lv.Stale = true
	}

	// Same host and a recorded PID: ask the OS. A dead process is dead now —
	// there is no reason to wait out the staleness window for it. A live PID
	// proves nothing (it may have been reused), so it never clears staleness.
	if pid > 0 && host != "" {
		if self, err := livenessHostname(); err == nil && self == host {
			gone := !livenessPIDAlive(pid)
			lv.ProcessGone = &gone
			if gone {
				lv.Stale = true
			}
		}
	}
	return lv
}

// effectiveStatus is the status a consumer should act on: the stored one,
// except that a "running" session whose liveness says it stopped is
// "abandoned", and a failed row whose error is the runner's cancellation
// marker is "cancelled".
func effectiveStatus(status, errorMessage string, lv Liveness) string {
	switch status {
	case "running", "":
		if status == "running" && lv.Stale {
			return "abandoned"
		}
		return status
	case "failed":
		if errorMessage == "cancelled" {
			return "cancelled"
		}
	}
	return status
}
