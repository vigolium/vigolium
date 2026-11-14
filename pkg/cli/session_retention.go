package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// Retention of the per-scan status.json heartbeat files, and the reaper that
// finalizes "running" rows whose process is gone.
//
// Every native scan writes {sessions_dir}/{uuid}/status.json, whether or not
// persist_logs is on, so the directory grows by one file per scan forever
// unless something prunes it. Nothing else in a session directory is touched:
// runtime.log is the operator's (persist_logs), and a directory is removed only
// when pruning its status.json left it empty.

// pruneSessionStatusFiles removes every status.json under sessionsDir whose last
// write is older than maxAge: a scan that finished (or died) that long ago. The
// last write is the newer of the file's heartbeat_at and its mtime, so a file
// whose content cannot be parsed still ages out, and a live scan (which
// rewrites the file every 10s) never qualifies. maxAge <= 0 prunes nothing.
//
// A missing sessions directory is not an error. Per-file failures are skipped
// (the next prune retries them); the first one is returned with the count of
// files that were removed.
func pruneSessionStatusFiles(sessionsDir string, maxAge time.Duration, now time.Time) (removed int, err error) {
	if maxAge <= 0 || sessionsDir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var firstErr error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := runner.SessionStatusPath(sessionsDir, e.Name())
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue
		}
		last := info.ModTime()
		if st, readErr := runner.ReadSessionStatus(path); readErr == nil && st != nil && st.HeartbeatAt.After(last) {
			last = st.HeartbeatAt
		}
		if now.Sub(last) <= maxAge {
			continue
		}
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			if firstErr == nil {
				firstErr = rmErr
			}
			continue
		}
		removed++
		// Only succeeds when the status file was all the directory held.
		_ = os.Remove(filepath.Dir(path))
	}
	return removed, firstErr
}

// pruneSessionStatusForSettings prunes the configured sessions directory with
// the configured retention (scanning_strategy.scan_logs.status_retention_days).
func pruneSessionStatusForSettings(settings *config.Settings) (int, error) {
	if settings == nil {
		return 0, nil
	}
	logs := settings.ScanningStrategy.ScanLogs
	return pruneSessionStatusFiles(logs.EffectiveSessionsDir(), logs.StatusRetention(), livenessNow())
}

// pruneSessionStatusInBackground runs the status.json retention once, off the
// caller's path: server start must not wait on a directory walk.
func pruneSessionStatusInBackground(settings *config.Settings) {
	go func() {
		n, err := pruneSessionStatusForSettings(settings)
		if err != nil {
			zap.L().Debug("status.json retention: some files could not be removed", zap.Int("removed", n), zap.Error(err))
			return
		}
		if n > 0 {
			zap.L().Info("Pruned expired native-scan status files", zap.Int("removed", n))
		}
	}()
}

// reapAbandonedScans finalizes every "running" scan row in projectUUID whose
// liveness says its process is gone (effective_status abandoned, the same
// verdict `log ls` and `scan status` show): status failed, stop_reason
// abandoned. It returns the UUIDs it reaped. A row the reaper cannot read the
// liveness of is left alone; a row that finalized in the meantime is skipped by
// the write itself.
func reapAbandonedScans(ctx context.Context, repo *database.Repository, projectUUID, sessionsDir string) ([]string, error) {
	running, err := repo.ListRunningScans(ctx, projectUUID)
	if err != nil {
		return nil, err
	}
	lastLogs := lastScanLogTimes(ctx, repo, running)
	reaped := []string{}
	for _, s := range running {
		logFile := resolveSessionLogPath(filepath.Join(sessionsDir, s.UUID))
		lv := sessionLiveness(s, runner.SessionStatusPath(sessionsDir, s.UUID), logFile, lastLogs[s.UUID])
		if effectiveStatus(s.Status, s.ErrorMessage, lv) != effStatusAbandoned {
			continue
		}
		ok, err := repo.ReapAbandonedScan(ctx, s, lv.LastWriteAt)
		if err != nil {
			return reaped, err
		}
		if ok {
			reaped = append(reaped, s.UUID)
		}
	}
	return reaped, nil
}

// abandonedReapInterval is how often a running server reaps abandoned scan
// rows. A crashed scan otherwise stays "running" in every project listing
// until someone runs `log ls --reap`.
const abandonedReapInterval = 5 * time.Minute

// reapAllProjects reaps abandoned scans in every project (the same verdict as
// `log ls --reap`) and returns how many rows it finalized.
func reapAllProjects(ctx context.Context, repo *database.Repository, sessionsDir string) int {
	if repo == nil {
		return 0
	}
	projects, err := repo.ListProjects(ctx, "")
	if err != nil {
		zap.L().Debug("abandoned-scan reaper: cannot list projects", zap.Error(err))
		return 0
	}
	// The default project always: scans land in it even on a store whose
	// projects table was never seeded.
	uuids := []string{database.DefaultProjectUUID}
	for _, p := range projects {
		if p.UUID != database.DefaultProjectUUID {
			uuids = append(uuids, p.UUID)
		}
	}
	total := 0
	for _, uuid := range uuids {
		reaped, err := reapAbandonedScans(ctx, repo, uuid, sessionsDir)
		if err != nil {
			zap.L().Debug("abandoned-scan reaper: project failed", zap.String("project", uuid), zap.Error(err))
		}
		if len(reaped) > 0 {
			zap.L().Info("Reaped abandoned scans", zap.String("project", uuid), zap.Strings("scans", reaped))
		}
		total += len(reaped)
	}
	return total
}

// startAbandonedScanReaper runs reapAllProjects now and every interval until
// stop is called. Each pass is bounded so a slow store cannot pile passes up.
func startAbandonedScanReaper(repo *database.Repository, sessionsDir string, interval time.Duration) (stop func()) {
	if repo == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			passCtx, passCancel := context.WithTimeout(ctx, time.Minute)
			reapAllProjects(passCtx, repo, sessionsDir)
			passCancel()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// reapOwnProjectAtScanStart finalizes the abandoned scans of the project a new
// scan is about to write into, so the new run's listings and diffs do not sit
// next to a crashed predecessor still claiming to run. Best-effort and bounded.
func reapOwnProjectAtScanStart(repo *database.Repository, settings *config.Settings, projectUUID string) {
	if repo == nil || settings == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sessionsDir := settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
	if reaped, err := reapAbandonedScans(ctx, repo, projectUUID, sessionsDir); err == nil && len(reaped) > 0 {
		zap.L().Info("Reaped abandoned scans before starting", zap.Strings("scans", reaped))
	}
}
