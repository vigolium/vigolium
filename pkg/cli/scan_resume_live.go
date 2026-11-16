package cli

import (
	"context"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// refuseResumeOfLiveScan refuses --resume-scan <uuid> while the scan's own
// process is still writing it (scan_running): two processes advancing one
// row's cursor and coverage ledger corrupt both. "Still writing" is the shared
// liveness verdict (sessionLiveness), so a row left `running` by a process
// that died is resumable once it reads abandoned (the process is gone, or no
// signal advanced for livenessStaleAfter). --force does not lift this. A
// missing row is left to the runner, which refuses it as scan_not_found.
func refuseResumeOfLiveScan(ctx context.Context, repo *database.Repository, settings *config.Settings, uuid string) error {
	if uuid == "" || repo == nil {
		return nil
	}
	row, err := repo.GetScanByUUID(ctx, uuid)
	if err != nil || row == nil || row.Status != "running" {
		return nil
	}
	sessionsDir := settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
	lv := scanRowLiveness(ctx, repo, row, sessionsDir, uuid, resolveSessionLogPath(filepath.Join(sessionsDir, uuid)))
	if lv.Stale {
		return nil
	}
	last := "unknown"
	if !lv.LastWriteAt.IsZero() {
		last = lv.LastWriteAt.UTC().Format(time.RFC3339)
	}
	return codedErrorf(apicontract.CodeScanRunning,
		"--resume-scan %s: the scan is still running (last write %s); wait for it (vigolium scan wait %s) or stop it (vigolium scan stop %s) first",
		uuid, last, uuid, uuid)
}
