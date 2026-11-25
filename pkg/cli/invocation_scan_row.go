package cli

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/database"
)

// Scan-row names for the commands that store records without running a scan.
// One spelling each, so `db ls --table scans` groups them. The hand-sent
// savers (replay, fuzz, unlock-walk) name their row by their record source.
const (
	invocationScanIngest = "ingest"
	invocationScanImport = "import"
)

// invocationScanRow is the scans row a record-writing command that runs no
// scan (replay, fuzz --save, kit unlock-walk, ingest, a bridge import) stamps
// on every record it stores, so each stored record joins to a row carrying
// the invocation's caller tags (--caller-tag). The hand-sent savers create it
// on their first store, so one that stores nothing leaves no row; ingest and
// import create it before their store pass. It is built with
// database.NewSingleRequestScan and written already completed: the command's
// records are the whole of what the row stands for.
//
// --scan-uuid names the row instead of a fresh uuid; a row that already
// exists under it is reused, not overwritten.
type invocationScanRow struct {
	name string

	once sync.Once
	uuid string
}

// newInvocationScanRow prepares (without writing) the row for one command.
func newInvocationScanRow(name string) *invocationScanRow {
	return &invocationScanRow{name: name}
}

// ensure creates the row on first use and returns its uuid; target (the
// origin or input the command works on) names the row and is read only on
// that first call. A failed write warns and still returns the uuid: the
// records are worth storing, and the row is the part that is missing.
func (r *invocationScanRow) ensure(ctx context.Context, repo *database.Repository, projectUUID, target string) string {
	if r == nil || repo == nil {
		return ""
	}
	r.once.Do(func() {
		id := globalScanUUID
		if id == "" {
			id = uuid.New().String()
		}
		r.uuid = id
		rowCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if globalScanUUID != "" {
			if existing, err := repo.GetScanByUUID(rowCtx, id); err == nil && existing != nil {
				return
			}
		}
		row := database.NewSingleRequestScan(id, projectUUID, r.name, target, "", "cli")
		row.Status = "completed"
		row.FinishedAt = time.Now()
		row.Tags = callerTags
		if err := repo.CreateScan(rowCtx, row); err != nil {
			zap.L().Warn("Failed to create the invocation's scan row; its records carry a scan_uuid with no row",
				zap.String("scan_uuid", id), zap.String("command", r.name), zap.Error(err))
		}
	})
	return r.uuid
}
