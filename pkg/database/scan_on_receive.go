package database

import (
	"context"
	"database/sql"
	"errors"
)

// LatestScanOnReceiveScan returns the project's newest scan-on-receive row
// still running (the runner that will pick up records ingested now), nil
// when none is.
func (r *Repository) LatestScanOnReceiveScan(ctx context.Context, projectUUID string) (*Scan, error) {
	var s Scan
	err := r.db.NewSelect().
		Model(&s).
		Column("uuid", "project_uuid", "status", "cursor_at", "cursor_uuid", "processed_count", "started_at").
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("scan_source = ?", ScanSourceScanOnReceive).
		Where("status = ?", "running").
		OrderExpr("created_at DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}
