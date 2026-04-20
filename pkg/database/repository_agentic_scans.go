package database

import (
	"context"
	"fmt"
	"time"
)

// CreateAgenticScan stores a new agent run record.
func (r *Repository) CreateAgenticScan(ctx context.Context, run *AgenticScan) error {
	run.ProjectUUID = defaultProjectUUID(run.ProjectUUID)
	if _, err := r.db.NewInsert().Model(run).Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert agent run: %w", err)
	}
	return nil
}

// GetAgenticScan retrieves an agent run by UUID.
func (r *Repository) GetAgenticScan(ctx context.Context, uuid string) (*AgenticScan, error) {
	run := &AgenticScan{}
	err := r.db.NewSelect().Model(run).Where("uuid = ?", uuid).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent run not found: %w", err)
	}
	return run, nil
}

// UpdateAgenticScan updates an agent run record (full update by UUID).
func (r *Repository) UpdateAgenticScan(ctx context.Context, run *AgenticScan) error {
	_, err := r.db.NewUpdate().Model(run).Where("uuid = ?", run.UUID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update agent run: %w", err)
	}
	return nil
}

// UpdateAgenticScanStorageURL sets the storage_url field on an agentic scan record.
func (r *Repository) UpdateAgenticScanStorageURL(ctx context.Context, runUUID, storageURL string) error {
	_, err := r.db.NewUpdate().Model((*AgenticScan)(nil)).
		Set("storage_url = ?", storageURL).
		Where("uuid = ?", runUUID).
		Exec(ctx)
	return err
}

// ListAgenticScans returns paginated agent runs for a project, ordered by created_at DESC.
func (r *Repository) ListAgenticScans(ctx context.Context, projectUUID string, mode string, limit, offset int) ([]*AgenticScan, int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)
	if limit <= 0 {
		limit = 50
	}

	countQ := r.db.NewSelect().Model((*AgenticScan)(nil)).
		Where("project_uuid = ?", projectUUID).
		Where("(parent_run_uuid IS NULL OR parent_run_uuid = '')")
	if mode != "" {
		countQ = countQ.Where("mode = ?", mode)
	}
	total, countErr := countQ.Count(ctx)

	var runs []*AgenticScan
	q := r.db.NewSelect().Model(&runs).
		Where("project_uuid = ?", projectUUID).
		Where("(parent_run_uuid IS NULL OR parent_run_uuid = '')").
		OrderExpr("created_at DESC").
		Limit(limit).
		Offset(offset)

	if mode != "" {
		q = q.Where("mode = ?", mode)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to list agent runs: %w", err)
	}
	if countErr != nil {
		total = len(runs)
	}
	return runs, int64(total), nil
}

// GetChildAgenticScans returns agent runs whose ParentRunUUID matches the given UUID.
func (r *Repository) GetChildAgenticScans(ctx context.Context, parentUUID string) ([]*AgenticScan, error) {
	var runs []*AgenticScan
	err := r.db.NewSelect().Model(&runs).
		Where("parent_run_uuid = ?", parentUUID).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get child agent runs: %w", err)
	}
	return runs, nil
}

// DeleteOldAgenticScans removes completed/failed agent runs older than the given duration.
func (r *Repository) DeleteOldAgenticScans(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	res, err := r.db.NewDelete().Model((*AgenticScan)(nil)).
		Where("status IN (?, ?)", "completed", "failed").
		Where("completed_at < ?", cutoff).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old agent runs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
