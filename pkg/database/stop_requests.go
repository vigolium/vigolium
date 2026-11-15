package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// A stop request is how one process asks another to end a run it does not own.
//
// Signalling a recorded pid is not safe: a scan the server runs records the
// server's pid, and pids are reused once a process exits. The request is
// instead a column on the run's own row that the running process polls (the
// native heartbeat for scans, a cancel watcher for agent runs) and acts on by
// cancelling its own context. The columns are deliberately not on the bun
// models: whole-model updates (UpdateAgenticScan, OmitZero saves) would
// otherwise write them back from a stale in-memory copy.

// ScanStopRequest is a pending stop request on a scan row.
type ScanStopRequest struct {
	At time.Time
	By string
}

// RequestScanStop records a stop request on a running scan. Only a row still
// "running" is touched, and an earlier request is kept (the first asker and
// time stand). requested reports whether the row is running and now carries a
// request, either this one or an earlier one.
func (r *Repository) RequestScanStop(ctx context.Context, scanUUID, by string) (requested bool, err error) {
	by = strings.TrimSpace(by)
	if by == "" {
		by = "unknown"
	}
	if _, err := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("stop_requested_at = ?", time.Now().UTC()).
		Set("stop_requested_by = ?", by).
		Where("uuid = ?", scanUUID).
		Where("status = ?", "running").
		Where("stop_requested_at IS NULL").
		Exec(ctx); err != nil {
		return false, err
	}
	req, status, err := r.scanStopState(ctx, scanUUID)
	if err != nil {
		return false, err
	}
	return status == "running" && req != nil, nil
}

// ScanStopRequested returns the pending stop request on a scan, nil when none
// was made (or the row does not exist).
func (r *Repository) ScanStopRequested(ctx context.Context, scanUUID string) (*ScanStopRequest, error) {
	req, _, err := r.scanStopState(ctx, scanUUID)
	return req, err
}

func (r *Repository) scanStopState(ctx context.Context, scanUUID string) (*ScanStopRequest, string, error) {
	var row struct {
		Status string     `bun:"status"`
		At     *time.Time `bun:"stop_requested_at"`
		By     *string    `bun:"stop_requested_by"`
	}
	err := r.db.NewSelect().
		TableExpr("scans").
		ColumnExpr("status, stop_requested_at, stop_requested_by").
		Where("uuid = ?", scanUUID).
		Limit(1).
		Scan(ctx, &row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", nil
		}
		return nil, "", err
	}
	if row.At == nil || row.At.IsZero() {
		return nil, row.Status, nil
	}
	req := &ScanStopRequest{At: *row.At}
	if row.By != nil {
		req.By = *row.By
	}
	return req, row.Status, nil
}

// RequestAgenticScanCancel records a cancel request on an agent run that has
// not finished. requested reports whether the run is still live and now
// carries a request (this one or an earlier one); status is the run's stored
// status ("" when there is no such run).
func (r *Repository) RequestAgenticScanCancel(ctx context.Context, runUUID string) (requested bool, status string, err error) {
	if _, err := r.db.NewUpdate().
		TableExpr("agentic_scans").
		Set("cancel_requested_at = ?", time.Now().UTC()).
		Where("uuid = ?", runUUID).
		Where("status NOT IN (?)", bun.List(TerminalAgenticScanStatuses)).
		Where("cancel_requested_at IS NULL").
		Exec(ctx); err != nil {
		return false, "", err
	}
	var row struct {
		Status string     `bun:"status"`
		At     *time.Time `bun:"cancel_requested_at"`
	}
	err = r.db.NewSelect().
		TableExpr("agentic_scans").
		ColumnExpr("status, cancel_requested_at").
		Where("uuid = ?", runUUID).
		Limit(1).
		Scan(ctx, &row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	return !IsTerminalAgenticScanStatus(row.Status) && row.At != nil && !row.At.IsZero(), row.Status, nil
}

// AgenticScanCancelRequested reports whether a cancel request is pending on
// an agent run. A missing row is false.
func (r *Repository) AgenticScanCancelRequested(ctx context.Context, runUUID string) (bool, error) {
	var at *time.Time
	err := r.db.NewSelect().
		TableExpr("agentic_scans").
		ColumnExpr("cancel_requested_at").
		Where("uuid = ?", runUUID).
		Limit(1).
		Scan(ctx, &at)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return at != nil && !at.IsZero(), nil
}
