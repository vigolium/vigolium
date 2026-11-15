package database

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// CreateAgenticScan stores a new agent run record. When a row with run.UUID
// already exists, the call is a no-op as long as the existing project_uuid
// matches — this is the get-or-create path used for cross-node sync via
// --scan-uuid. Returns ErrScanProjectMismatch when the existing row belongs
// to a different project.
func (r *Repository) CreateAgenticScan(ctx context.Context, run *AgenticScan) error {
	run.ProjectUUID = defaultProjectUUID(run.ProjectUUID)
	res, err := r.db.NewInsert().Model(run).On("CONFLICT (uuid) DO NOTHING").Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to insert agent run: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 && run.UUID != "" {
		existing := &AgenticScan{}
		if getErr := r.db.NewSelect().Model(existing).Where("uuid = ?", run.UUID).Scan(ctx); getErr == nil {
			if existing.ProjectUUID != run.ProjectUUID {
				return fmt.Errorf("%w: agentic scan %s belongs to project %s, not %s",
					ErrScanProjectMismatch, run.UUID, existing.ProjectUUID, run.ProjectUUID)
			}
		}
	}
	return nil
}

// AttributeScanToAgenticScan links a native scan (and every finding it
// produced) to the agentic scan that launched it. The run_native_scan tool calls this
// after a blocking LaunchScan returns, so the child scan's findings show up
// under `finding --agentic-scan <parent>` — which filters on
// finding.agentic_scan_uuid directly rather than joining through scans. Both
// the scan row and its findings are stamped; a no-op when either UUID is empty.
func (r *Repository) AttributeScanToAgenticScan(ctx context.Context, scanUUID, agenticScanUUID string) error {
	if scanUUID == "" || agenticScanUUID == "" {
		return nil
	}
	if _, err := r.db.NewUpdate().Model((*Scan)(nil)).
		Set("agentic_scan_uuid = ?", agenticScanUUID).
		Where("uuid = ?", scanUUID).
		Exec(ctx); err != nil {
		return fmt.Errorf("attribute scan %s to agentic scan %s: %w", scanUUID, agenticScanUUID, err)
	}
	if _, err := r.db.NewUpdate().Model((*Finding)(nil)).
		Set("agentic_scan_uuid = ?", agenticScanUUID).
		Where("scan_uuid = ?", scanUUID).
		Exec(ctx); err != nil {
		return fmt.Errorf("attribute findings of scan %s to agentic scan %s: %w", scanUUID, agenticScanUUID, err)
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

// UpdateAgenticScan updates an agent run record by UUID. Uses OmitZero so
// callers (SwarmRunner.Run and the API enrichAgenticScanRecord helpers) can
// pass partial structs without zeroing fields they don't intend to touch.
// To explicitly clear a field, use a column-list update via NewUpdate().
func (r *Repository) UpdateAgenticScan(ctx context.Context, run *AgenticScan) error {
	_, err := r.db.NewUpdate().Model(run).OmitZero().Where("uuid = ?", run.UUID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update agent run: %w", err)
	}
	return nil
}

// agenticScanBlobColumns are the agentic_scans columns holding uncapped
// JSON/text blobs — a single autopilot run's result_json is routinely
// megabytes. A list of 100 runs otherwise transfers, allocates and
// deserializes all of them so the handler can throw them away building a DTO
// of counters and timestamps. Mirrors recordBodyColumns / findingBodyColumns.
//
// Stated as an exclusion rather than as the complementary include list on
// purpose: the model has 40-odd columns, so an include list has to be updated
// for every column added or that column silently reads back as its zero value
// in every list view, with no compile-time or test signal.
var agenticScanBlobColumns = []string{
	"input_raw", "prompt_sent", "agent_raw_output",
	"attack_plan", "triage_result", "result_json",
}

// ListAgenticScanSummaries is ListAgenticScans with agenticScanBlobColumns
// dropped — same rows, same order, same total. Use it for any view that
// renders a run rather than replaying it; the omitted fields come back empty,
// so a caller that serializes the *AgenticScan verbatim (the `--json` CLI
// paths) must keep using ListAgenticScans.
func (r *Repository) ListAgenticScanSummaries(ctx context.Context, projectUUID string, mode string, limit, offset int) ([]*AgenticScan, int64, error) {
	return r.listAgenticScans(ctx, projectUUID, mode, nil, nil, limit, offset, agenticScanBlobColumns)
}

// AgenticScanStatusByUUID returns just the status column for a run.
//
// It exists for the SSE log follower, which asks "is this run finished yet?"
// twice a second for as long as a client watches: doing that through
// GetAgenticScan reads the run's full row — blobs included — so N followers on
// a finished-but-still-watched autopilot run pull 2N megabyte-scale reads per
// second out of the database to learn one short string.
func (r *Repository) AgenticScanStatusByUUID(ctx context.Context, uuid string) (string, error) {
	var status string
	err := r.db.NewSelect().
		Model((*AgenticScan)(nil)).
		Column("status").
		Where("uuid = ?", uuid).
		Scan(ctx, &status)
	if err != nil {
		return "", fmt.Errorf("agent run not found: %w", err)
	}
	return status, nil
}

// UpdateAgenticScanStorageURL sets the storage_url field on an agentic scan record.
func (r *Repository) UpdateAgenticScanStorageURL(ctx context.Context, agenticScanUUID, storageURL string) error {
	_, err := r.db.NewUpdate().Model((*AgenticScan)(nil)).
		Set("storage_url = ?", storageURL).
		Where("uuid = ?", agenticScanUUID).
		Exec(ctx)
	return err
}

// ListAgenticScans returns paginated agent runs for a project, ordered by
// created_at DESC, with every column populated. Callers that only render the
// run should prefer ListAgenticScanSummaries.
func (r *Repository) ListAgenticScans(ctx context.Context, projectUUID string, mode string, limit, offset int) ([]*AgenticScan, int64, error) {
	return r.listAgenticScans(ctx, projectUUID, mode, nil, nil, limit, offset, nil)
}

// ListAgenticScansCreatedBetween is ListAgenticScans restricted to runs
// created within [from, to]; a nil bound is open.
func (r *Repository) ListAgenticScansCreatedBetween(ctx context.Context, projectUUID string, from, to *time.Time, limit int) ([]*AgenticScan, error) {
	runs, _, err := r.listAgenticScans(ctx, projectUUID, "", from, to, limit, 0, nil)
	return runs, err
}

// listAgenticScans backs the list variants. A nil exclude slice selects every
// column; otherwise the named ones are left out. A nil from/to bound on
// created_at is open.
func (r *Repository) listAgenticScans(ctx context.Context, projectUUID, mode string, from, to *time.Time, limit, offset int, exclude []string) ([]*AgenticScan, int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)
	if limit <= 0 {
		limit = 50
	}

	filter := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("project_uuid = ?", projectUUID).
			Where("(parent_run_uuid IS NULL OR parent_run_uuid = '')")
		if mode != "" {
			q = q.Where("mode = ?", mode)
		}
		if from != nil {
			q = q.Where("created_at >= ?", *from)
		}
		if to != nil {
			q = q.Where("created_at <= ?", *to)
		}
		return q
	}
	total, countErr := filter(r.db.NewSelect().Model((*AgenticScan)(nil))).Count(ctx)

	var runs []*AgenticScan
	q := filter(r.db.NewSelect().Model(&runs)).
		OrderExpr("created_at DESC").
		Limit(int64(limit)).
		Offset(int64(offset))
	if len(exclude) > 0 {
		q = q.ExcludeColumn(exclude...)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to list agent runs: %w", err)
	}
	if countErr != nil {
		total = int64(len(runs))
	}
	return runs, total, nil
}

// GetChildAgenticScans returns agent runs whose ParentAgenticScanUUID matches the given UUID.
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

// TerminalAgenticScanStatuses is the authoritative set of agentic_scans.status
// values meaning the run has finished. Two subsystems must agree on it — the
// SSE log follower, which tails runtime.log until the run is terminal, and the
// retention sweep below, which only deletes finished runs — and a status
// present in one and absent from the other is either a stream that never ends
// or a row that is never cleaned. Both were true of "completed_with_errors",
// what a multi-driver audit writes when one leg fails: following its log spun
// until the two-hour cap and its row outlived every retention window. Add new
// terminal statuses here, not at either call site.
var TerminalAgenticScanStatuses = []string{
	"completed",
	"completed_with_errors",
	"completed_with_warnings",
	"failed",
	"cancelled",
	"timeout",
	"budget_exhausted",
	"error",
}

// CompletedAgenticScanStatuses are the terminal statuses of a run that ran to
// the end: cleanly, degraded, or with some drivers failed. Code that means
// "finished successfully" should match this set, not the literal "completed",
// or degraded runs silently drop out.
var CompletedAgenticScanStatuses = []string{
	"completed",
	"completed_with_warnings",
	"completed_with_errors",
}

// CompletedAgenticScanStatus is the status of a run that finished without an
// error. A degraded run (audit failed to start, discovery failed, the model
// never called a tool...) is "completed_with_warnings", so it can be told
// apart from a clean pass. Every writer - server handlers, the CLI finalizers,
// the swarm runner - goes through here so one outcome gets one status.
func CompletedAgenticScanStatus(degraded bool) string {
	if degraded {
		return "completed_with_warnings"
	}
	return "completed"
}

// Agentic-run statuses beyond the completed set. "timeout" and
// "budget_exhausted" are runs that ran but stopped at a limit (the CLI exits 5
// for them); "cancelled" is an interrupt; "failed" an error.
const (
	AgenticScanStatusTimeout         = "timeout"
	AgenticScanStatusBudgetExhausted = "budget_exhausted"
	AgenticScanStatusCancelled       = "cancelled"
	AgenticScanStatusFailed          = "failed"
)

// AgenticRunEnd describes how an agentic run ended, for AgenticRunStatus.
type AgenticRunEnd struct {
	// Err is the run's error, nil on a clean finish. A time or budget stop
	// still counts as that stop when Err is set: the loop often reports the
	// cancellation it caused as an error.
	Err error
	// TimedOut: the wall-clock budget (--max-duration) fired.
	TimedOut bool
	// BudgetExhausted: a command, token or cost budget fired.
	BudgetExhausted bool
	// Cancelled: an interrupt (Ctrl-C, SIGTERM) stopped the run.
	Cancelled bool
	// Degraded: the run finished but with warnings (see CompletedAgenticScanStatus).
	Degraded bool
	// FailedDrivers/TotalDrivers: a multi-driver run (audit), see
	// MultiDriverAgenticScanStatus. Zero TotalDrivers means single-driver.
	FailedDrivers, TotalDrivers int
}

// AgenticRunStatus is the agentic_scans.status for a finished run. It is the
// one place that decides it, for the CLI finalizers and the swarm runner alike,
// so a timed-out run is "timeout" whichever path wrote it (it used to be
// "failed" in the database while the JSON said "timed_out").
func AgenticRunStatus(e AgenticRunEnd) string {
	switch {
	case e.Cancelled:
		return AgenticScanStatusCancelled
	case e.TimedOut:
		return AgenticScanStatusTimeout
	case e.BudgetExhausted:
		return AgenticScanStatusBudgetExhausted
	case e.TotalDrivers > 0:
		if e.Err != nil && e.FailedDrivers == 0 {
			return AgenticScanStatusFailed
		}
		return MultiDriverAgenticScanStatus(e.FailedDrivers, e.TotalDrivers)
	case e.Err != nil:
		return AgenticScanStatusFailed
	}
	return CompletedAgenticScanStatus(e.Degraded)
}

// MultiDriverAgenticScanStatus is the parent status of a run made of several
// drivers: "failed" when every driver failed (nothing ran, so
// "completed_with_errors" overstated it), "completed_with_errors" when some
// did, "completed" otherwise.
func MultiDriverAgenticScanStatus(failed, total int) string {
	switch {
	case failed == 0:
		return "completed"
	case failed >= total:
		return "failed"
	default:
		return "completed_with_errors"
	}
}

// DeleteOldAgenticScans removes finished agent runs older than the given
// duration. "Finished" is TerminalAgenticScanStatuses, not a literal list —
// see that variable.
func (r *Repository) DeleteOldAgenticScans(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	res, err := r.db.NewDelete().Model((*AgenticScan)(nil)).
		Where("status IN (?)", bun.List(TerminalAgenticScanStatuses)).
		Where("completed_at < ?", cutoff).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old agent runs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
