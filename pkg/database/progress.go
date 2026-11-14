package database

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// ScanRecordProgress is one record's dynamic-assessment coverage in one scan
// (the light coverage ledger): which tiers of modules finished on it,
// which individual modules did (done_bits, by the module ordinals stored in
// scans.coverage_modules), whether the passive stage ran, and how many module
// calls timed out. It is what lets a curtailed scan resume without redoing the
// work it already did, and what tiered passes read to skip finished records.
type ScanRecordProgress struct {
	bun.BaseModel `bun:"table:scan_record_progress,alias:srp"`

	ScanUUID    string    `bun:"scan_uuid,pk"`
	RecordUUID  string    `bun:"record_uuid,pk"`
	ProjectUUID string    `bun:"project_uuid,notnull"`
	TierDone    int       `bun:"tier_done,notnull,default:-1"`
	PassiveDone bool      `bun:"passive_done,notnull,default:false"`
	TimedOut    int       `bun:"timed_out,notnull,default:0"`
	DoneBits    []byte    `bun:"done_bits"`
	UpdatedAt   time.Time `bun:"updated_at,notnull,default:current_timestamp"`
}

// RecordCoverage is a record's stored progress as the dispatch side reads it.
type RecordCoverage = work.Coverage

// LoadRecordProgress returns the stored progress of recordUUIDs in scanUUID
// (absent records are simply missing from the map), reading in SQLChunkSize
// chunks. Project-scoped.
func (r *Repository) LoadRecordProgress(ctx context.Context, projectUUID, scanUUID string, recordUUIDs []string) (map[string]RecordCoverage, error) {
	out := make(map[string]RecordCoverage, len(recordUUIDs))
	if r == nil || r.db == nil || scanUUID == "" || len(recordUUIDs) == 0 {
		return out, nil
	}
	for chunk := range slices.Chunk(recordUUIDs, SQLChunkSize) {
		var rows []ScanRecordProgress
		err := r.db.NewSelect().Model(&rows).
			Column("record_uuid", "tier_done", "passive_done", "done_bits").
			Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
			Where("scan_uuid = ?", scanUUID).
			Where("record_uuid IN (?)", bun.List(chunk)).
			Scan(ctx)
		if err != nil {
			return nil, fmt.Errorf("load record progress: %w", err)
		}
		for _, row := range rows {
			out[row.RecordUUID] = RecordCoverage{TierDone: row.TierDone, PassiveDone: row.PassiveDone, DoneBits: row.DoneBits}
		}
	}
	return out, nil
}

// SetScanCoverageModules records the module ordinal order done_bits refer to.
func (r *Repository) SetScanCoverageModules(ctx context.Context, scanUUID string, moduleIDs []string) error {
	b, err := json.Marshal(moduleIDs)
	if err != nil {
		return err
	}
	_, err = r.db.NewUpdate().Model((*Scan)(nil)).
		Set("coverage_modules = ?", string(b)).
		Where("uuid = ?", scanUUID).
		Exec(ctx)
	return err
}

// ScanCoverageModules returns the module ordinal order stored for scanUUID
// (nil when none).
func (r *Repository) ScanCoverageModules(ctx context.Context, scanUUID string) ([]string, error) {
	var raw string
	err := r.db.NewSelect().Model((*Scan)(nil)).ColumnExpr("COALESCE(coverage_modules, '')").
		Where("uuid = ?", scanUUID).Limit(1).Scan(ctx, &raw)
	if err != nil || raw == "" {
		return nil, err
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, fmt.Errorf("decode coverage_modules: %w", err)
	}
	return ids, nil
}

// upsertProgressSQL (bun aliases the table as srp in the INSERT): a row only moves forward — a stale update (lower tier)
// never overwrites a newer one. done_bits is written whole: the writer's
// caller already unioned it with the stored bits it loaded.
const upsertProgressSQL = `CONFLICT (scan_uuid, record_uuid) DO UPDATE SET
	tier_done = EXCLUDED.tier_done,
	passive_done = EXCLUDED.passive_done OR srp.passive_done,
	timed_out = srp.timed_out + EXCLUDED.timed_out,
	done_bits = EXCLUDED.done_bits,
	updated_at = EXCLUDED.updated_at
	WHERE srp.tier_done <= EXCLUDED.tier_done`

// saveProgressBatch upserts rows in one transaction.
func (r *Repository) saveProgressBatch(ctx context.Context, rows []ScanRecordProgress) error {
	if len(rows) == 0 {
		return nil
	}
	return RetryBusy(ctx, func() error {
		return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			_, err := tx.NewInsert().Model(&rows).On(upsertProgressSQL).Exec(ctx)
			return err
		})
	}, RetryPolicy{Op: "save record progress"})
}

// ProgressWriterBatch is how many progress rows one transaction writes.
const ProgressWriterBatch = 256

// ProgressWriter persists ledger rows asynchronously, batched
// ProgressWriterBatch per transaction (modelled on FindingWriter). Write never
// blocks on the database; Close drains.
type ProgressWriter struct {
	repo    *Repository
	ch      chan ScanRecordProgress
	flushes chan chan struct{}

	mu     sync.RWMutex
	closed bool
	wg     sync.WaitGroup
}

// NewProgressWriter starts a writer.
func NewProgressWriter(repo *Repository) *ProgressWriter {
	w := &ProgressWriter{repo: repo, ch: make(chan ScanRecordProgress, 4096), flushes: make(chan chan struct{})}
	w.wg.Add(1)
	go w.loop()
	return w
}

// Write enqueues one row. Safe for concurrent use; a closed writer writes inline.
func (w *ProgressWriter) Write(row ScanRecordProgress) {
	if w == nil {
		return
	}
	row.ProjectUUID = defaultProjectUUID(row.ProjectUUID)
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = time.Now().UTC()
	}
	w.mu.RLock()
	if w.closed {
		w.mu.RUnlock()
		if err := w.repo.saveProgressBatch(context.Background(), []ScanRecordProgress{row}); err != nil {
			zap.L().Debug("record progress write failed", zap.Error(err))
		}
		return
	}
	w.ch <- row
	w.mu.RUnlock()
}

func (w *ProgressWriter) loop() {
	defer w.wg.Done()
	batch := make([]ScanRecordProgress, 0, ProgressWriterBatch)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := w.repo.saveProgressBatch(context.Background(), batch); err != nil {
			zap.L().Warn("record progress batch failed; a resumed scan may redo these records",
				zap.Int("rows", len(batch)), zap.Error(err))
		}
		batch = batch[:0]
	}
	for {
		select {
		case row, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, row)
			if len(batch) >= ProgressWriterBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		case done := <-w.flushes:
			// Drain what is already queued, then write it.
			for drained := false; !drained; {
				select {
				case row, ok := <-w.ch:
					if !ok {
						drained = true
						break
					}
					batch = append(batch, row)
					if len(batch) >= ProgressWriterBatch {
						flush()
					}
				default:
					drained = true
				}
			}
			flush()
			close(done)
		}
	}
}

// Flush blocks until every row written so far is in the database — a later
// tier pass reads the ledger and must see the earlier pass's rows.
func (w *ProgressWriter) Flush() {
	if w == nil {
		return
	}
	w.mu.RLock()
	if w.closed {
		w.mu.RUnlock()
		return
	}
	done := make(chan struct{})
	w.flushes <- done
	w.mu.RUnlock()
	<-done
}

// Close drains the queue and stops the writer. Idempotent.
func (w *ProgressWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.ch)
	w.mu.Unlock()
	w.wg.Wait()
}

// DeleteScanProgress removes scanUUID's ledger rows (part of deleting a scan).
func (r *Repository) DeleteScanProgress(ctx context.Context, scanUUID string) error {
	_, err := r.db.NewDelete().Model((*ScanRecordProgress)(nil)).Where("scan_uuid = ?", scanUUID).Exec(ctx)
	return err
}
