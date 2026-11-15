package database

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"
)

// Finding history: which scans observed a finding (finding_observations) and
// how its status changed (finding_status_events). Both hang off findings.id, so
// every path that deletes findings or folds one into another has to carry them
// along — findingChildTables is the one list those paths read.

// findingChildTables are the tables keyed by findings.id that must not outlive
// their finding. finding_records is the evidence junction; the other two are
// the finding's history.
var findingChildTables = []string{"finding_records", "finding_observations", "finding_status_events", "finding_hash_aliases"}

// recordFindingObservation notes that scanUUID observed the finding. A repeat
// within one scan is a no-op (PRIMARY KEY (finding_id, scan_uuid)), and a save
// without a scan (an import, an out-of-band agent finding) records nothing:
// there is no run to attribute it to.
//
// Called with the same bun.IDB as the finding write it belongs to, so the
// observation commits or rolls back with it.
func recordFindingObservation(ctx context.Context, idb bun.IDB, projectUUID string, findingID int64, findingHash, scanUUID string) error {
	if scanUUID == "" || findingID == 0 {
		return nil
	}
	obs := &FindingObservation{
		ProjectUUID: defaultProjectUUID(projectUUID),
		FindingID:   findingID,
		FindingHash: findingHash,
		ScanUUID:    scanUUID,
		ObservedAt:  time.Now().UTC(),
	}
	if _, err := idb.NewInsert().Model(obs).
		On("CONFLICT (finding_id, scan_uuid) DO NOTHING").
		Exec(ctx); err != nil {
		return fmt.Errorf("record observation of finding %d by scan %s: %w", findingID, scanUUID, err)
	}
	return nil
}

// backfillFindingObservations is the one-time schema v3 backfill: one
// observation per existing finding, from the scan it was last attributed to and
// when it was found. History before the migration is therefore partial — a
// finding re-detected by several scans keeps only its latest observer — so the
// migration time is recorded as schema_meta.observation_history_since for
// readers (scan diffs) to label results that reach behind it.
//
// Idempotent: the insert skips existing (finding, scan) pairs and the marker is
// only ever set once. On a fresh store it inserts nothing and stamps the marker
// at creation, which is correct: such a store has complete history.
func (db *DB) backfillFindingObservations(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, `
		INSERT INTO finding_observations (project_uuid, finding_id, finding_hash, scan_uuid, observed_at)
		SELECT project_uuid, id, finding_hash, scan_uuid, found_at
		FROM findings
		WHERE scan_uuid IS NOT NULL AND scan_uuid <> ''
		ON CONFLICT (finding_id, scan_uuid) DO NOTHING`); err != nil {
		return fmt.Errorf("backfill finding_observations: %w", err)
	}
	// version 0 only matters on a store with no schema_meta row yet; the
	// setSchemaVersion that follows raises it (it only ever moves up).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO schema_meta (id, version, observation_history_since)
		VALUES (1, 0, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET
		  observation_history_since = COALESCE(schema_meta.observation_history_since, excluded.observation_history_since)`); err != nil {
		return fmt.Errorf("record observation_history_since: %w", err)
	}
	return nil
}

// ObservationHistorySince reports when this store started recording every
// finding observation (the schema v3 migration). Observations before it are
// the backfill's single row per finding, so a comparison involving a scan that
// started earlier is partial. The zero time means the marker is unset (a store
// not yet migrated).
func (r *Repository) ObservationHistorySince(ctx context.Context) (time.Time, error) {
	var since bun.NullTime
	if err := r.db.NewRaw("SELECT observation_history_since FROM schema_meta WHERE id = 1").
		Scan(ctx, &since); err != nil {
		return time.Time{}, fmt.Errorf("read observation_history_since: %w", err)
	}
	return since.Time, nil
}

// ListFindingObservations returns the observations of one finding, oldest
// first. projectUUID == "" drops the project predicate (scoping off).
func (r *Repository) ListFindingObservations(ctx context.Context, projectUUID string, findingID int64) ([]FindingObservation, error) {
	var out []FindingObservation
	q := r.db.NewSelect().Model(&out).Where("finding_id = ?", findingID).OrderExpr("observed_at ASC, scan_uuid ASC")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("list finding observations: %w", err)
	}
	return out, nil
}

// migrateFindingHistoryTx folds the duplicates' history into the survivor
// before the duplicates are deleted, the history counterpart of
// migrateFindingRecordsTx: each scan that observed any duplicate becomes an
// observation of the survivor (earliest time wins, under the survivor's hash),
// and status events are re-pointed so the survivor's history stays complete.
//
// The NOT EXISTS guard keeps the (finding_id, scan_uuid) primary key intact
// across chunks: a scan already recorded for the survivor — including by an
// earlier chunk in this transaction — is skipped.
func migrateFindingHistoryTx(ctx context.Context, tx bun.Tx, survivorID int64, dupIDs []int64) error {
	if len(dupIDs) == 0 {
		return nil
	}
	for chunk := range slices.Chunk(dupIDs, SQLChunkSize) {
		if _, err := tx.NewRaw(
			`INSERT INTO finding_observations (project_uuid, finding_id, finding_hash, scan_uuid, observed_at)
			 SELECT s.project_uuid, s.id, s.finding_hash, o.scan_uuid, MIN(o.observed_at)
			 FROM finding_observations o
			 JOIN findings s ON s.id = ?
			 WHERE o.finding_id IN (?)
			   AND NOT EXISTS (
			       SELECT 1 FROM finding_observations x
			       WHERE x.finding_id = s.id AND x.scan_uuid = o.scan_uuid
			   )
			 GROUP BY s.project_uuid, s.id, s.finding_hash, o.scan_uuid`,
			survivorID, bun.List(chunk),
		).Exec(ctx); err != nil {
			return fmt.Errorf("failed to migrate finding_observations to survivor: %w", err)
		}
		if _, err := tx.NewRaw(
			"UPDATE finding_status_events SET finding_id = ? WHERE finding_id IN (?)",
			survivorID, bun.List(chunk),
		).Exec(ctx); err != nil {
			return fmt.Errorf("failed to migrate finding_status_events to survivor: %w", err)
		}
		// Aliases the duplicates carried now name the survivor, and each
		// duplicate's own hash becomes one, so a hash someone already holds
		// (in a ticket, an ignore file, a CI log) still resolves after the merge.
		if _, err := tx.NewRaw(
			"UPDATE finding_hash_aliases SET finding_id = ? WHERE finding_id IN (?)",
			survivorID, bun.List(chunk),
		).Exec(ctx); err != nil {
			return fmt.Errorf("failed to migrate finding_hash_aliases to survivor: %w", err)
		}
		if _, err := tx.NewRaw(
			`INSERT INTO finding_hash_aliases (project_uuid, alias_hash, finding_id, created_at)
			 SELECT d.project_uuid, d.finding_hash, ?, CURRENT_TIMESTAMP
			 FROM findings d
			 WHERE d.id IN (?)
			   AND NOT EXISTS (
			       SELECT 1 FROM finding_hash_aliases a
			       WHERE a.project_uuid = d.project_uuid AND a.alias_hash = d.finding_hash
			   )`,
			survivorID, bun.List(chunk),
		).Exec(ctx); err != nil {
			return fmt.Errorf("failed to alias merged finding hashes: %w", err)
		}
	}
	return nil
}

// deleteFindingChildrenTx removes every findingChildTables row of the findings
// with the given ids, inside tx, chunking the IN list.
func deleteFindingChildrenTx(ctx context.Context, tx bun.Tx, ids []int64) error {
	for chunk := range slices.Chunk(ids, SQLChunkSize) {
		for _, table := range findingChildTables {
			res, err := tx.NewRaw("DELETE FROM "+table+" WHERE finding_id IN (?)", bun.List(chunk)).Exec(ctx)
			if err != nil {
				return fmt.Errorf("failed to delete %s: %w", table, err)
			}
			noteDeleted(ctx, table, res)
		}
	}
	return nil
}
