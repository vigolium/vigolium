package database

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"
)

// IsEvidenceRecordSource reports whether source marks a finding-evidence record.
func IsEvidenceRecordSource(source string) bool {
	return slices.Contains(EvidenceRecordSources, source)
}

// ResolveFindings loads the findings named by id and/or finding_hash (full or
// ≥MinFindingHashPrefix prefix) inside one project, ordered by id, with the
// same matching and ambiguity rules as UpdateFindingStatusScoped. Selectors
// that match nothing in scope come back in notFound.
func (r *Repository) ResolveFindings(ctx context.Context, projectUUID string, ids []int64, hashes []string) ([]*Finding, []string, error) {
	rows, notFound, err := resolveFindingSelectors(ctx, r.db, projectUUID, ids, hashes)
	if err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, notFound, nil
	}
	want := make([]int64, 0, len(rows))
	for _, row := range rows {
		want = append(want, row.ID)
	}
	var out []*Finding
	for chunk := range slices.Chunk(want, SQLChunkSize) {
		var part []*Finding
		if err := r.db.NewSelect().Model(&part).Where("id IN (?)", bun.List(chunk)).Scan(ctx); err != nil {
			return nil, nil, fmt.Errorf("load findings: %w", err)
		}
		out = append(out, part...)
	}
	slices.SortFunc(out, func(a, b *Finding) int { return int(a.ID - b.ID) })
	return out, notFound, nil
}

// FindingsInScan returns the reportable findings (record_kind finding) a scan
// produced inside one project, ordered by id. projectUUID == "" drops the
// project predicate (a standalone `-S --db` store).
func (r *Repository) FindingsInScan(ctx context.Context, projectUUID, scanUUID string) ([]*Finding, error) {
	var out []*Finding
	q := r.db.NewSelect().Model(&out).
		Where("(scan_uuid = ? OR EXISTS (SELECT 1 FROM finding_observations o WHERE o.finding_id = f.id AND o.scan_uuid = ?))", scanUUID, scanUUID).
		Where("COALESCE(record_kind, ?) = ?", RecordKindFinding, RecordKindFinding).
		OrderExpr("id ASC")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("load scan findings: %w", err)
	}
	return out, nil
}

// SetFindingVerification stores a `finding verify` result on one finding:
// the verification JSON and verified_at (its timestamp, for sorting). Status
// is not touched; a verdict reaches status only through the scoped status
// writer (`finding verify --mark`). A finding outside the project is left
// alone; callers resolve findings in scope first.
func (r *Repository) SetFindingVerification(ctx context.Context, projectUUID string, id int64, v *FindingVerification) error {
	if v == nil {
		return fmt.Errorf("nil verification")
	}
	at := v.At
	if at.IsZero() {
		at = time.Now().UTC()
		v.At = at
	}
	q := r.db.NewUpdate().Model((*Finding)(nil)).
		Set("verification = ?", v).
		Set("verified_at = ?", at).
		Where("id = ?", id)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("store verification: %w", err)
	}
	return nil
}

// ReplayBaselineCandidates returns recent scanned (non-evidence) records for
// one host and method inside a project, optionally narrowed to a scan, newest
// first: the pool `finding verify` searches for the baseline of a legacy
// finding whose only linked record is its own payload request.
func (r *Repository) ReplayBaselineCandidates(ctx context.Context, projectUUID, scanUUID, hostname, method string, limit int) ([]*HTTPRecord, error) {
	if limit <= 0 {
		limit = 500
	}
	var out []*HTTPRecord
	q := r.db.NewSelect().Model(&out).
		Where("hostname = ?", hostname).
		Where("method = ?", method).
		Where("COALESCE(source, '') NOT IN (?)", bun.List(EvidenceRecordSources)).
		OrderExpr("sent_at DESC").
		Limit(int64(limit))
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if scanUUID != "" {
		q = q.Where("scan_uuid = ?", scanUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("load baseline candidates: %w", err)
	}
	return out, nil
}

// VerificationVerdicts is the closed `finding verify` verdict vocabulary.
var VerificationVerdicts = []string{VerdictConfirmed, VerdictNotReproduced, VerdictInconclusive, VerdictUnsupported}
