package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vigolium/vigolium/pkg/work"
)

// RecordModuleCoverage is one (record, module) cell of a scan's coverage
// ledger: whether the module finished on the record (scan_record_progress.
// done_bits, decoded against scans.coverage_modules).
type RecordModuleCoverage struct {
	RecordUUID string `json:"record_uuid"`
	ModuleID   string `json:"module_id"`
	Done       bool   `json:"done"`
}

// ScanCoverage pages scanUUID's coverage ledger as (record, module) cells:
// records in record_uuid order, each expanded over the scan's coverage
// modules in ordinal order. total is every cell (ledger rows × modules);
// offset and limit (0 = all) count cells. A scan with no coverage modules or
// no ledger rows has none. Project-scoped.
func (r *Repository) ScanCoverage(ctx context.Context, projectUUID, scanUUID string, offset, limit int) ([]RecordModuleCoverage, int64, error) {
	if r == nil || r.db == nil || scanUUID == "" {
		return nil, 0, nil
	}
	modules, err := r.ScanCoverageModules(ctx, scanUUID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, 0, err
	}
	if len(modules) == 0 {
		return []RecordModuleCoverage{}, 0, nil
	}
	q := r.db.NewSelect().Model((*ScanRecordProgress)(nil)).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("scan_uuid = ?", scanUUID)
	records, err := q.Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count record progress: %w", err)
	}
	m := len(modules)
	total := int64(records) * int64(m)
	if offset < 0 {
		offset = 0
	}
	if int64(offset) >= total {
		return []RecordModuleCoverage{}, total, nil
	}
	end := total
	if limit > 0 && int64(offset+limit) < total {
		end = int64(offset + limit)
	}
	firstRec := offset / m
	lastRec := int((end - 1) / int64(m))

	var rows []ScanRecordProgress
	err = r.db.NewSelect().Model(&rows).
		Column("record_uuid", "done_bits").
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("scan_uuid = ?", scanUUID).
		Order("record_uuid ASC").
		Offset(int64(firstRec)).
		Limit(int64(lastRec - firstRec + 1)).
		Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("load record progress: %w", err)
	}
	out := make([]RecordModuleCoverage, 0, end-int64(offset))
	for i, row := range rows {
		cov := work.Coverage{DoneBits: row.DoneBits}
		for ord, id := range modules {
			cell := int64(firstRec+i)*int64(m) + int64(ord)
			if cell < int64(offset) || cell >= end {
				continue
			}
			out = append(out, RecordModuleCoverage{RecordUUID: row.RecordUUID, ModuleID: id, Done: cov.ModuleDone(ord)})
		}
	}
	return out, total, nil
}
