package database

import (
	"context"

	"github.com/uptrace/bun"
)

// RunRecordFilter narrows a record query to one run's records: those the
// scan wrote (scan_uuid) plus Seeds, the stored records an input of the run
// deduplicated onto. A nil filter keeps every record.
type RunRecordFilter struct {
	ScanUUID string
	Seeds    []string
}

// Apply adds the filter to q. A nil filter returns q unchanged.
func (f *RunRecordFilter) Apply(q *bun.SelectQuery) *bun.SelectQuery {
	if f == nil {
		return q
	}
	return q.WhereGroup(" AND ", func(g *bun.SelectQuery) *bun.SelectQuery {
		g = g.Where("scan_uuid = ?", f.ScanUUID)
		if len(f.Seeds) > 0 {
			g = g.WhereOr("uuid IN (?)", bun.In(f.Seeds))
		}
		return g
	})
}

// runSeedChunk bounds one IN list when resolving seeds.
const runSeedChunk = 500

// RecordsFromOtherScans returns the subset of uuids whose record was written
// by a scan other than scanUUID (or by none): the seeds a RunRecordFilter has
// to name, since the rest already match on scan_uuid.
func (r *Repository) RecordsFromOtherScans(ctx context.Context, scanUUID string, uuids []string) ([]string, error) {
	var out []string
	for start := 0; start < len(uuids); start += runSeedChunk {
		chunk := uuids[start:min(start+runSeedChunk, len(uuids))]
		var rows []string
		err := r.db.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid").
			Where("uuid IN (?)", bun.In(chunk)).
			Where("(scan_uuid IS NULL OR scan_uuid != ?)", scanUUID).
			Scan(ctx, &rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}
