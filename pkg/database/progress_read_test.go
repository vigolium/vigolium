package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/work"
)

// ScanCoverage decodes done_bits against the scan's coverage modules into
// (record, module) cells, ordered and paged by cell.
func TestScanCoverageDecodesDoneBits(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	const scan = "scan-cov-1"
	if _, err := db.NewInsert().Model(&Scan{UUID: scan, ProjectUUID: defaultProjectUUID("")}).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetScanCoverageModules(ctx, scan, []string{"xss", "sqli", "ssti"}); err != nil {
		t.Fatal(err)
	}
	a := work.Coverage{}
	a.SetModuleDone(0)
	a.SetModuleDone(2)
	b := work.Coverage{}
	b.SetModuleDone(1)
	if err := repo.saveProgressBatch(ctx, []ScanRecordProgress{
		{ScanUUID: scan, RecordUUID: "rec-b", ProjectUUID: defaultProjectUUID(""), DoneBits: b.DoneBits},
		{ScanUUID: scan, RecordUUID: "rec-a", ProjectUUID: defaultProjectUUID(""), DoneBits: a.DoneBits},
	}); err != nil {
		t.Fatal(err)
	}

	all, total, err := repo.ScanCoverage(ctx, "", scan, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []RecordModuleCoverage{
		{"rec-a", "xss", true}, {"rec-a", "sqli", false}, {"rec-a", "ssti", true},
		{"rec-b", "xss", false}, {"rec-b", "sqli", true}, {"rec-b", "ssti", false},
	}
	if total != 6 || len(all) != len(want) {
		t.Fatalf("total %d, %d cells: %+v", total, len(all), all)
	}
	for i := range want {
		if all[i] != want[i] {
			t.Errorf("cell %d = %+v, want %+v", i, all[i], want[i])
		}
	}

	// A page that starts and ends inside records.
	page, total, err := repo.ScanCoverage(ctx, "", scan, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total != 6 || len(page) != 3 || page[0] != want[2] || page[2] != want[4] {
		t.Errorf("page [2,5) = %+v (total %d)", page, total)
	}

	// Past the end: no cells, the total still reported.
	if page, total, _ := repo.ScanCoverage(ctx, "", scan, 6, 10); len(page) != 0 || total != 6 {
		t.Errorf("past the end = %+v (total %d)", page, total)
	}

	// A scan with no coverage modules has no cells.
	if cells, total, err := repo.ScanCoverage(ctx, "", "scan-none", 0, 0); err != nil || len(cells) != 0 || total != 0 {
		t.Errorf("no ledger = %+v, %d, %v", cells, total, err)
	}
}
