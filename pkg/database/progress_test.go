package database

import (
	"context"
	"testing"
)

// The ledger upsert only moves forward and unions passive_done; done_bits is
// written whole.
func TestProgressWriterUpsert(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.saveProgressBatch(ctx, []ScanRecordProgress{{
		ScanUUID: "s", RecordUUID: "r", ProjectUUID: DefaultProjectUUID, TierDone: 0, PassiveDone: true, TimedOut: 1, DoneBits: []byte{0x01},
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	w := NewProgressWriter(repo)
	w.Write(ScanRecordProgress{ScanUUID: "s", RecordUUID: "r", TierDone: 1, TimedOut: 2, DoneBits: []byte{0x03}})
	w.Write(ScanRecordProgress{ScanUUID: "s", RecordUUID: "r2", TierDone: 0, DoneBits: []byte{0x01}})
	w.Close()
	// A stale (lower-tier) update never regresses the row.
	if err := repo.saveProgressBatch(ctx, []ScanRecordProgress{{
		ScanUUID: "s", RecordUUID: "r", ProjectUUID: DefaultProjectUUID, TierDone: 0, DoneBits: []byte{0x01},
	}}); err != nil {
		t.Fatalf("stale save: %v", err)
	}

	got, err := repo.LoadRecordProgress(ctx, DefaultProjectUUID, "s", []string{"r", "r2", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	r := got["r"]
	if r.TierDone != 1 || !r.PassiveDone || len(r.DoneBits) != 1 || r.DoneBits[0] != 0x03 {
		t.Fatalf("r = %+v", r)
	}
	if _, ok := got["r2"]; !ok {
		t.Fatal("r2 not written")
	}
	if _, ok := got["missing"]; ok {
		t.Fatal("phantom row")
	}
}
