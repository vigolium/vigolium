package database

import (
	"context"
	"testing"
	"time"
)

// A run finalized with the cancellation marker is stored "cancelled", not
// "failed"; error_message keeps the marker for older readers.
func TestCompleteScanStoresCancelled(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	for _, c := range []struct{ uuid, msg, want string }{
		{"ok", "", "completed"},
		{"cx", ScanCancelledMessage, "cancelled"},
		{"bad", "boom", "failed"},
	} {
		if err := repo.CreateScan(ctx, &Scan{UUID: c.uuid, Status: "running", StartedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := repo.CompleteScanWithOutcome(ctx, c.uuid, c.msg, ScanCompletion{}); err != nil {
			t.Fatal(err)
		}
		row, err := repo.GetScanByUUID(ctx, c.uuid)
		if err != nil {
			t.Fatal(err)
		}
		if row.Status != c.want || row.ErrorMessage != c.msg {
			t.Errorf("%s: status=%q error=%q, want %q", c.uuid, row.Status, row.ErrorMessage, c.want)
		}
	}
}
