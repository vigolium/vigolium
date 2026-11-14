package database

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// SAFE-12: the same finding saved by two scans fires the new-finding callback
// once — a re-scan no longer re-notifies known findings.
func TestFindingWriter_OnInsertedOnlyForNewFindings(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	rec := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/x", 200)

	var notified atomic.Int64
	for scan := 0; scan < 2; scan++ {
		w := NewFindingWriter(repo, FindingWriterConfig{FlushInterval: 5 * time.Millisecond})
		w.SetOnInserted(func(*output.ResultEvent) { notified.Add(1) })
		ev := makeFindingEvent("mod", "/x", severity.High)
		if err := w.Save(ctx, ev, []string{rec}, "", DefaultProjectUUID); err != nil {
			t.Fatal(err)
		}
		w.Close()
	}
	if n := notified.Load(); n != 1 {
		t.Errorf("notifications = %d over two scans of one finding, want 1", n)
	}

	// The direct path reports the same.
	first, err := repo.SaveFindingInserted(ctx, makeFindingEvent("mod2", "/y", severity.Low), []string{rec}, "", DefaultProjectUUID)
	if err != nil || !first {
		t.Fatalf("first SaveFindingInserted = %v, %v", first, err)
	}
	again, err := repo.SaveFindingInserted(ctx, makeFindingEvent("mod2", "/y", severity.Low), []string{rec}, "", DefaultProjectUUID)
	if err != nil || again {
		t.Fatalf("repeat SaveFindingInserted = %v, %v (want false)", again, err)
	}
}
