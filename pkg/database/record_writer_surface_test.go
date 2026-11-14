package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// The writer stamps surface_score at ingest through the injected scorer
// (ECON-5), so a fresh scan's assessment order is not chronological.
func TestRecordWriterStampsIngestSurfaceScore(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	w := NewRecordWriter(repo, RecordWriterConfig{
		SurfaceScorer: func(rr *httpmsg.HttpRequestResponse) int {
			if rr.Request().Method() == "POST" {
				return 60
			}
			return 10
		},
	})
	ctx := context.Background()
	rr, err := httpmsg.ParseRawRequest("POST /login HTTP/1.1\r\nHost: s.test\r\nContent-Length: 3\r\n\r\na=b")
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := w.Write(ctx, rr, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	var rec HTTPRecord
	if err := db.NewSelect().Model(&rec).Where("uuid = ?", uuid).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.SurfaceScore != 60 {
		t.Fatalf("surface_score = %d, want 60 from the ingest scorer", rec.SurfaceScore)
	}
}
