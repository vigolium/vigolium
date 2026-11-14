package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// /admin, /backup and /.git at 403 survive as three records (each is
// a forbidden-bypass target), auth walls are capped at AuthWallCap per host,
// 429 still collapses to one per host, and the reflected-URL collapse leaves
// per-path statuses alone.
func TestDeparosAuthWallsKeptPerPath(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID
	now := time.Now()

	insert := func(path string, status int, norm string) string {
		id := uuid.NewString()
		_, err := db.NewInsert().Model(&HTTPRecord{
			UUID: id, ProjectUUID: projectUUID, Scheme: "https", Hostname: "h.com", Port: 443,
			Method: "GET", Path: path, URL: "https://h.com" + path, HTTPVersion: "HTTP/1.1",
			RequestHash: id, ResponseHash: id, ResponseNormHash: norm, ResponseContentType: "text/html",
			StatusCode: status, HasResponse: true, Source: "deparos", SentAt: now, CreatedAt: now,
		}).Exec(ctx)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		return id
	}

	walls := []string{insert("/admin", 403, "FORBIDDEN"), insert("/backup", 403, "FORBIDDEN"), insert("/.git", 403, "FORBIDDEN")}
	for i := 0; i < 40; i++ {
		insert(fmt.Sprintf("/zz-flood-%02d", i), 403, "FORBIDDEN")
	}
	insert("/r1", 429, "")
	insert("/r2", 429, "")

	keepPerPath := []int{401, 403, 405, 415, 422}
	if _, err := repo.ApplyDeparosStatusPolicy(ctx, projectUUID, DeparosStatusPolicy{
		KeepOnePerHost: []int{429},
		KeepPerPath:    keepPerPath,
		PerPathCap:     100,
		AuthWallCap:    25,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DeduplicateDeparosByNormHash(ctx, projectUUID, keepPerPath...); err != nil {
		t.Fatal(err)
	}

	count := func(status int) int64 {
		n, err := db.NewSelect().Model((*HTTPRecord)(nil)).Where("status_code = ?", status).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(403); got != 25 {
		t.Errorf("403 records = %d, want AuthWallCap 25", got)
	}
	if got := count(429); got != 1 {
		t.Errorf("429 records = %d, want one per host", got)
	}
	for _, id := range walls {
		n, err := db.NewSelect().Model((*HTTPRecord)(nil)).Where("uuid = ?", id).Count(ctx)
		if err != nil || n != 1 {
			t.Errorf("auth wall %s dropped (n=%d err=%v)", id, n, err)
		}
	}
}
