package database

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// 1500 origins used to build 1500 OR terms, past SQLite's expression
// depth limit, and the count query failed.
func TestHostScopeFilter_ManyOrigins(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	insertTestRecordsWithHost(t, repo, "in.example.com", 3)
	insertTestRecordsWithHost(t, repo, "out.example.com", 2)

	var hosts []HostTarget
	for i := 0; i < 1500; i++ {
		switch i % 4 {
		case 0:
			hosts = append(hosts, HostTarget{Scheme: "https", Hostname: fmt.Sprintf("h%d.test", i), Port: 443})
		case 1:
			hosts = append(hosts, HostTarget{Scheme: "http", Hostname: fmt.Sprintf("h%d.test", i)})
		case 2:
			hosts = append(hosts, HostTarget{Hostname: fmt.Sprintf("h%d.test", i), Port: 8080})
		default:
			hosts = append(hosts, HostTarget{Hostname: fmt.Sprintf("h%d.test", i)})
		}
	}
	hosts = append(hosts, HostTarget{Hostname: "in.example.com"}, HostTarget{Hostname: "in.example.com"})
	n, err := repo.CountRecordsAfterCursor(ctx, DefaultProjectUUID, time.Time{}, "", hosts...)
	if err != nil {
		t.Fatalf("CountRecordsAfterCursor with 1500 origins: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

// The grouped form keeps each field-shape's semantics.
func TestHostScopeFilter_Semantics(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	insertTestRecordsWithHost(t, repo, "a.example.com", 2)
	var rec HTTPRecord
	if err := db.NewSelect().Model(&rec).Where("hostname = ?", "a.example.com").Limit(1).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		h    HostTarget
		want int64
	}{
		{"exact origin", HostTarget{Scheme: rec.Scheme, Hostname: rec.Hostname, Port: rec.Port}, 2},
		{"wrong port", HostTarget{Scheme: rec.Scheme, Hostname: rec.Hostname, Port: rec.Port + 1}, 0},
		{"scheme+host", HostTarget{Scheme: rec.Scheme, Hostname: rec.Hostname}, 2},
		{"wrong scheme", HostTarget{Scheme: "gopher", Hostname: rec.Hostname}, 0},
		{"host+port", HostTarget{Hostname: rec.Hostname, Port: rec.Port}, 2},
		{"host only", HostTarget{Hostname: rec.Hostname}, 2},
		{"other host", HostTarget{Hostname: "b.example.com"}, 0},
	}
	for _, c := range cases {
		n, err := repo.CountRecordsAfterCursor(ctx, DefaultProjectUUID, time.Time{}, "", c.h)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if n != c.want {
			t.Errorf("%s: count = %d, want %d", c.name, n, c.want)
		}
	}
}
