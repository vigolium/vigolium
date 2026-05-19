package database

import (
	"context"
	"testing"
)

func TestAuthenticationHostname_SaveAndGet(t *testing.T) {
	db := newTestDB(t)
	defer func() { _ = db.Close() }()
	repo := NewRepository(db)
	ctx := context.Background()

	sh := &AuthenticationHostname{
		ProjectUUID: DefaultProjectUUID,
		Hostname:    "example.com",
		SessionName: "admin",
		SessionRole: "primary",
		Headers:     map[string]string{"Authorization": "Bearer tok123"},
		Source:      "agent",
	}

	if err := repo.SaveAuthenticationHostname(ctx, sh); err != nil {
		t.Fatalf("SaveAuthenticationHostname: %v", err)
	}
	if sh.ID == 0 {
		t.Fatal("expected non-zero ID after insert")
	}

	rows, err := repo.GetAuthenticationHostnamesByHostname(ctx, DefaultProjectUUID, "example.com")
	if err != nil {
		t.Fatalf("GetAuthenticationHostnamesByHostname: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].SessionName != "admin" {
		t.Errorf("expected session_name=admin, got %q", rows[0].SessionName)
	}
	if rows[0].Headers["Authorization"] != "Bearer tok123" {
		t.Errorf("expected Authorization header, got %v", rows[0].Headers)
	}
}

func TestAuthenticationHostname_Upsert(t *testing.T) {
	db := newTestDB(t)
	defer func() { _ = db.Close() }()
	repo := NewRepository(db)
	ctx := context.Background()

	sh := &AuthenticationHostname{
		ProjectUUID: DefaultProjectUUID,
		Hostname:    "example.com",
		SessionName: "admin",
		SessionRole: "primary",
		Headers:     map[string]string{"Authorization": "Bearer old"},
		Source:      "agent",
	}
	if err := repo.SaveAuthenticationHostname(ctx, sh); err != nil {
		t.Fatalf("first save: %v", err)
	}

	// Upsert same (project_uuid, hostname, session_name) with updated headers
	sh2 := &AuthenticationHostname{
		ProjectUUID: DefaultProjectUUID,
		Hostname:    "example.com",
		SessionName: "admin",
		SessionRole: "compare",
		Headers:     map[string]string{"Authorization": "Bearer new"},
		Source:      "manual",
	}
	if err := repo.SaveAuthenticationHostname(ctx, sh2); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	rows, err := repo.GetAuthenticationHostnamesByHostname(ctx, DefaultProjectUUID, "example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after upsert, got %d", len(rows))
	}
	if rows[0].SessionRole != "compare" {
		t.Errorf("expected role=compare after upsert, got %q", rows[0].SessionRole)
	}
	if rows[0].Headers["Authorization"] != "Bearer new" {
		t.Errorf("expected updated header, got %v", rows[0].Headers)
	}
}

func TestAuthenticationHostname_BatchSave(t *testing.T) {
	db := newTestDB(t)
	defer func() { _ = db.Close() }()
	repo := NewRepository(db)
	ctx := context.Background()

	batch := []*AuthenticationHostname{
		{ProjectUUID: DefaultProjectUUID, Hostname: "a.com", SessionName: "s1", Position: 0},
		{ProjectUUID: DefaultProjectUUID, Hostname: "a.com", SessionName: "s2", Position: 1},
		{ProjectUUID: DefaultProjectUUID, Hostname: "b.com", SessionName: "s1", Position: 0},
	}
	if err := repo.SaveAuthenticationHostnames(ctx, batch); err != nil {
		t.Fatalf("SaveAuthenticationHostnames: %v", err)
	}

	rows, err := repo.GetAuthenticationHostnamesByProject(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("GetAuthenticationHostnamesByProject: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	// Should be ordered: a.com(pos 0), a.com(pos 1), b.com(pos 0)
	if rows[0].Hostname != "a.com" || rows[0].Position != 0 {
		t.Errorf("unexpected first row: %s pos=%d", rows[0].Hostname, rows[0].Position)
	}
	if rows[1].Hostname != "a.com" || rows[1].Position != 1 {
		t.Errorf("unexpected second row: %s pos=%d", rows[1].Hostname, rows[1].Position)
	}
}

func TestAuthenticationHostname_GetByScan(t *testing.T) {
	db := newTestDB(t)
	defer func() { _ = db.Close() }()
	repo := NewRepository(db)
	ctx := context.Background()

	batch := []*AuthenticationHostname{
		{ProjectUUID: DefaultProjectUUID, ScanUUID: "scan-1", Hostname: "a.com", SessionName: "s1"},
		{ProjectUUID: DefaultProjectUUID, ScanUUID: "scan-2", Hostname: "a.com", SessionName: "s2"},
	}
	if err := repo.SaveAuthenticationHostnames(ctx, batch); err != nil {
		t.Fatalf("save: %v", err)
	}

	rows, err := repo.GetAuthenticationHostnamesByScan(ctx, DefaultProjectUUID, "scan-1")
	if err != nil {
		t.Fatalf("get by scan: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row for scan-1, got %d", len(rows))
	}
	if rows[0].SessionName != "s1" {
		t.Errorf("expected s1, got %q", rows[0].SessionName)
	}
}

func TestAuthenticationHostname_DeleteByID(t *testing.T) {
	db := newTestDB(t)
	defer func() { _ = db.Close() }()
	repo := NewRepository(db)
	ctx := context.Background()

	sh := &AuthenticationHostname{
		ProjectUUID: DefaultProjectUUID,
		Hostname:    "del.com",
		SessionName: "sess",
	}
	if err := repo.SaveAuthenticationHostname(ctx, sh); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := repo.DeleteAuthenticationHostname(ctx, sh.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rows, err := repo.GetAuthenticationHostnamesByHostname(ctx, DefaultProjectUUID, "del.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows after delete, got %d", len(rows))
	}
}

func TestAuthenticationHostname_DeleteByHostname(t *testing.T) {
	db := newTestDB(t)
	defer func() { _ = db.Close() }()
	repo := NewRepository(db)
	ctx := context.Background()

	batch := []*AuthenticationHostname{
		{ProjectUUID: DefaultProjectUUID, Hostname: "target.com", SessionName: "a"},
		{ProjectUUID: DefaultProjectUUID, Hostname: "target.com", SessionName: "b"},
		{ProjectUUID: DefaultProjectUUID, Hostname: "other.com", SessionName: "c"},
	}
	if err := repo.SaveAuthenticationHostnames(ctx, batch); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := repo.DeleteAuthenticationHostnamesByHostname(ctx, DefaultProjectUUID, "target.com"); err != nil {
		t.Fatalf("delete by hostname: %v", err)
	}

	rows, err := repo.GetAuthenticationHostnamesByProject(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row (other.com), got %d", len(rows))
	}
	if rows[0].Hostname != "other.com" {
		t.Errorf("expected other.com, got %q", rows[0].Hostname)
	}
}
