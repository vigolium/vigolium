package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAuthenticationHostnamesCRUD(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	proj := uuid.NewString()
	scanUUID := uuid.NewString()

	sh := &AuthenticationHostname{
		ProjectUUID:  proj,
		ScanUUID:     scanUUID,
		Hostname:     "app.example.com",
		SessionName:  "admin",
		SessionRole:  "admin",
		Position:     0,
		SessionToken: "tok-123",
		Headers:      map[string]string{"Authorization": "Bearer tok-123"},
	}
	if err := repo.SaveAuthenticationHostname(ctx, sh); err != nil {
		t.Fatalf("SaveAuthenticationHostname: %v", err)
	}

	// Upsert: same (project, hostname, session_name) updates rather than dups.
	sh2 := &AuthenticationHostname{
		ProjectUUID:  proj,
		ScanUUID:     scanUUID,
		Hostname:     "app.example.com",
		SessionName:  "admin",
		SessionToken: "tok-456",
	}
	if err := repo.SaveAuthenticationHostname(ctx, sh2); err != nil {
		t.Fatalf("SaveAuthenticationHostname (upsert): %v", err)
	}

	// Batch upsert adds a second session for the same host.
	if err := repo.SaveAuthenticationHostnames(ctx, []*AuthenticationHostname{
		{ProjectUUID: proj, ScanUUID: scanUUID, Hostname: "app.example.com", SessionName: "user", Position: 1},
	}); err != nil {
		t.Fatalf("SaveAuthenticationHostnames: %v", err)
	}

	byHost, err := repo.GetAuthenticationHostnamesByHostname(ctx, proj, "app.example.com")
	if err != nil {
		t.Fatalf("GetAuthenticationHostnamesByHostname: %v", err)
	}
	if len(byHost) != 2 {
		t.Fatalf("GetAuthenticationHostnamesByHostname = %d, want 2 (upsert kept one admin row)", len(byHost))
	}
	// admin row carries the upserted token.
	if byHost[0].SessionToken != "tok-456" {
		t.Errorf("upsert did not update token: %q", byHost[0].SessionToken)
	}

	byProject, err := repo.GetAuthenticationHostnamesByProject(ctx, proj)
	if err != nil {
		t.Fatalf("GetAuthenticationHostnamesByProject: %v", err)
	}
	if len(byProject) != 2 {
		t.Errorf("GetAuthenticationHostnamesByProject = %d, want 2", len(byProject))
	}

	byScan, err := repo.GetAuthenticationHostnamesByScan(ctx, proj, scanUUID)
	if err != nil {
		t.Fatalf("GetAuthenticationHostnamesByScan: %v", err)
	}
	if len(byScan) != 2 {
		t.Errorf("GetAuthenticationHostnamesByScan = %d, want 2", len(byScan))
	}

	// Delete one by ID.
	if err := repo.DeleteAuthenticationHostname(ctx, byHost[1].ID); err != nil {
		t.Fatalf("DeleteAuthenticationHostname: %v", err)
	}
	// Delete the rest by hostname.
	if err := repo.DeleteAuthenticationHostnamesByHostname(ctx, proj, "app.example.com"); err != nil {
		t.Fatalf("DeleteAuthenticationHostnamesByHostname: %v", err)
	}
	remaining, _ := repo.GetAuthenticationHostnamesByProject(ctx, proj)
	if len(remaining) != 0 {
		t.Errorf("after deletes remaining = %d, want 0", len(remaining))
	}

	// Nil insert / empty batch.
	if err := repo.SaveAuthenticationHostname(ctx, nil); err == nil {
		t.Error("SaveAuthenticationHostname(nil) should error")
	}
	if err := repo.SaveAuthenticationHostnames(ctx, nil); err != nil {
		t.Errorf("SaveAuthenticationHostnames(nil): %v", err)
	}
}
