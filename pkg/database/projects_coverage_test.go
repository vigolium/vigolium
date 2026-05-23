package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// makeProject inserts a project row and returns it.
func makeProject(t *testing.T, repo *Repository, name, owner string) *Project {
	t.Helper()
	ctx := context.Background()
	p := &Project{
		UUID:      uuid.NewString(),
		Name:      name,
		OwnerUUID: owner,
	}
	if err := repo.CreateProject(ctx, p); err != nil {
		t.Fatalf("CreateProject(%q): %v", name, err)
	}
	return p
}

func TestUserCRUD(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	u := &User{UUID: uuid.NewString(), Name: "alice", Email: "alice@example.com"}
	if err := repo.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := repo.GetUserByUUID(ctx, u.UUID)
	if err != nil {
		t.Fatalf("GetUserByUUID: %v", err)
	}
	if got.Name != "alice" || got.Email != "alice@example.com" {
		t.Errorf("user mismatch: %+v", got)
	}

	// UpsertUser updates name/email for existing UUID.
	u2 := &User{UUID: u.UUID, Name: "alice2", Email: "alice2@example.com"}
	if err := repo.UpsertUser(ctx, u2); err != nil {
		t.Fatalf("UpsertUser (update): %v", err)
	}
	got, err = repo.GetUserByUUID(ctx, u.UUID)
	if err != nil {
		t.Fatalf("GetUserByUUID after upsert: %v", err)
	}
	if got.Name != "alice2" {
		t.Errorf("upsert did not update name: %q", got.Name)
	}

	// UpsertUser inserts a brand-new UUID.
	u3 := &User{UUID: uuid.NewString(), Name: "bob"}
	if err := repo.UpsertUser(ctx, u3); err != nil {
		t.Fatalf("UpsertUser (insert): %v", err)
	}

	users, err := repo.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("ListUsers = %d, want 2", len(users))
	}

	// Error paths.
	if err := repo.CreateUser(ctx, nil); err == nil {
		t.Error("CreateUser(nil) should error")
	}
	if err := repo.UpsertUser(ctx, &User{}); err == nil {
		t.Error("UpsertUser with empty UUID should error")
	}
}

func TestProjectCRUD(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	owner := uuid.NewString()
	p := makeProject(t, repo, "proj-alpha", owner)

	got, err := repo.GetProjectByUUID(ctx, p.UUID)
	if err != nil {
		t.Fatalf("GetProjectByUUID: %v", err)
	}
	if got.Name != "proj-alpha" {
		t.Errorf("name mismatch: %q", got.Name)
	}

	byName, err := repo.GetProjectByName(ctx, "proj-alpha")
	if err != nil {
		t.Fatalf("GetProjectByName: %v", err)
	}
	if byName.UUID != p.UUID {
		t.Errorf("GetProjectByName returned wrong project: %q", byName.UUID)
	}

	// Update.
	got.Description = "updated desc"
	if err := repo.UpdateProject(ctx, got); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	reread, _ := repo.GetProjectByUUID(ctx, p.UUID)
	if reread.Description != "updated desc" {
		t.Errorf("UpdateProject did not persist: %q", reread.Description)
	}

	// Second project with same owner; list filtered by owner.
	makeProject(t, repo, "proj-beta", owner)
	makeProject(t, repo, "proj-other", uuid.NewString())

	owned, err := repo.ListProjects(ctx, owner)
	if err != nil {
		t.Fatalf("ListProjects(owner): %v", err)
	}
	if len(owned) != 2 {
		t.Errorf("ListProjects(owner) = %d, want 2", len(owned))
	}

	all, err := repo.ListProjects(ctx, "")
	if err != nil {
		t.Fatalf("ListProjects(all): %v", err)
	}
	if len(all) != 3 {
		t.Errorf("ListProjects(all) = %d, want 3", len(all))
	}

	// Delete.
	if err := repo.DeleteProject(ctx, p.UUID); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if _, err := repo.GetProjectByUUID(ctx, p.UUID); err == nil {
		t.Error("GetProjectByUUID should fail after delete")
	}

	// Error paths.
	if err := repo.CreateProject(ctx, nil); err == nil {
		t.Error("CreateProject(nil) should error")
	}
	if err := repo.UpdateProject(ctx, nil); err == nil {
		t.Error("UpdateProject(nil) should error")
	}
	if _, err := repo.GetProjectByName(ctx, "does-not-exist"); err == nil {
		t.Error("GetProjectByName(missing) should error")
	}
}

func TestGetProjectByName_AmbiguousErrors(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	makeProject(t, repo, "dup-name", uuid.NewString())
	makeProject(t, repo, "dup-name", uuid.NewString())

	if _, err := repo.GetProjectByName(ctx, "dup-name"); err == nil {
		t.Error("GetProjectByName with duplicate names should error")
	}
}

func TestReassignAndPurgeProjectData(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	src := uuid.NewString()
	dst := uuid.NewString()

	// Seed source project with one record and one finding.
	insertRecordP(t, repo, src, "GET", "src.example.com", "/x", 200)
	saveFindingP(t, repo, src, "mod", SeverityHigh)

	// Reassign moves data to dst.
	if err := repo.ReassignProjectData(ctx, src, dst); err != nil {
		t.Fatalf("ReassignProjectData: %v", err)
	}
	srcCount, _ := db.NewSelect().Model((*HTTPRecord)(nil)).Where("project_uuid = ?", src).Count(ctx)
	dstCount, _ := db.NewSelect().Model((*HTTPRecord)(nil)).Where("project_uuid = ?", dst).Count(ctx)
	if srcCount != 0 || dstCount != 1 {
		t.Errorf("reassign records: src=%d dst=%d, want 0/1", srcCount, dstCount)
	}

	// Purge wipes dst entirely.
	if err := repo.PurgeProjectData(ctx, dst); err != nil {
		t.Fatalf("PurgeProjectData: %v", err)
	}
	dstRecords, _ := db.NewSelect().Model((*HTTPRecord)(nil)).Where("project_uuid = ?", dst).Count(ctx)
	dstFindings, _ := db.NewSelect().Model((*Finding)(nil)).Where("project_uuid = ?", dst).Count(ctx)
	if dstRecords != 0 || dstFindings != 0 {
		t.Errorf("purge left data: records=%d findings=%d", dstRecords, dstFindings)
	}
}

func TestGetProjectStatsAndAll(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projA := uuid.NewString()
	projB := uuid.NewString()

	// Project A: 2 records (200, 404), 1 high finding, 1 scan.
	insertRecordP(t, repo, projA, "GET", "a.example.com", "/ok", 200)
	insertRecordP(t, repo, projA, "GET", "a.example.com", "/missing", 404)
	saveFindingP(t, repo, projA, "modA", SeverityHigh)
	if err := repo.CreateScan(ctx, &Scan{UUID: uuid.NewString(), ProjectUUID: projA, Status: "running"}); err != nil {
		t.Fatalf("CreateScan A: %v", err)
	}

	// Project B: 1 record (500), 1 critical finding.
	insertRecordP(t, repo, projB, "POST", "b.example.com", "/boom", 500)
	saveFindingP(t, repo, projB, "modB", SeverityCritical)

	statsA, err := repo.GetProjectStats(ctx, projA)
	if err != nil {
		t.Fatalf("GetProjectStats A: %v", err)
	}
	if statsA.HTTPRecords != 2 {
		t.Errorf("A http records = %d, want 2", statsA.HTTPRecords)
	}
	if statsA.HTTP2xx != 1 || statsA.HTTP4xx != 1 {
		t.Errorf("A status breakdown wrong: 2xx=%d 4xx=%d", statsA.HTTP2xx, statsA.HTTP4xx)
	}
	if statsA.Findings != 1 || statsA.High != 1 {
		t.Errorf("A findings wrong: total=%d high=%d", statsA.Findings, statsA.High)
	}
	if statsA.Scans != 1 {
		t.Errorf("A scans = %d, want 1", statsA.Scans)
	}

	all, err := repo.GetAllProjectsStats(ctx)
	if err != nil {
		t.Fatalf("GetAllProjectsStats: %v", err)
	}
	if all[projA] == nil || all[projB] == nil {
		t.Fatalf("GetAllProjectsStats missing projects: %v", all)
	}
	if all[projB].HTTP5xx != 1 || all[projB].Critical != 1 {
		t.Errorf("B aggregate wrong: 5xx=%d critical=%d", all[projB].HTTP5xx, all[projB].Critical)
	}
}
