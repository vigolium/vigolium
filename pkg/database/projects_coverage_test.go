package database

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vigolium/vigolium/pkg/apicontract"
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

// TestReassignProjectData_MovesAllOwnedTables guards the fix that reassignment
// covers the full project-owned table set (it previously omitted agentic_scans and
// authentication_hostnames, which then stayed pinned to the deleted source project).
func TestReassignProjectData_MovesAllOwnedTables(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	src := uuid.NewString()
	dst := uuid.NewString()

	agentUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: agentUUID, ProjectUUID: src, Status: "completed"}); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}
	if err := repo.SaveAuthenticationHostname(ctx, &AuthenticationHostname{ProjectUUID: src, Hostname: "auth.example.com"}); err != nil {
		t.Fatalf("SaveAuthenticationHostname: %v", err)
	}
	// analysis_artifacts carries project_uuid but was previously omitted from the
	// owned-table set, so reassignment left its rows pinned to the deleted source.
	if _, err := db.NewInsert().Model(&AnalysisArtifact{
		ProjectUUID:    src,
		HTTPRecordUUID: uuid.NewString(),
		Kind:           "test",
		SHA256:         "deadbeef",
		ByteLength:     3,
		Content:        []byte("xyz"),
	}).Exec(ctx); err != nil {
		t.Fatalf("insert analysis_artifact: %v", err)
	}

	if err := repo.ReassignProjectData(ctx, src, dst); err != nil {
		t.Fatalf("ReassignProjectData: %v", err)
	}

	agentSrc, _ := db.NewSelect().Model((*AgenticScan)(nil)).Where("project_uuid = ?", src).Count(ctx)
	agentDst, _ := db.NewSelect().Model((*AgenticScan)(nil)).Where("project_uuid = ?", dst).Count(ctx)
	if agentSrc != 0 || agentDst != 1 {
		t.Errorf("agentic_scans reassign: src=%d dst=%d, want 0/1 (was previously omitted)", agentSrc, agentDst)
	}
	authSrc, _ := db.NewSelect().Model((*AuthenticationHostname)(nil)).Where("project_uuid = ?", src).Count(ctx)
	authDst, _ := db.NewSelect().Model((*AuthenticationHostname)(nil)).Where("project_uuid = ?", dst).Count(ctx)
	if authSrc != 0 || authDst != 1 {
		t.Errorf("authentication_hostnames reassign: src=%d dst=%d, want 0/1 (was previously omitted)", authSrc, authDst)
	}
	artSrc, _ := db.NewSelect().Model((*AnalysisArtifact)(nil)).Where("project_uuid = ?", src).Count(ctx)
	artDst, _ := db.NewSelect().Model((*AnalysisArtifact)(nil)).Where("project_uuid = ?", dst).Count(ctx)
	if artSrc != 0 || artDst != 1 {
		t.Errorf("analysis_artifacts reassign: src=%d dst=%d, want 0/1 (was previously omitted)", artSrc, artDst)
	}
}

// TestProjectOwnedTablesMatchesSchema is a self-maintaining guard: it enumerates
// every table in the schema that actually carries a project_uuid column and fails
// if that set diverges from projectOwnedTables. This would have caught the
// analysis_artifacts omission the moment the table was added, without anyone
// remembering to update a hand-maintained seed list.
func TestProjectOwnedTablesMatchesSchema(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	var tableNames []string
	if err := db.NewRaw(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
	).Scan(ctx, &tableNames); err != nil {
		t.Fatalf("list tables: %v", err)
	}

	schemaOwned := map[string]bool{}
	for _, tbl := range tableNames {
		// Table names come from sqlite_master (trusted); the table-valued
		// pragma_table_info form lets us project just the column name.
		var colNames []string
		if err := db.NewRaw(fmt.Sprintf("SELECT name FROM pragma_table_info('%s')", tbl)).Scan(ctx, &colNames); err != nil {
			t.Fatalf("table_info(%s): %v", tbl, err)
		}
		for _, name := range colNames {
			if name == "project_uuid" {
				schemaOwned[tbl] = true
				break
			}
		}
	}

	listed := map[string]bool{}
	for _, tbl := range projectOwnedTables {
		listed[tbl] = true
		if !schemaOwned[tbl] {
			t.Errorf("projectOwnedTables lists %q but it has no project_uuid column in the schema", tbl)
		}
	}
	for tbl := range schemaOwned {
		if !listed[tbl] {
			t.Errorf("table %q has a project_uuid column but is missing from projectOwnedTables (reassign/purge would orphan its rows)", tbl)
		}
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

// A --project-name that resolves to no project or to several carries a code,
// so the CLI reports project_not_found / ambiguous_id instead of "failed".
func TestGetProjectByNameErrorCodes(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	makeProject(t, repo, "dup", "")
	makeProject(t, repo, "dup", "")

	codeOf := func(err error) string {
		var coded interface{ Code() apicontract.ErrorCode }
		if !errors.As(err, &coded) {
			return ""
		}
		return string(coded.Code())
	}
	_, err := repo.GetProjectByName(ctx, "nope")
	if codeOf(err) != "project_not_found" {
		t.Errorf("missing name: %v (%q)", err, codeOf(err))
	}
	_, err = repo.GetProjectByName(ctx, "dup")
	if codeOf(err) != "ambiguous_id" {
		t.Errorf("ambiguous name: %v (%q)", err, codeOf(err))
	}
}
