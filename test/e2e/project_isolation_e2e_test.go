//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/server"
)

// projectTestEnv wraps settingsTestEnv with project-aware request helpers.
type projectTestEnv struct {
	*settingsTestEnv
}

func newProjectTestEnv(t *testing.T) *projectTestEnv {
	t.Helper()
	return &projectTestEnv{newSettingsTestEnv(t, "")}
}

// postWithProject sends a POST with X-Project-UUID header.
func (env *projectTestEnv) postWithProject(t *testing.T, path, body, projectUUID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project-UUID", projectUUID)
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// getWithProject sends a GET with X-Project-UUID header.
func (env *projectTestEnv) getWithProject(t *testing.T, path, projectUUID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.url+path, nil)
	require.NoError(t, err)
	req.Header.Set("X-Project-UUID", projectUUID)
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// putWithProject sends a PUT with X-Project-UUID header.
func (env *projectTestEnv) putWithProject(t *testing.T, path, body, projectUUID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project-UUID", projectUUID)
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// deleteWithProject sends a DELETE with X-Project-UUID header.
func (env *projectTestEnv) deleteWithProject(t *testing.T, path, projectUUID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, env.url+path, nil)
	require.NoError(t, err)
	req.Header.Set("X-Project-UUID", projectUUID)
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// createProject creates a project and returns its UUID.
func (env *projectTestEnv) createProject(t *testing.T, name string) string {
	t.Helper()
	resp := env.post(t, "/api/projects", fmt.Sprintf(`{"name":"%s"}`, name))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var project database.Project
	readJSON(t, resp, &project)
	require.NotEmpty(t, project.UUID)
	return project.UUID
}

// ============================================================
// Project CRUD
// ============================================================

func TestProject_Create(t *testing.T) {
	env := newProjectTestEnv(t)

	resp := env.post(t, "/api/projects", `{"name":"Test Project","description":"A test project"}`)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var project database.Project
	readJSON(t, resp, &project)
	assert.Equal(t, "Test Project", project.Name)
	assert.Equal(t, "A test project", project.Description)
	assert.NotEmpty(t, project.UUID)
	assert.NotEqual(t, database.DefaultProjectUUID, project.UUID)
}

func TestProject_Create_MissingName(t *testing.T) {
	env := newProjectTestEnv(t)

	resp := env.post(t, "/api/projects", `{"description":"no name"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "name")
}

func TestProject_List(t *testing.T) {
	env := newProjectTestEnv(t)

	env.createProject(t, "Project A")
	env.createProject(t, "Project B")

	resp := env.get(t, "/api/projects")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var projects []database.Project
	readJSON(t, resp, &projects)
	// At least 2 created + the default project from SeedDefaults (if seeded)
	assert.GreaterOrEqual(t, len(projects), 2)
}

func TestProject_GetByUUID(t *testing.T) {
	env := newProjectTestEnv(t)

	uuid := env.createProject(t, "Fetchable Project")

	resp := env.get(t, "/api/projects/"+uuid)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var project database.Project
	readJSON(t, resp, &project)
	assert.Equal(t, uuid, project.UUID)
	assert.Equal(t, "Fetchable Project", project.Name)
}

func TestProject_GetByUUID_NotFound(t *testing.T) {
	env := newProjectTestEnv(t)

	resp := env.get(t, "/api/projects/nonexistent-uuid")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestProject_Update(t *testing.T) {
	env := newProjectTestEnv(t)

	uuid := env.createProject(t, "Original Name")

	resp := env.put(t, "/api/projects/"+uuid, `{"name":"Updated Name","description":"new desc"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var project database.Project
	readJSON(t, resp, &project)
	assert.Equal(t, "Updated Name", project.Name)
	assert.Equal(t, "new desc", project.Description)
}

func TestProject_Delete(t *testing.T) {
	env := newProjectTestEnv(t)

	uuid := env.createProject(t, "Deletable Project")

	resp := env.doDelete(t, "/api/projects/"+uuid)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	readJSON(t, resp, &body)
	assert.Equal(t, "project deleted", body["message"])

	// Confirm gone
	resp = env.get(t, "/api/projects/"+uuid)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestProject_Delete_DefaultProject_Forbidden(t *testing.T) {
	env := newProjectTestEnv(t)

	resp := env.doDelete(t, "/api/projects/"+database.DefaultProjectUUID)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "default project")
}

// ============================================================
// HTTP Records — project isolation
// ============================================================

func TestProject_Records_Isolation(t *testing.T) {
	env := newProjectTestEnv(t)

	projA := env.createProject(t, "Project A")
	projB := env.createProject(t, "Project B")

	// Ingest records into project A
	resp := env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://alpha.example.com/page1"}`, projA)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp = env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://alpha.example.com/page2"}`, projA)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Ingest records into project B
	resp = env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://beta.example.com/page1"}`, projB)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// List records for project A — should see 2
	resp = env.getWithProject(t, "/api/http-records", projA)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var bodyA server.PaginatedResponse
	readJSON(t, resp, &bodyA)
	assert.Equal(t, int64(2), bodyA.Total)
	assert.Equal(t, projA, bodyA.ProjectUUID)

	// List records for project B — should see 1
	resp = env.getWithProject(t, "/api/http-records", projB)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var bodyB server.PaginatedResponse
	readJSON(t, resp, &bodyB)
	assert.Equal(t, int64(1), bodyB.Total)
	assert.Equal(t, projB, bodyB.ProjectUUID)
}

func TestProject_Records_DefaultProject_Fallback(t *testing.T) {
	env := newProjectTestEnv(t)

	// Ingest without X-Project-UUID header → should go to default project
	resp := env.post(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://default.example.com/page"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var ingestResp server.IngestHTTPResponse
	readJSON(t, resp, &ingestResp)
	assert.Equal(t, database.DefaultProjectUUID, ingestResp.ProjectUUID)

	// List without header → default project
	resp = env.get(t, "/api/http-records")
	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(1), body.Total)
	assert.Equal(t, database.DefaultProjectUUID, body.ProjectUUID)
}

func TestProject_Records_CrossProject_NotVisible(t *testing.T) {
	env := newProjectTestEnv(t)

	projA := env.createProject(t, "Isolated A")
	projB := env.createProject(t, "Isolated B")

	// Ingest into project A only
	resp := env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://secret.example.com/data"}`, projA)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Query from project B — should see 0
	resp = env.getWithProject(t, "/api/http-records", projB)
	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(0), body.Total)
}

func TestProject_Records_FilterByDomain_WithinProject(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "Filter Test")

	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://alpha.test/a"}`, proj).Body.Close()
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://beta.test/b"}`, proj).Body.Close()

	// Filter by domain within project
	resp := env.getWithProject(t, "/api/http-records?domain=alpha.test", proj)
	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(1), body.Total)
}

// ============================================================
// Findings — project isolation
// ============================================================

func TestProject_Findings_Isolation(t *testing.T) {
	env := newProjectTestEnv(t)

	projA := env.createProject(t, "Findings A")
	projB := env.createProject(t, "Findings B")

	ctx := context.Background()

	// Insert findings directly into the DB for each project
	findingA := &database.Finding{
		ProjectUUID: projA,
		ModuleName:  "test-module",
		Severity:    "high",
		Description: "Finding in Project A",
		FindingHash: "hash-a-1",
	}
	_, err := env.db.NewInsert().Model(findingA).Exec(ctx)
	require.NoError(t, err)

	findingB := &database.Finding{
		ProjectUUID: projB,
		ModuleName:  "test-module",
		Severity:    "medium",
		Description: "Finding in Project B",
		FindingHash: "hash-b-1",
	}
	_, err = env.db.NewInsert().Model(findingB).Exec(ctx)
	require.NoError(t, err)

	// Query findings for project A
	resp := env.getWithProject(t, "/api/findings", projA)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var bodyA server.PaginatedResponse
	readJSON(t, resp, &bodyA)
	assert.Equal(t, int64(1), bodyA.Total)
	assert.Equal(t, projA, bodyA.ProjectUUID)

	// Query findings for project B
	resp = env.getWithProject(t, "/api/findings", projB)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var bodyB server.PaginatedResponse
	readJSON(t, resp, &bodyB)
	assert.Equal(t, int64(1), bodyB.Total)
	assert.Equal(t, projB, bodyB.ProjectUUID)
}

func TestProject_Findings_EmptyForNewProject(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "Empty Findings")

	resp := env.getWithProject(t, "/api/findings", proj)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(0), body.Total)
}

// ============================================================
// Stats — project scoping
// ============================================================

func TestProject_Stats_ScopedToProject(t *testing.T) {
	env := newProjectTestEnv(t)

	projA := env.createProject(t, "Stats A")
	projB := env.createProject(t, "Stats B")

	// Ingest records into project A
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://stats-a1.example.com/x"}`, projA).Body.Close()
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://stats-a2.example.com/y"}`, projA).Body.Close()

	// Ingest records into project B
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://stats-b1.example.com/z"}`, projB).Body.Close()

	// Stats for project A
	resp := env.getWithProject(t, "/api/stats", projA)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var statsA server.StatsResponse
	readJSON(t, resp, &statsA)
	assert.Equal(t, projA, statsA.ProjectUUID)
	assert.Equal(t, int64(2), statsA.HTTPRecords.Total)

	// Stats for project B
	resp = env.getWithProject(t, "/api/stats", projB)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var statsB server.StatsResponse
	readJSON(t, resp, &statsB)
	assert.Equal(t, projB, statsB.ProjectUUID)
	assert.Equal(t, int64(1), statsB.HTTPRecords.Total)
}

func TestProject_Stats_FindingsCount_ScopedToProject(t *testing.T) {
	env := newProjectTestEnv(t)

	projA := env.createProject(t, "Stats Findings A")
	projB := env.createProject(t, "Stats Findings B")

	ctx := context.Background()

	// Insert findings for project A
	for i := 0; i < 3; i++ {
		f := &database.Finding{
			ProjectUUID: projA,
			ModuleName:  "test-module",
			Severity:    "high",
			Description: fmt.Sprintf("Finding A-%d", i),
			FindingHash: fmt.Sprintf("stats-hash-a-%d", i),
		}
		_, err := env.db.NewInsert().Model(f).Exec(ctx)
		require.NoError(t, err)
	}

	// Insert findings for project B
	f := &database.Finding{
		ProjectUUID: projB,
		ModuleName:  "test-module",
		Severity:    "low",
		Description: "Finding B-0",
		FindingHash: "stats-hash-b-0",
	}
	_, err := env.db.NewInsert().Model(f).Exec(ctx)
	require.NoError(t, err)

	// Stats for project A
	resp := env.getWithProject(t, "/api/stats", projA)
	var statsA server.StatsResponse
	readJSON(t, resp, &statsA)
	assert.Equal(t, int64(3), statsA.Findings.Total)

	// Stats for project B
	resp = env.getWithProject(t, "/api/stats", projB)
	var statsB server.StatsResponse
	readJSON(t, resp, &statsB)
	assert.Equal(t, int64(1), statsB.Findings.Total)
}

// ============================================================
// Ingest — project_uuid in responses
// ============================================================

func TestProject_Ingest_ReturnsProjectUUID(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "Ingest UUID Test")

	resp := env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://example.com/ingest-uuid-test"}`, proj)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, proj, body.ProjectUUID)
	assert.Equal(t, 1, body.Imported)
}

func TestProject_Ingest_CurlMode_ProjectScoped(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "Curl Project")

	resp := env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"curl","content":"curl http://curl-project.example.com/api"}`, proj)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, proj, body.ProjectUUID)
	assert.Equal(t, 1, body.Imported)

	// Verify it shows up under the right project
	resp = env.getWithProject(t, "/api/http-records", proj)
	var records server.PaginatedResponse
	readJSON(t, resp, &records)
	assert.Equal(t, int64(1), records.Total)
}

// ============================================================
// PaginatedResponse includes project_uuid
// ============================================================

func TestProject_PaginatedResponse_IncludesProjectUUID(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "Paginated UUID")

	// Check records endpoint
	resp := env.getWithProject(t, "/api/http-records", proj)
	var recordsResp server.PaginatedResponse
	readJSON(t, resp, &recordsResp)
	assert.Equal(t, proj, recordsResp.ProjectUUID)

	// Check findings endpoint
	resp = env.getWithProject(t, "/api/findings", proj)
	var findingsResp server.PaginatedResponse
	readJSON(t, resp, &findingsResp)
	assert.Equal(t, proj, findingsResp.ProjectUUID)
}

// ============================================================
// Project delete — data reassignment
// ============================================================

func TestProject_Delete_ReassignsDataToDefault(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "Soon Deleted")

	// Ingest a record into this project
	resp := env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://reassign.example.com/page"}`, proj)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Verify it's in the project
	resp = env.getWithProject(t, "/api/http-records", proj)
	var before server.PaginatedResponse
	readJSON(t, resp, &before)
	assert.Equal(t, int64(1), before.Total)

	// Delete the project — data should be reassigned to default
	resp = env.doDelete(t, "/api/projects/"+proj)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// The record should now appear under the default project
	resp = env.getWithProject(t, "/api/http-records?domain=reassign.example.com", database.DefaultProjectUUID)
	var after server.PaginatedResponse
	readJSON(t, resp, &after)
	assert.Equal(t, int64(1), after.Total, "record should be reassigned to default project")
}

// ============================================================
// Multiple projects — full lifecycle
// ============================================================

func TestProject_FullLifecycle_MultiProject(t *testing.T) {
	env := newProjectTestEnv(t)

	// Create two projects
	projA := env.createProject(t, "Lifecycle A")
	projB := env.createProject(t, "Lifecycle B")

	// Ingest data into both
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://a1.example.com/x"}`, projA).Body.Close()
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://a2.example.com/y"}`, projA).Body.Close()
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://b1.example.com/z"}`, projB).Body.Close()

	// Insert findings
	ctx := context.Background()
	_, err := env.db.NewInsert().Model(&database.Finding{
		ProjectUUID: projA,
		ModuleName:  "xss-scanner",
		Severity:    "high",
		Description: "XSS in A",
		FindingHash: "lifecycle-a",
	}).Exec(ctx)
	require.NoError(t, err)

	// Verify full isolation: project A stats
	resp := env.getWithProject(t, "/api/stats", projA)
	var statsA server.StatsResponse
	readJSON(t, resp, &statsA)
	assert.Equal(t, int64(2), statsA.HTTPRecords.Total)
	assert.Equal(t, int64(1), statsA.Findings.Total)

	// Verify full isolation: project B stats
	resp = env.getWithProject(t, "/api/stats", projB)
	var statsB server.StatsResponse
	readJSON(t, resp, &statsB)
	assert.Equal(t, int64(1), statsB.HTTPRecords.Total)
	assert.Equal(t, int64(0), statsB.Findings.Total)

	// Verify project A records
	resp = env.getWithProject(t, "/api/http-records", projA)
	var recordsA server.PaginatedResponse
	readJSON(t, resp, &recordsA)
	assert.Equal(t, int64(2), recordsA.Total)

	// Verify project A findings
	resp = env.getWithProject(t, "/api/findings", projA)
	var findingsA server.PaginatedResponse
	readJSON(t, resp, &findingsA)
	assert.Equal(t, int64(1), findingsA.Total)

	// Verify project B findings
	resp = env.getWithProject(t, "/api/findings", projB)
	var findingsB server.PaginatedResponse
	readJSON(t, resp, &findingsB)
	assert.Equal(t, int64(0), findingsB.Total)
}

// ============================================================
// Scan — project scoping
// ============================================================

func TestProject_ScanAllRecords_NoRecords_ReturnsError(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "Empty Scan Project")

	// Trigger scan-all-records in empty project
	resp := env.postWithProject(t, "/api/scan-all-records", `{}`, proj)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "no records")
}

// ============================================================
// Raw JSON structure — verify project_uuid present in responses
// ============================================================

func TestProject_ResponseJSON_ContainsProjectUUID(t *testing.T) {
	env := newProjectTestEnv(t)

	proj := env.createProject(t, "JSON Check")

	// Ingest a record
	env.postWithProject(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://json-check.example.com/x"}`, proj).Body.Close()

	// Check raw JSON for http-records
	resp := env.getWithProject(t, "/api/http-records", proj)
	defer resp.Body.Close()
	var raw map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))
	assert.Contains(t, raw, "project_uuid", "http-records response should contain project_uuid field")

	// Check raw JSON for stats
	resp = env.getWithProject(t, "/api/stats", proj)
	defer resp.Body.Close()
	var rawStats map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rawStats))
	assert.Contains(t, rawStats, "project_uuid", "stats response should contain project_uuid field")
}
