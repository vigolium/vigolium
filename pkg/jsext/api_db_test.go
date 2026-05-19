package jsext

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

// setupDBTestVM creates a VM with the DB API installed and returns it along with the repo.
func setupDBTestVM(t *testing.T) (*sobek.Runtime, *database.Repository) {
	t.Helper()
	repo := newTestRepo(t)
	vm := sobek.New()
	opts := APIOptions{
		ScriptID:   "test",
		Repository: repo,
	}
	SetupAPI(vm, opts)
	return vm, repo
}

// insertTestRecord creates and persists a minimal HTTPRecord for testing.
func insertTestRecord(t *testing.T, repo *database.Repository, uuid, hostname, path string, statusCode int, body string) {
	t.Helper()
	rawResp := []byte(fmt.Sprintf(
		"HTTP/1.1 %d OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, len(body), body,
	))
	records := []*database.HTTPRecord{
		{
			UUID:        uuid,
			ProjectUUID: database.DefaultProjectUUID,
			Hostname:    hostname,
			Scheme:      "https",
			Port:        443,
			Method:      "GET",
			Path:        path,
			URL:         "https://" + hostname + path,
			HTTPVersion: "1.1",
			RequestHash: uuid + "-hash",
			StatusCode:  statusCode,
			HasResponse: true,
			RawResponse: rawResp,
			SentAt:      time.Now(),
			Source:      "test",
		},
	}
	_, err := repo.SaveRecordsBatch(context.Background(), records)
	require.NoError(t, err)
}

// insertTestFinding creates and persists a minimal Finding for testing.
func insertTestFinding(t *testing.T, repo *database.Repository, hash, moduleID, severity string, uuids []string) {
	t.Helper()
	f := &database.Finding{
		ProjectUUID:     database.DefaultProjectUUID,
		ModuleID:        moduleID,
		ModuleName:      moduleID + "-name",
		Severity:        severity,
		Confidence:      "firm",
		FindingHash:     hash,
		HTTPRecordUUIDs: uuids,
		FoundAt:         time.Now(),
	}
	err := repo.SaveFindingDirect(context.Background(), f)
	require.NoError(t, err)
}

// ── records.get ─────────────────────────────────────────────────────────────

func TestDBRecordsGet(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-001", "example.com", "/api/users/1", 200, `{"id":1}`)

	val, err := vm.RunString(`vigolium.db.records.get("uuid-001")`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	obj := val.ToObject(vm)
	assert.Equal(t, "uuid-001", obj.Get("uuid").String())
	assert.Equal(t, "example.com", obj.Get("hostname").String())
	assert.Equal(t, "/api/users/1", obj.Get("path").String())
	assert.Equal(t, int64(200), obj.Get("status_code").ToInteger())
	assert.Equal(t, `{"id":1}`, obj.Get("response_body").String())
}

func TestDBRecordsGetMissing(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.records.get("does-not-exist")`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(val))
}

// ── records.query ───────────────────────────────────────────────────────────

func TestDBRecordsQuery(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-q1", "example.com", "/api/users/1", 200, `{"id":1}`)
	insertTestRecord(t, repo, "uuid-q2", "example.com", "/api/users/2", 200, `{"id":2}`)
	insertTestRecord(t, repo, "uuid-q3", "other.com", "/api/users/3", 200, `{"id":3}`)

	// Filter by hostname
	val, err := vm.RunString(`vigolium.db.records.query({hostname: "example.com", limit: 10})`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.Equal(t, int64(2), arr.Get("length").ToInteger())
}

func TestDBRecordsQueryEmpty(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.records.query({hostname: "nonexistent.com"})`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.Equal(t, int64(0), arr.Get("length").ToInteger())
}

func TestDBRecordsQueryNoFilters(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-all1", "example.com", "/a", 200, "body")
	insertTestRecord(t, repo, "uuid-all2", "example.com", "/b", 200, "body")

	val, err := vm.RunString(`vigolium.db.records.query({limit: 5})`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.GreaterOrEqual(t, arr.Get("length").ToInteger(), int64(2))
}

// ── records.getRelated ──────────────────────────────────────────────────────

func TestDBRecordsGetRelated(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-r1", "example.com", "/api/users/1", 200, `{"id":1,"name":"Alice"}`)
	insertTestRecord(t, repo, "uuid-r2", "example.com", "/api/users/2", 200, `{"id":2,"name":"Bob"}`)
	insertTestRecord(t, repo, "uuid-r3", "example.com", "/api/users/3", 200, `{"id":3,"name":"Charlie"}`)
	insertTestRecord(t, repo, "uuid-r4", "other.com", "/api/users/4", 200, `{"id":4}`)       // Different host
	insertTestRecord(t, repo, "uuid-r5", "example.com", "/api/orders/1", 200, `{"order":1}`) // Different path

	val, err := vm.RunString(`vigolium.db.records.getRelated("uuid-r1", {limit: 10})`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	// Should find uuid-r2 and uuid-r3 (same hostname + path template, not self)
	assert.Equal(t, int64(2), arr.Get("length").ToInteger())
}

func TestDBRecordsGetRelatedNotFound(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.records.getRelated("nonexistent-uuid")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.Equal(t, int64(0), arr.Get("length").ToInteger())
}

// ── records.annotate ────────────────────────────────────────────────────────

func TestDBRecordsAnnotateRiskScore(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-ann1", "example.com", "/api/test", 200, "body")

	val, err := vm.RunString(`vigolium.db.records.annotate("uuid-ann1", {risk_score: 42})`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	// Verify the update
	rec, err := repo.GetRecordByUUID(context.Background(), "uuid-ann1")
	require.NoError(t, err)
	assert.Equal(t, 42, rec.RiskScore)
}

func TestDBRecordsAnnotateRemarks(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-ann2", "example.com", "/api/test2", 200, "body")

	val, err := vm.RunString(`vigolium.db.records.annotate("uuid-ann2", {remarks: ["idor-candidate", "high-value"]})`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	rec, err := repo.GetRecordByUUID(context.Background(), "uuid-ann2")
	require.NoError(t, err)
	assert.Equal(t, []string{"idor-candidate", "high-value"}, rec.Remarks)
}

func TestDBRecordsAnnotateMissingRecord(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.records.annotate("no-such-uuid", {risk_score: 10})`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

// ── findings.get ────────────────────────────────────────────────────────────

func TestDBFindingsGet(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-f1", "example.com", "/api/test", 200, "body")
	insertTestFinding(t, repo, "finding-hash-1", "sqli", "high", []string{"uuid-f1"})

	// Get the finding ID first
	findings, err := repo.GetFindingsByRecordUUID(context.Background(), "uuid-f1")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	id := findings[0].ID

	val, err := vm.RunString(`vigolium.db.findings.get(` + string(rune('0'+id)) + `)`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	obj := val.ToObject(vm)
	assert.Equal(t, "sqli", obj.Get("module_id").String())
	assert.Equal(t, "high", obj.Get("severity").String())
}

func TestDBFindingsGetMissing(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.findings.get(999999)`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(val))
}

// ── findings.query ──────────────────────────────────────────────────────────

func TestDBFindingsQuery(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-fq1", "example.com", "/api/test", 200, "body")
	insertTestFinding(t, repo, "fq-hash-1", "xss", "high", []string{"uuid-fq1"})
	insertTestFinding(t, repo, "fq-hash-2", "sqli", "critical", []string{"uuid-fq1"})

	// Query by severity
	val, err := vm.RunString(`vigolium.db.findings.query({severity: ["high"], limit: 10})`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.Equal(t, int64(1), arr.Get("length").ToInteger())
}

// ── findings.getByRecord ────────────────────────────────────────────────────

func TestDBFindingsGetByRecord(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-fbr1", "example.com", "/api/test", 200, "body")
	insertTestFinding(t, repo, "fbr-hash-1", "xss", "high", []string{"uuid-fbr1"})
	insertTestFinding(t, repo, "fbr-hash-2", "sqli", "critical", []string{"uuid-fbr1"})

	val, err := vm.RunString(`vigolium.db.findings.getByRecord("uuid-fbr1")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.Equal(t, int64(2), arr.Get("length").ToInteger())
}

func TestDBFindingsGetByRecordEmpty(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.findings.getByRecord("no-such-uuid")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.Equal(t, int64(0), arr.Get("length").ToInteger())
}

// ── findings.create ─────────────────────────────────────────────────────────

func TestDBFindingsCreate(t *testing.T) {
	vm, repo := setupDBTestVM(t)
	insertTestRecord(t, repo, "uuid-fc1", "example.com", "/api/test", 200, "body")

	val, err := vm.RunString(`
		vigolium.db.findings.create({
			module_id: "idor-test",
			module_name: "IDOR Test",
			severity: "high",
			confidence: "firm",
			description: "Potential IDOR vulnerability",
			finding_hash: "idor-hash-unique-001",
			http_record_uuids: ["uuid-fc1"]
		})
	`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	// Verify it was saved
	findings, err := repo.GetFindingsByRecordUUID(context.Background(), "uuid-fc1")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "idor-test", findings[0].ModuleID)
	assert.Equal(t, "high", findings[0].Severity)
}

func TestDBFindingsCreateMissingRequired(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	// Missing module_name — should fail
	val, err := vm.RunString(`
		vigolium.db.findings.create({
			module_id: "idor-test",
			severity: "high"
		})
	`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

// ── compareResponses ─────────────────────────────────────────────────────────

func TestDBCompareResponsesSimilar(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`
		vigolium.db.compareResponses([
			{uuid: "a", status_code: 200, response_body: '{"id":1,"name":"Alice"}', response_headers: {}},
			{uuid: "b", status_code: 200, response_body: '{"id":1,"name":"Alice"}', response_headers: {}},
			{uuid: "c", status_code: 200, response_body: '{"id":1,"name":"Alice"}', response_headers: {}}
		])
	`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.True(t, obj.Get("all_similar").ToBoolean())
	assert.Equal(t, int64(0), obj.Get("variant_count").ToInteger())
}

func TestDBCompareResponsesDiverge(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`
		vigolium.db.compareResponses([
			{uuid: "x1", status_code: 200, response_body: '{"id":1,"name":"Alice","email":"alice@example.com","role":"admin","balance":1000}', response_headers: {"Content-Type": ["application/json"]}},
			{uuid: "x2", status_code: 403, response_body: '{"error":"forbidden","code":403}', response_headers: {"Content-Type": ["application/json"]}},
			{uuid: "x3", status_code: 403, response_body: '{"error":"forbidden","code":403}', response_headers: {"Content-Type": ["application/json"]}}
		])
	`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.False(t, obj.Get("all_similar").ToBoolean())
	assert.Greater(t, obj.Get("variant_count").ToInteger(), int64(0))
	assert.NotEmpty(t, obj.Get("summary").String())
}

func TestDBCompareResponsesEmpty(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.compareResponses([])`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.True(t, obj.Get("all_similar").ToBoolean())
	assert.Equal(t, int64(0), obj.Get("variant_count").ToInteger())
}

func TestDBCompareResponsesNull(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`vigolium.db.compareResponses(null)`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.True(t, obj.Get("all_similar").ToBoolean())
}

// ── API availability ──────────────────────────────────────────────────────────

func TestDBAPINotSetupWhenRepoNil(t *testing.T) {
	vm := sobek.New()
	opts := APIOptions{ScriptID: "test", Repository: nil}
	SetupAPI(vm, opts)

	val, err := vm.RunString(`typeof vigolium.db`)
	require.NoError(t, err)
	assert.Equal(t, "undefined", val.String())
}

func TestDBAPISetupWhenRepoAvailable(t *testing.T) {
	vm, _ := setupDBTestVM(t)

	val, err := vm.RunString(`typeof vigolium.db`)
	require.NoError(t, err)
	assert.Equal(t, "object", val.String())
}
