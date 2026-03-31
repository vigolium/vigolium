package archon

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "test", "testdata", "archon-audit-data")
}

func harborDir() string {
	return filepath.Join(testdataDir(), "archon-output-harbor")
}

func TestParseAuditState(t *testing.T) {
	state, err := parseAuditState(filepath.Join(harborDir(), "audit-state.json"))
	require.NoError(t, err)
	require.Len(t, state.Audits, 1)

	audit := state.Audits[0]
	assert.Equal(t, "1c7d83141911da74d57dcd51bb708eb7b17a7980", audit.Commit)
	assert.Equal(t, "audit", audit.Branch)
	assert.Equal(t, "complete", audit.Status)
	assert.Len(t, audit.Phases, 11)

	// Check final phase summary
	p11 := audit.Phases["11"]
	assert.Equal(t, "complete", p11.Status)
	total, ok := p11.Summary["total_findings"]
	require.True(t, ok)
	assert.Equal(t, float64(47), total)
}

func TestParseFindingsDir(t *testing.T) {
	findings, err := parseFindingsDir(filepath.Join(harborDir(), "findings-draft"))
	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Count base findings (excluding .cold-verify files which are overlays)
	// From the testdata: p7 (5), p8 base (many), p10 (several)
	assert.True(t, len(findings) > 30, "expected > 30 findings, got %d", len(findings))
}

func TestParsePhase7Finding(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(harborDir(), "findings-draft", "p7-001-open-redirect-authproxy.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "P7-001", af.FindingID)
	assert.Equal(t, "7", af.Phase)
	assert.Equal(t, "001", af.Sequence)
	assert.Equal(t, "open-redirect-authproxy", af.Slug)
	assert.Equal(t, "Open Redirect via Unvalidated postURI in Auth-Proxy Controller", af.Title)
	assert.Equal(t, "HIGH", af.Severity)
	assert.Equal(t, "HIGH", af.Confidence)
	assert.Equal(t, "CWE-601", af.CWE)
	assert.Equal(t, "theoretical", af.PoCStatus)
	assert.NotEmpty(t, af.Body)
	assert.NotEmpty(t, af.Locations, "should extract code locations")
}

func TestParsePhase8Finding(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(harborDir(), "findings-draft", "p8-001-admin-db-auth-brute-force.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "P8-001", af.FindingID)
	assert.Equal(t, "8", af.Phase)
	assert.Equal(t, "001", af.Sequence)
	assert.Equal(t, "admin-db-auth-brute-force", af.Slug)
	assert.Equal(t, "VALID", af.Verdict)
	assert.Equal(t, "HIGH", af.SeverityOriginal)
	assert.Equal(t, "MEDIUM", af.SeverityFinal)
	assert.Equal(t, "MEDIUM", af.Severity) // Severity-Final takes precedence
	assert.Equal(t, "CONFIRMED", af.AdversarialVerdict)
	assert.NotEmpty(t, af.Body)
}

func TestParsePhase10Finding(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(harborDir(), "findings-draft", "p10-041-sql-injection-project-filterbynames.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "P10-041", af.FindingID)
	assert.Equal(t, "10", af.Phase)
	assert.Equal(t, "041", af.Sequence)
	assert.Equal(t, "VALID", af.Verdict)
	assert.Equal(t, "MEDIUM", af.SeverityOriginal)
}

func TestColdVerifyOverlay(t *testing.T) {
	findings, err := parseFindingsDir(filepath.Join(harborDir(), "findings-draft"))
	require.NoError(t, err)

	// Find p8-022 which has a cold-verify file
	var found *ArchonFinding
	for _, f := range findings {
		if f.FindingID == "P8-022" {
			found = f
			break
		}
	}
	require.NotNil(t, found, "should find P8-022")
	assert.Equal(t, "CONFIRMED", found.AdversarialVerdict)
	assert.Equal(t, "HIGH", found.Severity) // cold-verify confirms HIGH
	assert.Contains(t, found.Body, "Cold Verification", "should have cold-verify content merged")
}

func TestParseAuditFolder(t *testing.T) {
	result, err := ParseAuditFolder(harborDir())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.State)
	assert.NotEmpty(t, result.RawFindings)
}

func TestParseAuditFolderMissingState(t *testing.T) {
	_, err := ParseAuditFolder("/nonexistent/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audit-state.json not found")
}

func TestBuildAgentRun(t *testing.T) {
	state, err := parseAuditState(filepath.Join(harborDir(), "audit-state.json"))
	require.NoError(t, err)

	run := BuildAgentRun(state, harborDir(), database.DefaultProjectUUID)

	assert.Equal(t, "archon", run.Mode)
	assert.Equal(t, "archon-audit", run.AgentName)
	assert.Equal(t, "completed", run.Status)
	assert.Equal(t, "archon", run.InputType)
	assert.Contains(t, run.InputRaw, "commit:1c7d83141911da74d57dcd51bb708eb7b17a7980")
	assert.Contains(t, run.InputRaw, "branch:audit")
	assert.Equal(t, 47, run.FindingCount)
	assert.Len(t, run.PhasesRun, 11)
	assert.NotEmpty(t, run.UUID)
	assert.NotEmpty(t, run.ResultJSON)
	assert.True(t, run.DurationMs > 0)
}

func TestBuildFindings(t *testing.T) {
	result, err := ParseAuditFolder(harborDir())
	require.NoError(t, err)

	auditID := result.State.Audits[0].AuditID
	agentRunUUID := "test-run-uuid"
	findings := BuildFindings(result.RawFindings, auditID, agentRunUUID, database.DefaultProjectUUID)

	assert.Equal(t, len(result.RawFindings), len(findings))

	// Check a converted finding
	var p7001 *database.Finding
	for _, f := range findings {
		if f.ModuleID == "archon:p7-001" {
			p7001 = f
			break
		}
	}
	require.NotNil(t, p7001, "should have archon:p7-001")
	assert.Equal(t, "Open Redirect via Unvalidated postURI in Auth-Proxy Controller", p7001.ModuleName)
	assert.Equal(t, "high", p7001.Severity)
	assert.Equal(t, "firm", p7001.Confidence)
	assert.Equal(t, database.ModuleTypeWhitebox, p7001.ModuleType)
	assert.Equal(t, database.FindingSourceArchon, p7001.FindingSource)
	assert.Equal(t, "open-redirect-authproxy", p7001.ModuleShort)
	assert.Equal(t, "CWE-601", p7001.CWEID)
	assert.Equal(t, agentRunUUID, p7001.AgentRunUUID)
	assert.Equal(t, database.DefaultProjectUUID, p7001.ProjectUUID)
	assert.NotEmpty(t, p7001.FindingHash)
	assert.Contains(t, p7001.Tags, "archon")
	assert.Contains(t, p7001.Tags, "phase-7")
	assert.NotEmpty(t, p7001.Description)

	// Check severity distribution
	highCount := 0
	medCount := 0
	for _, f := range findings {
		switch f.Severity {
		case "high":
			highCount++
		case "medium":
			medCount++
		}
	}
	assert.True(t, highCount > 0, "should have high severity findings")
	assert.True(t, medCount > 0, "should have medium severity findings")
}

func TestMapConfidence(t *testing.T) {
	assert.Equal(t, "firm", mapConfidence("CONFIRMED"))
	assert.Equal(t, "firm", mapConfidence("HIGH"))
	assert.Equal(t, "firm", mapConfidence("VALID"))
	assert.Equal(t, "tentative", mapConfidence("MEDIUM"))
	assert.Equal(t, "tentative", mapConfidence("LOW"))
	assert.Equal(t, "tentative", mapConfidence(""))
}

func TestExtractCWE(t *testing.T) {
	assert.Equal(t, "CWE-601", extractCWE("CWE-601 (URL Redirection to Untrusted Site)"))
	assert.Equal(t, "CWE-918", extractCWE("CWE-918"))
	assert.Equal(t, "", extractCWE("no cwe here"))
}
