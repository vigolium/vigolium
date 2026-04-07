package archon

import (
	"encoding/json"
	"os"
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
	assert.Contains(t, err.Error(), "no audit-state.json and no findings")
}

func TestParseAuditFolderWithoutState(t *testing.T) {
	// Simulate a cancelled archon run: findings-draft/ exists but no audit-state.json
	dir := t.TempDir()
	findingsDir := filepath.Join(dir, "findings-draft")
	require.NoError(t, os.MkdirAll(findingsDir, 0o755))

	// Copy a real finding file from harbor testdata
	src := filepath.Join(harborDir(), "findings-draft", "p7-001-open-redirect-authproxy.md")
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(findingsDir, "p7-001-open-redirect-authproxy.md"), data, 0o644))

	result, err := ParseAuditFolder(dir)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.RawFindings)
	assert.NotNil(t, result.State) // synthetic empty state
	assert.Empty(t, result.State.Audits)
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
	findings := BuildFindings(result.RawFindings, auditID, agentRunUUID, database.DefaultProjectUUID, result.RepoName)

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
	assert.Equal(t, "https://github.com/goharbor/harbor", p7001.RepoName, "repo name should be extracted from commit-recon-report")

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

func stringSummaryDir() string {
	return filepath.Join(testdataDir(), "archon-output-string-summary")
}

func TestParseAuditStateStringSummary(t *testing.T) {
	state, err := parseAuditState(filepath.Join(stringSummaryDir(), "audit-state.json"))
	require.NoError(t, err)
	require.Len(t, state.Audits, 1)

	audit := state.Audits[0]
	assert.Equal(t, "abc123", audit.Commit)
	assert.Equal(t, "complete", audit.Status)
	assert.Len(t, audit.Phases, 3)

	// String summaries should be stored under "text" key
	p1 := audit.Phases["1"]
	assert.Equal(t, "complete", p1.Status)
	assert.Contains(t, p1.SummaryText(), "Advisory collection complete")

	// Finding count extraction should gracefully return 0 when summary is a string
	run := BuildAgentRun(state, stringSummaryDir(), database.DefaultProjectUUID)
	assert.Equal(t, 0, run.FindingCount, "string summary cannot provide total_findings, should be 0")
	assert.Equal(t, "completed", run.Status)
}

func TestPhaseEntryUnmarshalMixed(t *testing.T) {
	// Object summary
	data := `{"status":"complete","summary":{"total_findings":10}}`
	var p1 PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p1))
	assert.Equal(t, float64(10), p1.Summary["total_findings"])

	// String summary
	data = `{"status":"complete","summary":"all done"}`
	var p2 PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p2))
	assert.Equal(t, "all done", p2.SummaryText())

	// No summary
	data = `{"status":"pending"}`
	var p3 PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p3))
	assert.Nil(t, p3.Summary)

	// Null summary
	data = `{"status":"complete","summary":null}`
	var p4 PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p4))
	assert.Nil(t, p4.Summary)
}

func TestMapConfidence(t *testing.T) {
	assert.Equal(t, "firm", mapConfidence("CONFIRMED"))
	assert.Equal(t, "firm", mapConfidence("HIGH"))
	assert.Equal(t, "firm", mapConfidence("VALID"))
	assert.Equal(t, "tentative", mapConfidence("MEDIUM"))
	assert.Equal(t, "tentative", mapConfidence("LOW"))
	assert.Equal(t, "tentative", mapConfidence(""))
}

func TestResolveRepoName_FromCommitRecon(t *testing.T) {
	// Harbor has commit-recon-report.md with "**Repository**: goharbor/harbor (https://github.com/goharbor/harbor)"
	result, err := ParseAuditFolder(harborDir())
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/goharbor/harbor", result.RepoName)
}

func TestResolveRepoName_SlugWithoutURL(t *testing.T) {
	// Kong has commit-recon-report.md with "**Repository**: Kong/kong" (no URL in parens)
	kongDir := filepath.Join(testdataDir(), "archon-output-kong")
	result, err := ParseAuditFolder(kongDir)
	require.NoError(t, err)
	assert.Equal(t, "Kong/kong", result.RepoName)
}

func TestResolveRepoName_FallbackToFolderBasename(t *testing.T) {
	// String-summary fixture has no commit-recon-report.md and no repo in audit-state.json
	result, err := ParseAuditFolder(stringSummaryDir())
	require.NoError(t, err)
	assert.Equal(t, "archon-output-string-summary", result.RepoName)
}

func TestResolveRepoName_AuditStateRepoURL(t *testing.T) {
	// If audit-state.json has repo_url, it takes priority
	state := &AuditState{
		Audits: []AuditEntry{{
			RepoURL: "https://github.com/example/repo",
			Repo:    "example/repo",
		}},
	}
	name := resolveRepoName(state, "/some/path/my-folder")
	assert.Equal(t, "https://github.com/example/repo", name)
}

func TestResolveRepoName_AuditStateRepoSlug(t *testing.T) {
	// If audit-state.json has repo but no repo_url, use repo
	state := &AuditState{
		Audits: []AuditEntry{{
			Repo: "example/repo",
		}},
	}
	name := resolveRepoName(state, "/some/path/my-folder")
	assert.Equal(t, "example/repo", name)
}

func TestExtractRepoFromCommitRecon(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		expected string
	}{
		{"harbor with URL", harborDir(), "https://github.com/goharbor/harbor"},
		{"kong slug only", filepath.Join(testdataDir(), "archon-output-kong"), "Kong/kong"},
		{"redash slug only", filepath.Join(testdataDir(), "archon-output-redash"), "getredash/redash"},
		{"nonexistent dir", "/nonexistent/path", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, extractRepoFromCommitRecon(tc.dir))
		})
	}
}

func liteDir() string {
	return filepath.Join(testdataDir(), "archon-output-lite")
}

func TestParseLiteFinding(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(liteDir(), "findings-draft", "l2-001.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "L2-001", af.FindingID)
	assert.Equal(t, "2", af.Phase)
	assert.Equal(t, "001", af.Sequence)
	assert.Equal(t, "SQL Injection in User Lookup", af.Title)
	assert.Equal(t, "Critical", af.Severity)
	assert.Equal(t, "VALID", af.Verdict)
	assert.Equal(t, "VALID", af.Confidence) // raw verdict; mapped to "firm" by toDBFinding
	assert.NotEmpty(t, af.Locations, "should extract file location")
	assert.Equal(t, "models/user_model.py:72", af.Locations[0])
	assert.NotEmpty(t, af.Body)
	assert.NotEmpty(t, af.Slug)
}

func TestParseLiteFindingL1(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(liteDir(), "findings-draft", "l1-001.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "L1-001", af.FindingID)
	assert.Equal(t, "1", af.Phase)
	assert.Equal(t, "001", af.Sequence)
	assert.Equal(t, "Hardcoded JWT Secret Key", af.Title)
	assert.Equal(t, "High", af.Severity)
	assert.Equal(t, "VALID", af.Verdict)
	assert.Equal(t, "app.py:12", af.Locations[0])
}

func TestParseFindingsDirLite(t *testing.T) {
	findings, err := parseFindingsDir(filepath.Join(liteDir(), "findings-draft"))
	require.NoError(t, err)
	assert.Len(t, findings, 2, "should parse both l1 and l2 findings")
}

func TestParseAuditFolderLite(t *testing.T) {
	result, err := ParseAuditFolder(liteDir())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.RawFindings)
	assert.Equal(t, "erev0s/VAmPI", result.RepoName)
	assert.Equal(t, "complete", result.State.Audits[0].Status)
	assert.Equal(t, "lite", result.State.Audits[0].Mode)
}

func TestBuildFindingsLite(t *testing.T) {
	result, err := ParseAuditFolder(liteDir())
	require.NoError(t, err)

	auditID := result.State.Audits[0].AuditID
	findings := BuildFindings(result.RawFindings, auditID, "test-run", database.DefaultProjectUUID, result.RepoName)

	assert.Equal(t, len(result.RawFindings), len(findings))

	// Check a converted finding
	var l2001 *database.Finding
	for _, f := range findings {
		if f.ModuleID == "archon:l2-001" {
			l2001 = f
			break
		}
	}
	require.NotNil(t, l2001, "should have archon:l2-001")
	assert.Equal(t, "SQL Injection in User Lookup", l2001.ModuleName)
	assert.Equal(t, "critical", l2001.Severity)
	assert.Equal(t, "firm", l2001.Confidence)
	assert.Equal(t, database.ModuleTypeWhitebox, l2001.ModuleType)
	assert.Equal(t, database.FindingSourceArchon, l2001.FindingSource)
	assert.NotEmpty(t, l2001.FindingHash)
	assert.Contains(t, l2001.Tags, "archon")
	assert.Equal(t, "erev0s/VAmPI", l2001.RepoName)
}

func TestExtractCWE(t *testing.T) {
	assert.Equal(t, "CWE-601", extractCWE("CWE-601 (URL Redirection to Untrusted Site)"))
	assert.Equal(t, "CWE-918", extractCWE("CWE-918"))
	assert.Equal(t, "", extractCWE("no cwe here"))
}
