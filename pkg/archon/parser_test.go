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

func vampiLiteDir() string {
	return filepath.Join(testdataDir(), "archon-audit-vampi-lite")
}

func stringSummaryDir() string {
	return filepath.Join(testdataDir(), "archon-output-string-summary")
}

func TestParseAuditState_Lite(t *testing.T) {
	state, err := parseAuditState(filepath.Join(vampiLiteDir(), "audit-state.json"))
	require.NoError(t, err)
	require.Len(t, state.Audits, 1)

	audit := state.Audits[0]
	assert.Equal(t, "1713b54b601ad29582581eeda4b31fceb1319874", audit.Commit)
	assert.Equal(t, "audit", audit.Branch)
	assert.Equal(t, "lite", audit.Mode)
	assert.Equal(t, "complete", audit.Status)
	assert.Len(t, audit.Phases, 3)

	// Q-prefixed phase IDs
	for _, id := range []string{"Q0", "Q1", "Q2"} {
		p := audit.Phases[id]
		assert.Equal(t, "complete", p.Status, "phase %s should be complete", id)
	}
}

func TestParseAuditFolder_Lite_PrefersPromotedFindings(t *testing.T) {
	result, err := ParseAuditFolder(vampiLiteDir())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.State)

	// The vampi fixture has 4 critical, 5 high, 2 medium in findings/.
	assert.Equal(t, 11, len(result.RawFindings), "should prefer promoted findings")

	// IDs should be C*/H*/M*, not Q*-NNN (draft format).
	prefixes := make(map[byte]int)
	for _, f := range result.RawFindings {
		require.NotEmpty(t, f.FindingID)
		prefixes[f.FindingID[0]]++
	}
	assert.Equal(t, 4, prefixes['C'], "expected 4 critical findings")
	assert.Equal(t, 5, prefixes['H'], "expected 5 high findings")
	assert.Equal(t, 2, prefixes['M'], "expected 2 medium findings")
}

func TestParseAuditFolder_Lite_SortOrder(t *testing.T) {
	result, err := ParseAuditFolder(vampiLiteDir())
	require.NoError(t, err)

	// Findings should be ordered C* < H* < M* by sort key.
	want := []string{"C1", "C2", "C3", "C4", "H1", "H2", "H3", "H4", "H5", "M1", "M2"}
	got := make([]string, 0, len(result.RawFindings))
	for _, f := range result.RawFindings {
		got = append(got, f.FindingID)
	}
	assert.Equal(t, want, got)
}

func TestParsePromotedFindingFile(t *testing.T) {
	af := parsePromotedFindingFile(filepath.Join(vampiLiteDir(), "findings", "C1.md"), "C1")
	require.NotNil(t, af)

	assert.Equal(t, "C1", af.FindingID)
	assert.Equal(t, "Critical", af.Severity)
	assert.Equal(t, "Hardcoded JWT Secret Key", af.Title)
	assert.Equal(t, "VALID", af.Verdict)
	require.NotEmpty(t, af.Locations)
	assert.Equal(t, "config.py:13", af.Locations[0])
	assert.NotEmpty(t, af.Body)
}

func TestParsePromotedFindings_SkipsPoCFiles(t *testing.T) {
	findings, err := parsePromotedFindings(filepath.Join(vampiLiteDir(), "findings"))
	require.NoError(t, err)
	assert.Equal(t, 11, len(findings), "PoC companion files (-poc.md) should be excluded")

	for _, f := range findings {
		assert.NotContains(t, f.Filename, "-poc", "filename %q should not include PoC suffix", f.Filename)
	}
}

func TestParsePromotedFindings_MissingDir(t *testing.T) {
	findings, err := parsePromotedFindings("/nonexistent/findings")
	assert.NoError(t, err)
	assert.Nil(t, findings)
}

func TestParsePromotedFindings_DirectoryLayout(t *testing.T) {
	// Build a synthetic findings/<ID>-<slug>/draft.md layout matching what the
	// current archon lite skill produces at runtime.
	tmp := t.TempDir()
	findingsDir := filepath.Join(tmp, "findings")

	draftBody := `## Q1-001: SQL Injection in login

- **Severity**: High
- **File**: src/auth.py
- **Line**: 42
- **Verdict**: VALID

### Evidence
` + "```python" + `
cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
` + "```" + `
`
	subDir := filepath.Join(findingsDir, "H1-sqli-login")
	require.NoError(t, os.MkdirAll(subDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "draft.md"), []byte(draftBody), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "report.md"), []byte("# Full narrative report\n"), 0o644))

	findings, err := parsePromotedFindings(findingsDir)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	af := findings[0]
	assert.Equal(t, "H1", af.FindingID, "dir name should win over inline Q1-001 header")
	assert.Equal(t, "sqli-login", af.Slug)
	assert.Equal(t, "SQL Injection in login", af.Title)
	assert.Equal(t, "High", af.Severity)
	assert.Contains(t, af.Locations, "src/auth.py:42")
	assert.Contains(t, af.Body, "Full narrative report", "report.md should be appended to the body")
}

func TestParseQuickDraftFinding(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(vampiLiteDir(), "findings-draft", "q1-001.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "Q1-001", af.FindingID)
	assert.Equal(t, "1", af.Phase)
	assert.Equal(t, "001", af.Sequence)
	assert.Equal(t, "Hardcoded JWT Secret Key", af.Title)
	assert.Equal(t, "Critical", af.Severity)
	assert.Equal(t, "VALID", af.Verdict)
	require.NotEmpty(t, af.Locations)
	assert.Equal(t, "config.py:13", af.Locations[0])
}

func TestParseQuickDraftFinding_Q2(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(vampiLiteDir(), "findings-draft", "q2-001.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "Q2-001", af.FindingID)
	assert.Equal(t, "2", af.Phase)
	assert.Equal(t, "SQL Injection in User Lookup", af.Title)
	assert.Equal(t, "Critical", af.Severity)
	assert.Equal(t, "models/user_model.py:72-73", af.Locations[0])
}

func TestParseFindingsDir_QuickPrefix(t *testing.T) {
	findings, err := parseFindingsDir(filepath.Join(vampiLiteDir(), "findings-draft"))
	require.NoError(t, err)
	assert.Equal(t, 11, len(findings), "should parse all q1+q2 draft files")

	// All IDs should be Q-prefixed.
	for _, f := range findings {
		assert.True(t, f.FindingID[0] == 'Q', "draft IDs should use Q prefix, got %q", f.FindingID)
	}
}

func TestParseAuditFolder_FallbackToDrafts(t *testing.T) {
	// Simulate a cancelled/partial archon run: findings-draft/ exists but no
	// findings/ promotion step has run.
	tmp := t.TempDir()
	draftSrc := filepath.Join(vampiLiteDir(), "findings-draft", "q1-001.md")
	draftDst := filepath.Join(tmp, "findings-draft", "q1-001.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(draftDst), 0o755))
	data, err := os.ReadFile(draftSrc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(draftDst, data, 0o644))

	result, err := ParseAuditFolder(tmp)
	require.NoError(t, err)
	require.Len(t, result.RawFindings, 1)
	assert.Equal(t, "Q1-001", result.RawFindings[0].FindingID)
}

func TestParseAuditFolder_PromotedBeatsDrafts(t *testing.T) {
	// When both findings/ and findings-draft/ exist, the promoted (final) IDs
	// must be used — drafts are intermediate and get deleted by lite mode.
	result, err := ParseAuditFolder(vampiLiteDir())
	require.NoError(t, err)

	for _, f := range result.RawFindings {
		assert.NotContains(t, []byte{f.FindingID[0]}, byte('Q'), "should not see Q-prefixed drafts when findings/ exists")
	}
}

func TestParseAuditFolder_MissingAllInputs(t *testing.T) {
	_, err := ParseAuditFolder("/nonexistent/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no audit-state.json and no findings")
}

func TestBuildFindings_Lite(t *testing.T) {
	result, err := ParseAuditFolder(vampiLiteDir())
	require.NoError(t, err)

	auditID := result.State.Audits[0].AuditID
	findings := BuildFindings(result.RawFindings, auditID, "test-run", database.DefaultProjectUUID, result.RepoName)
	require.Equal(t, len(result.RawFindings), len(findings))

	// Look up the first critical.
	var c1 *database.Finding
	for _, f := range findings {
		if f.ModuleID == "archon:c1" {
			c1 = f
			break
		}
	}
	require.NotNil(t, c1)
	assert.Equal(t, "Hardcoded JWT Secret Key", c1.ModuleName)
	assert.Equal(t, "critical", c1.Severity)
	assert.Equal(t, "firm", c1.Confidence)
	assert.Equal(t, database.ModuleTypeWhitebox, c1.ModuleType)
	assert.Equal(t, database.FindingSourceArchon, c1.FindingSource)
	assert.Contains(t, c1.Tags, "archon")
	assert.NotEmpty(t, c1.FindingHash)
	assert.Equal(t, "test-run", c1.AgentRunUUID)

	// Severity distribution.
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	assert.Equal(t, 4, counts["critical"])
	assert.Equal(t, 5, counts["high"])
	assert.Equal(t, 2, counts["medium"])
}

// --- audit-state edge cases -------------------------------------------------

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

func TestResolveRepoName_FallbackToFolderBasename(t *testing.T) {
	// String-summary fixture has no commit-recon-report.md and no repo in audit-state.json
	result, err := ParseAuditFolder(stringSummaryDir())
	require.NoError(t, err)
	assert.Equal(t, "archon-output-string-summary", result.RepoName)
}

func TestResolveRepoName_AuditStateRepoURL(t *testing.T) {
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
	state := &AuditState{
		Audits: []AuditEntry{{
			Repo: "example/repo",
		}},
	}
	name := resolveRepoName(state, "/some/path/my-folder")
	assert.Equal(t, "example/repo", name)
}

func TestExtractCWE(t *testing.T) {
	assert.Equal(t, "CWE-601", extractCWE("CWE-601 (URL Redirection to Untrusted Site)"))
	assert.Equal(t, "CWE-918", extractCWE("CWE-918"))
	assert.Equal(t, "", extractCWE("no cwe here"))
}
