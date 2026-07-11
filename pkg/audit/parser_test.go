package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yuin/goldmark/text"

	"github.com/vigolium/vigolium/pkg/database"
)

// --- synthetic fixtures ----------------------------------------------------
//
// The vigolium-audit-data corpus was removed from the tree. These builders
// reconstruct the exact on-disk shapes the parser consumes (lite-mode
// audit-state.json, flat promoted findings, q-prefixed drafts, string-summary
// audit state) so the parser tests stay hermetic with no external fixtures.

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// liteFinding renders a lite-mode finding body in the
// "## <ID>: <title>" + "- **Key**: Value" shape audit emits in lite mode.
func liteFinding(id, title, severity, file, line, verdict string) string {
	return fmt.Sprintf("## %s: %s\n\n"+
		"- **Severity**: %s\n"+
		"- **File**: %s\n"+
		"- **Line**: %s\n"+
		"- **Verdict**: %s\n\n"+
		"### Evidence\n```\nsynthetic evidence for %s\n```\n\n"+
		"Synthetic body for %s.\n",
		id, title, severity, file, line, verdict, id, title)
}

// synthVampiLite builds a lite-mode audit folder equivalent to the former
// vigolium-audit-vampi-lite fixture: a complete audit-state.json, a promoted
// findings/ tree (flat C*/H*/M*.md + -poc companions, 4C/5H/2M = 11) and an
// intermediate findings-draft/ tree (q1-*/q2-* drafts, 11 total). C1/q1-001
// carry the canonical "Hardcoded JWT Secret Key" content the detail tests
// assert on; q2-001 carries the SQLi content.
func synthVampiLite(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	writeFixtureFile(t, filepath.Join(root, "audit-state.json"), `{
  "audits": [
    {
      "audit_id": "2026-04-10T00:00:00Z",
      "commit": "1713b54b601ad29582581eeda4b31fceb1319874",
      "branch": "audit",
      "mode": "lite",
      "model": "opus-4.6",
      "agent_sdk": "claude-code",
      "started_at": "2026-04-10T00:00:00Z",
      "completed_at": "2026-04-10T00:00:10Z",
      "status": "complete",
      "phases": {
        "Q0": {"status": "complete", "completed_at": "2026-04-10T00:00:01Z"},
        "Q1": {"status": "complete", "completed_at": "2026-04-10T00:00:02Z"},
        "Q2": {"status": "complete", "completed_at": "2026-04-10T00:00:02Z"}
      }
    }
  ]
}
`)

	// Promoted findings/: 4 critical, 5 high, 2 medium (11). The promoted
	// ID/severity come from the filename letter; C1's body supplies the
	// title/location the detail tests assert on.
	writeFixtureFile(t, filepath.Join(root, "findings", "C1.md"),
		liteFinding("Q1-001", "Hardcoded JWT Secret Key", "Critical", "config.py", "13", "VALID"))
	writeFixtureFile(t, filepath.Join(root, "findings", "C1-poc.md"),
		"# C1 - Hardcoded JWT Secret Key: Proof of Concept\n\n- **ID**: C1\n\nSynthetic PoC companion.\n")
	for _, id := range []string{"C2", "C3", "C4", "H1", "H2", "H3", "H4", "H5", "M1", "M2"} {
		writeFixtureFile(t, filepath.Join(root, "findings", id+".md"),
			liteFinding("Q9-001", "Synthetic "+id, "Medium", "src/app.py", "1", "VALID"))
		writeFixtureFile(t, filepath.Join(root, "findings", id+"-poc.md"),
			"# "+id+": Proof of Concept\n\nSynthetic PoC companion.\n")
	}

	// Intermediate findings-draft/: q1-001/q1-002 + q2-001..q2-009 (11).
	writeFixtureFile(t, filepath.Join(root, "findings-draft", "q1-001.md"),
		liteFinding("Q1-001", "Hardcoded JWT Secret Key", "Critical", "config.py", "13", "VALID"))
	writeFixtureFile(t, filepath.Join(root, "findings-draft", "q1-002.md"),
		liteFinding("Q1-002", "Synthetic Secret Finding", "High", "config.py", "20", "VALID"))
	writeFixtureFile(t, filepath.Join(root, "findings-draft", "q2-001.md"),
		liteFinding("Q2-001", "SQL Injection in User Lookup", "Critical", "models/user_model.py", "72-73", "VALID"))
	for i := 2; i <= 9; i++ {
		writeFixtureFile(t, filepath.Join(root, "findings-draft", fmt.Sprintf("q2-%03d.md", i)),
			liteFinding(fmt.Sprintf("Q2-%03d", i), "Synthetic SAST Finding", "Medium", "src/app.py", "1", "VALID"))
	}

	return root
}

// synthStringSummary builds a deep-mode audit folder whose phase summaries are
// plain strings (not objects) and which carries no repo metadata, so
// resolveRepoName falls back to the folder basename. The folder is created
// with a fixed basename so that fallback is assertable.
func synthStringSummary(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit-output-string-summary")
	writeFixtureFile(t, filepath.Join(dir, "audit-state.json"), `{
  "audits": [
    {
      "audit_id": "2026-03-31T21:30:00Z",
      "commit": "abc123",
      "branch": "main",
      "mode": "deep",
      "model": "claude-sonnet-4-6",
      "agent_sdk": "claude-code",
      "started_at": "2026-03-31T21:30:00Z",
      "completed_at": "2026-03-31T23:59:00Z",
      "status": "complete",
      "phases": {
        "1": {"status": "complete", "completed_at": "2026-03-31T21:45:00Z", "summary": "Advisory collection complete. 22 unique advisories collected."},
        "8": {"status": "complete", "completed_at": "2026-03-31T23:50:00Z", "summary": "Phase 8 Review Chambers complete. 3 chambers run. 46 finding drafts generated."},
        "11": {"status": "complete", "completed_at": "2026-03-31T23:59:00Z", "summary": "Phase 11 Report Assembly complete. Findings: 34 total (C:1, H:10, M:11, plus 22 variants)."}
      }
    }
  ]
}
`)
	return dir
}

func TestParseState_Lite(t *testing.T) {
	state, err := parseState(filepath.Join(synthVampiLite(t), "audit-state.json"))
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

func TestParseFolder_Lite_PrefersPromotedFindings(t *testing.T) {
	result, err := ParseFolder(synthVampiLite(t))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.State)

	// findings/ has 4 critical, 5 high, 2 medium (promoted); findings-draft/
	// has 11 q-drafts that are now imported alongside as informational
	// context. So: 11 confirmed (Provenance "") + 11 draft (Provenance
	// "draft") = 22 total.
	assert.Equal(t, 22, len(result.RawFindings), "promoted + supplementary drafts")

	prefixes := make(map[byte]int)
	draftCount := 0
	for _, f := range result.RawFindings {
		require.NotEmpty(t, f.FindingID)
		switch f.Provenance {
		case "":
			// Confirmed: severity-prefixed C*/H*/M* IDs.
			prefixes[f.FindingID[0]]++
		case "draft":
			draftCount++
			assert.Equal(t, byte('Q'), f.FindingID[0], "draft IDs stay Q-prefixed")
		default:
			t.Fatalf("unexpected provenance %q", f.Provenance)
		}
	}
	assert.Equal(t, 4, prefixes['C'], "expected 4 critical confirmed findings")
	assert.Equal(t, 5, prefixes['H'], "expected 5 high confirmed findings")
	assert.Equal(t, 2, prefixes['M'], "expected 2 medium confirmed findings")
	assert.Equal(t, 11, draftCount, "all 11 drafts imported as supplementary")
}

func TestParseFolder_Lite_SortOrder(t *testing.T) {
	result, err := ParseFolder(synthVampiLite(t))
	require.NoError(t, err)

	// The confirmed subset (Provenance "") must stay ordered C* < H* < M*
	// by sort key; supplementary drafts are appended after it.
	want := []string{"C1", "C2", "C3", "C4", "H1", "H2", "H3", "H4", "H5", "M1", "M2"}
	got := make([]string, 0, len(want))
	for _, f := range result.RawFindings {
		if f.Provenance == "" {
			got = append(got, f.FindingID)
		}
	}
	assert.Equal(t, want, got)
}

func TestParsePromotedFindingFile(t *testing.T) {
	af := parsePromotedFindingFile(filepath.Join(synthVampiLite(t), "findings", "C1.md"), "C1")
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
	findings, err := parsePromotedFindings(filepath.Join(synthVampiLite(t), "findings"))
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
	// current audit lite skill produces at runtime.
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
	reportBody := `# H1 — SQL Injection in Login Endpoint

**Severity**: HIGH
**PoC-Status**: executed
**Component**: ` + "`src/auth.py:42`" + `

---

## Summary

The login endpoint is vulnerable to SQL injection.

## Fix

Use parameterized queries instead of string concatenation.
`
	subDir := filepath.Join(findingsDir, "H1-sqli-login")
	require.NoError(t, os.MkdirAll(subDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "draft.md"), []byte(draftBody), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "report.md"), []byte(reportBody), 0o644))

	findings, err := parsePromotedFindings(findingsDir)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	af := findings[0]
	assert.Equal(t, "H1", af.FindingID, "dir name should win over inline Q1-001 header")
	assert.Equal(t, "sqli-login", af.Slug)
	assert.Equal(t, "SQL Injection in Login Endpoint", af.Title, "title from report.md H1 heading")
	// Headline severity is derived from the directory prefix (H → "High"),
	// not from report.md's "HIGH". toDBFinding normalizes to upper case
	// downstream; both spellings collapse to HIGH in the DB.
	assert.Equal(t, "High", af.Severity)
	assert.Equal(t, "executed", af.PoCStatus, "poc-status from report.md")
	assert.Contains(t, af.Body, "login endpoint is vulnerable", "body should be report.md content")
	assert.Contains(t, af.Remediation, "parameterized queries", "remediation from ## Fix section")
}

func TestParseQuickDraftFinding(t *testing.T) {
	af, err := parseFindingFile(filepath.Join(synthVampiLite(t), "findings-draft", "q1-001.md"))
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
	af, err := parseFindingFile(filepath.Join(synthVampiLite(t), "findings-draft", "q2-001.md"))
	require.NoError(t, err)
	require.NotNil(t, af)

	assert.Equal(t, "Q2-001", af.FindingID)
	assert.Equal(t, "2", af.Phase)
	assert.Equal(t, "SQL Injection in User Lookup", af.Title)
	assert.Equal(t, "Critical", af.Severity)
	assert.Equal(t, "models/user_model.py:72-73", af.Locations[0])
}

func TestParseFindingsDir_QuickPrefix(t *testing.T) {
	findings, err := parseFindingsDir(filepath.Join(synthVampiLite(t), "findings-draft"))
	require.NoError(t, err)
	assert.Equal(t, 11, len(findings), "should parse all q1+q2 draft files")

	// All IDs should be Q-prefixed.
	for _, f := range findings {
		assert.True(t, f.FindingID[0] == 'Q', "draft IDs should use Q prefix, got %q", f.FindingID)
	}
}

func TestParseFolder_FallbackToDrafts(t *testing.T) {
	// Simulate a cancelled/partial audit run: findings-draft/ exists but no
	// findings/ promotion step has run.
	tmp := t.TempDir()
	writeFixtureFile(t, filepath.Join(tmp, "findings-draft", "q1-001.md"),
		liteFinding("Q1-001", "Hardcoded JWT Secret Key", "Critical", "config.py", "13", "VALID"))

	result, err := ParseFolder(tmp)
	require.NoError(t, err)
	require.Len(t, result.RawFindings, 1)
	assert.Equal(t, "Q1-001", result.RawFindings[0].FindingID)
}

func TestParseFolder_PromotedPlusDraftInfo(t *testing.T) {
	// When both findings/ and findings-draft/ exist, the promoted (final)
	// severity-prefixed findings are the confirmed set (Provenance ""), and
	// every draft is additionally imported flagged Provenance "draft" so it
	// can be downgraded to INFO at DB-build time.
	result, err := ParseFolder(synthVampiLite(t))
	require.NoError(t, err)

	for _, f := range result.RawFindings {
		require.NotEmpty(t, f.FindingID)
		if f.Provenance == "draft" {
			assert.Equal(t, byte('Q'), f.FindingID[0], "draft entries keep Q-prefixed IDs")
		} else {
			assert.Equal(t, "", f.Provenance, "confirmed findings have empty provenance")
			assert.NotEqual(t, byte('Q'), f.FindingID[0], "confirmed findings are severity-prefixed, not Q")
		}
	}

	// BuildFindings must pin every draft to INFO with a "draft" tag while the
	// confirmed findings keep their real severities.
	findings := BuildFindings(result.RawFindings, "aid", "run", database.DefaultProjectUUID, result.RepoName)
	infoDrafts := 0
	for i, f := range findings {
		if result.RawFindings[i].Provenance == "draft" {
			infoDrafts++
			assert.Equal(t, "info", f.Severity, "draft → info severity")
			assert.Equal(t, "tentative", f.Confidence, "draft → tentative confidence")
			assert.Contains(t, f.Tags, "draft", "draft entries carry the draft tag")
		} else {
			assert.NotEqual(t, "info", f.Severity, "confirmed findings keep their real severity")
		}
	}
	assert.Equal(t, 11, infoDrafts, "all 11 drafts present as info")
}

func TestParseFolder_TheoreticalAndDraftAsInfo(t *testing.T) {
	root := t.TempDir()

	// Confirmed (findings/): keeps its real High severity.
	writeFixtureFile(t, filepath.Join(root, "findings", "H1-confirmed-xss", "report.md"),
		"# H1 — Confirmed XSS\n\n**Severity**: HIGH\n\n## Summary\n\nConfirmed and exploited.\n")
	writeFixtureFile(t, filepath.Join(root, "findings", "H1-confirmed-xss", "draft.md"),
		"Phase: 8\nSequence: 001\nSlug: confirmed-xss\nVerdict: VALID\nSeverity-Original: HIGH\n\n## Summary\n\nbody\n")

	// Theoretical (findings-theoretical/): VALID but not confirmed → INFO.
	writeFixtureFile(t, filepath.Join(root, "findings-theoretical", "H7-theory-xss", "report.md"),
		"# H7 — Theoretical XSS\n\n**Severity**: HIGH\n\n## Summary\n\nValid but not exploited.\n")
	writeFixtureFile(t, filepath.Join(root, "findings-theoretical", "H7-theory-xss", "draft.md"),
		"Phase: 8\nSequence: 007\nSlug: theory-xss\nVerdict: VALID\nSeverity-Original: HIGH\n\n## Summary\n\nbody\n")

	// Draft (findings-draft/): intermediate, imported alongside → INFO.
	writeFixtureFile(t, filepath.Join(root, "findings-draft", "q1-001.md"),
		liteFinding("Q1-001", "Draft Secret", "Critical", "config.py", "13", "VALID"))

	result, err := ParseFolder(root)
	require.NoError(t, err)
	require.Len(t, result.RawFindings, 3)

	prov := map[string]string{}
	for _, f := range result.RawFindings {
		prov[f.FindingID] = f.Provenance
	}
	assert.Equal(t, "", prov["H1"], "confirmed finding has empty provenance")
	assert.Equal(t, "theoretical", prov["H7"], "findings-theoretical/ entry tagged theoretical")
	assert.Equal(t, "draft", prov["Q1-001"], "findings-draft/ entry tagged draft")

	findings := BuildFindings(result.RawFindings, "aid", "run", database.DefaultProjectUUID, result.RepoName)
	bySev := map[string]*database.Finding{}
	for i, f := range findings {
		bySev[result.RawFindings[i].FindingID] = f
	}
	assert.Equal(t, "high", bySev["H1"].Severity, "confirmed keeps real severity")
	assert.NotContains(t, bySev["H1"].Tags, "theoretical")

	assert.Equal(t, "info", bySev["H7"].Severity, "theoretical → info")
	assert.Equal(t, "tentative", bySev["H7"].Confidence)
	assert.Contains(t, bySev["H7"].Tags, "theoretical")

	assert.Equal(t, "info", bySev["Q1-001"].Severity, "draft → info despite Critical in body")
	assert.Contains(t, bySev["Q1-001"].Tags, "draft")
}

func TestParseFolder_MissingAllInputs(t *testing.T) {
	_, err := ParseFolder("/nonexistent/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no audit-state.json and no findings")
}

func TestBuildFindings_Lite(t *testing.T) {
	result, err := ParseFolder(synthVampiLite(t))
	require.NoError(t, err)

	auditID := result.State.Audits[0].AuditID
	findings := BuildFindings(result.RawFindings, auditID, "test-run", database.DefaultProjectUUID, result.RepoName)
	require.Equal(t, len(result.RawFindings), len(findings))

	// Look up the first critical.
	var c1 *database.Finding
	for _, f := range findings {
		if f.ModuleID == "audit:c1" {
			c1 = f
			break
		}
	}
	require.NotNil(t, c1)
	assert.Equal(t, "Hardcoded JWT Secret Key", c1.ModuleName)
	assert.Equal(t, "critical", c1.Severity)
	assert.Equal(t, "firm", c1.Confidence)
	assert.Equal(t, database.ModuleTypeWhitebox, c1.ModuleType)
	assert.Equal(t, database.FindingSourceAudit, c1.FindingSource)
	assert.Contains(t, c1.Tags, "audit")
	assert.NotEmpty(t, c1.FindingHash)
	assert.Equal(t, "test-run", c1.AgenticScanUUID)

	// Severity distribution.
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	assert.Equal(t, 4, counts["critical"])
	assert.Equal(t, 5, counts["high"])
	assert.Equal(t, 2, counts["medium"])
	// The 11 findings-draft/ entries import as supplementary INFO.
	assert.Equal(t, 11, counts["info"])
}

// --- audit-state edge cases -------------------------------------------------

func TestParseStateStringSummary(t *testing.T) {
	dir := synthStringSummary(t)
	state, err := parseState(filepath.Join(dir, "audit-state.json"))
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
	run := BuildAgenticScan(state, dir, database.DefaultProjectUUID)
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

func TestFlexTimeDateOnly(t *testing.T) {
	// Phase entries with date-only completed_at (common in LLM-generated audit-state.json)
	data := `{"status":"complete","completed_at":"2026-04-11"}`
	var p PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p))
	assert.Equal(t, 2026, p.CompletedAt.Year())
	assert.Equal(t, time.Month(4), p.CompletedAt.Month())
	assert.Equal(t, 11, p.CompletedAt.Day())

	// RFC3339 still works
	data = `{"status":"complete","completed_at":"2026-04-11T10:30:00Z"}`
	var p2 PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p2))
	assert.Equal(t, 10, p2.CompletedAt.Hour())

	// Entry with date-only
	entryJSON := `{"audit_id":"test","started_at":"2026-04-11","completed_at":"2026-04-12","status":"complete","phases":{}}`
	var entry Entry
	require.NoError(t, json.Unmarshal([]byte(entryJSON), &entry))
	assert.Equal(t, 11, entry.StartedAt.Day())
	assert.Equal(t, 12, entry.CompletedAt.Day())

	// Empty/null completed_at is tolerated
	data = `{"status":"pending"}`
	var p3 PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p3))
	assert.True(t, p3.CompletedAt.IsZero())
}

func TestFlexTimeTimezoneLessDateTime(t *testing.T) {
	data := `{"status":"complete","completed_at":"2026-07-10T20:31:58"}`
	var p PhaseEntry
	require.NoError(t, json.Unmarshal([]byte(data), &p))
	assert.Equal(t, time.Date(2026, time.July, 10, 20, 31, 58, 0, time.UTC), p.CompletedAt.Time)
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
	// String-summary fixture has no commit-recon-report.md and no repo in
	// audit-state.json, so resolveRepoName falls back to the folder basename.
	dir := synthStringSummary(t)
	result, err := ParseFolder(dir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Base(dir), result.RepoName)
	assert.Equal(t, "audit-output-string-summary", result.RepoName)
}

func TestResolveRepoName_StateRepoURL(t *testing.T) {
	state := &State{
		Audits: []Entry{{
			RepoURL: "https://github.com/example/repo",
			Repo:    "example/repo",
		}},
	}
	name := resolveRepoName(state, "/some/path/my-folder")
	assert.Equal(t, "https://github.com/example/repo", name)
}

func TestResolveRepoName_StateRepoSlug(t *testing.T) {
	state := &State{
		Audits: []Entry{{
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

func TestParseReportMd_BoldHeaderFormat(t *testing.T) {
	content := `# H3 — Public Dashboard Credential Exposure

**ID**: H3
**Severity**: HIGH
**Status**: Confirmed — PoC Executed
**PoC-Status**: executed
**Component**: ` + "`pkg/api/frontendsettings.go:541-577`" + `

---

## Summary

Unauthenticated credential disclosure via public dashboard endpoint.

## Fix

Add an IsPublicDashboardView() guard around the credential extraction block.
`
	af := &Finding{}
	parseReportMd(af, content)

	assert.Equal(t, "Public Dashboard Credential Exposure", af.Title)
	assert.Equal(t, "HIGH", af.Severity)
	assert.Equal(t, "executed", af.PoCStatus)
	assert.Equal(t, "VALID", af.Verdict, "Confirmed status should set verdict to VALID")
	assert.Contains(t, af.Remediation, "IsPublicDashboardView()")
	assert.Contains(t, af.Locations, "pkg/api/frontendsettings.go:541-577")
}

func TestParseReportMd_PlainKVFormat(t *testing.T) {
	content := `ID: H6
Title: Auth Proxy Empty Whitelist Allows Any Client
Severity: HIGH
Component: pkg/services/authn/clients/proxy.go
PoC-Status: executed

---

## Summary

When auth proxy is enabled, the IP allowlist defaults to empty.

## Remediation

Default the allowlist to loopback addresses when empty.
`
	af := &Finding{}
	parseReportMd(af, content)

	assert.Equal(t, "Auth Proxy Empty Whitelist Allows Any Client", af.Title)
	assert.Equal(t, "HIGH", af.Severity)
	assert.Equal(t, "executed", af.PoCStatus)
	assert.Contains(t, af.Remediation, "loopback addresses")
}

func TestParseReportMd_NoHeaderFormat(t *testing.T) {
	content := `## Summary

` + "`IsAutoAllowed`" + ` performs strings.HasPrefix without metachar split.

## Root Cause

Validated rationale: prefix check with no metacharacter awareness.

## Proof of Concept

Run the poc.py script.

## Impact

Arbitrary command execution.
`
	af := &Finding{Slug: "autoallow-bypass"}
	parseReportMd(af, content)

	assert.Contains(t, af.Title, "IsAutoAllowed", "title should come from first summary line")
}

func TestParsePromotedFindingDir_ReportPriority(t *testing.T) {
	tmp := t.TempDir()
	findingsDir := filepath.Join(tmp, "findings")
	subDir := filepath.Join(findingsDir, "C1-test-vuln")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	draft := `Phase: 10
Sequence: 001
Slug: test-vuln
Verdict: VALID
Severity-Original: CRITICAL
Severity-Final: CRITICAL
PoC-Status: theoretical

## Summary

Draft summary here.
`
	report := `# C1 — Test Vulnerability Title

**Severity**: CRITICAL
**PoC-Status**: executed
**Status**: Confirmed — PoC Executed

---

## Summary

Report summary with more detail.

## Fix

Apply the suggested patch.
`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "draft.md"), []byte(draft), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "report.md"), []byte(report), 0o644))

	af := parsePromotedFindingDir(subDir, "C1-test-vuln")
	require.NotNil(t, af)

	assert.Equal(t, "C1", af.FindingID)
	assert.Equal(t, "Test Vulnerability Title", af.Title, "title from report.md")
	assert.Equal(t, "executed", af.PoCStatus, "poc-status upgraded by report.md")
	assert.Equal(t, "VALID", af.Verdict, "verdict preserved from draft.md")
	assert.Contains(t, af.Body, "Report summary", "body should be report.md")
	assert.NotContains(t, af.Body, "Draft summary", "body should NOT be draft.md when report exists")
	assert.Contains(t, af.Remediation, "suggested patch")
}

func TestParsePromotedFindingDir_DraftOnly(t *testing.T) {
	tmp := t.TempDir()
	findingsDir := filepath.Join(tmp, "findings")
	subDir := filepath.Join(findingsDir, "M1-minor-issue")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	draft := `Phase: 10
Sequence: 001
Slug: minor-issue
Verdict: VALID
Severity-Final: MEDIUM

## Summary

A minor issue found during audit.
`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "draft.md"), []byte(draft), 0o644))

	af := parsePromotedFindingDir(subDir, "M1-minor-issue")
	require.NotNil(t, af)

	assert.Equal(t, "M1", af.FindingID)
	assert.Contains(t, af.Body, "minor issue")
}

// TestParsePromotedFindingDir_ColdVerificationOverlay covers the kong-audit
// pattern: frontmatter records only Severity-Original at promotion time and
// the post-review fields (Adversarial-Verdict, Adversarial-Rationale,
// PoC-Status) live in a "## Cold Verification" body section. The overlay
// must fill those three fields when the frontmatter is silent. Headline
// severity is governed separately by the directory prefix.
func TestParsePromotedFindingDir_ColdVerificationOverlay(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "findings", "C2-sandbox-arbitrary-sql")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	draft := `Phase: 8
Sequence: 021
Slug: sandbox-arbitrary-sql
Verdict: VALID
Severity-Original: CRITICAL

## Summary

Body summary.

## Cold Verification

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path verified by direct trace.
Severity-Final: MEDIUM
PoC-Status: theoretical

### Verification Details

PoC-Status: should-not-overwrite from sub-section prose.
`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "draft.md"), []byte(draft), 0o644))

	af := parsePromotedFindingDir(subDir, "C2-sandbox-arbitrary-sql")
	require.NotNil(t, af)

	// The directory prefix is the canonical severity, even when a body
	// downgrade is documented. Operators expect a C-prefixed dir to count
	// as Critical in the import summary.
	assert.Equal(t, "Critical", af.Severity, "directory prefix wins for headline severity")
	assert.Equal(t, "CRITICAL", af.SeverityOriginal, "frontmatter Severity-Original preserved")
	assert.Equal(t, "CONFIRMED", af.AdversarialVerdict, "body Adversarial-Verdict fills empty frontmatter slot")
	assert.Contains(t, af.AdversarialRationale, "direct trace", "body rationale fills empty slot")
	assert.Equal(t, "theoretical", af.PoCStatus, "body PoC-Status overlays empty frontmatter slot")
}

// TestParsePromotedFindingDir_ColdVerificationFrontmatterWins ensures the
// overlay never overwrites a value the frontmatter already set.
func TestParsePromotedFindingDir_ColdVerificationFrontmatterWins(t *testing.T) {
	tmp := t.TempDir()
	subDir := filepath.Join(tmp, "findings", "H1-some-finding")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	draft := `Phase: 8
Sequence: 001
Slug: some-finding
Verdict: VALID
Severity-Original: HIGH
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Frontmatter rationale.
PoC-Status: executed

## Summary

Some summary.

## Cold Verification

Adversarial-Verdict: REJECTED
Adversarial-Rationale: Body rationale should not win.
PoC-Status: theoretical
`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "draft.md"), []byte(draft), 0o644))

	af := parsePromotedFindingDir(subDir, "H1-some-finding")
	require.NotNil(t, af)

	assert.Equal(t, "High", af.Severity, "directory prefix High wins")
	assert.Equal(t, "CONFIRMED", af.AdversarialVerdict, "frontmatter wins over body")
	assert.Contains(t, af.AdversarialRationale, "Frontmatter")
	assert.Equal(t, "executed", af.PoCStatus)
}

func TestDetectPoCFile(t *testing.T) {
	tmp := t.TempDir()

	// No poc file
	assert.Equal(t, "", detectPoCFile(tmp))

	// Add poc.py
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "poc.py"), []byte("#!/usr/bin/env python3\n"), 0o644))
	assert.Equal(t, "poc.py", detectPoCFile(tmp))
}

func TestParsePromotedFindingDir_WithPoCAndMetadata(t *testing.T) {
	tmp := t.TempDir()
	findingsDir := filepath.Join(tmp, "findings")
	subDir := filepath.Join(findingsDir, "C1-variant-finding")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	draft := `Phase: 10
Sequence: 001
Slug: variant-finding
Verdict: VALID
Severity-Final: CRITICAL

## Summary

A variant of H6.
`
	metadata := `{
  "is_variant": true,
  "origin_finding_id": "H6",
  "origin_pattern": "AP-065"
}
`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "draft.md"), []byte(draft), 0o644))
	pocScript := "#!/usr/bin/env python3\nprint('exploit')\n"
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "poc.py"), []byte(pocScript), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "metadata.json"), []byte(metadata), 0o644))

	af := parsePromotedFindingDir(subDir, "C1-variant-finding")
	require.NotNil(t, af)

	assert.Equal(t, "poc.py", af.PoCFile)
	assert.Equal(t, pocScript, af.PoCContent)
	assert.True(t, af.IsVariant)
	assert.Equal(t, "H6", af.OriginFindingID)

	// Verify tags and PoC content flow through to database finding
	dbFinding := toDBFinding(af, "test-audit", "test-run", "test-project", "test-repo")
	assert.Contains(t, dbFinding.Tags, "poc-available")
	assert.Contains(t, dbFinding.Tags, "variant-of:H6")
	assert.Contains(t, dbFinding.Description, "## Proof of Concept (`poc.py`)")
	assert.Contains(t, dbFinding.Description, "```py")
	assert.Contains(t, dbFinding.Description, "print('exploit')")
}

// TestParsePromotedFindings_DirPrefixSeverityGoverns replaces the former
// real-corpus kong/ollama/grafana tests. It builds a synthetic mixed
// findings/ tree (2 C, 3 H, 4 M directory-per-finding) where every draft.md
// documents a body "## Cold Verification" downgrade to LOW. The directory
// prefix must remain the headline severity for the aggregate count, while
// the body block still fills empty non-severity slots (Adversarial-Verdict)
// and never overrides a frontmatter value that is already set (PoC-Status).
func TestParsePromotedFindings_DirPrefixSeverityGoverns(t *testing.T) {
	findingsDir := filepath.Join(t.TempDir(), "findings")

	// draft with the body downgrade. frontmatterPoC, when non-empty, sets a
	// frontmatter PoC-Status that must win over the body's "theoretical".
	draft := func(origSeverity, frontmatterPoC string) string {
		fm := ""
		if frontmatterPoC != "" {
			fm = "PoC-Status: " + frontmatterPoC + "\n"
		}
		return fmt.Sprintf(`Phase: 8
Sequence: 001
Verdict: VALID
Severity-Original: %s
%s
## Summary

Synthetic body.

## Cold Verification

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path verified by direct trace.
Severity-Final: LOW
PoC-Status: theoretical
`, origSeverity, fm)
	}

	mk := func(name, body string) {
		writeFixtureFile(t, filepath.Join(findingsDir, name, "draft.md"), body)
	}
	// C1: frontmatter PoC-Status pending → must win over body theoretical.
	mk("C1-pending-poc", draft("CRITICAL", "pending"))
	// C2: no frontmatter PoC-Status → body fills the empty slot.
	mk("C2-empty-poc", draft("CRITICAL", ""))
	for _, n := range []string{"H1-a", "H2-b", "H3-c"} {
		mk(n, draft("HIGH", ""))
	}
	for _, n := range []string{"M1-a", "M2-b", "M3-c", "M4-d"} {
		mk(n, draft("MEDIUM", ""))
	}

	findings, err := parsePromotedFindings(findingsDir)
	require.NoError(t, err)
	require.Len(t, findings, 9)

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	assert.Equal(t, 2, counts["Critical"], "2 C-prefixed dirs → 2 Critical")
	assert.Equal(t, 3, counts["High"], "3 H-prefixed dirs → 3 High")
	assert.Equal(t, 4, counts["Medium"], "4 M-prefixed dirs → 4 Medium")
	assert.Equal(t, 0, counts["Low"], "body Severity-Final downgrade must not change headline severity")

	byID := map[string]*Finding{}
	for _, f := range findings {
		byID[f.FindingID] = f
	}

	c1 := byID["C1"]
	require.NotNil(t, c1)
	assert.Equal(t, "Critical", c1.Severity, "C1 dir-prefix overrides body downgrade")
	assert.Equal(t, "CRITICAL", c1.SeverityOriginal, "frontmatter Severity-Original preserved")
	assert.Equal(t, "pending", c1.PoCStatus, "frontmatter PoC-Status wins over body")

	c2 := byID["C2"]
	require.NotNil(t, c2)
	assert.Equal(t, "Critical", c2.Severity, "C2 dir-prefix overrides body downgrade")
	assert.Equal(t, "CONFIRMED", c2.AdversarialVerdict, "body Cold Verification fills empty Adversarial-Verdict")
	assert.Equal(t, "theoretical", c2.PoCStatus, "body PoC-Status overlays empty frontmatter slot")
}

func TestParseMdSections(t *testing.T) {
	content := `## Summary

Some summary.

## Fix

Apply the patch to fix it.

## Impact

High impact.
`
	source := []byte(content)
	reader := text.NewReader(source)
	doc := mdParser.Parse(reader)
	sections := parseMdSections(doc, source)

	assert.Contains(t, sections.sectionBody("Fix"), "Apply the patch")
	assert.Contains(t, sections.sectionBody("Impact"), "High impact")
	assert.Equal(t, "", sections.sectionBody("Nonexistent"))

	// Case-insensitive
	assert.Contains(t, sections.sectionBody("fix"), "Apply the patch")
}

func TestMaxBacktickRun(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 2},
		{"no backticks here", 2},
		{"one ` backtick", 2},
		{"two `` backticks", 2},
		{"three ``` backticks", 3},
		{"four ```` backticks", 4},
		{"mixed `` and ```` runs", 4},
		{"```\nfoo\n```", 3},
		{"poc with ```json\n{...}\n``` inside", 3},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := maxBacktickRun(tc.in); got != tc.want {
				t.Errorf("maxBacktickRun(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
