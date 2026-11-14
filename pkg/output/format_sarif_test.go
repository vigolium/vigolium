package output

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// findingEnvelope builds the export envelope shape buildReportData consumes, so
// these tests exercise the same entry point the real export path uses.
func findingEnvelope(fields map[string]any) map[string]any {
	return map[string]any{"type": "finding", "data": fields}
}

func buildLog(t *testing.T, items []any) sarifLog {
	t.Helper()
	log := buildSARIFLog(items, HTMLReportMeta{Version: "1.2.3", GeneratedAt: "2026-04-18T03:00:00Z"})
	// Round-tripping through JSON is the point of the format: a struct that
	// marshals to something a consumer rejects is not a passing test.
	raw, err := json.Marshal(log)
	require.NoError(t, err)
	var back sarifLog
	require.NoError(t, json.Unmarshal(raw, &back))
	return log
}

func TestSARIFLogSkeleton(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"id": 1, "module_id": "xss-reflected", "module_name": "Reflected XSS",
		"severity": "high", "url": "https://target.example.com/search?q=1",
	})})

	assert.Equal(t, "2.1.0", log.Version)
	assert.Equal(t, sarifSchemaURI, log.Schema)
	require.Len(t, log.Runs, 1)
	assert.Equal(t, "Vigolium", log.Runs[0].Tool.Driver.Name)
	assert.Equal(t, "1.2.3", log.Runs[0].Tool.Driver.Version)
	require.Len(t, log.Runs[0].Invocations, 1)
	assert.Equal(t, "2026-04-18T03:00:00Z", log.Runs[0].Invocations[0].EndTimeUTC)
}

// A clean scan must still be a well-formed run. An omitted results array reads
// to a consumer as a malformed file rather than as zero findings.
func TestSARIFEmptyRunSerializesEmptyArrays(t *testing.T) {
	log := buildSARIFLog(nil, HTMLReportMeta{})
	raw, err := json.Marshal(log)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"results":[]`)
	assert.Contains(t, string(raw), `"rules":[]`)
}

func TestSARIFResultsOrderedBySeverity(t *testing.T) {
	log := buildLog(t, []any{
		findingEnvelope(map[string]any{"module_id": "a", "severity": "low", "url": "https://t.example.com/a"}),
		findingEnvelope(map[string]any{"module_id": "b", "severity": "critical", "url": "https://t.example.com/b"}),
		findingEnvelope(map[string]any{"module_id": "c", "severity": "medium", "url": "https://t.example.com/c"}),
	})
	results := log.Runs[0].Results
	require.Len(t, results, 3)
	assert.Equal(t, "b", results[0].RuleID)
	assert.Equal(t, "c", results[1].RuleID)
	assert.Equal(t, "a", results[2].RuleID)
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[string]string{
		"critical": "error", "high": "error", "medium": "warning",
		"low": "note", "info": "note", "": "note",
	}
	for severity, want := range cases {
		assert.Equal(t, want, sarifLevel(severity), "severity %q", severity)
	}
}

// Info must not map to "none": consumers filter "none" out entirely, which
// would erase every informational observation from the export.
func TestSARIFInfoIsNoteNotNone(t *testing.T) {
	assert.NotEqual(t, "none", sarifLevel("info"))
}

func TestSARIFSecuritySeverityPrefersCVSS(t *testing.T) {
	assert.Equal(t, "8.8", sarifSecuritySeverity("medium", 8.8))
	assert.Equal(t, "9.5", sarifSecuritySeverity("critical", 0))
	assert.Equal(t, "3.0", sarifSecuritySeverity("low", 0))
	// Info gets no rating rather than a 0.0 a consumer would bucket unpredictably.
	assert.Equal(t, "", sarifSecuritySeverity("info", 0))
}

func TestSARIFCWETagsZeroPadded(t *testing.T) {
	assert.Equal(t, []string{"external/cwe/cwe-079"}, sarifCWETags("CWE-79"))
	assert.Equal(t, []string{"external/cwe/cwe-079", "external/cwe/cwe-080"}, sarifCWETags("CWE-79, CWE-80"))
	assert.Equal(t, []string{"external/cwe/cwe-089"}, sarifCWETags("89"))
	assert.Equal(t, []string{"external/cwe/cwe-1333"}, sarifCWETags("CWE-1333"))
	assert.Nil(t, sarifCWETags(""))
	assert.Nil(t, sarifCWETags("n/a"))
}

// A code finding anchors to its file so a consumer can annotate a diff; the
// trailing ":28" is a line number, not part of the path.
func TestSARIFSourceFindingAnchorsToFileWithLine(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "audit-sqli", "severity": "high",
		"source_file": "app/routes/auth.py:28", "repo_name": "shop-api",
	})})
	loc := log.Runs[0].Results[0].Locations
	require.Len(t, loc, 1)
	assert.Equal(t, "app/routes/auth.py", loc[0].PhysicalLocation.ArtifactLocation.URI)
	require.NotNil(t, loc[0].PhysicalLocation.Region)
	assert.Equal(t, 28, loc[0].PhysicalLocation.Region.StartLine)
}

func TestSARIFSourceFindingLineAndColumn(t *testing.T) {
	loc, ok := sarifSourceLocation("src/a.ts:12:5", "")
	require.True(t, ok)
	assert.Equal(t, "src/a.ts", loc.PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 12, loc.PhysicalLocation.Region.StartLine)
	assert.Equal(t, 5, loc.PhysicalLocation.Region.StartColumn)
}

// An absolute audit path is made repo-relative through the repo directory name,
// which is what makes the result annotatable. Without a match the path is kept
// verbatim — a guessed prefix strip points the annotation at the wrong file.
func TestSARIFAbsoluteSourcePathMadeRepoRelative(t *testing.T) {
	assert.Equal(t, "app/routes/auth.py",
		sarifSourceURI("/opt/repos/shop-api/app/routes/auth.py", "shop-api"))
	assert.Equal(t, "app/routes/auth.py",
		sarifSourceURI("/opt/repos/shop-api/app/routes/auth.py", "https://github.example.com/acme/shop-api.git"))
	assert.Equal(t, "/opt/repos/other/app.py",
		sarifSourceURI("/opt/repos/other/app.py", "shop-api"))
	assert.Equal(t, "/opt/repos/other/app.py",
		sarifSourceURI("/opt/repos/other/app.py", ""))
}

// A Windows drive letter is not a line number.
func TestSARIFWindowsDriveNotParsedAsLine(t *testing.T) {
	file, line, _ := splitSourceRef(`C:\src\a.cs`)
	assert.Equal(t, `C:\src\a.cs`, file)
	assert.Zero(t, line)
}

func TestSARIFHTTPFindingAnchorsToURL(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "xss-reflected", "severity": "high",
		"url": "https://target.example.com/search?q=%3Cscript%3E",
	})})
	loc := log.Runs[0].Results[0].Locations
	require.Len(t, loc, 1)
	assert.Equal(t, "https://target.example.com/search?q=%3Cscript%3E",
		loc[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Nil(t, loc[0].PhysicalLocation.Region)
}

// A bare parameter name is evidence, not a location: emitting it as an artifact
// URI produces a viewer entry pointing at a file that cannot exist.
func TestSARIFNonURIEvidenceIsNotALocation(t *testing.T) {
	_, ok := sarifURILocation("q")
	assert.False(t, ok)
	_, ok = sarifURILocation("/just/a/path")
	assert.False(t, ok)
	_, ok = sarifURILocation("https://target.example.com/x")
	assert.True(t, ok)
}

func TestSARIFMatchedAtBecomesRelatedLocation(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "open-redirect", "severity": "medium",
		"url":        "https://target.example.com/go",
		"matched_at": []string{"https://target.example.com/go?next=x", "redirect_uri"},
	})})
	res := log.Runs[0].Results[0]
	// The URI-shaped one becomes a location; the bare parameter name stays in
	// properties where it reads correctly.
	require.Len(t, res.RelatedLocations, 1)
	assert.Equal(t, "https://target.example.com/go?next=x",
		res.RelatedLocations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Contains(t, res.Properties["matchedAt"], "redirect_uri")
}

func TestSARIFWebRequestAndResponseParsed(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "sqli", "severity": "critical",
		"url":      "https://target.example.com/api/login",
		"request":  "POST /api/login HTTP/1.1\r\nHost: target.example.com\r\nContent-Type: application/json\r\n\r\n{\"u\":\"' OR 1=1--\"}",
		"response": "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nSQL syntax error",
	})})
	res := log.Runs[0].Results[0]

	require.NotNil(t, res.WebRequest)
	assert.Equal(t, "POST", res.WebRequest.Method)
	assert.Equal(t, "/api/login", res.WebRequest.Target)
	assert.Equal(t, "1.1", res.WebRequest.Version)
	assert.Equal(t, "http", res.WebRequest.Protocol)
	assert.Equal(t, "target.example.com", res.WebRequest.Headers["Host"])
	require.NotNil(t, res.WebRequest.Body)
	assert.Contains(t, res.WebRequest.Body.Text, "OR 1=1--")

	require.NotNil(t, res.WebResponse)
	assert.Equal(t, 500, res.WebResponse.StatusCode)
	assert.Equal(t, "Internal Server Error", res.WebResponse.ReasonPhrase)
	// Repeated headers are joined, not last-wins: dropping a Set-Cookie loses
	// evidence the finding may rest on. Values are redacted by default;
	// names survive.
	assert.Equal(t, "a=<redacted>, b=<redacted>", res.WebResponse.Headers["Set-Cookie"])
	assert.Equal(t, "SQL syntax error", res.WebResponse.Body.Text)
}

func TestSARIFWebMessageAcceptsLFOnlySeparator(t *testing.T) {
	req := parseSARIFWebRequest("GET /x HTTP/1.1\nHost: h.example.com\n\nbody")
	require.NotNil(t, req)
	assert.Equal(t, "h.example.com", req.Headers["Host"])
	assert.Equal(t, "body", req.Body.Text)
}

func TestSARIFNoExchangeYieldsNoWebFields(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "passive-header", "severity": "info", "url": "https://target.example.com/",
	})})
	assert.Nil(t, log.Runs[0].Results[0].WebRequest)
	assert.Nil(t, log.Runs[0].Results[0].WebResponse)
}

func TestSARIFBodiesTruncated(t *testing.T) {
	huge := strings.Repeat("A", sarifMaxBodyBytes*3)
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "big", "severity": "low", "url": "https://target.example.com/",
		"response": "HTTP/1.1 200 OK\r\n\r\n" + huge,
	})})
	res := log.Runs[0].Results[0]
	assert.Less(t, len(res.WebResponse.Body.Text), len(huge))
	// Truncation is recorded rather than silent.
	assert.Equal(t, true, res.Properties["evidenceTruncated"])
}

// The finding hash is what lets a consumer track one finding across re-scans
// instead of closing and reopening an alert every run.
func TestSARIFPartialFingerprintCarriesFindingHash(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "x", "severity": "high", "url": "https://target.example.com/",
		"finding_hash": "deadbeef",
	})})
	assert.Equal(t, "deadbeef",
		log.Runs[0].Results[0].PartialFingerprints["vigoliumFindingHash/v2"])
}

func TestSARIFRulesDedupedAndIndexed(t *testing.T) {
	log := buildLog(t, []any{
		findingEnvelope(map[string]any{"module_id": "xss", "module_name": "XSS", "severity": "medium", "url": "https://t.example.com/1"}),
		findingEnvelope(map[string]any{"module_id": "xss", "module_name": "XSS", "severity": "high", "url": "https://t.example.com/2", "cwe_id": "CWE-79"}),
		findingEnvelope(map[string]any{"module_id": "sqli", "module_name": "SQLi", "severity": "critical", "url": "https://t.example.com/3"}),
	})
	run := log.Runs[0]
	require.Len(t, run.Tool.Driver.Rules, 2)
	for _, res := range run.Results {
		require.Less(t, res.RuleIndex, len(run.Tool.Driver.Rules))
		assert.Equal(t, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID,
			"ruleIndex must address the rule named by ruleId")
	}
}

// A module whose findings differ in severity keeps the most severe as its rule
// default; each result still carries its own level.
func TestSARIFRuleWidensToHighestSeverity(t *testing.T) {
	log := buildLog(t, []any{
		findingEnvelope(map[string]any{"module_id": "xss", "severity": "critical", "url": "https://t.example.com/1"}),
		findingEnvelope(map[string]any{"module_id": "xss", "severity": "low", "url": "https://t.example.com/2", "cwe_id": "CWE-79"}),
	})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "error", rule.DefaultConfiguration.Level)
	// The CWE arrived on the *second* finding and must still reach the rule.
	assert.Contains(t, rule.Properties["tags"], "external/cwe/cwe-079")
	assert.Equal(t, "note", log.Runs[0].Results[1].Level)
}

// Suspect is a real severity in pkg/types/severity; a locally re-typed ladder
// that omits it ranks a suspect finding below info.
func TestSARIFSuspectSeverityRanksAboveInfo(t *testing.T) {
	assert.Greater(t, severity.ToSeverity("suspect"), severity.ToSeverity("info"))
	assert.Equal(t, "note", sarifLevel("suspect"))
}

// The rule keeps the FIRST finding's band at a given severity: re-deriving the
// rank from the emitted level made critical and high indistinguishable, so a
// later critical always compared as an upgrade and overwrote the CVSS.
func TestSARIFEqualSeverityDoesNotOverwriteRuleCVSS(t *testing.T) {
	log := buildLog(t, []any{
		findingEnvelope(map[string]any{"module_id": "x", "severity": "critical", "cvss_score": 9.8, "url": "https://t.example.com/1"}),
		findingEnvelope(map[string]any{"module_id": "x", "severity": "critical", "cvss_score": 7.0, "url": "https://t.example.com/2"}),
	})
	assert.Equal(t, "9.8", log.Runs[0].Tool.Driver.Rules[0].Properties["security-severity"])
}

// A finding whose only anchor is an evidence URL must not have that URL emitted
// as both its location and a related location.
func TestSARIFPrimaryAnchorNotRepeatedInRelated(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "x", "severity": "high",
		"matched_at": []string{"https://target.example.com/only", "https://target.example.com/other"},
	})})
	res := log.Runs[0].Results[0]
	require.Len(t, res.Locations, 1)
	assert.Equal(t, "https://target.example.com/only", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	require.Len(t, res.RelatedLocations, 1)
	assert.Equal(t, "https://target.example.com/other", res.RelatedLocations[0].PhysicalLocation.ArtifactLocation.URI)
}

// A URL repeated in MatchedAt is the same anchor, not a second one.
func TestSARIFDuplicateURLAnchorDeduped(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "x", "severity": "high",
		"url":        "https://target.example.com/a",
		"matched_at": []string{"https://target.example.com/a"},
	})})
	assert.Empty(t, log.Runs[0].Results[0].RelatedLocations)
}

// Binary evidence carries nothing a consumer can read but ~4x its size in
// escape sequences, against a format that caps bodies precisely for size.
func TestSARIFBinaryBodyOmitted(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "x", "severity": "low", "url": "https://t.example.com/",
		"response": "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\xff\xfe\xfd",
	})})
	res := log.Runs[0].Results[0]
	require.NotNil(t, res.WebResponse)
	assert.Equal(t, 200, res.WebResponse.StatusCode, "headers still parsed")
	assert.Nil(t, res.WebResponse.Body, "binary body dropped rather than escaped")
}

// A still-compressed body is unreadable and undecodable at this layer (the
// export's json.Marshal round-trip destroys the bytes before the renderer sees
// them), so it must be dropped rather than embedded as replacement characters.
func TestSARIFGzipBodyDropped(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte("SQL syntax error near 'OR 1=1'"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "sqli", "severity": "critical", "url": "https://t.example.com/",
		"response": "HTTP/1.1 500 Internal Server Error\r\nContent-Encoding: gzip\r\n\r\n" + buf.String(),
	})})
	res := log.Runs[0].Results[0]
	assert.Equal(t, 500, res.WebResponse.StatusCode, "headers still parsed")
	assert.Nil(t, res.WebResponse.Body)
}

// Plain text with the odd accented character is not binary.
func TestSARIFTextBodyKept(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "x", "severity": "low", "url": "https://t.example.com/",
		"response": "HTTP/1.1 200 OK\r\n\r\n{\"error\":\"café — naïve\"}",
	})})
	body := log.Runs[0].Results[0].WebResponse.Body
	require.NotNil(t, body)
	assert.Contains(t, body.Text, "café")
}

// Evidence lists are the other half of the size problem the body cap addresses.
func TestSARIFEvidenceStringsCapped(t *testing.T) {
	huge := strings.Repeat("E", sarifMaxEvidenceBytes*3)
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "x", "severity": "low", "url": "https://t.example.com/",
		"additional_evidence": []string{huge}, "remediation": huge,
	})})
	props := log.Runs[0].Results[0].Properties
	assert.Less(t, len(props["additionalEvidence"].([]string)[0]), len(huge))
	assert.Less(t, len(props["remediation"].(string)), len(huge))
}

func TestSARIFRuleUsesModuleDescriptionWhenExported(t *testing.T) {
	log := buildLog(t, []any{
		map[string]any{"type": "module", "data": map[string]any{
			"id": "xss", "name": "XSS", "type": "active", "enabled": true,
			"description": "Detects reflected cross-site scripting.",
		}},
		findingEnvelope(map[string]any{"module_id": "xss", "module_name": "XSS", "severity": "high", "url": "https://t.example.com/1"}),
	})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	require.NotNil(t, rule.FullDescription)
	assert.Equal(t, "Detects reflected cross-site scripting.", rule.FullDescription.Text)
}

// Module envelopes are excluded from `vigolium export` by default, so a SARIF
// file must describe its own rules without them.
func TestSARIFRulesSynthesizedWithoutModuleEnvelopes(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "xss", "module_name": "Reflected XSS", "severity": "high",
		"module_short": "Detects reflected cross-site scripting in query parameters.",
		"url":          "https://t.example.com/1", "remediation": "Encode output.",
	})})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "xss", rule.ID)
	// name is the compact module name, not the sentence-shaped short
	// description the HTML/markdown reports display in its place.
	assert.Equal(t, "Reflected XSS", rule.Name)
	require.NotNil(t, rule.ShortDescription)
	assert.Equal(t, "Detects reflected cross-site scripting in query parameters.", rule.ShortDescription.Text)
	require.NotNil(t, rule.Help)
	assert.Equal(t, "Encode output.", rule.Help.Text)
	assert.Contains(t, rule.Properties["tags"], "security")
}

func TestSARIFFindingWithoutModuleIDStillGetsRule(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"severity": "high", "url": "https://t.example.com/1",
	})})
	require.Len(t, log.Runs[0].Tool.Driver.Rules, 1)
	assert.NotEmpty(t, log.Runs[0].Results[0].RuleID)
}

// Vigolium evidence is full of &, < and > — Go's default HTML escaping would
// rewrite every one of them and mangle a consumer that string-matches a payload.
func TestSARIFFileNotHTMLEscaped(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "run.sarif")
	require.NoError(t, GenerateSARIFReport([]any{findingEnvelope(map[string]any{
		"module_id": "xss", "severity": "high",
		"url":      "https://target.example.com/s?q=a&b=c",
		"response": "HTTP/1.1 200 OK\r\n\r\n<script>alert(1)</script>",
	})}, out, HTMLReportMeta{}))

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "<script>alert(1)</script>")
	assert.Contains(t, string(raw), "q=a&b=c")
	assert.NotContains(t, string(raw), `\u0026`)

	var log sarifLog
	require.NoError(t, json.Unmarshal(raw, &log), "written file must be valid JSON")
	require.Len(t, log.Runs, 1)
}

func TestSARIFRankDerivedFromCVSS(t *testing.T) {
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "x", "severity": "high", "url": "https://t.example.com/",
		"cvss_score": 7.5,
	})})
	require.NotNil(t, log.Runs[0].Results[0].Rank)
	assert.InDelta(t, 75.0, *log.Runs[0].Results[0].Rank, 0.001)
}

func TestCollapseToTextStripsMarkdown(t *testing.T) {
	in := "## Summary\nA problem.\n\n```http\nGET / HTTP/1.1\n```\n"
	assert.Equal(t, "Summary\nA problem.\n\nGET / HTTP/1.1", collapseToText(in))
}

// A multibyte body cut at the cap must stay valid UTF-8: a split rune is
// re-encoded as U+FFFD by encoding/json and rejected by strict SARIF readers.
func TestSARIFTruncatedMultibyteBodyStaysValidUTF8(t *testing.T) {
	huge := "x" + strings.Repeat("日", sarifMaxBodyBytes) // 3 bytes per rune, offset by one
	log := buildLog(t, []any{findingEnvelope(map[string]any{
		"module_id": "big", "severity": "low", "url": "https://target.example.com/",
		"response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + huge,
	})})
	text := log.Runs[0].Results[0].WebResponse.Body.Text
	require.NotEmpty(t, text)
	assert.True(t, utf8.ValidString(text), "truncated SARIF body split a rune")
	raw, err := json.Marshal(log)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `�`)
}
