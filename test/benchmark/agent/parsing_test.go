//go:build agent_benchmark

package agent

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestParsing_All loads all parsing definitions and runs each.
func TestParsing_All(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "parsing")
	defs, err := harness.LoadAgentParsingDefinitionsFromDir(dir)
	require.NoError(t, err, "failed to load parsing definitions")
	require.NotEmpty(t, defs, "no parsing definitions found in %s", dir)

	for _, def := range defs {
		t.Run(def.Fixture, func(t *testing.T) {
			runParsingDefinition(t, def)
		})
	}
}

func TestParsing_GinFindings(t *testing.T) {
	runParsingForFixture(t, "gin-findings-parsing.yaml")
}

func TestParsing_GinRecords(t *testing.T) {
	runParsingForFixture(t, "gin-records-parsing.yaml")
}

func TestParsing_FlaskFindings(t *testing.T) {
	runParsingForFixture(t, "flask-findings-parsing.yaml")
}

func TestParsing_FlaskRecords(t *testing.T) {
	runParsingForFixture(t, "flask-records-parsing.yaml")
}

// TestParsing_EmptyOutput validates that empty/whitespace output returns an error.
func TestParsing_EmptyOutput(t *testing.T) {
	cases := []string{"", "   ", "\n\n"}
	for _, raw := range cases {
		_, err := agent.ParseFindings(raw)
		assert.Error(t, err, "expected error for empty output %q", raw)

		_, err = agent.ParseHTTPRecords(raw)
		assert.Error(t, err, "expected error for empty output %q", raw)
	}
}

// TestParsing_MalformedJSON validates error handling for bad JSON.
func TestParsing_MalformedJSON(t *testing.T) {
	malformed := []string{
		"this is not json",
		"{invalid json",
		"```json\n{broken}\n```",
	}
	for _, raw := range malformed {
		_, err := agent.ParseFindings(raw)
		assert.Error(t, err, "expected error for malformed JSON %q", raw)
	}
}

// TestParsing_MarkdownFences validates JSON extraction from markdown fences.
func TestParsing_MarkdownFences(t *testing.T) {
	raw := "Here are the findings:\n```json\n{\"findings\": [{\"title\": \"Test\", \"severity\": \"low\"}]}\n```\nDone."
	findings, err := agent.ParseFindings(raw)
	require.NoError(t, err, "should parse JSON from markdown fences")
	assert.Len(t, findings, 1)
	assert.Equal(t, "Test", findings[0].Title)
}

// TestParsing_BareArray validates parsing of bare JSON arrays.
func TestParsing_BareArray(t *testing.T) {
	raw := `[{"method": "GET", "url": "http://localhost/test"}]`
	records, err := agent.ParseHTTPRecords(raw)
	require.NoError(t, err, "should parse bare JSON array")
	assert.Len(t, records, 1)
	assert.Equal(t, "GET", records[0].Method)
}

func runParsingForFixture(t *testing.T, filename string) {
	t.Helper()
	defPath := filepath.Join(definitionsDir(), "parsing", filename)
	def, err := harness.LoadAgentParsingDefinition(defPath)
	require.NoError(t, err, "failed to load parsing definition %s", filename)
	runParsingDefinition(t, def)
}

func runParsingDefinition(t *testing.T, def *harness.AgentParsingDefinition) {
	t.Helper()

	fPath := fixturePath(def.Fixture)
	fixture, err := harness.LoadAgentFixture(fPath)
	require.NoError(t, err, "failed to load fixture %s", fPath)

	switch def.OutputSchema {
	case "findings":
		findings, parseErr := agent.ParseFindings(fixture.RawOutput)
		if def.Expected.Error {
			assert.Error(t, parseErr, "[%s] expected parse error", def.Fixture)
			return
		}
		require.NoError(t, parseErr, "[%s] unexpected parse error", def.Fixture)

		t.Logf("[%s] Parsed %d findings", def.Fixture, len(findings))
		for _, f := range findings {
			t.Logf("  Finding: title=%q severity=%s cwe=%s", f.Title, f.Severity, f.CWE)
		}

		assert.Equal(t, def.Expected.FindingCount, len(findings),
			"[%s] expected %d findings, got %d", def.Fixture, def.Expected.FindingCount, len(findings))

		// Validate required fields
		for _, rf := range def.Expected.RequiredFields {
			for i, f := range findings {
				if rf.NonEmpty {
					val := getFieldValue(f, rf.Field)
					assert.NotEmpty(t, val,
						"[%s] finding[%d] field %q should not be empty", def.Fixture, i, rf.Field)
				}
			}
		}

	case "http_records":
		records, parseErr := agent.ParseHTTPRecords(fixture.RawOutput)
		if def.Expected.Error {
			assert.Error(t, parseErr, "[%s] expected parse error", def.Fixture)
			return
		}
		require.NoError(t, parseErr, "[%s] unexpected parse error", def.Fixture)

		t.Logf("[%s] Parsed %d records", def.Fixture, len(records))
		for _, r := range records {
			t.Logf("  Record: %s %s", r.Method, r.URL)
		}

		assert.Equal(t, def.Expected.RecordCount, len(records),
			"[%s] expected %d records, got %d", def.Fixture, def.Expected.RecordCount, len(records))

		// Validate required fields
		for _, rf := range def.Expected.RequiredFields {
			for i, r := range records {
				if rf.NonEmpty {
					val := getRecordFieldValue(r, rf.Field)
					assert.NotEmpty(t, val,
						"[%s] record[%d] field %q should not be empty", def.Fixture, i, rf.Field)
				}
			}
		}

	default:
		t.Fatalf("[%s] unknown output_schema: %s", def.Fixture, def.OutputSchema)
	}
}

// getFieldValue returns the value of a named field from an AgentFinding.
func getFieldValue(f agent.AgentFinding, field string) string {
	switch field {
	case "title":
		return f.Title
	case "description":
		return f.Description
	case "severity":
		return f.Severity
	case "confidence":
		return f.Confidence
	case "file":
		return f.File
	case "cwe":
		return f.CWE
	case "snippet":
		return f.Snippet
	default:
		return ""
	}
}

// getRecordFieldValue returns the value of a named field from an AgentHTTPRecord.
func getRecordFieldValue(r agent.AgentHTTPRecord, field string) string {
	switch field {
	case "method":
		return r.Method
	case "url":
		return r.URL
	case "body":
		return r.Body
	case "notes":
		return r.Notes
	default:
		return ""
	}
}
